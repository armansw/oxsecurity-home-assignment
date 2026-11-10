import fs from 'node:fs';
import path from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { ScanError } from '../../src/domain/errors.js';
import { GitRepositoryFetcher, classifyGitError } from '../../src/infrastructure/git/git-repository-fetcher.js';
import { CommandError } from '../../src/infrastructure/process/run-command.js';
import { TrivyScanner, classifyTrivyError, trivyReason } from '../../src/infrastructure/scanner/trivy-scanner.js';
import { FixtureScanner } from '../../src/infrastructure/scanner/fixture-scanner.js';
import { fakeBinary, tempDir } from '../helpers/index.js';

const cmdErr = (kind: CommandError['kind'], stderr = '', signal: NodeJS.Signals | null = null, code: number | null = 1) =>
  new CommandError(kind, 'x', code, signal, stderr);
const signal = () => new AbortController().signal;

describe('GitRepositoryFetcher', () => {
  let dir: string;
  beforeAll(() => {
    dir = tempDir();
  });
  afterAll(() => {
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('runs a shallow, hardened clone with the URL after `--`, then reports the commit', async () => {
    const argsFile = path.join(dir, 'git-args');
    const envFile = path.join(dir, 'git-env');
    const sha = '0123456789abcdef0123456789abcdef01234567';
    const git = fakeBinary(
      dir,
      'git',
      `if [ "$3" = rev-parse ]; then echo ${sha}; exit 0; fi; printf '%s\\n' "$@" > ${argsFile}; env > ${envFile}; for a; do last=$a; done; mkdir -p "$last/.git/objects/pack" "$last/src"`,
    );
    const dest = path.join(dir, 'dest');
    const result = await new GitRepositoryFetcher({ gitBin: git, timeoutMs: 5000 }).clone('https://github.com/a/b.git', dest, signal());
    expect(result).toEqual({ commitSha: sha });
    expect(fs.existsSync(path.join(dest, '.git'))).toBe(false); // packfile cache released before scanning
    expect(fs.existsSync(path.join(dest, 'src'))).toBe(true); // working tree kept
    let text = '';
    for await (const chunk of fs.createReadStream(argsFile, 'utf8')) text += String(chunk);
    expect(text.trim().split('\n')).toEqual([
      '-c', 'protocol.file.allow=never', '-c', 'credential.helper=', '-c', 'pack.threads=1', '-c', 'core.deltaBaseCacheLimit=8m',
      '-c', 'core.packedGitLimit=32m', '-c', 'core.packedGitWindowSize=1m', 'clone', '--depth', '1', '--single-branch',
      '--no-tags', '--no-recurse-submodules', '--', 'https://github.com/a/b.git', dest,
    ]);
    let env = '';
    for await (const chunk of fs.createReadStream(envFile, 'utf8')) env += String(chunk);
    expect(env).toContain('GIT_TERMINAL_PROMPT=0');
    expect(env).toContain('GIT_CONFIG_GLOBAL=/dev/null');
  });

  it('fails the clone when the commit cannot be determined', async () => {
    const git = fakeBinary(dir, 'git-nosha', 'if [ "$3" = rev-parse ]; then echo "not-a-sha"; fi; exit 0');
    await expect(new GitRepositoryFetcher({ gitBin: git, timeoutMs: 5000 }).clone('u', 'd', signal())).rejects.toMatchObject({
      code: 'CLONE_FAILED',
    });
  });

  it('classifies a failing clone', async () => {
    const git = fakeBinary(dir, 'git-404', `echo "remote: Repository not found." >&2; exit 128`);
    await expect(new GitRepositoryFetcher({ gitBin: git, timeoutMs: 5000 }).clone('u', 'd', signal())).rejects.toMatchObject({
      code: 'REPO_NOT_FOUND',
      retryable: false,
    });
  });

  it.each([
    [cmdErr('timeout'), 'CLONE_TIMEOUT', true],
    [cmdErr('spawn'), 'INTERNAL', false],
    [cmdErr('exit', 'fatal: write error: No space left on device'), 'DISK_FULL', true],
    [cmdErr('exit', 'fatal: could not read Username for https://github.com'), 'REPO_NOT_FOUND', false],
    [cmdErr('exit', 'fatal: unable to access: Could not resolve host'), 'CLONE_FAILED', true],
  ])('classifyGitError %#', (err, code, retryable) => {
    expect(classifyGitError(err)).toMatchObject({ code, retryable });
  });

  it('passes through aborts and unknown errors', () => {
    const aborted = cmdErr('aborted');
    const other = new Error('x');
    expect(classifyGitError(aborted)).toBe(aborted);
    expect(classifyGitError(other)).toBe(other);
  });
});

describe('TrivyScanner', () => {
  let dir: string;
  beforeAll(() => {
    dir = tempDir();
  });
  afterAll(() => {
    fs.rmSync(dir, { recursive: true, force: true });
  });

  const scanner = (bin: string, extra: Partial<ConstructorParameters<typeof TrivyScanner>[0]> = {}) =>
    new TrivyScanner({ trivyBin: bin, timeoutMs: 5000, cacheDir: '/cache', goMemLimit: '64MiB', ...extra });

  it('runs trivy fs with JSON output (client/server mode) and checks the report', async () => {
    const argsFile = path.join(dir, 'trivy-args');
    // Write `{}` to the path following --output, and record args + env.
    const bin = fakeBinary(
      dir,
      'trivy',
      `printf '%s\\n' "$@" > ${argsFile}; env | grep -E '^(GOMEMLIMIT|GOGC|TMPDIR)=' >> ${argsFile}; while [ $# -gt 0 ]; do if [ "$1" = --output ]; then echo '{}' > "$2"; fi; shift; done`,
    );
    const reportPath = path.join(dir, 'report.json');
    await scanner(bin, { serverUrl: 'http://trivy:4954', token: 't0k', offlineScan: true }).scan({ sourceDir: '/src', reportPath, tmpDir: '/tmpdir', signal: signal() });
    let text = '';
    for await (const chunk of fs.createReadStream(argsFile, 'utf8')) text += String(chunk);
    const lines = text.trim().split('\n');
    expect(lines).toEqual(
      expect.arrayContaining(['fs', '--scanners', 'vuln', '--format', 'json', '--output', reportPath, '--offline-scan', '--server', 'http://trivy:4954', '--token', 't0k', '/src', 'GOMEMLIMIT=64MiB', 'GOGC=50', 'TMPDIR=/tmpdir']),
    );
    expect(lines).not.toContain('--severity');
  });

  it('standalone mode omits --server and --token', async () => {
    const argsFile = path.join(dir, 'trivy-args-2');
    const bin = fakeBinary(dir, 'trivy2', `printf '%s\\n' "$@" > ${argsFile}; while [ $# -gt 0 ]; do if [ "$1" = --output ]; then echo '{}' > "$2"; fi; shift; done`);
    await scanner(bin, { serverUrl: 'http://s', token: undefined }).scan({ sourceDir: '/s', reportPath: path.join(dir, 'r2.json'), tmpDir: dir, signal: signal() });
    let text = '';
    for await (const chunk of fs.createReadStream(argsFile, 'utf8')) text += String(chunk);
    expect(text).toContain('--server');
    expect(text).not.toContain('--token');
    expect(text).not.toContain('--offline-scan');
  });

  it('rejects a successful run that produced no or an empty report', async () => {
    const none = fakeBinary(dir, 'trivy-none', 'exit 0');
    await expect(scanner(none).scan({ sourceDir: '/s', reportPath: path.join(dir, 'missing.json'), tmpDir: dir, signal: signal() })).rejects.toMatchObject({
      code: 'REPORT_INVALID',
    });
    const empty = fakeBinary(dir, 'trivy-empty', `while [ $# -gt 0 ]; do if [ "$1" = --output ]; then : > "$2"; fi; shift; done`);
    await expect(scanner(empty).scan({ sourceDir: '/s', reportPath: path.join(dir, 'empty.json'), tmpDir: dir, signal: signal() })).rejects.toMatchObject({
      code: 'REPORT_INVALID',
    });
  });

  it('classifies a non-zero exit', async () => {
    const bad = fakeBinary(dir, 'trivy-bad', 'echo "FATAL db error" >&2; exit 1');
    await expect(scanner(bad).scan({ sourceDir: '/s', reportPath: path.join(dir, 'x.json'), tmpDir: dir, signal: signal() })).rejects.toMatchObject({
      code: 'SCANNER_FAILED',
      retryable: true,
    });
  });

  it('checkAvailable reports availability', async () => {
    expect(await scanner(fakeBinary(dir, 'trivy-ok', 'echo Version: 0.76.1')).checkAvailable()).toEqual({ ok: true, detail: 'trivy (standalone)' });
    expect(await scanner(fakeBinary(dir, 'trivy-ok2', 'exit 0'), { serverUrl: 'http://s' }).checkAvailable()).toEqual({ ok: true, detail: 'trivy (client/server)' });
    const missing = await scanner('/nonexistent/trivy').checkAvailable();
    expect(missing.ok).toBe(false);
    expect(missing.detail).toContain('spawn');
  });

  it.each([
    [cmdErr('timeout'), 'SCAN_TIMEOUT', true],
    [cmdErr('spawn'), 'SCANNER_UNAVAILABLE', false],
    [cmdErr('exit', 'write /work/report.json: no space left on device'), 'DISK_FULL', true],
    [cmdErr('exit', '', 'SIGKILL', null), 'SCANNER_KILLED', true],
    [cmdErr('exit', 'FATAL'), 'SCANNER_FAILED', true],
    [cmdErr('exit', 'FATAL Error remote Maven repository returned 429 Too Many Requests. Retry-After: 1800.'), 'UPSTREAM_RATE_LIMITED', true],
  ])('classifyTrivyError %#', (err, code, retryable) => {
    const out = classifyTrivyError(err);
    expect(out).toBeInstanceOf(ScanError);
    expect(out).toMatchObject({ code, retryable });
  });

  it('honours Retry-After on upstream rate limits, within bounds', () => {
    const withHeader = classifyTrivyError(cmdErr('exit', '2026-11-10T20:08:40Z\tFATAL\tError\tremote Maven repository returned 429 Too Many Requests. Retry-After: 1800.'));
    expect(withHeader).toMatchObject({ code: 'UPSTREAM_RATE_LIMITED', retryAfterMs: 1_800_000 });
    expect((withHeader as ScanError).message).toContain('retrying in 30 min');
    expect(classifyTrivyError(cmdErr('exit', 'HTTP 429 Too Many Requests'))).toMatchObject({ retryAfterMs: 600_000 });
    expect(classifyTrivyError(cmdErr('exit', '429 Too Many Requests. Retry-After: 5'))).toMatchObject({ retryAfterMs: 60_000 });
    expect(classifyTrivyError(cmdErr('exit', '429 Too Many Requests. Retry-After: 99999'))).toMatchObject({ retryAfterMs: 3_600_000 });
  });

  it('puts a sanitized Trivy reason in SCANNER_FAILED messages', () => {
    const err = classifyTrivyError(
      cmdErr('exit', 'INFO starting\n2026-11-10T20:08:40Z\tFATAL\tError\tfailed to analyze /work/scan-11111111-1111-4111-8111-111111111111/repo/pom.xml: boom\n'),
    );
    expect(err).toMatchObject({ code: 'SCANNER_FAILED', message: 'Trivy exited with code 1: Error failed to analyze pom.xml: boom' });
  });

  it('trivyReason falls back to the last line, or a placeholder', () => {
    expect(trivyReason('first\nsecond line\n')).toBe('second line');
    expect(trivyReason('')).toBe('no error output');
    expect(trivyReason('x'.repeat(1000))).toHaveLength(300);
  });

  it('passes through aborts and unknown errors', () => {
    const aborted = cmdErr('aborted');
    expect(classifyTrivyError(aborted)).toBe(aborted);
    const other = new Error('x');
    expect(classifyTrivyError(other)).toBe(other);
  });
});

describe('FixtureScanner', () => {
  it('writes a synthetic report and is always available', async () => {
    const dir = tempDir();
    const reportPath = path.join(dir, 'r.json');
    const s = new FixtureScanner({ sizeMb: 0.05, criticalRatio: 0.5 });
    await s.scan({ sourceDir: dir, reportPath, tmpDir: dir, signal: signal() });
    expect(fs.statSync(reportPath).size).toBeGreaterThan(40_000);
    expect(await s.checkAvailable()).toEqual({ ok: true, detail: 'fixture (0.05 MB synthetic report)' });
    fs.rmSync(dir, { recursive: true, force: true });
  });
});
