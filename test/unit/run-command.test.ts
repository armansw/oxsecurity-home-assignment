import { describe, expect, it } from 'vitest';
import { CommandError, baseChildEnv, isNoSpaceMessage, runCommand } from '../../src/infrastructure/process/run-command.js';

const sh = (script: string, extra: Partial<Parameters<typeof runCommand>[1]> = {}) =>
  runCommand('sh', { args: ['-c', script], env: baseChildEnv(), timeoutMs: 5000, signal: new AbortController().signal, ...extra });

describe('runCommand', () => {
  it('resolves on exit 0', async () => {
    await expect(sh('exit 0')).resolves.toBe('');
  });

  it('rejects with exit details and the stderr tail', async () => {
    const err = await sh('echo "fatal: boom" >&2; exit 3').catch((e: unknown) => e);
    expect(err).toBeInstanceOf(CommandError);
    expect(err).toMatchObject({ kind: 'exit', exitCode: 3, command: 'sh' });
    expect((err as CommandError).stderrTail).toContain('fatal: boom');
    expect((err as CommandError).message).toContain('exit 3');
  });

  it('keeps only a bounded tail of stderr', async () => {
    const err = (await sh('i=0; while [ $i -lt 2000 ]; do echo "line-$i" >&2; i=$((i+1)); done; exit 1', { stderrLimit: 100 }).catch(
      (e: unknown) => e,
    )) as CommandError;
    expect(err.stderrTail.length).toBeLessThanOrEqual(100);
    expect(err.stderrTail).toContain('line-1999');
  });

  it('reports a missing binary as a spawn failure with errno', async () => {
    const err = (await runCommand('definitely-not-a-binary-xyz', {
      args: [],
      env: baseChildEnv(),
      timeoutMs: 1000,
      signal: new AbortController().signal,
    }).catch((e: unknown) => e)) as CommandError;
    expect(err.kind).toBe('spawn');
    expect(err.errno).toBe('ENOENT');
  });

  it('kills the whole process group on timeout', async () => {
    const started = Date.now();
    const err = (await sh('sleep 30 & sleep 30; wait', { timeoutMs: 100, killGraceMs: 200 }).catch((e: unknown) => e)) as CommandError;
    expect(err.kind).toBe('timeout');
    expect(Date.now() - started).toBeLessThan(5000);
  });

  it('escalates to SIGKILL when SIGTERM is ignored', async () => {
    const err = (await sh("trap '' TERM; sleep 30", { timeoutMs: 100, killGraceMs: 100 }).catch((e: unknown) => e)) as CommandError;
    expect(err.kind).toBe('timeout');
    expect(err.signal).toBe('SIGKILL');
  });

  it('aborts on signal, before and during the run', async () => {
    const pre = new AbortController();
    pre.abort(new Error('early'));
    await expect(sh('exit 0', { signal: pre.signal })).rejects.toMatchObject({ kind: 'aborted' });

    const during = new AbortController();
    const p = sh('sleep 30', { signal: during.signal, killGraceMs: 100 });
    setTimeout(() => {
      during.abort(new Error('stop'));
    }, 50);
    await expect(p).rejects.toMatchObject({ kind: 'aborted' });
  });

  it('passes only the given environment to the child', async () => {
    process.env.CG_SECRET_FOR_TEST = 'leak';
    try {
      await expect(sh('[ -z "$CG_SECRET_FOR_TEST" ] && [ "$FOO" = bar ]', { env: baseChildEnv({ FOO: 'bar', SKIP: undefined }) })).resolves.toBe('');
    } finally {
      delete process.env.CG_SECRET_FOR_TEST;
    }
  });

  it('captures a bounded amount of stdout when asked, and none otherwise', async () => {
    await expect(sh('echo hello; echo world', { captureStdout: 100 })).resolves.toBe('hello\nworld\n');
    await expect(sh('i=0; while [ $i -lt 500 ]; do printf x; i=$((i+1)); done', { captureStdout: 10 })).resolves.toBe('xxxxxxxxxx');
    await expect(sh('echo hidden')).resolves.toBe('');
  });

  it('errno is undefined for non-spawn failures', async () => {
    const err = (await sh('exit 1').catch((e: unknown) => e)) as CommandError;
    expect(err.errno).toBeUndefined();
  });
});

describe('baseChildEnv / isNoSpaceMessage', () => {
  it('falls back to a default PATH and omits HOME when unset', () => {
    const { PATH, HOME } = process.env;
    delete process.env.PATH;
    delete process.env.HOME;
    try {
      expect(baseChildEnv()).toEqual({ PATH: '/usr/local/bin:/usr/bin:/bin' });
    } finally {
      process.env.PATH = PATH;
      process.env.HOME = HOME;
    }
  });

  it.each([
    ['fatal: write error: No space left on device', true],
    ['ENOSPC: no space', true],
    ['Disk quota exceeded', true],
    ['fatal: repository not found', false],
  ])('%s → %s', (text, expected) => {
    expect(isNoSpaceMessage(text)).toBe(expected);
  });
});
