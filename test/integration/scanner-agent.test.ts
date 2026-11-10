import fs from 'node:fs';
import path from 'node:path';
import type { FastifyInstance } from 'fastify';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { loadConfig } from '../../src/config/env.js';
import { ScanError } from '../../src/domain/errors.js';
import type { RepositoryFetcher, Scanner } from '../../src/domain/ports.js';
import { RemoteScanAgent } from '../../src/infrastructure/scanner/remote-scan-agent.js';
import { buildScannerAgentApp, insideWorkspace } from '../../src/interfaces/http/scanner-agent.js';
import { FAKE_COMMIT, FakeFetcher, FakeScanner, tempDir, waitFor } from '../helpers/index.js';

const TOKEN = 'test-token-0123456789';
const ID = '11111111-1111-4111-8111-111111111111';

describe('scanner agent + RemoteScanAgent (over real HTTP)', () => {
  let work: string;
  let app: FastifyInstance | undefined;
  let ws: { root: string; repoDir: string; reportPath: string; tmpDir: string };

  beforeEach(() => {
    work = tempDir();
    const root = path.join(work, `scan-${ID}`);
    ws = { root, repoDir: path.join(root, 'repo'), reportPath: path.join(root, 'report.json'), tmpDir: path.join(root, 'tmp') };
    fs.mkdirSync(ws.tmpDir, { recursive: true });
  });
  afterEach(async () => {
    await app?.close();
    app = undefined;
    fs.rmSync(work, { recursive: true, force: true });
  });

  async function start(fetcher: RepositoryFetcher = new FakeFetcher(), scanner: Scanner = FakeScanner.writing('{}')): Promise<string> {
    app = buildScannerAgentApp({ fetcher, scanner, workDir: work, token: TOKEN, allowedHosts: ['github.com'], logger: false });
    await app.listen({ host: '127.0.0.1', port: 0 });
    const addr = app.server.address();
    if (addr === null || typeof addr === 'string') throw new Error('no address');
    return `http://127.0.0.1:${addr.port}`;
  }
  const signal = () => new AbortController().signal;

  it('clones and scans through the agent, returning the commit', async () => {
    const remote = new RemoteScanAgent({ url: await start(), token: TOKEN });
    await expect(remote.clone('https://github.com/a/b', ws.repoDir, signal())).resolves.toEqual({ commitSha: FAKE_COMMIT });
    expect(fs.existsSync(ws.repoDir)).toBe(true);
    await remote.scan({ sourceDir: ws.repoDir, reportPath: ws.reportPath, tmpDir: ws.tmpDir, signal: signal() });
    expect(fs.existsSync(ws.reportPath)).toBe(true);
  });

  it('carries classified errors across (code, retryable, unicode message)', async () => {
    const scanner = new FakeScanner(() => Promise.reject(new ScanError('SCANNER_KILLED', 'Trivy wurde beendet — OOM', true)));
    const remote = new RemoteScanAgent({ url: await start(undefined, scanner), token: TOKEN });
    await expect(remote.scan({ sourceDir: ws.repoDir, reportPath: ws.reportPath, tmpDir: ws.tmpDir, signal: signal() })).rejects.toMatchObject({
      code: 'SCANNER_KILLED',
      retryable: true,
      message: 'Trivy wurde beendet — OOM',
    });
  });

  it('carries an upstream Retry-After across the agent', async () => {
    const scanner = new FakeScanner(() => Promise.reject(new ScanError('UPSTREAM_RATE_LIMITED', 'Maven 429', true, { retryAfterMs: 900_000 })));
    const remote = new RemoteScanAgent({ url: await start(undefined, scanner), token: TOKEN });
    await expect(remote.scan({ sourceDir: ws.repoDir, reportPath: ws.reportPath, tmpDir: ws.tmpDir, signal: signal() })).rejects.toMatchObject({
      code: 'UPSTREAM_RATE_LIMITED',
      retryAfterMs: 900_000,
    });
  });

  it('maps unexpected agent failures to INTERNAL', async () => {
    const remote = new RemoteScanAgent({ url: await start(undefined, new FakeScanner(() => Promise.reject(new Error('boom')))), token: TOKEN });
    await expect(remote.scan({ sourceDir: ws.repoDir, reportPath: ws.reportPath, tmpDir: ws.tmpDir, signal: signal() })).rejects.toMatchObject({
      code: 'INTERNAL',
      retryable: false,
    });
  });

  it('rejects a wrong token and paths outside the workspace', async () => {
    const url = await start();
    await expect(new RemoteScanAgent({ url, token: 'wrong-token-0123456' }).clone('https://github.com/a/b', ws.repoDir, signal())).rejects.toMatchObject({
      code: 'SCANNER_FAILED',
      retryable: false,
    });
    const remote = new RemoteScanAgent({ url, token: TOKEN });
    await expect(remote.clone('https://github.com/a/b', '/etc/evil', signal())).rejects.toMatchObject({ code: 'SCANNER_FAILED', retryable: false });
    await expect(remote.clone('file:///etc/passwd', ws.repoDir, signal())).rejects.toMatchObject({ code: 'SCANNER_FAILED' });
    await expect(
      remote.scan({ sourceDir: path.join(ws.root, '..', '..'), reportPath: ws.reportPath, tmpDir: ws.tmpDir, signal: signal() }),
    ).rejects.toMatchObject({ code: 'SCANNER_FAILED' });
  });

  it('reports an unreachable agent as retryable SCANNER_UNAVAILABLE', async () => {
    const remote = new RemoteScanAgent({ url: 'http://127.0.0.1:9', token: TOKEN });
    await expect(remote.clone('https://github.com/a/b', ws.repoDir, signal())).rejects.toMatchObject({ code: 'SCANNER_UNAVAILABLE', retryable: true });
    expect((await remote.checkAvailable()).ok).toBe(false);
  });

  it('cancels the job on the agent when the caller aborts', async () => {
    let agentSawAbort = false;
    const scanner = new FakeScanner(
      ({ signal: s }) =>
        new Promise((_res, rej) => {
          s.addEventListener('abort', () => {
            agentSawAbort = true;
            rej(new Error('aborted'));
          });
        }),
    );
    const remote = new RemoteScanAgent({ url: await start(undefined, scanner), token: TOKEN });
    const controller = new AbortController();
    const reason = new Error('shutdown');
    const p = remote.scan({ sourceDir: ws.repoDir, reportPath: ws.reportPath, tmpDir: ws.tmpDir, signal: controller.signal });
    await waitFor(() => scanner.calls === 1);
    controller.abort(reason);
    await expect(p).rejects.toBe(reason);
    await waitFor(() => agentSawAbort);
  });

  it('exposes health and readiness, and checkAvailable reflects it', async () => {
    const url = await start();
    expect((await fetch(`${url}/healthz`)).status).toBe(200);
    expect(await new RemoteScanAgent({ url, token: TOKEN }).checkAvailable()).toMatchObject({ ok: true });
    await app?.close();
    const unavailable: Scanner = { scan: () => Promise.resolve(), checkAvailable: () => Promise.resolve({ ok: false, detail: 'no trivy' }) };
    const url2 = await start(undefined, unavailable);
    expect((await fetch(`${url2}/readyz`)).status).toBe(503);
  });

  it('rejects a malformed commit from the agent', async () => {
    const fetcher: RepositoryFetcher = { clone: () => Promise.resolve({ commitSha: 'not-a-sha' }) };
    const remote = new RemoteScanAgent({ url: await start(fetcher), token: TOKEN });
    await expect(remote.clone('https://github.com/a/b', ws.repoDir, signal())).rejects.toMatchObject({ code: 'CLONE_FAILED' });
  });

  it('rejects malformed request bodies', async () => {
    const url = await start();
    const res = await fetch(`${url}/internal/scan`, {
      method: 'POST',
      headers: { authorization: `Bearer ${TOKEN}`, 'content-type': 'application/json' },
      body: JSON.stringify({ sourceDir: 1 }),
    });
    expect(res.status).toBe(400);
  });
});

describe('insideWorkspace', () => {
  it.each([
    ['/work/scan-11111111-1111-4111-8111-111111111111/repo', true],
    ['/work/scan-11111111-1111-4111-8111-111111111111', true],
    ['/work/scan-11111111-1111-4111-8111-111111111111/../../etc', false],
    ['/work/other/repo', false],
    ['/work', false],
    ['/etc/passwd', false],
    ['/work/.trivy-cache', false],
  ])('%s → %s', (p, expected) => {
    expect(insideWorkspace('/work', p)).toBe(expected);
  });
});

describe('remote scanner configuration', () => {
  it('requires URL and token for SCANNER=remote, and a token for ROLE=scanner', () => {
    expect(() => loadConfig({ SCANNER: 'remote' })).toThrow(/SCANNER_URL and SCANNER_TOKEN/);
    expect(() => loadConfig({ ROLE: 'scanner' })).toThrow(/requires SCANNER_TOKEN/);
    expect(loadConfig({ SCANNER: 'remote', SCANNER_URL: 'http://scanner:3001', SCANNER_TOKEN: TOKEN })).toMatchObject({ SCANNER: 'remote' });
  });
});
