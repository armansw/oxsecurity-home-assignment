import fs from 'node:fs';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { MavenCacheProxy, isCacheable, safeRepoPath } from '../../src/infrastructure/scanner/maven-cache-proxy.js';
import { recordingLogger, tempDir } from '../helpers/index.js';

const POM = 'org/springframework/boot/spring-boot-dependencies/3.3.0/spring-boot-dependencies-3.3.0.pom';

/** A fake upstream repository: records every request, answers from `files`, 404 otherwise. */
function fakeUpstream(files: Record<string, string>, extra: Record<string, () => Response> = {}) {
  const calls: { url: string; method: string }[] = [];
  const fetchImpl = ((input: string | URL | Request, init?: RequestInit) => {
    const url = input instanceof Request ? input.url : input.toString();
    calls.push({ url, method: init?.method ?? 'GET' });
    const key = url.replace('https://mirror.test/maven2/', '');
    const special = extra[key];
    if (special !== undefined) return Promise.resolve(special());
    const body = files[key];
    return Promise.resolve(
      body === undefined ? new Response('not found', { status: 404 }) : new Response(body, { status: 200, headers: { 'content-type': 'text/xml' } }),
    );
  }) as typeof fetch;
  return { calls, fetchImpl };
}

describe('MavenCacheProxy', () => {
  let dir: string | undefined;
  let proxy: MavenCacheProxy | undefined;
  afterEach(async () => {
    await proxy?.close();
    proxy = undefined;
    if (dir) fs.rmSync(dir, { recursive: true, force: true });
  });

  async function start(upstream: ReturnType<typeof fakeUpstream>, maxBytes = 1024 * 1024) {
    dir = tempDir();
    proxy = new MavenCacheProxy({ upstream: 'https://mirror.test/maven2', dir, maxBytes, log: recordingLogger(), fetchImpl: upstream.fetchImpl });
    return proxy.start();
  }

  it('downloads a released POM once, then serves it from disk', async () => {
    const upstream = fakeUpstream({ [POM]: '<project>boot</project>' });
    const base = await start(upstream);

    const first = await fetch(`${base}${POM}`);
    expect(first.status).toBe(200);
    expect(await first.text()).toBe('<project>boot</project>');
    const second = await fetch(`${base}${POM}`);
    expect(await second.text()).toBe('<project>boot</project>');
    expect(second.headers.get('x-cache')).toBe('HIT');

    expect(upstream.calls).toHaveLength(1);
    expect(fs.statSync(path.join(dir ?? '', ...POM.split('/'))).size).toBe('<project>boot</project>'.length);
  });

  it('survives a restart: the cache is on disk', async () => {
    const upstream = fakeUpstream({ [POM]: '<project/>' });
    const base = await start(upstream);
    await (await fetch(`${base}${POM}`)).text();
    await proxy?.close();

    proxy = new MavenCacheProxy({ upstream: 'https://mirror.test/maven2/', dir: dir ?? '', maxBytes: 1 << 20, log: recordingLogger(), fetchImpl: upstream.fetchImpl });
    const again = await proxy.start();
    expect(await (await fetch(`${again}${POM}`)).text()).toBe('<project/>');
    expect(upstream.calls).toHaveLength(1);
  });

  it('shares one download between concurrent requests for the same POM', async () => {
    const upstream = fakeUpstream({ [POM]: '<project/>' });
    const base = await start(upstream);
    const bodies = await Promise.all(Array.from({ length: 5 }, async () => (await fetch(`${base}${POM}`)).text()));
    expect(bodies).toEqual(Array(5).fill('<project/>'));
    expect(upstream.calls).toHaveLength(1);
  });

  it('passes 404 and 429 (with Retry-After) through, and caches neither', async () => {
    const limited = 'com/acme/x/1.0/x-1.0.pom';
    const upstream = fakeUpstream({}, { [limited]: () => new Response('slow down', { status: 429, headers: { 'retry-after': '1800' } }) });
    const base = await start(upstream);

    expect((await fetch(`${base}com/acme/missing/1.0/missing-1.0.pom`)).status).toBe(404);
    const r = await fetch(`${base}${limited}`);
    expect(r.status).toBe(429);
    expect(r.headers.get('retry-after')).toBe('1800');
    await fetch(`${base}${limited}`);
    // one upstream request per client request: the refusal is forwarded, not fetched again; nothing is stored
    expect(upstream.calls.filter((c) => c.url.endsWith(limited))).toHaveLength(2);
    expect(upstream.calls).toHaveLength(3);
    expect(fs.existsSync(path.join(dir ?? '', 'com'))).toBe(false);
  });

  it('remembers a missing released POM for a while instead of asking again', async () => {
    dir = tempDir();
    const missing = 'com/acme/own-module/1.0/own-module-1.0.pom';
    const upstream = fakeUpstream({});
    proxy = new MavenCacheProxy({ upstream: 'https://mirror.test/maven2/', dir, maxBytes: 1 << 20, log: recordingLogger(), fetchImpl: upstream.fetchImpl, notFoundTtlMs: 200 });
    const base = await proxy.start();
    for (let i = 0; i < 5; i += 1) expect((await fetch(`${base}${missing}`)).status).toBe(404);
    expect(upstream.calls).toHaveLength(1);
    await new Promise((r) => setTimeout(r, 250));
    expect((await fetch(`${base}${missing}`)).status).toBe(404);
    expect(upstream.calls).toHaveLength(2); // asked again once the entry expired
  });

  it('never caches snapshots or metadata, which change', async () => {
    const meta = 'com/acme/x/maven-metadata.xml';
    const snap = 'com/acme/x/1.0-SNAPSHOT/x-1.0-SNAPSHOT.pom';
    const upstream = fakeUpstream({ [meta]: '<metadata/>', [snap]: '<project/>' });
    const base = await start(upstream);
    for (let i = 0; i < 2; i += 1) {
      expect(await (await fetch(`${base}${meta}`)).text()).toBe('<metadata/>');
      expect(await (await fetch(`${base}${snap}`)).text()).toBe('<project/>');
    }
    expect(upstream.calls).toHaveLength(4);
  });

  it('rejects path traversal and anything outside /maven2/', async () => {
    const upstream = fakeUpstream({});
    const base = await start(upstream);
    const root = base.replace('/maven2/', '');
    expect((await fetch(`${root}/maven2/..%2F..%2Fetc%2Fpasswd.pom`)).status).toBe(400);
    expect((await fetch(`${root}/elsewhere/a.pom`)).status).toBe(400);
    expect((await fetch(`${base}${POM}`, { method: 'POST' })).status).toBe(405);
    expect(upstream.calls).toHaveLength(0);
  });

  it('answers 502 when the upstream cannot be reached', async () => {
    dir = tempDir();
    const failing = (() => Promise.reject(new TypeError('fetch failed'))) as typeof fetch;
    proxy = new MavenCacheProxy({ upstream: 'https://mirror.test/maven2/', dir, maxBytes: 1 << 20, log: recordingLogger(), fetchImpl: failing });
    const base = await proxy.start();
    expect((await fetch(`${base}${POM}`)).status).toBe(502);
  });

  it('evicts the least recently used POMs once past its size limit', async () => {
    const files: Record<string, string> = {};
    for (let i = 0; i < 10; i += 1) files[`g/a${String(i)}/1/a${String(i)}-1.pom`] = 'x'.repeat(100);
    const upstream = fakeUpstream(files);
    const base = await start(upstream, 500);
    for (const p of Object.keys(files)) {
      await (await fetch(`${base}${p}`)).text();
      await new Promise((r) => setTimeout(r, 15)); // distinct mtimes
    }
    await proxy?.prune();
    const kept = Object.keys(files).filter((p) => fs.existsSync(path.join(dir ?? '', ...p.split('/'))));
    expect(kept.length).toBeLessThanOrEqual(4); // 80 % of 500 bytes
    expect(kept).toContain('g/a9/1/a9-1.pom'); // the newest survive
  });

  it('removes temporary files left by a hard kill on start', async () => {
    dir = tempDir();
    fs.writeFileSync(path.join(dir, '.tmp-abandoned'), 'partial');
    proxy = new MavenCacheProxy({ upstream: 'https://mirror.test/maven2/', dir, maxBytes: 1 << 20, log: recordingLogger(), fetchImpl: fakeUpstream({}).fetchImpl });
    await proxy.start();
    expect(fs.existsSync(path.join(dir, '.tmp-abandoned'))).toBe(false);
  });
});

describe('maven cache path rules', () => {
  it('caches released POMs only', () => {
    expect(isCacheable(POM)).toBe(true);
    expect(isCacheable('a/b/1.0-SNAPSHOT/b-1.0-SNAPSHOT.pom')).toBe(false);
    expect(isCacheable('a/b/maven-metadata.xml')).toBe(false);
    expect(isCacheable('a/b/1.0/b-1.0.jar')).toBe(false);
  });

  it('accepts plain repository paths and refuses the rest', () => {
    expect(safeRepoPath(`/${POM}`)).toBe(POM);
    expect(safeRepoPath('/a/../b.pom')).toBeNull();
    expect(safeRepoPath('/a/%2e%2e/b.pom')).toBeNull();
    expect(safeRepoPath('/a//b.pom')).toBeNull();
    expect(safeRepoPath('/a/b c.pom')).toBeNull();
    expect(safeRepoPath('/%zz')).toBeNull();
  });
});
