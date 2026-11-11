import fs from 'node:fs';
import { createInterface } from 'node:readline';
import { describe, expect, it } from 'vitest';
import { TEST_CORPUS, type CorpusRepo } from '../../src/application/test-corpus.js';
import { TestRunService, type TestRunServiceOptions } from '../../src/application/test-run.service.js';
import { RequestError, ScanError } from '../../src/domain/errors.js';
import type { ScanStats } from '../../src/domain/scan.js';
import type { MemoryCounters, TestRunId } from '../../src/domain/test-run.js';
import { SqliteScanStore } from '../../src/infrastructure/db/sqlite-scan.store.js';
import { SqliteTestRunStore } from '../../src/infrastructure/db/sqlite-test-run.store.js';
import { openDatabase } from '../../src/infrastructure/db/sqlite.js';

const STATS: ScanStats = { reportBytes: 1000, vulnerabilitiesScanned: 40, criticalCount: 3, malformedSkipped: 0, durationMs: 500, peakMemoryMb: 52 };

const CORPUS: CorpusRepo[] = [
  ...['a', 'b', 'c'].map((n) => ({ url: `https://github.com/go/${n}`, language: 'Go', sizeMb: 10 })),
  ...['a', 'b'].map((n) => ({ url: `https://github.com/py/${n}`, language: 'Python', sizeMb: 10 })),
  { url: 'https://github.com/rs/a', language: 'Rust', sizeMb: 10 },
  { url: 'https://github.com/huge/repo', language: 'Rust', sizeMb: 5000 },
  { url: 'https://gitlab.com/not/allowed', language: 'Go', sizeMb: 1 },
];

function setup(overrides: Partial<TestRunServiceOptions> = {}) {
  let t = 1_000;
  const now = (): number => (t += 1);
  const db = openDatabase(':memory:');
  const scans = new SqliteScanStore(db, now);
  const runs = new SqliteTestRunStore(db, now);
  let counters: MemoryCounters | null = { limitMb: 150, limitHits: 4, oomKills: 1 };
  let wakes = 0;
  const service = new TestRunService(runs, {
    corpus: CORPUS,
    allowedHosts: ['github.com'],
    maxSize: 30,
    maxRepoMb: 500,
    readCounters: () => Promise.resolve(counters),
    wake: () => {
      wakes += 1;
    },
    random: () => 0.5,
    ...overrides,
  });
  return {
    db,
    scans,
    runs,
    service,
    wakes: () => wakes,
    setCounters: (c: MemoryCounters | null) => {
      counters = c;
    },
    /** Let a worker process every queued scan with the given outcome. */
    drain(outcome: (repoUrl: string) => 'finish' | 'fail' = () => 'finish', stats: Partial<ScanStats> = {}) {
      for (let s = scans.claimNext('w'); s !== undefined; s = scans.claimNext('w')) {
        if (outcome(s.repoUrl) === 'finish') scans.markFinished(s.id, 'w', { ...STATS, ...stats });
        else scans.markFailed(s.id, 'w', { code: 'CLONE_FAILED', message: 'nope' });
      }
    },
  };
}

async function requestError(p: Promise<unknown>): Promise<RequestError> {
  const err = await p.then(
    () => undefined,
    (e: unknown) => e,
  );
  if (!(err instanceof RequestError)) throw new Error(`expected RequestError, got ${String(err)}`);
  return err;
}

describe('TEST_CORPUS', () => {
  it('matches test/large/corpus.tsv exactly', async () => {
    const rows: string[][] = [];
    const lines = createInterface({ input: fs.createReadStream(new URL('../large/corpus.tsv', import.meta.url)) });
    for await (const line of lines) if (line !== '' && !line.startsWith('#')) rows.push(line.split('\t'));
    expect(TEST_CORPUS.map((r) => [r.url, r.language, String(r.sizeMb)])).toEqual(rows.map((r) => r.slice(0, 3)));
    expect(TEST_CORPUS.length).toBeGreaterThanOrEqual(100);
  });
});

describe('SqliteTestRunStore + queue', () => {
  it('creates background scans that never block or outrank user scans', () => {
    const h = setup();
    const run = h.runs.create({
      entries: [{ repoUrl: 'https://github.com/go/a', language: 'Go', sizeMb: 10 }],
      baseline: null,
    });
    const user = h.scans.create('https://github.com/user/repo');
    expect(run.items[0]?.scan?.status).toBe('Queued');
    expect(h.scans.countQueued()).toBe(1); // only the user's scan counts towards MAX_QUEUED
    expect(h.scans.claimNext('w')?.id).toBe(user.id); // the user scan goes first despite being newer
    expect(h.scans.claimNext('w')?.id).toBe(run.items[0]?.scanId);
  });

  it('cancels only queued scans and keeps a running one', () => {
    const h = setup();
    const run = h.runs.create({
      entries: ['a', 'b'].map((n) => ({ repoUrl: `https://github.com/go/${n}`, language: 'Go', sizeMb: 1 })),
      baseline: null,
    });
    h.scans.claimNext('w');
    expect(h.runs.findActive()?.id).toBe(run.id);
    expect(h.runs.cancel(run.id)).toBe(1);
    const after = h.runs.findById(run.id);
    expect(after?.cancelledAt).toBeInstanceOf(Date);
    expect(after?.items.map((i) => i.scan?.status)).toEqual(['Scanning', 'Failed']);
    expect(after?.items[1]?.scan?.error?.code).toBe('CANCELLED');
    expect(h.runs.findActive()).toBeUndefined();
  });

  it('purges a run once all of its scans are gone, and shows purged scans as null', () => {
    const h = setup();
    const run = h.runs.create({ entries: [{ repoUrl: 'https://github.com/go/a', language: 'Go', sizeMb: 1 }], baseline: null });
    h.drain();
    expect(h.runs.findLatest()?.id).toBe(run.id);
    h.db.prepare(`DELETE FROM scans`).run();
    expect(h.runs.findById(run.id)?.items[0]?.scan).toBeNull();
    h.scans.purgeFinishedBefore(Number.MAX_SAFE_INTEGER);
    expect(h.runs.findById(run.id)).toBeUndefined();
    expect(h.runs.findById('00000000-0000-4000-8000-000000000000' as TestRunId)).toBeUndefined();
  });
});

describe('TestRunService', () => {
  it('samples across languages, skips oversized and disallowed repos, and wakes the worker', async () => {
    const h = setup();
    expect(h.service.poolSize).toBe(6);
    const r = await h.service.start(3);
    expect(new Set(r.run.items.map((i) => i.language))).toEqual(new Set(['Go', 'Python', 'Rust']));
    expect(r.state).toBe('running');
    expect(r.counts).toMatchObject({ total: 3, queued: 3 });
    expect(h.wakes()).toBe(1);

    h.drain();
    const all = await h.service.start(30);
    expect(all.run.items).toHaveLength(6); // the whole pool, no duplicates
    expect(new Set(all.run.items.map((i) => i.repoUrl)).size).toBe(6);
    expect(all.run.items.some((i) => i.sizeMb > 500 || i.repoUrl.includes('gitlab'))).toBe(false);
  });

  it('rejects bad sizes and a second concurrent run', async () => {
    const h = setup();
    expect((await requestError(h.service.start(0))).code).toBe('INVALID_TEST_RUN');
    expect((await requestError(h.service.start(31))).code).toBe('INVALID_TEST_RUN');
    expect((await requestError(h.service.start(1.5))).code).toBe('INVALID_TEST_RUN');
    await h.service.start(2);
    expect((await requestError(h.service.start(2))).code).toBe('TEST_RUN_ACTIVE');
  });

  it('reports a clean run as within the limit, with deltas of the kernel counters', async () => {
    const h = setup();
    const started = await h.service.start(4);
    h.drain((url) => (url.endsWith('/b') ? 'fail' : 'finish'), { peakMemoryMb: 61 });
    const r = await h.service.get(started.run.id);
    expect(r.state).toBe('finished');
    expect(r.counts).toMatchObject({ total: 4, finished: r.counts.total - r.counts.failed, queued: 0, scanning: 0 });
    expect(r.totals.criticalCount).toBe(3 * r.counts.finished);
    expect(r.memory).toEqual({ limitMb: 150, maxScanPeakMb: 61, limitHitsDuringRun: 0, oomKillsDuringRun: 0, withinLimit: true });
    expect((await h.service.latest()).run.id).toBe(started.run.id);
  });

  it('flags an OOM kill or a limit hit during the run', async () => {
    const h = setup();
    const { run } = await h.service.start(2);
    h.drain();
    h.setCounters({ limitMb: 150, limitHits: 4, oomKills: 2 });
    expect((await h.service.get(run.id)).memory).toMatchObject({ oomKillsDuringRun: 1, withinLimit: false });
    h.setCounters({ limitMb: 150, limitHits: 9, oomKills: 1 });
    expect((await h.service.get(run.id)).memory).toMatchObject({ limitHitsDuringRun: 5, withinLimit: false });
  });

  it('works without cgroup counters, judging by per-scan peaks', async () => {
    const h = setup();
    h.setCounters(null);
    const { run } = await h.service.start(1);
    h.drain();
    expect((await h.service.get(run.id)).memory).toEqual({
      limitMb: null,
      maxScanPeakMb: 52,
      limitHitsDuringRun: null,
      oomKillsDuringRun: null,
      withinLimit: null,
    });
  });

  it('cancels a run', async () => {
    const h = setup();
    const { run } = await h.service.start(3);
    const r = await h.service.cancel(run.id);
    expect(r.state).toBe('cancelled');
    expect(r.counts.failed).toBe(3);
    expect(r.memory.maxScanPeakMb).toBeNull();
    await expect(h.service.start(1)).resolves.toBeDefined(); // a new run may start
  });

  it('maps lookups and capacity failures to request errors', async () => {
    const h = setup();
    expect((await requestError(h.service.latest())).code).toBe('NOT_FOUND');
    expect((await requestError(h.service.get('nope'))).code).toBe('INVALID_TEST_RUN');
    expect((await requestError(h.service.get('00000000-0000-4000-8000-000000000000'))).code).toBe('NOT_FOUND');

    const full = setup({ checkCapacity: () => Promise.reject(new ScanError('INSUFFICIENT_DISK', 'disk')) });
    expect((await requestError(full.service.start(1))).code).toBe('NOT_READY');
    const broken = setup({ checkCapacity: () => Promise.reject(new Error('boom')) });
    await expect(broken.service.start(1)).rejects.toThrow('boom');
  });

  it('uses Math.random by default', async () => {
    const runs = new SqliteTestRunStore(openDatabase(':memory:'));
    const service = new TestRunService(runs, { corpus: CORPUS, allowedHosts: ['github.com'], maxSize: 5, maxRepoMb: 500, readCounters: () => Promise.resolve(null) });
    expect((await service.start(2)).run.items).toHaveLength(2);
  });
});
