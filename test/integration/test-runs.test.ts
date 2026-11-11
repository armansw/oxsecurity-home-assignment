import type { FastifyInstance } from 'fastify';
import { afterEach, describe, expect, it } from 'vitest';
import { ScanProcessor } from '../../src/application/scan.processor.js';
import { ScanService } from '../../src/application/scan.service.js';
import { TestRunService } from '../../src/application/test-run.service.js';
import { SqliteScanStore } from '../../src/infrastructure/db/sqlite-scan.store.js';
import { SqliteTestRunStore } from '../../src/infrastructure/db/sqlite-test-run.store.js';
import { openDatabase } from '../../src/infrastructure/db/sqlite.js';
import { DiskWorkspace } from '../../src/infrastructure/fs/disk-workspace.js';
import { StreamReportProcessor } from '../../src/infrastructure/report/stream-report-processor.js';
import { buildApp } from '../../src/interfaces/http/app.js';
import type { TestRunDto } from '../../src/interfaces/rest/test-run.controller.js';
import { Worker } from '../../src/worker/worker.js';
import { FakeFetcher, FakeScanner, recordingLogger, report, tempDir, vuln } from '../helpers/index.js';

async function poll(app: FastifyInstance, id: string, state: TestRunDto['state']): Promise<TestRunDto> {
  const deadline = Date.now() + 10_000;
  for (;;) {
    const run = (await app.inject({ method: 'GET', url: `/api/test-runs/${id}` })).json<TestRunDto>();
    if (run.state === state) return run;
    if (Date.now() > deadline) throw new Error(`run stayed ${run.state}`);
    await new Promise((r) => setTimeout(r, 20));
  }
}

const CORPUS = ['express', 'koa', 'flask', 'django'].map((name, i) => ({
  url: `https://github.com/acme/${name}`,
  language: i < 2 ? 'JavaScript' : 'Python',
  sizeMb: 5,
}));

let cleanup: (() => Promise<void>) | undefined;
afterEach(async () => {
  await cleanup?.();
  cleanup = undefined;
});

async function harness(enabled = true): Promise<FastifyInstance> {
  const db = openDatabase(':memory:');
  const store = new SqliteScanStore(db);
  const log = recordingLogger();
  const workspace = new DiskWorkspace(tempDir(), 0, log);
  const scanner = FakeScanner.writing(
    report([{ Target: 'package-lock.json', Type: 'npm', Vulnerabilities: [vuln({ id: 'CVE-2024-1' }), vuln({ id: 'CVE-2024-2', severity: 'HIGH' })] }]),
  );
  const processor = new ScanProcessor(
    { store, workspace, log, fetcher: new FakeFetcher(), scanner, reports: new StreamReportProcessor(store, { batchSize: 10, maxValueBytes: 1 << 20 }) },
    { maxAttempts: 1, heartbeatMs: 50, retryBaseMs: 1 },
  );
  const worker = new Worker({ store, workspace, log, processor }, { concurrency: 1, pollMs: 20, staleAfterMs: 10_000, maxAttempts: 1, ttlMs: 1e9 });
  const wake = (): void => {
    worker.wake();
  };
  const testRuns = new TestRunService(new SqliteTestRunStore(db), {
    corpus: CORPUS,
    allowedHosts: ['github.com'],
    maxSize: 10,
    maxRepoMb: 500,
    readCounters: () => Promise.resolve({ limitMb: 150, limitHits: 0, oomKills: 0 }),
    wake,
  });
  const app = await buildApp({
    service: new ScanService(store, { allowedHosts: ['github.com'], maxQueued: 10, wake }),
    store,
    testRuns: enabled ? testRuns : undefined,
    readiness: () => Promise.resolve({}),
    logger: false,
    responsePageSize: 10,
    rateLimitPerMinute: 1000,
    graphiql: false,
  });
  worker.start();
  cleanup = async () => {
    await app.close();
    await worker.stop(1000);
    store.close();
  };
  return app;
}

describe('self-test API', () => {
  it('runs a sample of the corpus to completion and reports memory against the limit', async () => {
    const app = await harness();
    expect((await app.inject({ method: 'GET', url: '/api/test-runs/latest' })).statusCode).toBe(404);

    const started = await app.inject({ method: 'POST', url: '/api/test-runs', payload: { size: 3 } });
    expect(started.statusCode).toBe(202);
    const run = started.json<TestRunDto>();
    expect(started.headers.location).toBe(`/api/test-runs/${run.testRunId}`);
    expect(run).toMatchObject({ state: 'running', poolSize: 4, counts: { total: 3 } });

    const conflict = await app.inject({ method: 'POST', url: '/api/test-runs', payload: { size: 1 } });
    expect(conflict.statusCode).toBe(409);
    expect(conflict.json()).toMatchObject({ error: { code: 'TEST_RUN_ACTIVE' } });

    const done = await poll(app, run.testRunId, 'finished');
    expect(done.counts).toMatchObject({ total: 3, finished: 3, failed: 0 });
    expect(done.totals.criticalCount).toBe(3);
    expect(done.memory).toMatchObject({ limitMb: 150, limitHitsDuringRun: 0, oomKillsDuringRun: 0, withinLimit: true });
    expect(done.items[0]).toMatchObject({ status: 'Finished', criticalCount: 1, vulnerabilitiesScanned: 2, error: null });
    expect(done.items[0]?.peakMemoryMb).toBeGreaterThan(0);

    const latest = await app.inject({ method: 'GET', url: '/api/test-runs/latest' });
    expect(latest.headers['cache-control']).toBe('no-store');
    expect(latest.json<TestRunDto>().testRunId).toBe(run.testRunId);
  });

  it('cancels a run and validates input', async () => {
    const app = await harness();
    expect((await app.inject({ method: 'POST', url: '/api/test-runs', payload: { size: 0 } })).statusCode).toBe(400);
    expect((await app.inject({ method: 'POST', url: '/api/test-runs', payload: { size: 11 } })).json()).toMatchObject({
      error: { code: 'INVALID_TEST_RUN' },
    });
    expect((await app.inject({ method: 'GET', url: '/api/test-runs/not-a-uuid' })).statusCode).toBe(400);

    const run = (await app.inject({ method: 'POST', url: '/api/test-runs', payload: { size: 4 } })).json<TestRunDto>();
    const cancelled = await app.inject({ method: 'POST', url: `/api/test-runs/${run.testRunId}/cancel` });
    expect(cancelled.statusCode).toBe(200);
    expect(cancelled.json<TestRunDto>().cancelledAt).not.toBeNull();
    await poll(app, run.testRunId, 'cancelled');
  });

  it('is absent when disabled', async () => {
    const app = await harness(false);
    expect((await app.inject({ method: 'POST', url: '/api/test-runs', payload: { size: 1 } })).statusCode).toBe(404);
  });
});
