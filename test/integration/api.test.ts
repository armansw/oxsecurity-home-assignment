import fs from 'node:fs';
import type { FastifyInstance } from 'fastify';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { ScanProcessor } from '../../src/application/scan.processor.js';
import { ScanService } from '../../src/application/scan.service.js';
import { ScanError } from '../../src/domain/errors.js';
import type { Scanner } from '../../src/domain/ports.js';
import type { SqliteScanStore } from '../../src/infrastructure/db/sqlite-scan.store.js';
import { DiskWorkspace } from '../../src/infrastructure/fs/disk-workspace.js';
import { StreamReportProcessor } from '../../src/infrastructure/report/stream-report-processor.js';
import { buildApp } from '../../src/interfaces/http/app.js';
import { PrometheusMetrics } from '../../src/infrastructure/metrics/prometheus-metrics.js';
import type { ReadinessCheck } from '../../src/interfaces/http/health.controller.js';
import { Worker } from '../../src/worker/worker.js';
import { FAKE_COMMIT, FakeFetcher, FakeScanner, memoryStore, recordingLogger, report, tempDir, vuln, waitFor } from '../helpers/index.js';

const REPO = 'https://github.com/OWASP/NodeGoat';

function trivyReport(criticals: number, others = 3): string {
  const vulns = [
    ...Array.from({ length: criticals }, (_, i) => vuln({ id: `CVE-2024-${String(i).padStart(5, '0')}`, pkg: `pkg-${i}` })),
    ...Array.from({ length: others }, (_, i) => vuln({ id: `CVE-2023-${i}`, severity: 'HIGH' })),
  ];
  return report([{ Target: 'package-lock.json', Type: 'npm', Vulnerabilities: vulns }]);
}

interface PageBody {
  criticalVulnerabilities: { id: string }[];
  nextCursor: string | null;
}

interface Harness {
  app: FastifyInstance;
  store: SqliteScanStore;
  worker: Worker;
  dir: string;
}

async function harness(opts: { scanner?: Scanner; maxQueued?: number; readyChecks?: Record<string, ReadinessCheck>; rateLimit?: number; withMetrics?: boolean; dedupe?: boolean } = {}): Promise<Harness> {
  const dir = tempDir();
  const store = memoryStore();
  const log = recordingLogger();
  const workspace = new DiskWorkspace(dir, 0, log);
  const processor = new ScanProcessor(
    {
      store,
      workspace,
      log,
      fetcher: new FakeFetcher(),
      scanner: opts.scanner ?? FakeScanner.writing(trivyReport(2)),
      reports: new StreamReportProcessor(store, { batchSize: 100, maxValueBytes: 1 << 20 }),
    },
    { maxAttempts: 1, heartbeatMs: 50, retryBaseMs: 1 },
  );
  const worker = new Worker({ store, workspace, log, processor }, { concurrency: 1, pollMs: 20, staleAfterMs: 10_000, maxAttempts: 1, ttlMs: 1e9 });
  const service = new ScanService(store, {
    allowedHosts: ['github.com'],
    maxQueued: opts.maxQueued ?? 10,
    dedupeActiveScans: opts.dedupe ?? false,
    wake: () => {
      worker.wake();
    },
  });
  const app = await buildApp({
    service,
    store,
    readiness: () => Promise.resolve(opts.readyChecks ?? { database: { ok: true, detail: 'ok' } }),
    metrics: opts.withMetrics ? new PrometheusMetrics(store, { collectDefaults: false }) : undefined,
    logger: false,
    responsePageSize: 7,
    rateLimitPerMinute: opts.rateLimit ?? 1000,
    graphiql: false,
  });
  return { app, store, worker, dir };
}

async function teardown(h: Harness): Promise<void> {
  await h.app.close();
  await h.worker.stop(1000);
  h.store.close();
  fs.rmSync(h.dir, { recursive: true, force: true });
}

async function startScan(h: Harness, repoUrl = REPO): Promise<string> {
  const res = await h.app.inject({ method: 'POST', url: '/api/scan', payload: { repoUrl } });
  expect(res.statusCode).toBe(202);
  return res.json<{ scanId: string }>().scanId;
}

async function waitForStatus(h: Harness, id: string, status: string): Promise<void> {
  await waitFor(() => h.store.findById(id as never)?.status === status, 5000);
}

describe('REST API', () => {
  let h: Harness;
  beforeEach(async () => {
    h = await harness();
  });
  afterEach(async () => {
    await teardown(h);
  });

  it('POST /api/scan returns 202 Queued immediately with a Location header', async () => {
    const res = await h.app.inject({ method: 'POST', url: '/api/scan', payload: { repoUrl: REPO } });
    expect(res.statusCode).toBe(202);
    const body = res.json<{ scanId: string; status: string }>();
    expect(body).toEqual({ scanId: expect.stringMatching(/^[0-9a-f-]{36}$/) as unknown, status: 'Queued' });
    expect(res.headers.location).toBe(`/api/scan/${body.scanId}`);
  });

  it('runs the scan in the background and reports Queued → Finished with the critical list', async () => {
    const id = await startScan(h);
    const first = await h.app.inject({ method: 'GET', url: `/api/scan/${id}` });
    expect(first.statusCode).toBe(200);
    expect(first.headers['cache-control']).toBe('no-store');
    expect(['Queued', 'Scanning', 'Finished']).toContain(first.json<{ status: string }>().status);

    h.worker.start();
    await waitForStatus(h, id, 'Finished');
    const res = await h.app.inject({ method: 'GET', url: `/api/scan/${id}` });
    expect(res.headers['content-type']).toBe('application/json; charset=utf-8');
    const body = res.json<{ status: string; criticalCount: number; criticalVulnerabilities: { id: string; severity: string }[]; stats: { vulnerabilitiesScanned: number } }>();
    expect(body).toMatchObject({ scanId: id, status: 'Finished', criticalCount: 2, repoUrl: 'https://github.com/OWASP/NodeGoat.git', commitSha: FAKE_COMMIT, stats: { vulnerabilitiesScanned: 5 } });
    expect(body.criticalVulnerabilities.map((v) => v.id)).toEqual(['CVE-2024-00000', 'CVE-2024-00001']);
    expect(body.criticalVulnerabilities.every((v) => v.severity === 'CRITICAL')).toBe(true);
  });

  it('answers every POST with a new scanId and status Queued, even for the same repository', async () => {
    const a = await startScan(h);
    const res = await h.app.inject({ method: 'POST', url: '/api/scan', payload: { repoUrl: `${REPO}.git` } });
    expect(res.statusCode).toBe(202);
    const body = res.json<{ scanId: string; status: string }>();
    expect(body.status).toBe('Queued');
    expect(body.scanId).not.toBe(a);
  });

  it('deduplicates an active scan when DEDUPE_ACTIVE_SCANS is enabled', async () => {
    const d = await harness({ dedupe: true });
    try {
      const a = await startScan(d);
      const res = await d.app.inject({ method: 'POST', url: '/api/scan', payload: { repoUrl: `${REPO}.git` } });
      expect(res.statusCode).toBe(202);
      expect(res.json()).toEqual({ scanId: a, status: 'Queued', deduplicated: true });
    } finally {
      await teardown(d);
    }
  });

  it.each([
    [{ repoUrl: 'file:///etc/passwd' }, 'INVALID_REPO_URL'],
    [{ repoUrl: '' }, 'VALIDATION_ERROR'],
    [{}, 'VALIDATION_ERROR'],
    [{ repoUrl: REPO, extra: 1 }, 'VALIDATION_ERROR'],
    [{ repoUrl: 42 }, 'VALIDATION_ERROR'],
  ])('rejects invalid input %o with 400', async (payload, code) => {
    const res = await h.app.inject({ method: 'POST', url: '/api/scan', payload });
    expect(res.statusCode).toBe(400);
    expect(res.json<{ error: { code: string } }>().error.code).toBe(code);
  });

  it('rejects non-JSON and oversized bodies', async () => {
    const bad = await h.app.inject({ method: 'POST', url: '/api/scan', headers: { 'content-type': 'application/json' }, payload: '{not json' });
    expect(bad.statusCode).toBe(400);
    const big = await h.app.inject({ method: 'POST', url: '/api/scan', payload: { repoUrl: 'x'.repeat(5000) } });
    expect(big.statusCode).toBe(413);
    expect(big.json<{ error: { code: string } }>().error.code).toBe('CTP_BODY_TOO_LARGE');
  });

  it('GET validates the id and returns 404 for unknown scans', async () => {
    const bad = await h.app.inject({ method: 'GET', url: '/api/scan/not-a-uuid' });
    expect(bad.statusCode).toBe(400);
    expect(bad.json<{ error: { code: string } }>().error.code).toBe('INVALID_SCAN_ID');
    const missing = await h.app.inject({ method: 'GET', url: '/api/scan/00000000-0000-4000-8000-000000000000' });
    expect(missing.statusCode).toBe(404);
    expect(missing.json<{ error: { code: string } }>().error.code).toBe('NOT_FOUND');
  });

  it('unknown routes return the error envelope', async () => {
    const res = await h.app.inject({ method: 'GET', url: '/nope' });
    expect(res.statusCode).toBe(404);
    expect(res.json<{ error: { code: string } }>().error.code).toBe('ROUTE_NOT_FOUND');
  });
});

describe('REST API — results at scale and pagination', () => {
  it.each([0, 1, 2500])('streams a valid JSON body with %i criticals (page size 7)', async (n) => {
    const h = await harness({ scanner: FakeScanner.writing(trivyReport(n, 1)) });
    try {
      h.worker.start();
      const id = await startScan(h);
      await waitForStatus(h, id, 'Finished');
      const res = await h.app.inject({ method: 'GET', url: `/api/scan/${id}` });
      const body = res.json<{ criticalCount: number; criticalVulnerabilities: { id: string }[] }>();
      expect(body.criticalCount).toBe(n);
      expect(body.criticalVulnerabilities).toHaveLength(n);
      expect(new Set(body.criticalVulnerabilities.map((v) => v.id)).size).toBe(n);
    } finally {
      await teardown(h);
    }
  });

  it('pages with limit/cursor, covering every item exactly once', async () => {
    const h = await harness({ scanner: FakeScanner.writing(trivyReport(25)) });
    try {
      h.worker.start();
      const id = await startScan(h);
      await waitForStatus(h, id, 'Finished');
      const ids: string[] = [];
      let cursor: string | null = null;
      let pages = 0;
      do {
        const url = `/api/scan/${id}?limit=10${cursor ? `&cursor=${cursor}` : ''}`;
        const body: PageBody = (await h.app.inject({ method: 'GET', url })).json<PageBody>();
        ids.push(...body.criticalVulnerabilities.map((v) => v.id));
        cursor = body.nextCursor;
        pages += 1;
      } while (cursor !== null);
      expect(pages).toBe(3);
      expect(ids).toHaveLength(25);
      expect(new Set(ids).size).toBe(25);

      const onlyCursor = await h.app.inject({ method: 'GET', url: `/api/scan/${id}?cursor=${encodeURIComponent(Buffer.from('v1:0').toString('base64url'))}` });
      expect(onlyCursor.json<{ criticalVulnerabilities: unknown[] }>().criticalVulnerabilities).toHaveLength(25);
      const badCursor = await h.app.inject({ method: 'GET', url: `/api/scan/${id}?limit=5&cursor=zzz` });
      expect(badCursor.statusCode).toBe(400);
      const badLimit = await h.app.inject({ method: 'GET', url: `/api/scan/${id}?limit=5000` });
      expect(badLimit.statusCode).toBe(400);
    } finally {
      await teardown(h);
    }
  });
});

describe('REST API — failures and limits', () => {
  it('reports Failed with a stable code when the scanner fails', async () => {
    const h = await harness({ scanner: new FakeScanner(() => Promise.reject(new ScanError('SCANNER_FAILED', 'Trivy exited with code 1', true))) });
    try {
      h.worker.start();
      const id = await startScan(h);
      await waitForStatus(h, id, 'Failed');
      const body = (await h.app.inject({ method: 'GET', url: `/api/scan/${id}` })).json<Record<string, unknown>>();
      expect(body).toMatchObject({ status: 'Failed', error: { code: 'SCANNER_FAILED', message: 'Trivy exited with code 1' } });
      // Cleanup runs in the processor's `finally`, just after the status is recorded.
      await waitFor(() => fs.readdirSync(h.dir).length === 0);
    } finally {
      await teardown(h);
    }
  });

  it('shows Scanning with phase and progress while running', async () => {
    let release: () => void = () => undefined;
    const h = await harness({
      scanner: new FakeScanner(
        () =>
          new Promise((resolve) => {
            release = resolve;
          }),
      ),
    });
    try {
      h.worker.start();
      const id = await startScan(h);
      await waitFor(() => h.store.findById(id as never)?.phase === 'scanning');
      const body = (await h.app.inject({ method: 'GET', url: `/api/scan/${id}` })).json<Record<string, unknown>>();
      expect(body).toMatchObject({ status: 'Scanning', phase: 'scanning', attempt: 1 });
      release();
    } finally {
      await teardown(h);
    }
  });

  it('returns 429 with Retry-After when the queue is full', async () => {
    const h = await harness({ maxQueued: 1 });
    try {
      await startScan(h, 'https://github.com/a/one');
      const res = await h.app.inject({ method: 'POST', url: '/api/scan', payload: { repoUrl: 'https://github.com/a/two' } });
      expect(res.statusCode).toBe(429);
      expect(res.headers['retry-after']).toBe('30');
      expect(res.json<{ error: { code: string } }>().error.code).toBe('QUEUE_FULL');
    } finally {
      await teardown(h);
    }
  });

  it('rate-limits the GraphQL startScan mutation too, but never status polling', async () => {
    const h = await harness({ rateLimit: 2 });
    try {
      const id = await startScan(h, 'https://github.com/a/one');
      const gql = (query: string) => h.app.inject({ method: 'POST', url: '/graphql', payload: { query } });
      expect((await gql('mutation { startScan(repoUrl: "https://github.com/a/two") { id } }')).statusCode).toBe(200);
      expect((await gql('mutation { startScan(repoUrl: "https://github.com/a/three") { id } }')).statusCode).toBe(200);
      const third = await gql('mutation { startScan(repoUrl: "https://github.com/a/four") { id } }');
      expect(third.statusCode).toBe(429);
      expect(third.json<{ errors: { extensions: { code: string } }[] }>().errors[0]?.extensions.code).toBe('RATE_LIMITED');
      for (let i = 0; i < 10; i += 1) {
        expect((await gql(`{ scan(id: "${id}") { status } }`)).statusCode).toBe(200);
        expect((await h.app.inject({ method: 'GET', url: `/api/scan/${id}` })).statusCode).toBe(200);
      }
    } finally {
      await teardown(h);
    }
  });

  it('rate-limits POST /api/scan per client', async () => {
    const h = await harness({ rateLimit: 2 });
    try {
      await startScan(h, 'https://github.com/a/one');
      await startScan(h, 'https://github.com/a/two');
      const res = await h.app.inject({ method: 'POST', url: '/api/scan', payload: { repoUrl: 'https://github.com/a/three' } });
      expect(res.statusCode).toBe(429);
      expect(res.json<{ error: { code: string } }>().error.code).toBe('RATE_LIMITED');
    } finally {
      await teardown(h);
    }
  });

  it('hides internal errors behind a generic 500', async () => {
    const h = await harness();
    try {
      h.store.findById = () => {
        throw new Error('SQLITE_CORRUPT /var/lib/secret.db');
      };
      const res = await h.app.inject({ method: 'GET', url: '/api/scan/00000000-0000-4000-8000-000000000000' });
      expect(res.statusCode).toBe(500);
      expect(res.json()).toEqual({ error: { code: 'INTERNAL', message: 'Internal server error' } });
    } finally {
      await teardown(h);
    }
  });
});

describe('health endpoints', () => {
  it('/metrics exposes Prometheus metrics when configured', async () => {
    const h = await harness({ withMetrics: true });
    try {
      const res = await h.app.inject({ method: 'GET', url: '/metrics' });
      expect(res.statusCode).toBe(200);
      expect(res.headers['content-type']).toContain('text/plain');
      expect(res.body).toContain('code_guardian_queue_depth');
    } finally {
      await teardown(h);
    }
  });

  it('/healthz reports liveness and memory', async () => {
    const h = await harness();
    try {
      const body = (await h.app.inject({ method: 'GET', url: '/healthz' })).json<{ status: string; memoryMb: { rss: number } }>();
      expect(body.status).toBe('ok');
      expect(body.memoryMb.rss).toBeGreaterThan(0);
    } finally {
      await teardown(h);
    }
  });

  it('/readyz is 200 when all checks pass and 503 otherwise', async () => {
    const ok = await harness();
    const bad = await harness({ readyChecks: { database: { ok: true, detail: '' }, scanner: { ok: false, detail: 'missing' } } });
    try {
      expect((await ok.app.inject({ method: 'GET', url: '/readyz' })).statusCode).toBe(200);
      const res = await bad.app.inject({ method: 'GET', url: '/readyz' });
      expect(res.statusCode).toBe(503);
      expect(res.json()).toMatchObject({ status: 'not_ready', checks: { scanner: { ok: false } } });
    } finally {
      await teardown(ok);
      await teardown(bad);
    }
  });
});
