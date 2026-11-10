import fs from 'node:fs';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { ScanProcessor } from '../../src/application/scan.processor.js';
import { ScanError, ShutdownError } from '../../src/domain/errors.js';
import type { ReportProcessor, RepositoryFetcher, Scanner, Workspace } from '../../src/domain/ports.js';
import type { Scan } from '../../src/domain/scan.js';
import type { SqliteScanStore } from '../../src/infrastructure/db/sqlite-scan.store.js';
import { DiskWorkspace } from '../../src/infrastructure/fs/disk-workspace.js';
import { StreamReportProcessor } from '../../src/infrastructure/report/stream-report-processor.js';
import { FAKE_COMMIT, FakeFetcher, FakeScanner, enospc, memoryStore, recordingLogger, report, tempDir, vuln } from '../helpers/index.js';

const WORKER = 'w1';
const REPORT = report([{ Target: 'package-lock.json', Type: 'npm', Vulnerabilities: [vuln({ id: 'CVE-1' }), vuln({ id: 'CVE-2', severity: 'HIGH' })] }]);

describe('ScanProcessor', () => {
  let dir: string;
  let store: SqliteScanStore;
  let workspace: Workspace;
  let clock: number;

  beforeEach(() => {
    dir = tempDir();
    clock = 1_000_000;
    store = memoryStore(() => clock);
    workspace = new DiskWorkspace(dir, 0, recordingLogger());
  });
  afterEach(() => {
    store.close();
    fs.rmSync(dir, { recursive: true, force: true });
  });

  const outcomes: string[] = [];
  beforeEach(() => {
    outcomes.length = 0;
  });

  function processor(
    parts: { fetcher?: RepositoryFetcher; scanner?: Scanner; reports?: ReportProcessor; ws?: Workspace } = {},
    opts: Partial<ConstructorParameters<typeof ScanProcessor>[1]> = {},
  ) {
    const log = recordingLogger();
    const p = new ScanProcessor(
      {
        store,
        workspace: parts.ws ?? workspace,
        log,
        fetcher: parts.fetcher ?? new FakeFetcher(),
        scanner: parts.scanner ?? FakeScanner.writing(REPORT),
        reports: parts.reports ?? new StreamReportProcessor(store, { batchSize: 10, maxValueBytes: 1 << 20 }),
        now: () => clock,
        random: () => 0.5,
        metrics: { recordOutcome: (o, info) => outcomes.push(info.code ? `${o}:${info.code}` : o) },
      },
      { maxAttempts: 3, heartbeatMs: 5, retryBaseMs: 1000, memorySampleMs: 1, ...opts },
    );
    return { p, log };
  }

  const claim = (): Scan => {
    store.create('https://github.com/a/b.git');
    const scan = store.claimNext(WORKER);
    if (!scan) throw new Error('no scan');
    return scan;
  };
  const workspaceIsEmpty = () => fs.readdirSync(dir).length === 0;

  it('runs clone → scan → parse, stores criticals, finishes, and cleans up', async () => {
    const fetcher = new FakeFetcher();
    const scan = claim();
    const { p } = processor({ fetcher });
    await p.run(scan, WORKER, new AbortController().signal);

    const done = store.findById(scan.id);
    expect(done?.commitSha).toBe(FAKE_COMMIT);
    expect(done).toMatchObject({ status: 'Finished', stats: { vulnerabilitiesScanned: 2, criticalCount: 1, malformedSkipped: 0 } });
    expect(done?.stats?.peakMemoryMb).toBeGreaterThan(0);
    expect(store.listVulnerabilities(scan.id, { afterRowId: 0, limit: 10 }).map((v) => v.vulnerabilityId)).toEqual(['CVE-1']);
    expect(fetcher.calls).toEqual(['https://github.com/a/b.git']);
    expect(workspaceIsEmpty()).toBe(true);
    expect(outcomes).toEqual(['finished']);
  });

  it('reports the peak of the memory probe as peakMemoryMb', async () => {
    const scan = claim();
    const samples = [10, 40, 25].map((mb) => mb * 1024 * 1024);
    let i = 0;
    const log = recordingLogger();
    const p = new ScanProcessor(
      {
        store, workspace, log, fetcher: new FakeFetcher(), scanner: FakeScanner.writing(REPORT),
        reports: new StreamReportProcessor(store, { batchSize: 10, maxValueBytes: 1 << 20 }), now: () => clock,
        memoryProbe: () => Promise.resolve(samples[Math.min(i++, samples.length - 1)] ?? 0),
      },
      { maxAttempts: 3, heartbeatMs: 5, retryBaseMs: 1000, memorySampleMs: 1 },
    );
    await p.run(scan, WORKER, new AbortController().signal);
    expect(store.findById(scan.id)?.stats?.peakMemoryMb).toBe(40);
  });

  it('deletes the clone before parsing starts', async () => {
    let repoExistedDuringParse: boolean | undefined;
    const scan = claim();
    const reports: ReportProcessor = {
      process: (input) => {
        repoExistedDuringParse = fs.existsSync(path.join(path.dirname(input.reportPath), 'repo'));
        input.onProgress(50);
        return Promise.resolve({ reportBytes: 1, vulnerabilitiesScanned: 0, criticalCount: 0, malformedSkipped: 0 });
      },
    };
    await processor({ reports }).p.run(scan, WORKER, new AbortController().signal);
    expect(repoExistedDuringParse).toBe(false);
    expect(store.findById(scan.id)?.status).toBe('Finished');
  });

  it('publishes phase and progress through heartbeats', async () => {
    const scan = claim();
    const seen: string[] = [];
    const reports: ReportProcessor = {
      process: async (input) => {
        input.onProgress(42);
        await new Promise((r) => setTimeout(r, 30));
        const s = store.findById(scan.id);
        seen.push(`${s?.phase}:${s?.progressPct}`);
        return { reportBytes: 1, vulnerabilitiesScanned: 0, criticalCount: 0, malformedSkipped: 0 };
      },
    };
    await processor({ reports }).p.run(scan, WORKER, new AbortController().signal);
    expect(seen).toEqual(['parsing:42']);
  });

  it('re-queues a retryable failure with backoff and cleans up', async () => {
    const scan = claim();
    const scanner = new FakeScanner(() => Promise.reject(new ScanError('SCANNER_FAILED', 'trivy exit 1', true)));
    await processor({ scanner }).p.run(scan, WORKER, new AbortController().signal);
    expect(store.findById(scan.id)).toMatchObject({ status: 'Queued', attempts: 1 });
    expect(store.claimNext(WORKER)).toBeUndefined(); // backoff: not yet runnable
    clock += 1000;
    expect(store.claimNext(WORKER)?.id).toBe(scan.id);
    expect(workspaceIsEmpty()).toBe(true);
    expect(outcomes).toEqual(['retried:SCANNER_FAILED']);
  });

  it('waits at least the upstream Retry-After before retrying', async () => {
    const scan = claim();
    const scanner = new FakeScanner(() => Promise.reject(new ScanError('UPSTREAM_RATE_LIMITED', 'Maven Central 429', true, { retryAfterMs: 1_800_000 })));
    await processor({ scanner }).p.run(scan, WORKER, new AbortController().signal);
    expect(store.findById(scan.id)).toMatchObject({ status: 'Queued' });
    clock += 1_799_000;
    expect(store.claimNext(WORKER)).toBeUndefined();
    clock += 1_000;
    expect(store.claimNext(WORKER)?.id).toBe(scan.id);
  });

  it('fails permanently once attempts are exhausted', async () => {
    store.create('https://github.com/a/b.git');
    let scan = store.claimNext(WORKER)!;
    const scanner = new FakeScanner(() => Promise.reject(new ScanError('SCANNER_FAILED', 'trivy exit 1', true)));
    const { p } = processor({ scanner });
    for (let i = 0; i < 3; i += 1) {
      await p.run(scan, WORKER, new AbortController().signal);
      clock += 1_000_000;
      const next = store.claimNext(WORKER);
      if (next) scan = next;
    }
    expect(store.findById(scan.id)).toMatchObject({ status: 'Failed', attempts: 3, error: { code: 'SCANNER_FAILED', message: 'trivy exit 1' } });
  });

  it('fails immediately on a non-retryable error', async () => {
    const scan = claim();
    const fetcher = new FakeFetcher(() => Promise.reject(new ScanError('REPO_NOT_FOUND', 'Repository not found or not public')));
    await processor({ fetcher }).p.run(scan, WORKER, new AbortController().signal);
    expect(store.findById(scan.id)).toMatchObject({ status: 'Failed', error: { code: 'REPO_NOT_FOUND' } });
    expect(workspaceIsEmpty()).toBe(true);
    expect(outcomes).toEqual(['failed:REPO_NOT_FOUND']);
  });

  it('maps a full disk (ENOSPC) to DISK_FULL and still cleans up', async () => {
    const scan = claim();
    const scanner = new FakeScanner(async ({ reportPath }) => {
      await fs.promises.writeFile(reportPath, '{"partial":');
      throw enospc();
    });
    await processor({ scanner }, { maxAttempts: 1 }).p.run(scan, WORKER, new AbortController().signal);
    expect(store.findById(scan.id)).toMatchObject({ status: 'Failed', error: { code: 'DISK_FULL' } });
    expect(workspaceIsEmpty()).toBe(true);
  });

  it('fails a truncated report instead of finishing with partial results', async () => {
    const scan = claim();
    await processor({ scanner: FakeScanner.writing(REPORT.slice(0, REPORT.length - 20)) }).p.run(scan, WORKER, new AbortController().signal);
    expect(store.findById(scan.id)).toMatchObject({ status: 'Failed', error: { code: 'REPORT_INVALID' } });
    expect(store.listVulnerabilities(scan.id, { afterRowId: 0, limit: 10 })).toEqual([]);
  });

  it('refuses to start when disk space is below the floor', async () => {
    const scan = claim();
    const ws = new DiskWorkspace(dir, Number.MAX_SAFE_INTEGER, recordingLogger());
    await processor({ ws }, { maxAttempts: 1 }).p.run(scan, WORKER, new AbortController().signal);
    expect(store.findById(scan.id)).toMatchObject({ status: 'Failed', error: { code: 'INSUFFICIENT_DISK' } });
  });

  it('marks unexpected errors as INTERNAL without leaking details', async () => {
    const scan = claim();
    const scanner = new FakeScanner(() => Promise.reject(new Error('/secret/host/path exploded')));
    await processor({ scanner }).p.run(scan, WORKER, new AbortController().signal);
    expect(store.findById(scan.id)?.error).toEqual({ code: 'INTERNAL', message: 'Unexpected error while processing the scan' });
  });

  it('re-queues with the attempt refunded on shutdown, killing in-flight work', async () => {
    const scan = claim();
    const shutdown = new AbortController();
    let sawAbort = false;
    const scanner = new FakeScanner(
      ({ signal }) =>
        new Promise((_resolve, reject) => {
          signal.addEventListener('abort', () => {
            sawAbort = true;
            reject(asError(signal.reason));
          });
          shutdown.abort(new ShutdownError());
        }),
    );
    await processor({ scanner }).p.run(scan, WORKER, shutdown.signal);
    expect(sawAbort).toBe(true);
    expect(store.findById(scan.id)).toMatchObject({ status: 'Queued', attempts: 0 });
    expect(outcomes).toEqual(['requeued']);
    expect(workspaceIsEmpty()).toBe(true);
  });

  it('handles a shutdown that was already signalled', async () => {
    const scan = claim();
    const shutdown = new AbortController();
    shutdown.abort(new ShutdownError());
    await processor().p.run(scan, WORKER, shutdown.signal);
    expect(store.findById(scan.id)).toMatchObject({ status: 'Queued', attempts: 0 });
  });

  it('aborts and leaves the scan alone when its lease is taken over', async () => {
    const scan = claim();
    const scanner = new FakeScanner(
      ({ signal }) =>
        new Promise((_resolve, reject) => {
          signal.addEventListener('abort', () => {
            reject(asError(signal.reason));
          });
          // Simulate the reaper handing the scan to another worker.
          store.reclaimStale(Number.MAX_SAFE_INTEGER, 10);
          store.claimNext('other-worker');
        }),
    );
    const { p, log } = processor({ scanner });
    await p.run(scan, WORKER, new AbortController().signal);
    expect(store.findById(scan.id)).toMatchObject({ status: 'Scanning', attempts: 2 });
    expect(log.entries.some((e) => e.msg.includes('lease lost'))).toBe(true);
  });

  it('discards the result if the lease was lost just before finishing', async () => {
    const scan = claim();
    const reports: ReportProcessor = {
      process: () => {
        store.reclaimStale(Number.MAX_SAFE_INTEGER, 10);
        return Promise.resolve({ reportBytes: 1, vulnerabilitiesScanned: 0, criticalCount: 0, malformedSkipped: 0 });
      },
    };
    const { p, log } = processor({ reports }, { heartbeatMs: 60_000 });
    await p.run(scan, WORKER, new AbortController().signal);
    expect(store.findById(scan.id)?.status).toBe('Queued');
    expect(log.entries.some((e) => e.msg.includes('result discarded'))).toBe(true);
    expect(outcomes).toEqual(['lease_lost']);
  });

  it('survives failing heartbeats and failing outcome writes', async () => {
    const scan = claim();
    const original = store.heartbeat.bind(store);
    let beats = 0;
    store.heartbeat = (...args) => {
      beats += 1;
      if (beats === 2) throw new Error('db busy');
      return original(...args);
    };
    store.markFailed = () => {
      throw new Error('db down');
    };
    const scanner = new FakeScanner(async () => {
      await new Promise((r) => setTimeout(r, 30));
      throw new ScanError('REPO_NOT_FOUND', 'x');
    });
    const { p, log } = processor({ scanner });
    await expect(p.run(scan, WORKER, new AbortController().signal)).resolves.toBeUndefined();
    expect(log.entries.map((e) => e.msg)).toEqual(expect.arrayContaining(['heartbeat failed', 'could not record scan outcome']));
  });

  it('never throws even if the workspace cannot be created', async () => {
    const scan = claim();
    const ws: Workspace = { ...workspace, create: () => Promise.reject(new Error('EACCES')) };
    await processor({ ws }).p.run(scan, WORKER, new AbortController().signal);
    expect(store.findById(scan.id)?.error?.code).toBe('INTERNAL');
  });
});

function asError(reason: unknown): Error {
  return reason instanceof Error ? reason : new Error(String(reason));
}
