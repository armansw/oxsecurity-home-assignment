import fs from 'node:fs';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { ScanProcessor } from '../../src/application/scan.processor.js';
import type { ScanStore } from '../../src/domain/ports.js';
import type { SqliteScanStore } from '../../src/infrastructure/db/sqlite-scan.store.js';
import { DiskWorkspace } from '../../src/infrastructure/fs/disk-workspace.js';
import { StreamReportProcessor } from '../../src/infrastructure/report/stream-report-processor.js';
import { Worker } from '../../src/worker/worker.js';
import { FakeFetcher, FakeScanner, memoryStore, recordingLogger, report, tempDir, vuln, waitFor } from '../helpers/index.js';

const REPORT = report([{ Target: 't', Vulnerabilities: [vuln()] }]);

describe('Worker', () => {
  let dir: string;
  let store: SqliteScanStore;
  let worker: Worker | undefined;

  beforeEach(() => {
    dir = tempDir();
    store = memoryStore();
  });
  afterEach(async () => {
    await worker?.stop(1000);
    worker = undefined;
    store.close();
    fs.rmSync(dir, { recursive: true, force: true });
  });

  function build(scanner = FakeScanner.writing(REPORT), opts: Partial<ConstructorParameters<typeof Worker>[1]> = {}, s: ScanStore = store) {
    const log = recordingLogger();
    const workspace = new DiskWorkspace(dir, 0, log);
    const processor = new ScanProcessor(
      { store: s, workspace, log, fetcher: new FakeFetcher(), scanner, reports: new StreamReportProcessor(s, { batchSize: 10, maxValueBytes: 1 << 20 }) },
      { maxAttempts: 2, heartbeatMs: 20, retryBaseMs: 1 },
    );
    worker = new Worker({ store: s, workspace, log, processor }, { concurrency: 1, pollMs: 5000, staleAfterMs: 200, maxAttempts: 2, ttlMs: 60_000, ...opts });
    return { worker, log };
  }

  it('picks up queued scans immediately when woken', async () => {
    const { worker: w } = build();
    w.start();
    expect(w.running).toBe(true);
    const id = store.create('https://github.com/a/b.git').id;
    w.wake();
    await waitFor(() => store.findById(id)?.status === 'Finished', 3000);
  });

  it('processes scans present at start-up, in order', async () => {
    const a = store.create('a').id;
    const b = store.create('b').id;
    build().worker.start();
    await waitFor(() => store.findById(a)?.status === 'Finished' && store.findById(b)?.status === 'Finished', 3000);
  });

  it('polls when not woken', async () => {
    const { worker: w } = build(undefined, { pollMs: 20 });
    w.start();
    const id = store.create('x').id;
    await waitFor(() => store.findById(id)?.status === 'Finished', 3000);
  });

  it('removes the workspace left by a crashed worker as soon as its scan is reclaimed', async () => {
    const id = store.create('x').id;
    store.claimNext('dead-worker');
    // The dead worker's workspace, and a scan that already exhausted its attempts.
    store.requeue(id, 'dead-worker', { runAfter: 0, refundAttempt: false });
    store.claimNext('dead-worker');
    store.requeue(id, 'dead-worker', { runAfter: 0, refundAttempt: false });
    store.claimNext('dead-worker');
    const leftover = `${dir}/scan-${id}`;
    fs.mkdirSync(leftover);
    const { worker: w } = build(undefined, { pollMs: 60_000, staleAfterMs: 200, maxAttempts: 2, janitorIntervalMs: 3_600_000 });
    w.start();
    await waitFor(() => store.findById(id)?.status === 'Failed' && !fs.existsSync(leftover), 3000);
    expect(store.findById(id)?.error?.code).toBe('WORKER_CRASHED');
  });

  it('reaps stale leases from crashed workers and finishes them', async () => {
    const id = store.create('x').id;
    store.claimNext('dead-worker'); // heartbeat at now, never renewed
    build(undefined, { pollMs: 20 }).worker.start();
    await waitFor(() => store.findById(id)?.status === 'Finished', 3000);
    expect(store.findById(id)?.attempts).toBe(2);
  });

  it('janitor removes orphaned workspaces and purges expired scans', async () => {
    const orphan = `${dir}/scan-33333333-3333-4333-8333-333333333333`;
    fs.mkdirSync(orphan);
    const old = store.create('old').id;
    store.claimNext('w');
    store.markFailed(old, 'w', { code: 'INTERNAL', message: 'x' });
    const { worker: w, log } = build(undefined, { ttlMs: -1000 });
    w.start();
    await waitFor(() => !fs.existsSync(orphan) && store.findById(old) === undefined, 3000);
    await waitFor(() => log.entries.some((e) => e.msg === 'janitor cleaned up'));
  });

  it('stop() re-queues the in-flight scan with its attempt refunded', async () => {
    let started = false;
    const slow = new FakeScanner(
      ({ signal }) =>
        new Promise((_res, rej) => {
          started = true;
          signal.addEventListener('abort', () => {
            rej(signal.reason instanceof Error ? signal.reason : new Error('aborted'));
          });
        }),
    );
    const { worker: w } = build(slow);
    w.start();
    const id = store.create('x').id;
    w.wake();
    await waitFor(() => started);
    await w.stop(2000);
    expect(w.running).toBe(false);
    expect(store.findById(id)).toMatchObject({ status: 'Queued', attempts: 0 });
    await w.stop(10); // idempotent
  });

  it('warns when loops do not stop within the grace period', async () => {
    let entered = false;
    const stuck = new FakeScanner(() => {
      entered = true;
      return new Promise(() => undefined); // ignores abort
    });
    const { worker: w, log } = build(stuck);
    w.start();
    store.create('x');
    w.wake();
    // Wait for the scanner itself, not just the claim: a scan still cloning would stop promptly and log nothing.
    await waitFor(() => entered);
    await w.stop(30);
    expect(log.entries.some((e) => e.msg.includes('grace period'))).toBe(true);
    worker = undefined; // already stopped
  });

  it('keeps running when the store throws', async () => {
    let claims = 0;
    const failing = memoryStore();
    failing.claimNext = () => {
      claims += 1;
      throw new Error('db locked');
    };
    failing.reclaimStale = () => {
      throw new Error('db locked');
    };
    failing.purgeFinishedBefore = () => {
      throw new Error('db locked');
    };
    const { worker: w, log } = build(undefined, { pollMs: 5, staleAfterMs: 200 }, failing);
    w.start();
    await waitFor(() => claims >= 3);
    const msgs = log.entries.map((e) => e.msg);
    expect(msgs).toEqual(expect.arrayContaining(['failed to claim next scan', 'reaper failed', 'janitor failed']));
  });
});
