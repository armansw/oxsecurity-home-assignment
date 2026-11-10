import path from 'node:path';
import fs from 'node:fs';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { LeaseLostError } from '../../src/domain/errors.js';
import type { ScanId } from '../../src/domain/scan.js';
import type { CriticalVulnerability } from '../../src/domain/vulnerability.js';
import { openDatabase } from '../../src/infrastructure/db/sqlite.js';
import { SqliteScanStore } from '../../src/infrastructure/db/sqlite-scan.store.js';
import { tempDir } from '../helpers/index.js';

const v = (id: string): CriticalVulnerability => ({
  vulnerabilityId: id,
  pkgName: 'p',
  installedVersion: '1',
  fixedVersion: '2',
  severity: 'CRITICAL',
  title: 't',
  description: 'd',
  primaryUrl: 'u',
  target: 'tg',
  pkgType: 'npm',
  cvssScore: 9.8,
  publishedDate: '2024',
});

const stats = { reportBytes: 10, vulnerabilitiesScanned: 5, criticalCount: 2, malformedSkipped: 1, durationMs: 100, peakRssMb: 80 };

describe('SqliteScanStore', () => {
  let clock: number;
  let store: SqliteScanStore;
  beforeEach(() => {
    clock = 1_000_000;
    store = new SqliteScanStore(openDatabase(':memory:'), () => clock);
  });
  afterEach(() => {
    store.close();
  });

  it('creates Queued scans with a UUID and finds them', () => {
    const s = store.create('https://github.com/a/b.git');
    expect(s).toMatchObject({ status: 'Queued', repoUrl: 'https://github.com/a/b.git', attempts: 0, phase: null, stats: null, error: null });
    expect(s.id).toMatch(/^[0-9a-f-]{36}$/);
    expect(s.createdAt.getTime()).toBe(clock);
    expect(store.findById(s.id)).toEqual(s);
    expect(store.findById('00000000-0000-4000-8000-000000000000' as ScanId)).toBeUndefined();
    expect(store.countQueued()).toBe(1);
  });

  it('finds the active scan for a repo, but not finished ones', () => {
    const s = store.create('r');
    expect(store.findActiveByRepo('r')?.id).toBe(s.id);
    store.claimNext('w');
    expect(store.findActiveByRepo('r')?.status).toBe('Scanning');
    store.markFinished(s.id, 'w', stats);
    expect(store.findActiveByRepo('r')).toBeUndefined();
  });

  it('claims FIFO, exclusively, and respects run_after', () => {
    const a = store.create('a');
    clock += 1;
    const b = store.create('b');
    const first = store.claimNext('w1');
    const second = store.claimNext('w2');
    expect([first?.id, second?.id]).toEqual([a.id, b.id]);
    expect(first).toMatchObject({ status: 'Scanning', attempts: 1, phase: 'cloning' });
    expect(first?.startedAt?.getTime()).toBe(clock);
    expect(store.claimNext('w3')).toBeUndefined();

    store.requeue(a.id, 'w1', { runAfter: clock + 5000, refundAttempt: false });
    expect(store.claimNext('w3')).toBeUndefined();
    clock += 5000;
    expect(store.claimNext('w3')).toMatchObject({ id: a.id, attempts: 2 });
  });

  it('heartbeat renews the lease and publishes phase/progress only for the owner', () => {
    const s = store.create('r');
    store.claimNext('w');
    expect(store.heartbeat(s.id, 'w', { phase: 'parsing', progressPct: 42 })).toBe(true);
    expect(store.findById(s.id)).toMatchObject({ phase: 'parsing', progressPct: 42 });
    expect(store.heartbeat(s.id, 'w')).toBe(true);
    expect(store.findById(s.id)).toMatchObject({ phase: 'parsing', progressPct: 42 });
    expect(store.heartbeat(s.id, 'w', { progressPct: null })).toBe(true);
    expect(store.findById(s.id)?.progressPct).toBeNull();
    expect(store.heartbeat(s.id, 'intruder', { phase: 'scanning' })).toBe(false);
  });

  it('fences every write by lease owner', () => {
    const s = store.create('r');
    store.claimNext('w');
    expect(() => {
      store.appendVulnerabilities(s.id, 'zombie', [v('X')]);
    }).toThrow(LeaseLostError);
    expect(() => {
      store.clearVulnerabilities(s.id, 'zombie');
    }).toThrow(LeaseLostError);
    expect(store.markFinished(s.id, 'zombie', stats)).toBe(false);
    expect(store.markFailed(s.id, 'zombie', { code: 'INTERNAL', message: 'x' })).toBe(false);
    expect(store.requeue(s.id, 'zombie', { runAfter: 0, refundAttempt: true })).toBe(false);
    expect(store.findById(s.id)?.status).toBe('Scanning');
  });

  it('stores vulnerabilities in batches and pages them by keyset', () => {
    const s = store.create('r');
    store.claimNext('w');
    store.appendVulnerabilities(s.id, 'w', []);
    store.appendVulnerabilities(s.id, 'w', [v('A'), v('B'), v('C')]);
    store.appendVulnerabilities(s.id, 'w', [v('D'), v('E')]);
    const p1 = store.listVulnerabilities(s.id, { afterRowId: 0, limit: 2 });
    const p2 = store.listVulnerabilities(s.id, { afterRowId: p1.at(-1)!.rowId, limit: 2 });
    const p3 = store.listVulnerabilities(s.id, { afterRowId: p2.at(-1)!.rowId, limit: 2 });
    expect([...p1, ...p2, ...p3].map((r) => r.vulnerabilityId)).toEqual(['A', 'B', 'C', 'D', 'E']);
    expect(p1[0]).toEqual({ ...v('A'), rowId: p1[0]!.rowId });
    store.clearVulnerabilities(s.id, 'w');
    expect(store.listVulnerabilities(s.id, { afterRowId: 0, limit: 10 })).toEqual([]);
  });

  it('marks Finished with stats and releases the lease', () => {
    const s = store.create('r');
    store.claimNext('w');
    clock += 50;
    expect(store.markFinished(s.id, 'w', stats)).toBe(true);
    const f = store.findById(s.id);
    expect(f).toMatchObject({ status: 'Finished', phase: null, progressPct: 100, stats });
    expect(f?.finishedAt?.getTime()).toBe(clock);
    expect(store.isScanning(s.id)).toBe(false);
  });

  it('marks Failed, records the error and drops partial rows', () => {
    const s = store.create('r');
    store.claimNext('w');
    store.appendVulnerabilities(s.id, 'w', [v('A')]);
    expect(store.markFailed(s.id, 'w', { code: 'SCANNER_FAILED', message: 'boom' })).toBe(true);
    expect(store.findById(s.id)).toMatchObject({ status: 'Failed', error: { code: 'SCANNER_FAILED', message: 'boom' }, stats: null });
    expect(store.listVulnerabilities(s.id, { afterRowId: 0, limit: 10 })).toEqual([]);
  });

  it('requeue can refund the attempt (graceful shutdown)', () => {
    const s = store.create('r');
    store.claimNext('w');
    expect(store.requeue(s.id, 'w', { runAfter: clock, refundAttempt: true })).toBe(true);
    expect(store.findById(s.id)).toMatchObject({ status: 'Queued', attempts: 0, phase: null });
  });

  it('reclaims stale leases: re-queues below the cap, fails at the cap', () => {
    const young = store.create('young');
    const old = store.create('old');
    const poison = store.create('poison');
    store.claimNext('w'); // young
    store.claimNext('w'); // old
    store.claimNext('w'); // poison
    // poison has used all attempts
    for (let i = 0; i < 2; i += 1) {
      store.requeue(poison.id, 'w', { runAfter: 0, refundAttempt: false });
      store.claimNext('w');
    }
    clock += 10_000;
    store.heartbeat(young.id, 'w');
    expect(store.reclaimStale(clock - 5000, 3)).toEqual({ requeued: 1, failed: 1 });
    expect(store.findById(young.id)?.status).toBe('Scanning');
    expect(store.findById(old.id)?.status).toBe('Queued');
    expect(store.findById(poison.id)).toMatchObject({ status: 'Failed', error: { code: 'WORKER_CRASHED' } });
    expect(store.reclaimStale(clock - 5000, 3)).toEqual({ requeued: 0, failed: 0 });
  });

  it('purges terminal scans older than the cutoff, cascading to vulnerabilities', () => {
    const s = store.create('r');
    store.claimNext('w');
    store.appendVulnerabilities(s.id, 'w', [v('A')]);
    store.markFinished(s.id, 'w', stats);
    const queued = store.create('q');
    expect(store.purgeFinishedBefore(clock)).toBe(0);
    clock += 1;
    expect(store.purgeFinishedBefore(clock)).toBe(1);
    expect(store.findById(s.id)).toBeUndefined();
    expect(store.listVulnerabilities(s.id, { afterRowId: 0, limit: 10 })).toEqual([]);
    expect(store.findById(queued.id)).toBeDefined();
  });

  it('maps an unknown stored error code to INTERNAL and rejects corrupt rows', () => {
    const dir = tempDir();
    const file = path.join(dir, 'nested', 'x.db');
    const db = openDatabase(file);
    const s = new SqliteScanStore(db);
    const scan = s.create('r');
    db.prepare(`UPDATE scans SET status='Failed', error_code='LEGACY', error_message=NULL WHERE id=?`).run(scan.id);
    expect(s.findById(scan.id)?.error).toEqual({ code: 'INTERNAL', message: '' });
    db.pragma('ignore_check_constraints = ON');
    db.prepare(`UPDATE scans SET status='Bogus' WHERE id=?`).run(scan.id);
    expect(() => s.findById(scan.id)).toThrow(/unknown status/);
    db.prepare(`UPDATE scans SET status='Scanning', phase='bogus' WHERE id=?`).run(scan.id);
    expect(() => s.findById(scan.id)).toThrow(/unknown phase/);
    s.close();
    s.close(); // idempotent
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('migrations are idempotent across reopen', () => {
    const dir = tempDir();
    const file = path.join(dir, 'x.db');
    const a = new SqliteScanStore(openDatabase(file));
    const id = a.create('r').id;
    a.close();
    const b = new SqliteScanStore(openDatabase(file));
    expect(b.findById(id)?.repoUrl).toBe('r');
    b.close();
    fs.rmSync(dir, { recursive: true, force: true });
  });
});
