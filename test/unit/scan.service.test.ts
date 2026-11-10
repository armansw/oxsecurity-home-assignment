import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ScanService, decodeCursor, encodeCursor } from '../../src/application/scan.service.js';
import { RequestError, ScanError } from '../../src/domain/errors.js';
import type { SqliteScanStore } from '../../src/infrastructure/db/sqlite-scan.store.js';
import { memoryStore } from '../helpers/index.js';

const URL = 'https://github.com/OWASP/NodeGoat';
const stats = { reportBytes: 1, vulnerabilitiesScanned: 1, criticalCount: 1, malformedSkipped: 0, durationMs: 1, peakMemoryMb: 1 };

describe('ScanService', () => {
  let store: SqliteScanStore;
  beforeEach(() => {
    store = memoryStore();
  });

  const service = (opts: Partial<ConstructorParameters<typeof ScanService>[1]> = {}) =>
    new ScanService(store, { allowedHosts: ['github.com'], maxQueued: 10, ...opts });

  it('queues a normalised scan and wakes the worker', async () => {
    const wake = vi.fn();
    const { scan, deduplicated } = await service({ wake }).requestScan(URL);
    expect(scan).toMatchObject({ status: 'Queued', repoUrl: 'https://github.com/OWASP/NodeGoat.git' });
    expect(deduplicated).toBe(false);
    expect(wake).toHaveBeenCalledOnce();
  });

  it('creates a new Queued scan for every request by default, as the brief specifies', async () => {
    const svc = service();
    const first = await svc.requestScan(URL);
    const second = await svc.requestScan(URL);
    expect(second.scan.id).not.toBe(first.scan.id);
    expect([first.scan.status, second.scan.status, second.deduplicated]).toEqual(['Queued', 'Queued', false]);
  });

  it('optionally returns the active scan for the same repository instead of queueing a duplicate', async () => {
    const svc = service({ dedupeActiveScans: true });
    const first = await svc.requestScan(URL);
    const second = await svc.requestScan(`${URL}.git/`);
    expect(second).toEqual({ scan: first.scan, deduplicated: true });
    expect(store.countQueued()).toBe(1);
  });

  it('rejects invalid URLs', async () => {
    await expect(service().requestScan('file:///etc/passwd')).rejects.toMatchObject({ code: 'INVALID_REPO_URL' });
  });

  it('applies back-pressure when the queue is full', async () => {
    const svc = service({ maxQueued: 1 });
    await svc.requestScan('https://github.com/a/one');
    await expect(svc.requestScan('https://github.com/a/two')).rejects.toMatchObject({ code: 'QUEUE_FULL' });
  });

  it('refuses work when the capacity check fails, and propagates unexpected errors', async () => {
    await expect(
      service({ checkCapacity: () => Promise.reject(new ScanError('INSUFFICIENT_DISK', 'disk low', true)) }).requestScan(URL),
    ).rejects.toEqual(new RequestError('NOT_READY', 'disk low'));
    const bug = new Error('bug');
    await expect(service({ checkCapacity: () => Promise.reject(bug) }).requestScan(URL)).rejects.toBe(bug);
    await expect(service({ checkCapacity: () => Promise.resolve() }).requestScan(URL)).resolves.toMatchObject({ deduplicated: false });
  });

  it('gets scans by id with validation', async () => {
    const svc = service();
    const { scan } = await svc.requestScan(URL);
    expect(svc.getScan(scan.id)).toEqual(scan);
    expect(() => svc.getScan('nope')).toThrow(expect.objectContaining({ code: 'INVALID_SCAN_ID' }));
    expect(() => svc.getScan('00000000-0000-4000-8000-000000000000')).toThrow(expect.objectContaining({ code: 'NOT_FOUND' }));
  });

  it('pages critical vulnerabilities of finished scans only', async () => {
    const svc = service();
    const { scan } = await svc.requestScan(URL);
    expect(svc.listCriticalVulnerabilities(scan, { limit: 10 })).toBeNull();
    store.claimNext('w');
    const v = (id: string) => ({
      vulnerabilityId: id, pkgName: 'p', installedVersion: null, fixedVersion: null, severity: 'CRITICAL' as const,
      title: null, description: null, primaryUrl: null, target: 't', pkgType: null, cvssScore: null, publishedDate: null,
    });
    store.appendVulnerabilities(scan.id, 'w', [v('A'), v('B'), v('C')]);
    store.markFinished(scan.id, 'w', stats);
    const finished = svc.getScan(scan.id);

    const p1 = svc.listCriticalVulnerabilities(finished, { limit: 2 });
    expect(p1?.items.map((i) => i.vulnerabilityId)).toEqual(['A', 'B']);
    expect(p1?.nextCursor).not.toBeNull();
    const p2 = svc.listCriticalVulnerabilities(finished, { limit: 2, cursor: p1?.nextCursor });
    expect(p2).toMatchObject({ nextCursor: null });
    expect(p2?.items.map((i) => i.vulnerabilityId)).toEqual(['C']);
    expect(svc.listCriticalVulnerabilities(finished, { limit: 0 })?.items).toHaveLength(1);
    expect(svc.listCriticalVulnerabilities(finished, { limit: 1e9 })?.items).toHaveLength(3);
    expect(() => svc.listCriticalVulnerabilities(finished, { limit: 2, cursor: 'garbage' })).toThrow(expect.objectContaining({ code: 'INVALID_CURSOR' }));
  });
});

describe('cursor encoding', () => {
  it('round-trips and rejects tampering', () => {
    expect(decodeCursor(encodeCursor(12345))).toBe(12345);
    expect(() => decodeCursor(Buffer.from('v1:-1').toString('base64url'))).toThrow(RequestError);
    expect(() => decodeCursor(Buffer.from('v2:1').toString('base64url'))).toThrow(RequestError);
  });
});
