import fs from 'node:fs';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import type { ScanId } from '../../src/domain/scan.js';
import type { SqliteScanStore } from '../../src/infrastructure/db/sqlite-scan.store.js';
import { StreamReportProcessor } from '../../src/infrastructure/report/stream-report-processor.js';
import { writeFixtureReport } from '../../src/infrastructure/scanner/fixture-report.js';
import { memoryStore, report, tempDir, vuln } from '../helpers/index.js';

describe('StreamReportProcessor', () => {
  let dir: string;
  let store: SqliteScanStore;
  let scanId: ScanId;
  const workerId = 'w1';

  beforeEach(() => {
    dir = tempDir();
    store = memoryStore();
    scanId = store.create('https://github.com/a/b.git').id;
    store.claimNext(workerId);
  });
  afterEach(() => {
    store.close();
    fs.rmSync(dir, { recursive: true, force: true });
  });

  const run = (reportPath: string, opts: { signal?: AbortSignal; onProgress?: (n: number) => void; batchSize?: number; highWaterMark?: number; progressIntervalMs?: number } = {}) =>
    new StreamReportProcessor(store, {
      batchSize: opts.batchSize ?? 3,
      maxValueBytes: 1024 * 1024,
      ...(opts.highWaterMark ? { highWaterMark: opts.highWaterMark } : {}),
      ...(opts.progressIntervalMs ? { progressIntervalMs: opts.progressIntervalMs } : {}),
    }).process({ scanId, workerId, reportPath, signal: opts.signal ?? new AbortController().signal, onProgress: opts.onProgress ?? (() => undefined) });

  it('streams a report into the store and returns stats', async () => {
    const file = path.join(dir, 'r.json');
    const vulns = Array.from({ length: 10 }, (_, i) => vuln({ id: `CVE-${i}`, severity: i % 2 === 0 ? 'CRITICAL' : 'MEDIUM' }));
    fs.writeFileSync(file, report([{ Target: 't', Type: 'npm', Vulnerabilities: vulns }]));

    const stats = await run(file);
    expect(stats).toEqual({ reportBytes: fs.statSync(file).size, vulnerabilitiesScanned: 10, criticalCount: 5, malformedSkipped: 0 });
    expect(store.listVulnerabilities(scanId, { afterRowId: 0, limit: 100 }).map((v) => v.vulnerabilityId)).toEqual([
      'CVE-0', 'CVE-2', 'CVE-4', 'CVE-6', 'CVE-8',
    ]);
  });

  it('processes a multi-megabyte single-Result fixture exactly, with small read chunks', async () => {
    const file = path.join(dir, 'big.json');
    const fixture = await writeFixtureReport({ path: file, sizeMb: 3, criticalRatio: 0.1 });
    const progress: number[] = [];
    const stats = await run(file, { batchSize: 50, highWaterMark: 16 * 1024, progressIntervalMs: 1, onProgress: (p) => progress.push(p) });
    expect(stats.vulnerabilitiesScanned).toBe(fixture.total);
    expect(stats.criticalCount).toBe(fixture.critical);
    expect(progress.every((p) => p >= 0 && p <= 99)).toBe(true);
  });

  it.each([
    ['missing', null],
    ['empty', ''],
  ])('rejects a %s report as REPORT_INVALID', async (_name, content) => {
    const file = path.join(dir, 'r.json');
    if (content !== null) fs.writeFileSync(file, content);
    await expect(run(file)).rejects.toMatchObject({ code: 'REPORT_INVALID' });
  });

  it('rejects a directory in place of the report', async () => {
    await expect(run(dir)).rejects.toMatchObject({ code: 'REPORT_INVALID' });
  });

  it('rejects truncated JSON and never reports a partial result', async () => {
    const file = path.join(dir, 'r.json');
    const full = report([{ Target: 't', Vulnerabilities: Array.from({ length: 20 }, (_, i) => vuln({ id: `CVE-${i}` })) }]);
    fs.writeFileSync(file, full.slice(0, Math.floor(full.length * 0.7)));
    await expect(run(file)).rejects.toMatchObject({ code: 'REPORT_INVALID' });
  });

  it('stops with the abort reason when aborted', async () => {
    const file = path.join(dir, 'big.json');
    await writeFixtureReport({ path: file, sizeMb: 2, criticalRatio: 0.5 });
    const controller = new AbortController();
    const reason = new Error('stop');
    const promise = run(file, { signal: controller.signal, highWaterMark: 1024 });
    setImmediate(() => {
      controller.abort(reason);
    });
    await expect(promise).rejects.toBe(reason);
  });

  it('fails when the lease is lost mid-stream', async () => {
    const file = path.join(dir, 'r.json');
    fs.writeFileSync(file, report([{ Target: 't', Vulnerabilities: [vuln()] }]));
    store.reclaimStale(Date.now() + 1000, 5); // steal the lease
    await expect(run(file)).rejects.toMatchObject({ name: 'LeaseLostError' });
  });
});
