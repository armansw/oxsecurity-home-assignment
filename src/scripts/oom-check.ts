/**
 * OOM harness — proves the memory claim on a report far larger than the heap.
 *
 *   npm run oom:check                       # 600 MB single-Result report, 5 % CRITICAL
 *   npm run oom:check -- --critical-ratio 1 # every finding CRITICAL: stresses the store path too
 *
 * Runs under `node --max-old-space-size=150` (see package.json). Exits non-zero unless every CRITICAL
 * finding was stored AND peak heap stayed under the budget.
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { parseArgs } from 'node:util';
import v8 from 'node:v8';
import { openDatabase } from '../infrastructure/db/sqlite.js';
import { SqliteScanStore } from '../infrastructure/db/sqlite-scan.store.js';
import { StreamReportProcessor } from '../infrastructure/report/stream-report-processor.js';
import { writeFixtureReport, type FixtureLayout } from '../infrastructure/scanner/fixture-report.js';

const { values } = parseArgs({
  options: {
    'size-mb': { type: 'string', default: '600' },
    'critical-ratio': { type: 'string', default: '0.05' },
    layout: { type: 'string', default: 'single-result' },
    dir: { type: 'string', default: path.join(os.tmpdir(), 'code-guardian-oom') },
    'heap-budget-mb': { type: 'string', default: '100' },
    keep: { type: 'boolean', default: false },
  },
});

const sizeMb = Number(values['size-mb']);
const criticalRatio = Number(values['critical-ratio']);
const heapBudgetMb = Number(values['heap-budget-mb']);
const layout: FixtureLayout = values.layout === 'many-results' ? 'many-results' : 'single-result';
const MB = 1024 * 1024;

async function main(): Promise<void> {
  fs.mkdirSync(values.dir, { recursive: true });
  const reportPath = path.join(values.dir, `report-${sizeMb}mb-${layout}-${criticalRatio}.json`);
  const dbPath = path.join(values.dir, `oom-${process.pid}.db`);

  log(`Generating ${sizeMb} MB ${layout} report (critical ratio ${criticalRatio}) → ${reportPath}`);
  const fixture = await writeFixtureReport({ path: reportPath, sizeMb, criticalRatio, layout });
  log(`  ${(fixture.bytes / MB).toFixed(1)} MB, ${fixture.total.toLocaleString()} vulnerabilities, ${fixture.critical.toLocaleString()} CRITICAL`);

  const store = new SqliteScanStore(openDatabase(dbPath));
  const scan = store.create('https://github.com/OWASP/NodeGoat.git');
  const claimed = store.claimNext('oom-check');
  if (claimed === undefined) throw new Error('could not claim scan');

  global.gc?.();
  const base = process.memoryUsage();
  let peakHeap = base.heapUsed;
  let peakRss = base.rss;
  const sampler = setInterval(() => {
    const m = process.memoryUsage();
    peakHeap = Math.max(peakHeap, m.heapUsed);
    peakRss = Math.max(peakRss, m.rss);
  }, 100);

  let lastLogged = 0;
  log(`Stream-parsing with --max-old-space-size=${heapLimitMb()} MB heap…`);
  const started = performance.now();
  const stats = await new StreamReportProcessor(store, { batchSize: 500, maxValueBytes: MB }).process({
    scanId: scan.id,
    workerId: 'oom-check',
    reportPath,
    signal: new AbortController().signal,
    onProgress: (pct) => {
      const bucket = Math.floor(pct / 10) * 10;
      if (bucket > lastLogged) {
        lastLogged = bucket;
        log(`  ${String(bucket).padStart(3)}%  heapUsed=${mb(process.memoryUsage().heapUsed)} MB  rss=${mb(process.memoryUsage().rss)} MB`);
      }
    },
  });
  const seconds = (performance.now() - started) / 1000;
  clearInterval(sampler);

  let stored = 0;
  for (let after = 0; ; ) {
    const page = store.listVulnerabilities(scan.id, { afterRowId: after, limit: 5000 });
    const last = page.at(-1);
    if (last === undefined) break;
    stored += page.length;
    after = last.rowId;
  }
  store.close();
  fs.rmSync(dbPath, { force: true });
  fs.rmSync(`${dbPath}-wal`, { force: true });
  fs.rmSync(`${dbPath}-shm`, { force: true });
  if (!values.keep) fs.rmSync(reportPath, { force: true });

  const ok = stored === fixture.critical && stats.criticalCount === fixture.critical && mb(peakHeap) < heapBudgetMb;
  const rows: [string, string][] = [
    ['report size', `${(stats.reportBytes / MB).toFixed(1)} MB`],
    ['vulnerabilities scanned', stats.vulnerabilitiesScanned.toLocaleString()],
    ['CRITICAL expected / stored', `${fixture.critical.toLocaleString()} / ${stored.toLocaleString()}`],
    ['duration', `${seconds.toFixed(1)} s (${(stats.reportBytes / MB / seconds).toFixed(1)} MB/s)`],
    ['heap limit', `${heapLimitMb()} MB`],
    ['peak heapUsed', `${mb(peakHeap)} MB (budget ${heapBudgetMb} MB)`],
    ['peak RSS', `${mb(peakRss)} MB`],
    ['result', ok ? 'PASS' : 'FAIL'],
  ];
  for (const [k, v] of rows) log(`${k.padEnd(28)} ${v}`);
  process.exitCode = ok ? 0 : 1;
}

/** The effective V8 heap ceiling (reflects --max-old-space-size). */
function heapLimitMb(): number {
  return mb(v8.getHeapStatistics().heap_size_limit);
}

function mb(bytes: number): number {
  return Math.round(bytes / MB);
}

function log(msg: string): void {
  process.stdout.write(`${msg}\n`);
}

main().catch((err: unknown) => {
  process.stderr.write(`oom-check failed: ${err instanceof Error ? (err.stack ?? err.message) : String(err)}\n`);
  process.exitCode = 1;
});
