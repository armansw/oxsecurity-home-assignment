/**
 * Composition root — the only place that knows concrete implementations.
 *
 *   node --max-old-space-size=150 dist/index.js        # ROLE=all: API + worker (the brief's self-test)
 *   ROLE=api    node dist/index.js                     # HTTP only
 *   ROLE=worker node dist/index.js                     # background processing only
 */
import { mkdir } from 'node:fs/promises';
import type { FastifyBaseLogger } from 'fastify';
import { pino } from 'pino';
import { ScanProcessor } from './application/scan.processor.js';
import { ScanService } from './application/scan.service.js';
import { loadConfig } from './config/env.js';
import type { RepositoryFetcher, Scanner } from './domain/ports.js';
import { RemoteScanAgent } from './infrastructure/scanner/remote-scan-agent.js';
import { buildScannerAgentApp } from './interfaces/http/scanner-agent.js';
import type { Config } from './config/env.js';
import { openDatabase } from './infrastructure/db/sqlite.js';
import { SqliteScanStore } from './infrastructure/db/sqlite-scan.store.js';
import { DiskWorkspace } from './infrastructure/fs/disk-workspace.js';
import { GitRepositoryFetcher } from './infrastructure/git/git-repository-fetcher.js';
import { StreamReportProcessor } from './infrastructure/report/stream-report-processor.js';
import { FixtureScanner } from './infrastructure/scanner/fixture-scanner.js';
import { TrivyScanner } from './infrastructure/scanner/trivy-scanner.js';
import { buildApp, buildOpsApp } from './interfaces/http/app.js';
import { PrometheusMetrics } from './infrastructure/metrics/prometheus-metrics.js';
import type { ReadinessCheck } from './interfaces/http/health.controller.js';
import { Worker } from './worker/worker.js';

async function main(): Promise<void> {
  const config = loadConfig();
  const log = pino({ level: config.LOG_LEVEL, base: { role: config.ROLE } });

  await mkdir(config.WORK_DIR, { recursive: true });
  if (config.ROLE === 'scanner') {
    await runScannerAgent(config, log);
    return;
  }
  const store = new SqliteScanStore(openDatabase(config.DATABASE_PATH));
  const workspace = new DiskWorkspace(config.WORK_DIR, config.MIN_FREE_DISK_MB * 1024 * 1024, log);

  const remote =
    config.SCANNER === 'remote' && config.SCANNER_URL !== undefined && config.SCANNER_TOKEN !== undefined
      ? new RemoteScanAgent({ url: config.SCANNER_URL, token: config.SCANNER_TOKEN })
      : undefined;
  const scanner: Scanner =
    remote ??
    (config.SCANNER === 'fixture'
      ? new FixtureScanner({ sizeMb: config.FIXTURE_SIZE_MB, criticalRatio: config.FIXTURE_CRITICAL_RATIO })
      : localTrivy(config));
  const fetcher: RepositoryFetcher = remote ?? new GitRepositoryFetcher({ gitBin: config.GIT_BIN, timeoutMs: config.CLONE_TIMEOUT_MS });

  const metrics = new PrometheusMetrics(store);
  const runsWorker = config.ROLE !== 'api';
  const runsApi = config.ROLE !== 'worker';

  const worker = runsWorker
    ? new Worker(
        {
          store,
          workspace,
          log: log.child({ component: 'worker' }),
          processor: new ScanProcessor(
            {
              store,
              workspace,
              log: log.child({ component: 'processor' }),
              metrics,
              fetcher,
              scanner,
              reports: new StreamReportProcessor(store, { batchSize: config.BATCH_SIZE, maxValueBytes: config.MAX_JSON_VALUE_BYTES }),
            },
            { maxAttempts: config.MAX_ATTEMPTS, heartbeatMs: config.HEARTBEAT_MS, retryBaseMs: config.RETRY_BASE_MS },
          ),
        },
        {
          concurrency: config.WORKER_CONCURRENCY,
          pollMs: config.WORKER_POLL_MS,
          staleAfterMs: config.STALE_AFTER_MS,
          maxAttempts: config.MAX_ATTEMPTS,
          ttlMs: config.SCAN_TTL_HOURS * 60 * 60 * 1000,
        },
      )
    : undefined;

  if (runsWorker) {
    const available = await scanner.checkAvailable();
    if (available.ok) log.info({ scanner: available.detail }, 'scanner available');
    else log.warn({ detail: available.detail }, 'scanner NOT available — scans will fail with SCANNER_UNAVAILABLE');
  }

  const service = new ScanService(store, {
    allowedHosts: config.ALLOWED_GIT_HOSTS,
    maxQueued: config.MAX_QUEUED,
    dedupeActiveScans: config.DEDUPE_ACTIVE_SCANS,
    ...(worker ? { wake: () => { worker.wake(); }, checkCapacity: () => workspace.assertFreeSpace() } : {}),
  });

  // Probes can be frequent; never spawn `trivy --version` more than once per 30 s.
  let scannerCheck: { at: number; result: ReadinessCheck } | undefined;
  const checkScanner = async (): Promise<ReadinessCheck> => {
    if (scannerCheck === undefined || Date.now() - scannerCheck.at > 30_000) {
      scannerCheck = { at: Date.now(), result: await scanner.checkAvailable() };
    }
    return scannerCheck.result;
  };

  const readiness = async (): Promise<Record<string, ReadinessCheck>> => {
    const checks: Record<string, ReadinessCheck> = {};
    try {
      checks.database = { ok: true, detail: `${store.countQueued()} queued` };
    } catch (err) {
      checks.database = { ok: false, detail: err instanceof Error ? err.message : String(err) };
    }
    if (runsWorker) {
      checks.scanner = await checkScanner();
      const free = await workspace.freeBytes().catch(() => 0);
      checks.disk = { ok: free >= config.MIN_FREE_DISK_MB * 1024 * 1024, detail: `${Math.floor(free / 1024 / 1024)} MB free` };
      checks.worker = { ok: worker?.running ?? false, detail: worker?.id ?? 'none' };
    }
    return checks;
  };

  const app = runsApi
    ? await buildApp({
        service,
        store,
        readiness,
        metrics,
        trustProxy: config.TRUST_PROXY,
        logger: log,
        responsePageSize: config.RESPONSE_PAGE_SIZE,
        rateLimitPerMinute: config.RATE_LIMIT_PER_MIN,
        graphiql: config.NODE_ENV !== 'production',
      })
    : buildOpsApp({ readiness, metrics, trustProxy: config.TRUST_PROXY, logger: log }); // ROLE=worker: health + metrics only

  worker?.start();
  await app.listen({ host: config.HOST, port: config.PORT });

  let stopping = false;
  const shutdown = async (signal: string): Promise<void> => {
    if (stopping) return;
    stopping = true;
    log.info({ signal }, 'shutting down');
    const hardExit = setTimeout(() => {
      log.error('graceful shutdown timed out; exiting');
      process.exit(1);
    }, config.SHUTDOWN_GRACE_MS + 2000);
    hardExit.unref();
    try {
      await app.close(); // stop accepting requests first
      await worker?.stop(config.SHUTDOWN_GRACE_MS); // in-flight scan is re-queued, workspace removed
    } finally {
      store.close();
      log.info('shutdown complete');
    }
  };
  for (const sig of ['SIGTERM', 'SIGINT'] as const) {
    process.once(sig, () => void shutdown(sig));
  }
}

function localTrivy(config: Config): TrivyScanner {
  return new TrivyScanner({
    trivyBin: config.TRIVY_BIN,
    timeoutMs: config.SCAN_TIMEOUT_MS,
    cacheDir: config.trivyCacheDir,
    serverUrl: config.TRIVY_SERVER_URL,
    token: config.TRIVY_TOKEN,
    goMemLimit: config.TRIVY_GOMEMLIMIT,
    goGc: config.TRIVY_GOGC,
  });
}

/** ROLE=scanner: run git + Trivy for the service, in this container's own memory budget. */
async function runScannerAgent(config: Config, log: FastifyBaseLogger): Promise<void> {
  const app = buildScannerAgentApp({
    fetcher: new GitRepositoryFetcher({ gitBin: config.GIT_BIN, timeoutMs: config.CLONE_TIMEOUT_MS }),
    scanner: localTrivy(config),
    workDir: config.WORK_DIR,
    token: config.SCANNER_TOKEN ?? '',
    allowedHosts: config.ALLOWED_GIT_HOSTS,
    logger: log,
  });
  await app.listen({ host: config.HOST, port: config.PORT });
  for (const sig of ['SIGTERM', 'SIGINT'] as const) {
    process.once(sig, () => {
      log.info({ signal: sig }, 'scanner agent shutting down');
      void app.close().then(() => process.exit(0));
    });
  }
}

main().catch((err: unknown) => {
  process.stderr.write(`fatal: ${err instanceof Error ? (err.stack ?? err.message) : String(err)}\n`);
  process.exit(1);
});
