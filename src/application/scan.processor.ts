import { LeaseLostError } from '../domain/errors.js';
import type { Clock, Logger, ReportProcessor, RepositoryFetcher, Scanner, ScanStore, ScanWorkspace, Workspace } from '../domain/ports.js';
import type { Scan, ScanPhase } from '../domain/scan.js';
import { classifyFailure, retryDelayMs } from '../infrastructure/errors/classify-error.js';

export interface ScanProcessorDeps {
  readonly store: ScanStore;
  readonly fetcher: RepositoryFetcher;
  readonly scanner: Scanner;
  readonly reports: ReportProcessor;
  readonly workspace: Workspace;
  readonly log: Logger;
  readonly now?: Clock;
  readonly random?: () => number;
}

export interface ScanProcessorOptions {
  readonly maxAttempts: number;
  readonly heartbeatMs: number;
  readonly retryBaseMs: number;
  readonly memorySampleMs?: number;
}

/**
 * Runs one claimed scan through clone → scan → parse → cleanup. `run` never throws: every outcome ends in
 * Finished, Failed, or a re-queue, and the workspace (clone + report) is always deleted.
 */
export class ScanProcessor {
  private readonly now: Clock;
  private readonly random: () => number;

  constructor(
    private readonly deps: ScanProcessorDeps,
    private readonly opts: ScanProcessorOptions,
  ) {
    this.now = deps.now ?? Date.now;
    this.random = deps.random ?? Math.random;
  }

  async run(scan: Scan, workerId: string, shutdown: AbortSignal): Promise<void> {
    const { store, fetcher, scanner, reports, workspace } = this.deps;
    const log = this.deps.log.child({ scanId: scan.id, attempt: scan.attempts });
    const started = this.now();

    // Job-scoped abort: fired by shutdown or by losing the lease. Kills child processes, tears down streams.
    const job = new AbortController();
    const onShutdown = (): void => {
      job.abort(shutdown.reason);
    };
    if (shutdown.aborted) onShutdown();
    else shutdown.addEventListener('abort', onShutdown, { once: true });

    let phase: ScanPhase = 'cloning';
    let progressPct: number | null = null;
    const beat = (): void => {
      try {
        if (!store.heartbeat(scan.id, workerId, { phase, progressPct })) job.abort(new LeaseLostError(scan.id));
      } catch (err) {
        log.warn({ err }, 'heartbeat failed');
      }
    };
    const enter = (next: ScanPhase): void => {
      phase = next;
      progressPct = null;
      beat();
      log.info({ phase }, 'phase started');
    };
    const heartbeat = setInterval(beat, this.opts.heartbeatMs);

    // Peak RSS of this process while this scan ran (includes everything in-process, measured not estimated).
    let peakRss = process.memoryUsage.rss();
    const sampler = setInterval(() => {
      peakRss = Math.max(peakRss, process.memoryUsage.rss());
    }, this.opts.memorySampleMs ?? 250);

    let ws: ScanWorkspace | undefined;
    try {
      log.info({ repoUrl: scan.repoUrl }, 'scan started');
      ws = await workspace.create(scan.id);
      await workspace.assertFreeSpace();
      store.clearVulnerabilities(scan.id, workerId); // idempotent retries

      enter('cloning');
      await fetcher.clone(scan.repoUrl, ws.repoDir, job.signal);
      throwIfAborted(job.signal);

      enter('scanning');
      await scanner.scan({ sourceDir: ws.repoDir, reportPath: ws.reportPath, tmpDir: ws.tmpDir, signal: job.signal });
      throwIfAborted(job.signal);
      await workspace.remove(ws.repoDir); // free the clone's disk before parsing

      enter('parsing');
      const stats = await reports.process({
        scanId: scan.id,
        workerId,
        reportPath: ws.reportPath,
        signal: job.signal,
        onProgress: (pct) => {
          progressPct = pct;
        },
      });
      throwIfAborted(job.signal);

      peakRss = Math.max(peakRss, process.memoryUsage.rss());
      const finished = store.markFinished(scan.id, workerId, {
        ...stats,
        durationMs: this.now() - started,
        peakRssMb: Math.round(peakRss / (1024 * 1024)),
      });
      if (finished) log.info({ ...stats, durationMs: this.now() - started }, 'scan finished');
      else log.warn('scan finished but lease was lost; result discarded');
    } catch (err) {
      this.handleFailure(scan, workerId, err, job.signal, log);
    } finally {
      clearInterval(heartbeat);
      clearInterval(sampler);
      shutdown.removeEventListener('abort', onShutdown);
      if (ws !== undefined) await workspace.remove(ws.root);
    }
  }

  private handleFailure(scan: Scan, workerId: string, err: unknown, signal: AbortSignal, log: Logger): void {
    const { store } = this.deps;
    const outcome = classifyFailure(err, signal);
    try {
      switch (outcome.kind) {
        case 'lease-lost':
          log.warn('lease lost; another worker owns this scan now');
          return;
        case 'shutdown':
          // Not the job's fault: give the attempt back and let the next worker start immediately.
          store.requeue(scan.id, workerId, { runAfter: this.now(), refundAttempt: true });
          log.info('scan re-queued on shutdown');
          return;
        case 'failure': {
          const { error } = outcome;
          if (error.retryable && scan.attempts < this.opts.maxAttempts) {
            const delay = retryDelayMs(scan.attempts, this.opts.retryBaseMs, this.random);
            store.requeue(scan.id, workerId, { runAfter: this.now() + delay, refundAttempt: false });
            log.warn({ err, code: error.code, retryInMs: delay }, 'scan attempt failed; will retry');
            return;
          }
          store.markFailed(scan.id, workerId, { code: error.code, message: error.message });
          log.error({ err, code: error.code }, 'scan failed');
          return;
        }
      }
    } catch (storeErr) {
      // Even the failure could not be recorded (e.g. DB unavailable). The reaper will recover the lease.
      log.error({ err: storeErr, original: err }, 'could not record scan outcome');
    }
  }
}

function throwIfAborted(signal: AbortSignal): void {
  if (signal.aborted) throw signal.reason;
}
