import os from 'node:os';
import { randomBytes } from 'node:crypto';
import { setTimeout as sleep } from 'node:timers/promises';
import type { ScanProcessor } from '../application/scan.processor.js';
import { ShutdownError } from '../domain/errors.js';
import type { Clock, Logger, ScanStore, Workspace } from '../domain/ports.js';

export interface WorkerOptions {
  readonly concurrency: number;
  readonly pollMs: number;
  readonly staleAfterMs: number;
  readonly maxAttempts: number;
  readonly ttlMs: number;
  readonly janitorIntervalMs?: number;
}

export interface WorkerDeps {
  readonly store: ScanStore;
  readonly processor: ScanProcessor;
  readonly workspace: Workspace;
  readonly log: Logger;
  readonly now?: Clock;
}

/**
 * Pulls scans from the durable queue and runs them. Concurrency defaults to 1 on purpose: every job owns a
 * git process, a Trivy process and a parse, so concurrency is a memory decision, not a throughput knob.
 *
 * Background duties:
 *  - reaper:  re-queues scans whose worker stopped heart-beating (crash / OOM-kill); fails them after
 *             maxAttempts so a poison job cannot loop forever;
 *  - janitor: deletes workspaces orphaned by a hard kill and purges scans older than the TTL.
 */
export class Worker {
  readonly id = `${os.hostname()}:${process.pid}:${randomBytes(3).toString('hex')}`;
  private readonly shutdown = new AbortController();
  private readonly loops: Promise<void>[] = [];
  private readonly timers: NodeJS.Timeout[] = [];
  private readonly waiters = new Set<() => void>();
  private readonly now: Clock;

  constructor(
    private readonly deps: WorkerDeps,
    private readonly opts: WorkerOptions,
  ) {
    this.now = deps.now ?? Date.now;
  }

  get running(): boolean {
    return this.loops.length > 0 && !this.shutdown.signal.aborted;
  }

  start(): void {
    this.deps.log.info({ workerId: this.id, concurrency: this.opts.concurrency }, 'worker started');
    this.reap();
    void this.janitor();
    this.timers.push(
      setInterval(() => {
        this.reap();
      }, Math.max(100, Math.floor(this.opts.staleAfterMs / 2))),
      setInterval(() => void this.janitor(), this.opts.janitorIntervalMs ?? 10 * 60 * 1000),
    );
    for (const t of this.timers) t.unref();
    for (let i = 0; i < this.opts.concurrency; i += 1) this.loops.push(this.loop(`${this.id}#${i}`));
  }

  /** Called by the API after enqueueing, so an in-process worker starts immediately instead of next poll. */
  wake(): void {
    for (const resume of [...this.waiters]) resume();
  }

  /** Stop claiming, abort in-flight jobs (they are re-queued with the attempt refunded), wait for loops. */
  async stop(graceMs: number): Promise<void> {
    if (!this.shutdown.signal.aborted) this.shutdown.abort(new ShutdownError());
    for (const t of this.timers) clearInterval(t);
    this.wake();
    const done = Promise.allSettled(this.loops).then(() => true);
    const timedOut = sleep(graceMs, false, { ref: false });
    if (!(await Promise.race([done, timedOut]))) this.deps.log.warn('worker did not stop within the grace period');
  }

  private async loop(workerId: string): Promise<void> {
    const { store, processor, log } = this.deps;
    const signal = this.shutdown.signal;
    while (!signal.aborted) {
      let scan;
      try {
        scan = store.claimNext(workerId);
      } catch (err) {
        log.error({ err }, 'failed to claim next scan');
      }
      if (scan === undefined) {
        await this.idle();
        continue;
      }
      await processor.run(scan, workerId, signal);
    }
  }

  /** Sleep until the poll interval elapses, `wake()` is called, or shutdown begins. */
  private idle(): Promise<void> {
    return new Promise<void>((resolve) => {
      const finish = (): void => {
        clearTimeout(timer);
        this.shutdown.signal.removeEventListener('abort', finish);
        this.waiters.delete(finish);
        resolve();
      };
      const timer = setTimeout(finish, this.opts.pollMs);
      this.shutdown.signal.addEventListener('abort', finish, { once: true });
      this.waiters.add(finish);
    });
  }

  private reap(): void {
    try {
      const { requeued, failed } = this.deps.store.reclaimStale(this.now() - this.opts.staleAfterMs, this.opts.maxAttempts);
      if (requeued + failed > 0) {
        this.deps.log.warn({ requeued, failed }, 'reclaimed scans from unresponsive workers');
        // A dead worker cannot delete its workspace: reclaim the disk now rather than at the next janitor run.
        void this.janitor();
      }
    } catch (err) {
      this.deps.log.error({ err }, 'reaper failed');
    }
  }

  private async janitor(): Promise<void> {
    const { store, workspace, log } = this.deps;
    try {
      const orphans = await workspace.removeOrphans((id) => store.isScanning(id));
      const purged = store.purgeFinishedBefore(this.now() - this.opts.ttlMs);
      if (orphans + purged > 0) log.info({ orphans, purged }, 'janitor cleaned up');
    } catch (err) {
      log.error({ err }, 'janitor failed');
    }
  }
}
