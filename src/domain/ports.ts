/**
 * Ports: the interfaces the application layer depends on. Adapters in `infrastructure/` implement them;
 * `src/index.ts` wires them together. Nothing here performs I/O or imports a framework.
 */
import type { ScanFailure, Scan, ScanId, ScanPhase, ScanStats } from './scan.js';
import type { CriticalVulnerability, StoredVulnerability } from './vulnerability.js';

export interface LogFn {
  (obj: object, msg?: string): void;
  (msg: string): void;
}

/** Structural subset of pino's logger, so the domain does not depend on pino. */
export interface Logger {
  readonly debug: LogFn;
  readonly info: LogFn;
  readonly warn: LogFn;
  readonly error: LogFn;
  child(bindings: Record<string, unknown>): Logger;
}

export type Clock = () => number;

/**
 * Durable scan state and job queue (see ADR-1). Methods are synchronous: the SQLite adapter executes
 * each as a single indexed statement or transaction in well under a millisecond.
 *
 * Every worker-side mutation is *fenced* by `workerId`: it only applies while that worker still holds
 * the lease, so a worker whose lease was reclaimed can never overwrite the new owner's state.
 */
export interface ScanStore {
  create(repoUrl: string): Scan;
  findById(id: ScanId): Scan | undefined;
  /** A Queued or Scanning scan for the same normalised URL, used to deduplicate requests. */
  findActiveByRepo(repoUrl: string): Scan | undefined;
  countQueued(): number;

  /** Atomically move the oldest runnable Queued scan to Scanning and lease it to `workerId`. */
  claimNext(workerId: string): Scan | undefined;
  /** Renew the lease and publish progress. Returns false when the lease has been lost. */
  heartbeat(id: ScanId, workerId: string, patch?: { phase?: ScanPhase; progressPct?: number | null }): boolean;
  clearVulnerabilities(id: ScanId, workerId: string): void;
  /** Insert one batch in a single transaction. Throws LeaseLostError when the lease has been lost. */
  appendVulnerabilities(id: ScanId, workerId: string, batch: readonly CriticalVulnerability[]): void;
  markFinished(id: ScanId, workerId: string, stats: ScanStats): boolean;
  markFailed(id: ScanId, workerId: string, failure: ScanFailure): boolean;
  /** Return a Scanning scan to the queue (retry with backoff, or graceful shutdown with refund). */
  requeue(id: ScanId, workerId: string, opts: { runAfter: number; refundAttempt: boolean }): boolean;
  /** Recover scans whose worker stopped heart-beating (crash, OOM-kill). */
  reclaimStale(staleBefore: number, maxAttempts: number): { requeued: number; failed: number };
  isScanning(id: ScanId): boolean;

  /** Keyset page of a scan's stored vulnerabilities (row_id > afterRowId, ascending). */
  listVulnerabilities(id: ScanId, opts: { afterRowId: number; limit: number }): StoredVulnerability[];
  /** Delete terminal scans (and, by cascade, their vulnerabilities) finished before `cutoff`. */
  purgeFinishedBefore(cutoff: number): number;
  close(): void;
}

export interface RepositoryFetcher {
  /** Shallow-clone `repoUrl` into `destDir`. Throws ScanError on failure. */
  clone(repoUrl: string, destDir: string, signal: AbortSignal): Promise<void>;
}

export interface Scanner {
  /** Scan `sourceDir`, writing a Trivy JSON report to `reportPath`. Throws ScanError on failure. */
  scan(input: { sourceDir: string; reportPath: string; tmpDir: string; signal: AbortSignal }): Promise<void>;
  checkAvailable(): Promise<{ ok: boolean; detail: string }>;
}

export interface ScanWorkspace {
  readonly root: string;
  readonly repoDir: string;
  readonly reportPath: string;
  readonly tmpDir: string;
}

export interface Workspace {
  create(id: ScanId): Promise<ScanWorkspace>;
  /** Throws ScanError('INSUFFICIENT_DISK') when free space is below the configured floor. */
  assertFreeSpace(): Promise<void>;
  freeBytes(): Promise<number>;
  /** Best-effort recursive delete. Never throws. */
  remove(path: string): Promise<void>;
  /** Delete workspaces left behind by a hard kill (SIGKILL / OOM-kill skip `finally`). */
  removeOrphans(isActive: (id: ScanId) => boolean): Promise<number>;
}

export type ReportStats = Pick<ScanStats, 'reportBytes' | 'vulnerabilitiesScanned' | 'criticalCount' | 'malformedSkipped'>;

export interface ReportProcessor {
  process(input: {
    scanId: ScanId;
    workerId: string;
    reportPath: string;
    signal: AbortSignal;
    onProgress: (pct: number) => void;
  }): Promise<ReportStats>;
}
