import type { Scan } from './scan.js';

/** Opaque self-test run identifier (a v4 UUID). */
export type TestRunId = string & { readonly __brand: 'TestRunId' };

/**
 * Kernel counters of the service's cgroup (memory.events + memory.max). They only ever grow, so the difference
 * between a run's start and now is what happened during the run.
 */
export interface MemoryCounters {
  /** Hard limit (memory.max) in MB; null when unlimited. */
  readonly limitMb: number | null;
  /** Times usage reached the hard limit and the kernel had to reclaim (memory.events `max`). */
  readonly limitHits: number;
  /** Processes in the cgroup killed by the OOM killer (memory.events `oom_kill`). */
  readonly oomKills: number;
}

export interface TestRunEntry {
  readonly repoUrl: string;
  readonly language: string;
  readonly sizeMb: number;
}

export interface TestRunItem extends TestRunEntry {
  readonly position: number;
  readonly scanId: string;
  /** The scan, or null once it has been purged by the retention janitor. */
  readonly scan: Scan | null;
}

/** One click of "Run self-test": a sample of corpus repositories, each scanned as a background scan. */
export interface TestRun {
  readonly id: TestRunId;
  readonly createdAt: Date;
  readonly cancelledAt: Date | null;
  /** Counters when the run started; null where the server cannot read its cgroup. */
  readonly baseline: MemoryCounters | null;
  readonly items: readonly TestRunItem[];
}
