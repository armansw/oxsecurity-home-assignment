import type { ScanErrorCode } from './errors.js';

/** Opaque scan identifier (a v4 UUID). Branded so a random string cannot be passed by accident. */
export type ScanId = string & { readonly __brand: 'ScanId' };

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export function isScanId(value: string): value is ScanId {
  return UUID_RE.test(value);
}

/** The public lifecycle required by the assignment. */
export const SCAN_STATUSES = ['Queued', 'Scanning', 'Finished', 'Failed'] as const;
export type ScanStatus = (typeof SCAN_STATUSES)[number];

/** Extra detail while a scan is `Scanning`. Never replaces the public status. */
export const SCAN_PHASES = ['cloning', 'scanning', 'parsing'] as const;
export type ScanPhase = (typeof SCAN_PHASES)[number];

export interface ScanStats {
  /** Size of the Trivy JSON report that was stream-parsed. */
  readonly reportBytes: number;
  /** Every vulnerability object seen in the stream, any severity. */
  readonly vulnerabilitiesScanned: number;
  readonly criticalCount: number;
  /** CRITICAL entries that failed schema validation and were skipped (not fatal). */
  readonly malformedSkipped: number;
  readonly durationMs: number;
  /** Peak resident set size of the worker process, measured — not estimated. */
  readonly peakRssMb: number;
}

export interface ScanFailure {
  readonly code: ScanErrorCode;
  readonly message: string;
}

export interface Scan {
  readonly id: ScanId;
  /** Normalised repository URL (see infrastructure/git/repo-url.ts). */
  readonly repoUrl: string;
  readonly status: ScanStatus;
  readonly phase: ScanPhase | null;
  /** Parse progress 0–100 while phase = parsing. */
  readonly progressPct: number | null;
  readonly attempts: number;
  readonly stats: ScanStats | null;
  readonly error: ScanFailure | null;
  readonly createdAt: Date;
  readonly startedAt: Date | null;
  readonly finishedAt: Date | null;
}

export function isTerminal(status: ScanStatus): boolean {
  return status === 'Finished' || status === 'Failed';
}
