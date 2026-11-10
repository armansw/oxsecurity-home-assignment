/**
 * Normalized frontend model. Both transports (REST and GraphQL) map their wire formats onto these
 * types, so components never know which one produced the data.
 */

export const SCAN_PHASES = ['cloning', 'scanning', 'parsing'] as const;
export type ScanPhase = (typeof SCAN_PHASES)[number];

export type ScanStatus = 'Queued' | 'Scanning' | 'Finished' | 'Failed';

export interface ScanFailure {
  readonly code: string;
  readonly message: string;
}

export interface ScanStats {
  readonly reportBytes: number;
  readonly vulnerabilitiesScanned: number;
  readonly malformedSkipped: number;
  readonly durationMs: number;
  readonly peakRssMb: number;
}

export interface Vulnerability {
  readonly id: string;
  readonly pkgName: string;
  readonly installedVersion: string | null;
  readonly fixedVersion: string | null;
  readonly severity: string;
  readonly title: string | null;
  readonly description: string | null;
  readonly primaryUrl: string | null;
  readonly target: string;
  readonly pkgType: string | null;
  readonly cvssScore: number | null;
  readonly publishedDate: string | null;
}

export interface VulnerabilityPage {
  readonly items: readonly Vulnerability[];
  /** Opaque cursor for the next page, or null when this is the last page. */
  readonly nextCursor: string | null;
}

interface ScanBase {
  readonly scanId: string;
  readonly repoUrl: string;
  readonly attempt: number;
  readonly createdAt: string;
}

export interface QueuedScan extends ScanBase {
  readonly status: 'Queued';
}

export interface ScanningScan extends ScanBase {
  readonly status: 'Scanning';
  readonly phase: ScanPhase | null;
  readonly progressPct: number | null;
  readonly startedAt: string | null;
}

export interface FailedScan extends ScanBase {
  readonly status: 'Failed';
  readonly error: ScanFailure;
  readonly finishedAt: string | null;
}

export interface FinishedScan extends ScanBase {
  readonly status: 'Finished';
  readonly startedAt: string | null;
  readonly finishedAt: string | null;
  readonly criticalCount: number;
  readonly stats: ScanStats;
  /** The requested page of critical vulnerabilities. */
  readonly page: VulnerabilityPage;
}

export type ScanView = QueuedScan | ScanningScan | FailedScan | FinishedScan;

export interface StartScanResult {
  readonly scanId: string;
  readonly status: ScanStatus;
  /** True when the server reused an already queued/scanning scan of the same repo. */
  readonly deduplicated: boolean;
}

/** Page size the UI always requests (the REST API streams the unbounded list without one). */
export const PAGE_SIZE = 100;

export interface PageRequest {
  readonly limit: number;
  readonly cursor: string | null;
}

export interface ScanApi {
  startScan(repoUrl: string, signal?: AbortSignal): Promise<StartScanResult>;
  getScan(scanId: string, page?: PageRequest, signal?: AbortSignal): Promise<ScanView>;
}

export type Transport = 'rest' | 'graphql';

export function isTerminal(status: ScanStatus): boolean {
  return status === 'Finished' || status === 'Failed';
}
