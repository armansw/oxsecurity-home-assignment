import type { Scan, ScanFailure } from '../../domain/scan.js';
import type { CriticalVulnerability } from '../../domain/vulnerability.js';

export interface VulnerabilityDto {
  readonly id: string;
  readonly pkgName: string;
  readonly installedVersion: string | null;
  readonly fixedVersion: string | null;
  readonly severity: 'CRITICAL';
  readonly title: string | null;
  readonly description: string | null;
  readonly primaryUrl: string | null;
  readonly target: string;
  readonly pkgType: string | null;
  readonly cvssScore: number | null;
  readonly publishedDate: string | null;
}

interface ScanViewBase {
  readonly scanId: string;
  readonly repoUrl: string;
  /** The exact commit scanned; null until the clone completes. */
  readonly commitSha: string | null;
  readonly attempt: number;
  readonly createdAt: string;
}

export interface QueuedScanView extends ScanViewBase {
  readonly status: 'Queued';
}

export interface ScanningScanView extends ScanViewBase {
  readonly status: 'Scanning';
  readonly phase: Scan['phase'];
  readonly progressPct: number | null;
  readonly startedAt: string | null;
}

export interface FailedScanView extends ScanViewBase {
  readonly status: 'Failed';
  readonly error: ScanFailure;
  readonly finishedAt: string | null;
}

/** Header of a Finished response; `criticalVulnerabilities` is appended by the streaming serializer. */
export interface FinishedScanHeader extends ScanViewBase {
  readonly status: 'Finished';
  readonly startedAt: string | null;
  readonly finishedAt: string | null;
  readonly criticalCount: number;
  readonly stats: {
    readonly reportBytes: number;
    readonly vulnerabilitiesScanned: number;
    readonly malformedSkipped: number;
    readonly durationMs: number;
    readonly peakMemoryMb: number;
  };
}

export type ScanHeaderView = QueuedScanView | ScanningScanView | FailedScanView | FinishedScanHeader;

export function toScanHeaderView(scan: Scan): ScanHeaderView {
  const base: ScanViewBase = {
    scanId: scan.id,
    repoUrl: scan.repoUrl,
    commitSha: scan.commitSha,
    attempt: scan.attempts,
    createdAt: scan.createdAt.toISOString(),
  };
  switch (scan.status) {
    case 'Queued':
      return { ...base, status: 'Queued' };
    case 'Scanning':
      return { ...base, status: 'Scanning', phase: scan.phase, progressPct: scan.progressPct, startedAt: iso(scan.startedAt) };
    case 'Failed':
      return {
        ...base,
        status: 'Failed',
        error: scan.error ?? { code: 'INTERNAL', message: 'Scan failed' },
        finishedAt: iso(scan.finishedAt),
      };
    case 'Finished': {
      const s = scan.stats;
      return {
        ...base,
        status: 'Finished',
        startedAt: iso(scan.startedAt),
        finishedAt: iso(scan.finishedAt),
        criticalCount: s?.criticalCount ?? 0,
        stats: {
          reportBytes: s?.reportBytes ?? 0,
          vulnerabilitiesScanned: s?.vulnerabilitiesScanned ?? 0,
          malformedSkipped: s?.malformedSkipped ?? 0,
          durationMs: s?.durationMs ?? 0,
          peakMemoryMb: s?.peakMemoryMb ?? 0,
        },
      };
    }
  }
}

export function toVulnerabilityDto(v: CriticalVulnerability): VulnerabilityDto {
  return {
    id: v.vulnerabilityId,
    pkgName: v.pkgName,
    installedVersion: v.installedVersion,
    fixedVersion: v.fixedVersion,
    severity: v.severity,
    title: v.title,
    description: v.description,
    primaryUrl: v.primaryUrl,
    target: v.target,
    pkgType: v.pkgType,
    cvssScore: v.cvssScore,
    publishedDate: v.publishedDate,
  };
}

function iso(d: Date | null): string | null {
  return d === null ? null : d.toISOString();
}
