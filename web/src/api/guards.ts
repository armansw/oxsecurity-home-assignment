/**
 * Tiny hand-written readers that narrow `unknown` JSON into typed values. Each throws an
 * INVALID_RESPONSE ApiError naming the offending field, so a contract drift fails loudly at the
 * boundary instead of as `undefined` deep inside a component.
 */
import { invalidResponse } from './errors';
import {
  SCAN_PHASES,
  type ScanFailure,
  type ScanPhase,
  type ScanStats,
  type ScanStatus,
  type ScanView,
  type Vulnerability,
  type VulnerabilityPage,
} from './types';

export type JsonObject = Readonly<Record<string, unknown>>;

export function isObject(value: unknown): value is JsonObject {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

export function asObject(value: unknown, path: string): JsonObject {
  if (!isObject(value)) throw invalidResponse(path);
  return value;
}

export function asArray(value: unknown, path: string): readonly unknown[] {
  if (!Array.isArray(value)) throw invalidResponse(path);
  return value;
}

export function str(obj: JsonObject, key: string): string {
  const value = obj[key];
  if (typeof value !== 'string') throw invalidResponse(key);
  return value;
}

/** A nullable string; a missing key reads as null. */
export function optStr(obj: JsonObject, key: string): string | null {
  const value = obj[key];
  if (value === undefined || value === null) return null;
  if (typeof value !== 'string') throw invalidResponse(key);
  return value;
}

export function num(obj: JsonObject, key: string): number {
  const value = obj[key];
  if (typeof value !== 'number' || !Number.isFinite(value)) throw invalidResponse(key);
  return value;
}

/** A nullable number; a missing key reads as null. */
export function optNum(obj: JsonObject, key: string): number | null {
  const value = obj[key];
  if (value === undefined || value === null) return null;
  return num(obj, key);
}

const STATUSES: readonly ScanStatus[] = ['Queued', 'Scanning', 'Finished', 'Failed'];

export function status(obj: JsonObject, key: string): ScanStatus {
  const value = str(obj, key);
  const match = STATUSES.find((s) => s === value);
  if (match === undefined) throw invalidResponse(key);
  return match;
}

export function optPhase(obj: JsonObject, key: string): ScanPhase | null {
  const value = optStr(obj, key);
  if (value === null) return null;
  const match = SCAN_PHASES.find((p) => p === value);
  if (match === undefined) throw invalidResponse(key);
  return match;
}

export function failure(value: unknown, path: string): ScanFailure {
  const obj = asObject(value, path);
  return { code: str(obj, 'code'), message: str(obj, 'message') };
}

export function stats(value: unknown, path: string): ScanStats {
  const obj = asObject(value, path);
  return {
    reportBytes: num(obj, 'reportBytes'),
    vulnerabilitiesScanned: num(obj, 'vulnerabilitiesScanned'),
    malformedSkipped: num(obj, 'malformedSkipped'),
    durationMs: num(obj, 'durationMs'),
    peakRssMb: num(obj, 'peakRssMb'),
  };
}

export function vulnerability(value: unknown, path: string): Vulnerability {
  const obj = asObject(value, path);
  return {
    id: str(obj, 'id'),
    pkgName: str(obj, 'pkgName'),
    installedVersion: optStr(obj, 'installedVersion'),
    fixedVersion: optStr(obj, 'fixedVersion'),
    severity: str(obj, 'severity'),
    title: optStr(obj, 'title'),
    description: optStr(obj, 'description'),
    primaryUrl: optStr(obj, 'primaryUrl'),
    target: str(obj, 'target'),
    pkgType: optStr(obj, 'pkgType'),
    cvssScore: optNum(obj, 'cvssScore'),
    publishedDate: optStr(obj, 'publishedDate'),
  };
}

/**
 * Map the status-specific scan fields shared by both wire formats (REST and GraphQL use the same
 * field names apart from the id and the vulnerability page, which the caller supplies).
 */
export function scanView(obj: JsonObject, scanId: string, readPage: () => VulnerabilityPage): ScanView {
  const base = { scanId, repoUrl: str(obj, 'repoUrl'), attempt: num(obj, 'attempt'), createdAt: str(obj, 'createdAt') };
  const scanStatus = status(obj, 'status');
  switch (scanStatus) {
    case 'Queued':
      return { ...base, status: scanStatus };
    case 'Scanning':
      return {
        ...base,
        status: scanStatus,
        phase: optPhase(obj, 'phase'),
        progressPct: optNum(obj, 'progressPct'),
        startedAt: optStr(obj, 'startedAt'),
      };
    case 'Failed':
      return { ...base, status: scanStatus, error: failure(obj.error, 'error'), finishedAt: optStr(obj, 'finishedAt') };
    case 'Finished':
      return {
        ...base,
        status: scanStatus,
        startedAt: optStr(obj, 'startedAt'),
        finishedAt: optStr(obj, 'finishedAt'),
        criticalCount: num(obj, 'criticalCount'),
        stats: stats(obj.stats, 'stats'),
        page: readPage(),
      };
  }
}
