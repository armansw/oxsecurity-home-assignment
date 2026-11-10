import { vi } from 'vitest';
import type {
  FailedScan,
  FinishedScan,
  QueuedScan,
  ScanApi,
  ScanningScan,
  ScanStats,
  Vulnerability,
  VulnerabilityPage,
} from '../api/types';

export const SCAN_ID = '0b7f8a3e-1c2d-4e5f-8a9b-0c1d2e3f4a5b';
export const REPO_URL = 'https://github.com/acme/widgets';

export function vuln(overrides: Partial<Vulnerability> = {}): Vulnerability {
  return {
    id: 'CVE-2024-0001',
    pkgName: 'lodash',
    installedVersion: '4.17.20',
    fixedVersion: '4.17.21',
    severity: 'CRITICAL',
    title: 'Prototype pollution',
    description: 'Bad things.',
    primaryUrl: 'https://avd.aquasec.com/nvd/cve-2024-0001',
    target: 'package-lock.json',
    pkgType: 'npm',
    cvssScore: 9.8,
    publishedDate: '2024-01-01T00:00:00Z',
    ...overrides,
  };
}

const base = { scanId: SCAN_ID, repoUrl: REPO_URL, attempt: 1, createdAt: '2026-11-10T10:00:00.000Z' };

export const STATS: ScanStats = {
  reportBytes: 1_572_864,
  vulnerabilitiesScanned: 1234,
  malformedSkipped: 0,
  durationMs: 12_300,
  peakRssMb: 87,
};

export function queued(): QueuedScan {
  return { ...base, status: 'Queued' };
}

export function scanning(overrides: Partial<ScanningScan> = {}): ScanningScan {
  return { ...base, status: 'Scanning', phase: 'scanning', progressPct: 40, startedAt: base.createdAt, ...overrides };
}

export function failed(): FailedScan {
  return { ...base, status: 'Failed', error: { code: 'CLONE_FAILED', message: 'repository not found' }, finishedAt: null };
}

export function finished(page: VulnerabilityPage = { items: [vuln()], nextCursor: null }, criticalCount = page.items.length): FinishedScan {
  return {
    ...base,
    status: 'Finished',
    startedAt: base.createdAt,
    finishedAt: '2026-11-10T10:00:12.300Z',
    criticalCount,
    stats: STATS,
    page,
  };
}

export interface FakeApi extends ScanApi {
  readonly startScan: ReturnType<typeof vi.fn<ScanApi['startScan']>>;
  readonly getScan: ReturnType<typeof vi.fn<ScanApi['getScan']>>;
}

/** A ScanApi double; unconfigured calls return a promise that never settles (like a hung request). */
export function fakeApi(): FakeApi {
  const never = (): Promise<never> => new Promise<never>(() => undefined);
  return {
    startScan: vi.fn<ScanApi['startScan']>(never),
    getScan: vi.fn<ScanApi['getScan']>(never),
  };
}

/** A promise plus its resolvers, for controlling exactly when a fake request settles. */
export function deferred<T>(): { promise: Promise<T>; resolve: (value: T) => void; reject: (err: unknown) => void } {
  let resolve!: (value: T) => void;
  let reject!: (err: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

export function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
}
