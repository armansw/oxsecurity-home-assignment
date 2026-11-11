import { invalidResponse } from './errors';
import { API_BASE, errorFromEnvelope, fetchJson } from './http';
import { asArray, asObject, num, optNum, optStr, str, type JsonObject } from './guards';

/** Self-test runs (see POST /api/test-runs): a sample of the large-repository corpus, scanned by the live service. */

export type TestRunState = 'running' | 'finished' | 'cancelled';
export type TestRunItemStatus = 'Queued' | 'Scanning' | 'Finished' | 'Failed' | 'Expired';

export interface TestRunItem {
  readonly position: number;
  readonly repoUrl: string;
  readonly language: string;
  readonly sizeMb: number;
  readonly scanId: string;
  readonly status: TestRunItemStatus;
  readonly phase: string | null;
  readonly progressPct: number | null;
  readonly criticalCount: number | null;
  readonly vulnerabilitiesScanned: number | null;
  readonly reportBytes: number | null;
  readonly peakMemoryMb: number | null;
  readonly durationMs: number | null;
  readonly error: { readonly code: string; readonly message: string } | null;
}

export interface TestRun {
  readonly testRunId: string;
  readonly state: TestRunState;
  readonly createdAt: string;
  readonly cancelledAt: string | null;
  /** How many corpus repositories a run samples from. */
  readonly poolSize: number;
  readonly counts: {
    readonly total: number;
    readonly queued: number;
    readonly scanning: number;
    readonly finished: number;
    readonly failed: number;
    readonly expired: number;
  };
  readonly totals: { readonly criticalCount: number; readonly vulnerabilitiesScanned: number; readonly reportBytes: number };
  readonly memory: {
    readonly limitMb: number | null;
    readonly maxScanPeakMb: number | null;
    readonly limitHitsDuringRun: number | null;
    readonly oomKillsDuringRun: number | null;
    readonly withinLimit: boolean | null;
  };
  readonly items: readonly TestRunItem[];
}

/** GET /api/test-runs/settings: limits and a measured time per repository. */
export interface TestRunSettings {
  readonly maxSize: number;
  readonly poolSize: number;
  /** Mean duration of recent self-test scans on the live service; null before any has finished. */
  readonly secondsPerRepo: number | null;
  readonly basedOnScans: number;
}

export function testRunSettings(value: unknown): TestRunSettings {
  const o = asObject(value, 'settings');
  return { maxSize: num(o, 'maxSize'), poolSize: num(o, 'poolSize'), secondsPerRepo: optNum(o, 'secondsPerRepo'), basedOnScans: num(o, 'basedOnScans') };
}

export interface TestRunApi {
  readonly settings: (signal?: AbortSignal) => Promise<TestRunSettings>;
  /** The most recent run, or null when none has been started. */
  readonly latest: (signal?: AbortSignal) => Promise<TestRun | null>;
  readonly get: (id: string, signal?: AbortSignal) => Promise<TestRun>;
  readonly start: (size: number) => Promise<TestRun>;
  readonly cancel: (id: string) => Promise<TestRun>;
}

const STATES: readonly TestRunState[] = ['running', 'finished', 'cancelled'];
const ITEM_STATUSES: readonly TestRunItemStatus[] = ['Queued', 'Scanning', 'Finished', 'Failed', 'Expired'];

function oneOf<T extends string>(obj: JsonObject, key: string, allowed: readonly T[]): T {
  const value = str(obj, key);
  const match = allowed.find((a) => a === value);
  if (match === undefined) throw invalidResponse(key);
  return match;
}

function optBool(obj: JsonObject, key: string): boolean | null {
  const value = obj[key];
  if (value === null || value === undefined) return null;
  if (typeof value !== 'boolean') throw invalidResponse(key);
  return value;
}

function item(value: unknown): TestRunItem {
  const o = asObject(value, 'items[]');
  const err: unknown = o.error;
  let error: TestRunItem['error'] = null;
  if (err !== null && err !== undefined) {
    const e = asObject(err, 'error');
    error = { code: str(e, 'code'), message: str(e, 'message') };
  }
  return {
    position: num(o, 'position'),
    repoUrl: str(o, 'repoUrl'),
    language: str(o, 'language'),
    sizeMb: num(o, 'sizeMb'),
    scanId: str(o, 'scanId'),
    status: oneOf(o, 'status', ITEM_STATUSES),
    phase: optStr(o, 'phase'),
    progressPct: optNum(o, 'progressPct'),
    criticalCount: optNum(o, 'criticalCount'),
    vulnerabilitiesScanned: optNum(o, 'vulnerabilitiesScanned'),
    reportBytes: optNum(o, 'reportBytes'),
    peakMemoryMb: optNum(o, 'peakMemoryMb'),
    durationMs: optNum(o, 'durationMs'),
    error,
  };
}

export function testRun(value: unknown): TestRun {
  const o = asObject(value, 'testRun');
  const c = asObject(o.counts, 'counts');
  const t = asObject(o.totals, 'totals');
  const m = asObject(o.memory, 'memory');
  return {
    testRunId: str(o, 'testRunId'),
    state: oneOf(o, 'state', STATES),
    createdAt: str(o, 'createdAt'),
    cancelledAt: optStr(o, 'cancelledAt'),
    poolSize: num(o, 'poolSize'),
    counts: {
      total: num(c, 'total'),
      queued: num(c, 'queued'),
      scanning: num(c, 'scanning'),
      finished: num(c, 'finished'),
      failed: num(c, 'failed'),
      expired: num(c, 'expired'),
    },
    totals: { criticalCount: num(t, 'criticalCount'), vulnerabilitiesScanned: num(t, 'vulnerabilitiesScanned'), reportBytes: num(t, 'reportBytes') },
    memory: {
      limitMb: optNum(m, 'limitMb'),
      maxScanPeakMb: optNum(m, 'maxScanPeakMb'),
      limitHitsDuringRun: optNum(m, 'limitHitsDuringRun'),
      oomKillsDuringRun: optNum(m, 'oomKillsDuringRun'),
      withinLimit: optBool(m, 'withinLimit'),
    },
    items: asArray(o.items, 'items').map(item),
  };
}

export function createTestRunApi(base: string = API_BASE): TestRunApi {
  const call = async (path: string, init: RequestInit): Promise<TestRun> => {
    const res = await fetchJson(`${base}${path}`, init);
    if (!res.ok) throw errorFromEnvelope(res.status, res.body);
    return testRun(res.body);
  };
  const post = (body?: object): RequestInit =>
    body === undefined ? { method: 'POST' } : { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) };
  return {
    settings: async (signal) => {
      const res = await fetchJson(`${base}/api/test-runs/settings`, signal ? { signal } : {});
      if (!res.ok) throw errorFromEnvelope(res.status, res.body);
      return testRunSettings(res.body);
    },
    latest: async (signal) => {
      const res = await fetchJson(`${base}/api/test-runs/latest`, signal ? { signal } : {});
      if (res.status === 404) return null;
      if (!res.ok) throw errorFromEnvelope(res.status, res.body);
      return testRun(res.body);
    },
    get: (id, signal) => call(`/api/test-runs/${encodeURIComponent(id)}`, signal ? { signal } : {}),
    start: (size) => call('/api/test-runs', post({ size })),
    cancel: (id) => call(`/api/test-runs/${encodeURIComponent(id)}/cancel`, post()),
  };
}
