/**
 * Stable, client-facing failure codes. Raw failures (exit codes, errno, stderr) are mapped to these in
 * exactly one place per adapter, so the API never leaks host paths or stack traces.
 */
export const SCAN_ERROR_CODES = [
  'INVALID_REPO_URL',
  'REPO_NOT_FOUND',
  'CLONE_FAILED',
  'CLONE_TIMEOUT',
  'SCANNER_UNAVAILABLE',
  'SCANNER_FAILED',
  'SCAN_TIMEOUT',
  'SCANNER_KILLED',
  'REPORT_INVALID',
  'INSUFFICIENT_DISK',
  'DISK_FULL',
  'WORKER_CRASHED',
  'INTERNAL',
] as const;
export type ScanErrorCode = (typeof SCAN_ERROR_CODES)[number];

export function isScanErrorCode(value: string): value is ScanErrorCode {
  return (SCAN_ERROR_CODES as readonly string[]).includes(value);
}

/** A classified scan failure. `retryable` decides between re-queue (with backoff) and `Failed`. */
export class ScanError extends Error {
  override readonly name = 'ScanError';

  constructor(
    readonly code: ScanErrorCode,
    message: string,
    readonly retryable = false,
    options?: ErrorOptions,
  ) {
    super(message, options);
  }
}

/** Thrown when a worker's lease on a scan was taken over (e.g. by the stale-lease reaper). */
export class LeaseLostError extends Error {
  override readonly name = 'LeaseLostError';

  constructor(readonly scanId: string) {
    super(`Lease on scan ${scanId} was lost`);
  }
}

/** Abort reason used on graceful shutdown: the job is re-queued with its attempt refunded. */
export class ShutdownError extends Error {
  override readonly name = 'ShutdownError';

  constructor() {
    super('Worker is shutting down');
  }
}

/** Request-level errors raised by the application service and mapped to HTTP/GraphQL by the interfaces. */
export type RequestErrorCode = 'INVALID_REPO_URL' | 'INVALID_SCAN_ID' | 'INVALID_CURSOR' | 'NOT_FOUND' | 'QUEUE_FULL' | 'NOT_READY';

export class RequestError extends Error {
  override readonly name = 'RequestError';

  constructor(
    readonly code: RequestErrorCode,
    message: string,
  ) {
    super(message);
  }
}
