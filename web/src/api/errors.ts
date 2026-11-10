/** Error codes the client itself produces (server codes are passed through verbatim). */
export const NETWORK_ERROR = 'NETWORK_ERROR';
export const INVALID_RESPONSE = 'INVALID_RESPONSE';

/** Server codes that describe a temporary condition: polling should keep going. */
const TRANSIENT_CODES: ReadonlySet<string> = new Set([NETWORK_ERROR, 'RATE_LIMITED', 'NOT_READY', 'INTERNAL']);

export class ApiError extends Error {
  override readonly name = 'ApiError';

  constructor(
    readonly code: string,
    message: string,
    /** HTTP status, or null when no response was received (or the transport has no status). */
    readonly status: number | null,
    readonly details: readonly string[] = [],
  ) {
    super(message);
  }

  /** Whether retrying the same request later may succeed. */
  get transient(): boolean {
    return TRANSIENT_CODES.has(this.code) || (this.status !== null && this.status >= 500);
  }
}

export function invalidResponse(what: string): ApiError {
  return new ApiError(INVALID_RESPONSE, `Unexpected response from server (${what}).`, null);
}

/** Normalize anything thrown by fetch/parsing into an ApiError. AbortErrors are rethrown untouched. */
export function toApiError(err: unknown): ApiError {
  if (err instanceof ApiError) return err;
  if (isAbortError(err)) throw err;
  return new ApiError(NETWORK_ERROR, 'Could not reach the server.', null);
}

export function isAbortError(err: unknown): boolean {
  return err instanceof DOMException && err.name === 'AbortError';
}
