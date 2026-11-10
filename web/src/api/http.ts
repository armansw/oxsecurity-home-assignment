import { ApiError, toApiError } from './errors';
import { asArray, isObject, optStr } from './guards';

/** Base URL prefix for API calls; empty means same-origin (Vite dev proxy / nginx). */
export const API_BASE: string = readApiBase(import.meta.env.VITE_API_BASE);

export function readApiBase(raw: unknown): string {
  return typeof raw === 'string' ? raw.replace(/\/+$/, '') : '';
}

export interface JsonResponse {
  readonly status: number;
  readonly ok: boolean;
  readonly body: unknown;
}

/**
 * fetch + JSON decode, with every failure normalized to ApiError (network errors become
 * NETWORK_ERROR; aborts propagate as AbortError). The body is returned as `unknown`: callers narrow it.
 */
export async function fetchJson(url: string, init: RequestInit): Promise<JsonResponse> {
  try {
    const response = await fetch(url, init);
    const body = await readBody(response);
    return { status: response.status, ok: response.ok, body };
  } catch (err) {
    throw toApiError(err);
  }
}

async function readBody(response: Response): Promise<unknown> {
  const text = await response.text();
  if (text === '') return null;
  try {
    return JSON.parse(text) as unknown;
  } catch {
    // e.g. an HTML error page from a proxy; the status code still tells the story.
    return null;
  }
}

/** Build an ApiError from the REST error envelope `{error:{code,message,details?}}`, or from the status alone. */
export function errorFromEnvelope(status: number, body: unknown): ApiError {
  if (isObject(body) && isObject(body.error)) {
    const envelope = body.error;
    const code = optStr(envelope, 'code');
    const message = optStr(envelope, 'message');
    if (code !== null && message !== null) {
      const details = Array.isArray(envelope.details)
        ? asArray(envelope.details, 'details').filter((d): d is string => typeof d === 'string')
        : [];
      return new ApiError(code, message, status, details);
    }
  }
  return new ApiError(`HTTP_${String(status)}`, `Request failed with status ${String(status)}.`, status);
}
