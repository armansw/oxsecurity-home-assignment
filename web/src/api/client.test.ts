import { describe, expect, it } from 'vitest';
import { ApiError, isAbortError, toApiError } from './errors';
import { GraphqlScanApi } from './graphql';
import { readApiBase } from './http';
import { createScanApi } from './index';
import { RestScanApi } from './rest';
import { isTerminal } from './types';

describe('createScanApi', () => {
  it('picks the implementation for the transport', () => {
    expect(createScanApi('rest')).toBeInstanceOf(RestScanApi);
    expect(createScanApi('graphql', '')).toBeInstanceOf(GraphqlScanApi);
  });
});

describe('readApiBase', () => {
  it('defaults to same-origin and strips trailing slashes', () => {
    expect(readApiBase(undefined)).toBe('');
    expect(readApiBase('https://scanner.example.com//')).toBe('https://scanner.example.com');
  });
});

describe('errors', () => {
  it('classifies transient errors', () => {
    expect(new ApiError('RATE_LIMITED', 'slow down', 429).transient).toBe(true);
    expect(new ApiError('QUEUE_FULL', 'full', 429).transient).toBe(false);
    expect(new ApiError('SOMETHING', 'x', 502).transient).toBe(true);
    expect(new ApiError('INVALID_SCAN_ID', 'x', 400).transient).toBe(false);
  });

  it('normalizes unknown throwables and rethrows aborts', () => {
    const original = new ApiError('X', 'y', 400);
    expect(toApiError(original)).toBe(original);
    expect(toApiError(new Error('boom'))).toMatchObject({ code: 'NETWORK_ERROR', status: null });
    const abort = new DOMException('aborted', 'AbortError');
    expect(isAbortError(abort)).toBe(true);
    expect(() => toApiError(abort)).toThrow(abort);
  });

  it('knows terminal statuses', () => {
    expect(isTerminal('Finished')).toBe(true);
    expect(isTerminal('Failed')).toBe(true);
    expect(isTerminal('Scanning')).toBe(false);
  });
});
