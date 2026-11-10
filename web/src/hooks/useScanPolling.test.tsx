import { act, renderHook } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { vi } from 'vitest';
import { ApiError } from '../api/errors';
import type { ScanApi } from '../api/types';
import { deferred, fakeApi, failed, finished, queued, SCAN_ID, scanning } from '../test/fixtures';
import { POLL_INTERVAL_MS, useScanPolling } from './useScanPolling';

beforeEach(() => {
  vi.useFakeTimers();
});
afterEach(() => {
  vi.useRealTimers();
});

/** Let pending promise callbacks run, then advance the clock. */
async function advance(ms: number): Promise<void> {
  await act(async () => {
    await vi.advanceTimersByTimeAsync(ms);
  });
}

function render(api: ScanApi, scanId: string | null = SCAN_ID) {
  return renderHook(({ id, client }) => useScanPolling(client, id), { initialProps: { id: scanId, client: api } });
}

describe('useScanPolling', () => {
  it('exports the 2 second interval', () => {
    expect(POLL_INTERVAL_MS).toBe(2000);
  });

  it('is idle without a scan id', () => {
    const api = fakeApi();
    const { result } = render(api, null);
    expect(result.current).toEqual({ scan: null, error: null, reconnecting: false });
    expect(api.getScan).not.toHaveBeenCalled();
  });

  it('fetches immediately (paginated), then every 2s until Finished', async () => {
    const api = fakeApi();
    api.getScan.mockResolvedValueOnce(queued()).mockResolvedValueOnce(scanning()).mockResolvedValueOnce(finished());
    const { result } = render(api);

    await advance(0);
    expect(api.getScan).toHaveBeenCalledTimes(1);
    expect(api.getScan).toHaveBeenLastCalledWith(SCAN_ID, { limit: 100, cursor: null }, expect.any(AbortSignal));
    expect(result.current.scan?.status).toBe('Queued');

    await advance(POLL_INTERVAL_MS - 1);
    expect(api.getScan).toHaveBeenCalledTimes(1);
    await advance(1);
    expect(api.getScan).toHaveBeenCalledTimes(2);
    expect(result.current.scan?.status).toBe('Scanning');

    await advance(POLL_INTERVAL_MS);
    expect(result.current.scan?.status).toBe('Finished');

    await advance(POLL_INTERVAL_MS * 5);
    expect(api.getScan).toHaveBeenCalledTimes(3);
  });

  it('stops on Failed', async () => {
    const api = fakeApi();
    api.getScan.mockResolvedValue(failed());
    const { result } = render(api);
    await advance(POLL_INTERVAL_MS * 3);
    expect(api.getScan).toHaveBeenCalledTimes(1);
    expect(result.current.scan?.status).toBe('Failed');
  });

  it('never overlaps requests: the next poll waits for the slow one to settle', async () => {
    const api = fakeApi();
    const slow = deferred<ReturnType<typeof queued>>();
    api.getScan.mockReturnValueOnce(slow.promise).mockResolvedValue(finished());
    render(api);

    await advance(POLL_INTERVAL_MS * 5);
    expect(api.getScan).toHaveBeenCalledTimes(1);

    slow.resolve(queued());
    await advance(0);
    expect(api.getScan).toHaveBeenCalledTimes(1);
    await advance(POLL_INTERVAL_MS);
    expect(api.getScan).toHaveBeenCalledTimes(2);
  });

  it('keeps polling through transient errors and flags reconnecting', async () => {
    const api = fakeApi();
    api.getScan
      .mockResolvedValueOnce(scanning())
      .mockRejectedValueOnce(new ApiError('NETWORK_ERROR', 'offline', null))
      .mockResolvedValueOnce(finished());
    const { result } = render(api);

    await advance(0);
    await advance(POLL_INTERVAL_MS);
    expect(result.current).toMatchObject({ reconnecting: true, error: null });
    expect(result.current.scan?.status).toBe('Scanning'); // last good snapshot is kept

    await advance(POLL_INTERVAL_MS);
    expect(result.current).toMatchObject({ reconnecting: false, error: null });
    expect(result.current.scan?.status).toBe('Finished');
  });

  it('stops and reports non-transient errors', async () => {
    const api = fakeApi();
    api.getScan.mockRejectedValue(new ApiError('NOT_FOUND', 'scan not found', 404));
    const { result } = render(api);
    await advance(POLL_INTERVAL_MS * 3);
    expect(api.getScan).toHaveBeenCalledTimes(1);
    expect(result.current.error).toMatchObject({ code: 'NOT_FOUND' });
  });

  it('aborts the in-flight request and stops the timer on unmount', async () => {
    const api = fakeApi();
    const pending = deferred<ReturnType<typeof queued>>();
    api.getScan.mockReturnValue(pending.promise);
    const { unmount } = render(api);
    await advance(0);

    const signal = api.getScan.mock.calls[0]?.[2];
    unmount();
    expect(signal?.aborted).toBe(true);

    pending.resolve(queued()); // a late response must not schedule another poll
    await advance(POLL_INTERVAL_MS * 3);
    expect(api.getScan).toHaveBeenCalledTimes(1);
  });

  it('ignores the abort rejection of a cancelled request', async () => {
    const api = fakeApi();
    api.getScan.mockImplementation(
      (_id, _page, signal) =>
        new Promise((_resolve, reject) => {
          signal?.addEventListener('abort', () => {
            reject(new DOMException('aborted', 'AbortError'));
          });
        }),
    );
    const { unmount } = render(api);
    await advance(0);
    unmount();
    await advance(POLL_INTERVAL_MS);
    expect(api.getScan).toHaveBeenCalledTimes(1);
  });

  it('restarts for a new scan id without showing the previous scan', async () => {
    const api = fakeApi();
    api.getScan.mockResolvedValueOnce(scanning());
    const { result, rerender } = render(api);
    await advance(0);
    expect(result.current.scan?.status).toBe('Scanning');

    const firstSignal = api.getScan.mock.calls[0]?.[2];
    api.getScan.mockReturnValueOnce(new Promise(() => undefined));
    rerender({ id: 'other-id', client: api });
    expect(result.current.scan).toBeNull();
    await advance(0);
    expect(api.getScan).toHaveBeenLastCalledWith('other-id', { limit: 100, cursor: null }, expect.any(AbortSignal));
    expect(firstSignal?.aborted).toBe(true); // the old poll loop is torn down

    rerender({ id: null, client: api });
    expect(result.current.scan).toBeNull();
  });

  it('keeps the snapshot when only the transport changes', async () => {
    const rest = fakeApi();
    const graphql = fakeApi();
    rest.getScan.mockResolvedValue(scanning());
    graphql.getScan.mockResolvedValue(finished());
    const { result, rerender } = render(rest);
    await advance(0);

    rerender({ id: SCAN_ID, client: graphql });
    expect(result.current.scan?.status).toBe('Scanning');
    await advance(0);
    expect(graphql.getScan).toHaveBeenCalledTimes(1);
    expect(result.current.scan?.status).toBe('Finished');
  });
});
