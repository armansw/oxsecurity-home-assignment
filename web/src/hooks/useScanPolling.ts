import { useEffect, useState } from 'react';
import { type ApiError, toApiError } from '../api/errors';
import { isTerminal, PAGE_SIZE, type ScanApi, type ScanView } from '../api/types';

export const POLL_INTERVAL_MS = 2000;

export interface ScanPollingState {
  /** Latest successful snapshot of the scan, or null before the first response. */
  readonly scan: ScanView | null;
  /** A non-retryable error (e.g. NOT_FOUND); polling has stopped. */
  readonly error: ApiError | null;
  /** The last poll failed transiently; polling continues. */
  readonly reconnecting: boolean;
}

const IDLE: ScanPollingState = { scan: null, error: null, reconnecting: false };

/**
 * State tagged with the scan it belongs to, so a previous scan's data is never shown for a new id.
 * (A transport switch keeps the snapshot: it is the same scan, just fetched differently.)
 */
interface TaggedState extends ScanPollingState {
  readonly scanId: string;
}

/**
 * Poll a scan: fetch immediately, then every POLL_INTERVAL_MS until it is Finished or Failed.
 * The next poll is scheduled only after the previous one settles (no overlapping requests), and
 * the in-flight request is aborted when the scan id or transport changes or the component unmounts.
 */
export function useScanPolling(api: ScanApi, scanId: string | null): ScanPollingState {
  const [state, setState] = useState<TaggedState | null>(null);

  useEffect(() => {
    if (scanId === null) return undefined;
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    const update = (patch: Partial<ScanPollingState>): void => {
      setState((prev) => {
        const base = prev?.scanId === scanId ? prev : { ...IDLE, scanId };
        return { ...base, ...patch };
      });
    };

    const poll = async (): Promise<void> => {
      try {
        const scan = await api.getScan(scanId, { limit: PAGE_SIZE, cursor: null }, controller.signal);
        if (controller.signal.aborted) return;
        update({ scan, error: null, reconnecting: false });
        if (isTerminal(scan.status)) return;
      } catch (err) {
        if (controller.signal.aborted) return;
        const error = toApiError(err);
        if (!error.transient) {
          update({ error, reconnecting: false });
          return;
        }
        update({ reconnecting: true });
      }
      timer = setTimeout(() => void poll(), POLL_INTERVAL_MS);
    };

    void poll();
    return () => {
      controller.abort();
      clearTimeout(timer);
    };
  }, [api, scanId]);

  if (scanId === null || state?.scanId !== scanId) return IDLE;
  return { scan: state.scan, error: state.error, reconnecting: state.reconnecting };
}
