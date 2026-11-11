import { useCallback, useEffect, useState } from 'react';
import { toApiError } from '../api/errors';
import type { TestRun, TestRunApi, TestRunSettings } from '../api/testRuns';

export const TEST_RUN_POLL_INTERVAL_MS = 3000;

export interface TestRunControls {
  readonly run: TestRun | null;
  /** Limits and the measured time per repository; null until loaded (or if the server cannot say). */
  readonly settings: TestRunSettings | null;
  readonly error: string | null;
  readonly busy: boolean;
  readonly start: (size: number) => void;
  readonly cancel: () => void;
}

/**
 * The latest self-test run, polled while it runs. It lives on the server, so reloading the page (or opening it
 * on another machine) picks the run up where it is.
 */
export function useTestRun(api: TestRunApi): TestRunControls {
  const [run, setRun] = useState<TestRun | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [settings, setSettings] = useState<TestRunSettings | null>(null);

  useEffect(() => {
    const controller = new AbortController();
    api
      .latest(controller.signal)
      .then(setRun)
      .catch((err: unknown) => {
        if (!controller.signal.aborted) setError(toApiError(err).message);
      });
    return () => {
      controller.abort();
    };
  }, [api]);

  const runId = run?.testRunId;
  const running = run?.state === 'running';

  // Reload when a run ends: its scans refine the measured time per repository.
  useEffect(() => {
    if (running) return;
    const controller = new AbortController();
    api
      .settings(controller.signal)
      .then(setSettings)
      .catch(() => {
        // Without settings the panel falls back to its defaults and shows no estimate.
      });
    return () => {
      controller.abort();
    };
  }, [api, running]);
  useEffect(() => {
    if (runId === undefined || !running) return;
    const controller = new AbortController();
    const timer = setInterval(() => {
      api
        .get(runId, controller.signal)
        .then((r) => {
          setRun(r);
          setError(null);
        })
        .catch((err: unknown) => {
          if (!controller.signal.aborted) setError(toApiError(err).message);
        });
    }, TEST_RUN_POLL_INTERVAL_MS);
    return () => {
      controller.abort();
      clearInterval(timer);
    };
  }, [api, runId, running]);

  const act = useCallback((action: () => Promise<TestRun>) => {
    setBusy(true);
    setError(null);
    action()
      .then(setRun)
      .catch((err: unknown) => {
        setError(toApiError(err).message);
      })
      .finally(() => {
        setBusy(false);
      });
  }, []);

  return {
    run,
    settings,
    error,
    busy,
    start: (size) => {
      act(() => api.start(size));
    },
    cancel: () => {
      if (runId !== undefined) act(() => api.cancel(runId));
    },
  };
}
