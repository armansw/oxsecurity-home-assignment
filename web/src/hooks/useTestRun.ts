import { useCallback, useEffect, useState } from 'react';
import { toApiError } from '../api/errors';
import type { TestRun, TestRunApi } from '../api/testRuns';

export const TEST_RUN_POLL_INTERVAL_MS = 3000;

export interface TestRunControls {
  readonly run: TestRun | null;
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
