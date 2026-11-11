import { useCallback, useEffect, useState } from 'react';
import { ApiError, toApiError } from '../api/errors';
import type { TestRun, TestRunApi, TestRunSettings } from '../api/testRuns';

export const TEST_RUN_POLL_INTERVAL_MS = 3000;
export const OWN_RUN_KEY = 'code-guardian.selfTestRunId';

/** The run this browser started, so a reload resumes it. Storage can be unavailable (private mode): then none. */
export const ownRunStore = {
  read(): string | null {
    try {
      return window.localStorage.getItem(OWN_RUN_KEY);
    } catch {
      return null;
    }
  },
  write(id: string | null): void {
    try {
      if (id === null) window.localStorage.removeItem(OWN_RUN_KEY);
      else window.localStorage.setItem(OWN_RUN_KEY, id);
    } catch {
      // not remembered across reloads; the panel still works
    }
  },
};

export interface TestRunControls {
  readonly run: TestRun | null;
  /** True when the shown run was started from this browser (only then can it be cancelled here). */
  readonly ownsRun: boolean;
  /** Limits and the measured time per repository; null until loaded (or if the server cannot say). */
  readonly settings: TestRunSettings | null;
  readonly error: string | null;
  /** Starting failed because someone else's self-test is running (one at a time per server). */
  readonly othersRunActive: boolean;
  readonly busy: boolean;
  readonly start: (size: number) => void;
  readonly cancel: () => void;
  /** Show the self-test that is currently running on the server, whoever started it. */
  readonly watchActive: () => void;
}

/**
 * The self-test this browser started, polled while it runs. Runs are per browser: another device or visitor starts
 * with an empty panel, and sees someone else's run only by choosing to watch it.
 */
export function useTestRun(api: TestRunApi): TestRunControls {
  const [run, setRun] = useState<TestRun | null>(null);
  const [ownId, setOwnId] = useState<string | null>(() => ownRunStore.read());
  const [error, setError] = useState<string | null>(null);
  const [othersRunActive, setOthersRunActive] = useState(false);
  const [busy, setBusy] = useState(false);
  const [settings, setSettings] = useState<TestRunSettings | null>(null);

  // Resume this browser's own run after a reload; forget it if the server no longer has it.
  const [initialOwnId] = useState(ownId);
  useEffect(() => {
    if (initialOwnId === null) return;
    const controller = new AbortController();
    api
      .get(initialOwnId, controller.signal)
      .then(setRun)
      .catch((err: unknown) => {
        if (controller.signal.aborted) return;
        const e = toApiError(err);
        if (e.status === 404 || e.status === 400) {
          ownRunStore.write(null);
          setOwnId(null);
        } else setError(e.message);
      });
    return () => {
      controller.abort();
    };
  }, [api, initialOwnId]);

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

  const act = useCallback((action: () => Promise<TestRun>, own: boolean) => {
    setBusy(true);
    setError(null);
    setOthersRunActive(false);
    action()
      .then((r) => {
        setRun(r);
        if (own) {
          ownRunStore.write(r.testRunId);
          setOwnId(r.testRunId);
        }
      })
      .catch((err: unknown) => {
        const e = toApiError(err);
        if (e.code === 'TEST_RUN_ACTIVE') {
          setOthersRunActive(true);
          setError('Another self-test is running on this server right now (one at a time).');
        } else setError(e.message);
      })
      .finally(() => {
        setBusy(false);
      });
  }, []);

  const watchActive = useCallback(() => {
    act(async () => {
      const latest = await api.latest();
      if (latest === null) throw new ApiError('NOT_FOUND', 'No self-test is running.', 404);
      return latest;
    }, false);
  }, [act, api]);

  return {
    run,
    ownsRun: run !== null && run.testRunId === ownId,
    settings,
    error,
    othersRunActive,
    busy,
    start: (size) => {
      act(() => api.start(size), true);
    },
    cancel: () => {
      if (runId !== undefined && runId === ownId) act(() => api.cancel(runId), true);
    },
    watchActive,
  };
}
