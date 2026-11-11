import { act, render, renderHook, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { ApiError } from '../api/errors';
import { createTestRunApi, testRun, type TestRun, type TestRunApi, type TestRunItem } from '../api/testRuns';
import { TEST_RUN_POLL_INTERVAL_MS, useTestRun, type TestRunControls } from '../hooks/useTestRun';
import { TestRunPanel } from './TestRunPanel';

const ID = '11111111-1111-4111-8111-111111111111';

function item(overrides: Partial<TestRunItem> = {}): TestRunItem {
  return {
    position: 0,
    repoUrl: 'https://github.com/gin-gonic/gin.git',
    language: 'Go',
    sizeMb: 12,
    scanId: '22222222-2222-4222-8222-222222222222',
    status: 'Finished',
    phase: null,
    progressPct: 100,
    criticalCount: 2,
    vulnerabilitiesScanned: 40,
    reportBytes: 2048,
    peakMemoryMb: 52,
    durationMs: 61_000,
    error: null,
    ...overrides,
  };
}

function run(overrides: Partial<TestRun> = {}): TestRun {
  return {
    testRunId: ID,
    state: 'finished',
    createdAt: '2026-11-11T08:00:00.000Z',
    cancelledAt: null,
    poolSize: 107,
    counts: { total: 2, queued: 0, scanning: 0, finished: 1, failed: 1, expired: 0 },
    totals: { criticalCount: 2, vulnerabilitiesScanned: 40, reportBytes: 2048 },
    memory: { limitMb: 150, maxScanPeakMb: 52, limitHitsDuringRun: 0, oomKillsDuringRun: 0, withinLimit: true },
    items: [
      item(),
      item({
        position: 1,
        repoUrl: 'https://github.com/acme/gone',
        status: 'Failed',
        criticalCount: null,
        peakMemoryMb: null,
        durationMs: null,
        error: { code: 'REPO_NOT_FOUND', message: 'gone' },
      }),
    ],
    ...overrides,
  };
}

const json = (body: unknown, status = 200): Response => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });

afterEach(() => {
  vi.restoreAllMocks();
  vi.useRealTimers();
});

describe('testRun guard and client', () => {
  it('round-trips a valid run and rejects contract drift', () => {
    expect(testRun(run())).toEqual(run());
    expect(() => testRun({ ...run(), state: 'paused' })).toThrow();
    expect(() => testRun({ ...run(), memory: { ...run().memory, withinLimit: 'yes' } })).toThrow();
    expect(() => testRun({ ...run(), items: [{ ...item(), error: 'x' }] })).toThrow();
  });

  it('calls the REST endpoints and maps errors and the empty state', async () => {
    const fetchMock = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(json({ error: { code: 'NOT_FOUND', message: 'none' } }, 404))
      .mockResolvedValueOnce(json(run()))
      .mockResolvedValueOnce(json(run(), 202))
      .mockResolvedValueOnce(json(run({ state: 'cancelled' })))
      .mockResolvedValueOnce(json({ error: { code: 'TEST_RUN_ACTIVE', message: 'busy' } }, 409))
      .mockResolvedValueOnce(json({ error: { code: 'INTERNAL', message: 'boom' } }, 500));
    const api = createTestRunApi('/base');
    await expect(api.latest()).resolves.toBeNull();
    await expect(api.get(ID)).resolves.toEqual(run());
    await expect(api.start(20)).resolves.toEqual(run());
    expect(fetchMock.mock.calls[2]?.[0]).toBe('/base/api/test-runs');
    expect(fetchMock.mock.calls[2]?.[1]).toMatchObject({ method: 'POST', body: '{"size":20}' });
    await expect(api.cancel(ID)).resolves.toMatchObject({ state: 'cancelled' });
    expect(fetchMock.mock.calls[3]?.[0]).toBe(`/base/api/test-runs/${ID}/cancel`);
    await expect(api.start(20)).rejects.toMatchObject({ code: 'TEST_RUN_ACTIVE' });
    await expect(api.latest()).rejects.toMatchObject({ code: 'INTERNAL' });
  });
});

function fakeApi(overrides: Partial<TestRunApi> = {}): TestRunApi {
  return {
    latest: vi.fn(() => Promise.resolve(null)),
    get: vi.fn(() => Promise.resolve(run())),
    start: vi.fn(() => Promise.resolve(run({ state: 'running' }))),
    cancel: vi.fn(() => Promise.resolve(run({ state: 'cancelled' }))),
    ...overrides,
  };
}

describe('useTestRun', () => {
  it('loads the latest run and polls only while it is running', async () => {
    vi.useFakeTimers();
    const api = fakeApi({ latest: vi.fn(() => Promise.resolve(run({ state: 'running' }))) });
    const { result } = renderHook(() => useTestRun(api));
    await act(async () => {
      await vi.advanceTimersByTimeAsync(0);
    });
    expect(result.current.run?.state).toBe('running');
    await act(async () => {
      await vi.advanceTimersByTimeAsync(TEST_RUN_POLL_INTERVAL_MS);
    });
    expect(api.get).toHaveBeenCalledWith(ID, expect.any(AbortSignal));
    expect(result.current.run?.state).toBe('finished');
    await act(async () => {
      await vi.advanceTimersByTimeAsync(TEST_RUN_POLL_INTERVAL_MS * 3);
    });
    expect(api.get).toHaveBeenCalledTimes(1);
  });

  it('surfaces load, poll and action errors', async () => {
    vi.useFakeTimers();
    const api = fakeApi({
      latest: vi.fn(() => Promise.resolve(run({ state: 'running' }))),
      get: vi.fn(() => Promise.reject(new ApiError('X', 'offline', 500))),
      cancel: vi.fn(() => Promise.reject(new ApiError('X', 'nope', 500))),
    });
    const { result } = renderHook(() => useTestRun(api));
    await act(async () => {
      await vi.advanceTimersByTimeAsync(0);
    });
    await act(async () => {
      await vi.advanceTimersByTimeAsync(TEST_RUN_POLL_INTERVAL_MS);
    });
    expect(result.current.error).toBe('offline');
    act(() => {
      result.current.cancel();
    });
    await act(async () => {
      await vi.advanceTimersByTimeAsync(0);
    });
    expect(result.current.error).toBe('nope');
    expect(result.current.busy).toBe(false);

    const failing = fakeApi({ latest: vi.fn(() => Promise.reject(new ApiError('X', 'down', 500))) });
    const second = renderHook(() => useTestRun(failing));
    await act(async () => {
      await vi.advanceTimersByTimeAsync(0);
    });
    expect(second.result.current.error).toBe('down');
    act(() => {
      second.result.current.cancel(); // no run: nothing to cancel
    });
    expect(failing.cancel).not.toHaveBeenCalled();
  });

  it('starts a run', async () => {
    const api = fakeApi();
    const { result } = renderHook(() => useTestRun(api));
    act(() => {
      result.current.start(10);
    });
    await vi.waitFor(() => {
      expect(result.current.run?.state).toBe('running');
    });
    expect(api.start).toHaveBeenCalledWith(10);
  });
});

function controls(overrides: Partial<TestRunControls> = {}): TestRunControls {
  return { run: null, error: null, busy: false, start: vi.fn(), cancel: vi.fn(), ...overrides };
}

describe('TestRunPanel', () => {
  it('offers a run size and starts the self-test', async () => {
    const c = controls();
    render(<TestRunPanel controls={c} />);
    await userEvent.selectOptions(screen.getByLabelText('Repositories to scan'), '30');
    await userEvent.click(screen.getByRole('button', { name: 'Run self-test' }));
    expect(c.start).toHaveBeenCalledWith(30);
  });

  it('shows a finished run: verdict, totals and one row per repository', () => {
    render(<TestRunPanel controls={controls({ run: run() })} />);
    expect(screen.getByRole('status')).toHaveTextContent(
      '✓ · 1 of 2 repositories scanned · every scan within the 150 MB limit · limit never reached · 0 OOM kills',
    );
    expect(screen.getByText('52 MB / 150 MB')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'gin-gonic/gin' })).toHaveAttribute('href', 'https://github.com/gin-gonic/gin.git');
    expect(screen.getByText('REPO_NOT_FOUND')).toBeInTheDocument();
    expect(screen.getByText('1m 1s')).toBeInTheDocument();
    expect(screen.getByRole('progressbar')).toHaveAttribute('aria-valuenow', '2');
    expect(screen.getByText(/107 repositories across 9 ecosystems/)).toBeInTheDocument();
  });

  it('shows progress and a cancel button while running', async () => {
    const c = controls({
      run: run({
        state: 'running',
        counts: { total: 3, queued: 1, scanning: 1, finished: 1, failed: 0, expired: 0 },
        items: [item(), item({ position: 1, status: 'Scanning', phase: 'cloning', peakMemoryMb: null }), item({ position: 2, status: 'Queued' })],
      }),
    });
    render(<TestRunPanel controls={c} />);
    expect(screen.getByRole('status')).toHaveTextContent('Running · 1 of 3 done · within the 150 MB limit so far');
    expect(screen.getByText('cloning')).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Cancel' }));
    expect(c.cancel).toHaveBeenCalled();
  });

  it('reports a breach, a cancelled run, a missing limit and errors honestly', () => {
    const breach = run({ memory: { limitMb: 150, maxScanPeakMb: 151, limitHitsDuringRun: 2, oomKillsDuringRun: 1, withinLimit: false } });
    const { unmount } = render(<TestRunPanel controls={controls({ run: breach, error: 'Self-test is still running' })} />);
    expect(screen.getByRole('status')).toHaveTextContent('✕ 1 of 2 repositories scanned · the memory limit was reached');
    expect(screen.getByRole('alert')).toHaveTextContent('Self-test is still running');
    unmount();

    const running = run({ state: 'running', memory: breach.memory });
    const r2 = render(<TestRunPanel controls={controls({ run: running })} />);
    expect(screen.getByRole('status')).toHaveTextContent('memory limit exceeded');
    r2.unmount();

    const noLimit = run({
      state: 'cancelled',
      counts: { total: 0, queued: 0, scanning: 0, finished: 0, failed: 0, expired: 0 },
      memory: { limitMb: null, maxScanPeakMb: null, limitHitsDuringRun: null, oomKillsDuringRun: null, withinLimit: null },
      items: [item({ status: 'Expired', peakMemoryMb: 40 })],
    });
    render(<TestRunPanel controls={controls({ run: noLimit })} />);
    expect(screen.getByRole('status')).toHaveTextContent('Cancelled · 0 of 0 repositories scanned');
    expect(screen.getByText('40 MB')).toBeInTheDocument();
    expect(screen.queryByText('OOM kills')).toBeNull();
  });
});
