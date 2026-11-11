import { act, fireEvent, render, renderHook, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ApiError } from '../api/errors';
import { createTestRunApi, testRun, testRunSettings, type TestRun, type TestRunApi, type TestRunItem, type TestRunSettings } from '../api/testRuns';
import { ownRunStore, TEST_RUN_POLL_INTERVAL_MS, useTestRun, type TestRunControls } from '../hooks/useTestRun';
import { formatEstimate, TestRunPanel } from './TestRunPanel';

const SETTINGS: TestRunSettings = { maxSize: 100, poolSize: 107, secondsPerRepo: 5.4, basedOnScans: 58 };

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

  it('reads the settings', async () => {
    expect(testRunSettings(SETTINGS)).toEqual(SETTINGS);
    expect(() => testRunSettings({ ...SETTINGS, maxSize: 'x' })).toThrow();
    vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(json(SETTINGS))
      .mockResolvedValueOnce(json({ error: { code: 'INTERNAL', message: 'boom' } }, 500));
    const api = createTestRunApi('');
    await expect(api.settings()).resolves.toEqual(SETTINGS);
    await expect(api.settings()).rejects.toMatchObject({ code: 'INTERNAL' });
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
    settings: vi.fn(() => Promise.resolve(SETTINGS)),
    latest: vi.fn(() => Promise.resolve(null)),
    get: vi.fn(() => Promise.resolve(run())),
    start: vi.fn(() => Promise.resolve(run({ state: 'running' }))),
    cancel: vi.fn(() => Promise.resolve(run({ state: 'cancelled' }))),
    ...overrides,
  };
}

describe('useTestRun', () => {
  beforeEach(() => {
    window.localStorage.clear();
  });

  const settle = async (ms = 0) => {
    await act(async () => {
      await vi.advanceTimersByTimeAsync(ms);
    });
  };

  it('shows nothing in a fresh browser: runs are per browser, not per server', async () => {
    vi.useFakeTimers();
    const api = fakeApi();
    const { result } = renderHook(() => useTestRun(api));
    await settle();
    expect(result.current.run).toBeNull();
    expect(api.get).not.toHaveBeenCalled();
    expect(api.latest).not.toHaveBeenCalled();
    expect(result.current.settings).toEqual(SETTINGS);
  });

  it("resumes this browser's own run after a reload and polls it until it ends", async () => {
    vi.useFakeTimers();
    ownRunStore.write(ID);
    const api = fakeApi({ get: vi.fn().mockResolvedValueOnce(run({ state: 'running' })).mockResolvedValue(run()) });
    const { result } = renderHook(() => useTestRun(api));
    await settle();
    expect(result.current.run?.state).toBe('running');
    expect(result.current.ownsRun).toBe(true);
    await settle(TEST_RUN_POLL_INTERVAL_MS);
    expect(result.current.run?.state).toBe('finished');
    await settle(TEST_RUN_POLL_INTERVAL_MS * 3);
    expect(api.get).toHaveBeenCalledTimes(2);
  });

  it('forgets a stored run the server no longer has, and reports other load errors', async () => {
    vi.useFakeTimers();
    ownRunStore.write(ID);
    const gone = renderHook(() => useTestRun(fakeApi({ get: vi.fn(() => Promise.reject(new ApiError('NOT_FOUND', 'gone', 404))) })));
    await settle();
    expect(gone.result.current.run).toBeNull();
    expect(gone.result.current.error).toBeNull();
    expect(ownRunStore.read()).toBeNull();

    ownRunStore.write(ID);
    const down = renderHook(() => useTestRun(fakeApi({ get: vi.fn(() => Promise.reject(new ApiError('X', 'down', 500))) })));
    await settle();
    expect(down.result.current.error).toBe('down');
    expect(ownRunStore.read()).toBe(ID);
  });

  it('starts and remembers a run, cancels only its own, and surfaces poll and action errors', async () => {
    vi.useFakeTimers();
    const api = fakeApi({
      get: vi.fn(() => Promise.reject(new ApiError('X', 'offline', 500))),
      cancel: vi.fn(() => Promise.reject(new ApiError('X', 'nope', 500))),
    });
    const { result } = renderHook(() => useTestRun(api));
    act(() => {
      result.current.start(10);
    });
    await settle();
    expect(api.start).toHaveBeenCalledWith(10);
    expect(ownRunStore.read()).toBe(ID);
    expect(result.current.ownsRun).toBe(true);
    await settle(TEST_RUN_POLL_INTERVAL_MS);
    expect(result.current.error).toBe('offline');
    act(() => {
      result.current.cancel();
    });
    await settle();
    expect(api.cancel).toHaveBeenCalledWith(ID);
    expect(result.current.error).toBe('nope');
    expect(result.current.busy).toBe(false);
  });

  it("offers to watch someone else's run when the server is busy, without taking ownership", async () => {
    vi.useFakeTimers();
    const api = fakeApi({
      start: vi.fn(() => Promise.reject(new ApiError('TEST_RUN_ACTIVE', 'busy', 409))),
      latest: vi.fn().mockResolvedValueOnce(run({ state: 'running' })).mockResolvedValueOnce(null),
    });
    const { result } = renderHook(() => useTestRun(api));
    act(() => {
      result.current.start(5);
    });
    await settle();
    expect(result.current.othersRunActive).toBe(true);
    expect(result.current.error).toMatch(/Another self-test is running/);

    act(() => {
      result.current.watchActive();
    });
    await settle();
    expect(result.current.run?.state).toBe('running');
    expect(result.current.ownsRun).toBe(false);
    expect(ownRunStore.read()).toBeNull();
    act(() => {
      result.current.cancel(); // not ours: nothing happens
    });
    expect(api.cancel).not.toHaveBeenCalled();

    act(() => {
      result.current.watchActive();
    });
    await settle();
    expect(result.current.error).toBe('No self-test is running.');
  });

  it('works when browser storage is unavailable', () => {
    const get = vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => {
      throw new Error('denied');
    });
    const set = vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
      throw new Error('denied');
    });
    expect(ownRunStore.read()).toBeNull();
    expect(() => {
      ownRunStore.write(ID);
    }).not.toThrow();
    get.mockRestore();
    set.mockRestore();
  });
});

function controls(overrides: Partial<TestRunControls> = {}): TestRunControls {
  return { run: null, ownsRun: true, settings: SETTINGS, error: null, othersRunActive: false, busy: false, start: vi.fn(), cancel: vi.fn(), watchActive: vi.fn(), ...overrides };
}

describe('TestRunPanel', () => {
  it('takes any size from 1 to 100 by slider or by typing, and starts the self-test', async () => {
    const c = controls();
    render(<TestRunPanel controls={c} />);
    const box = screen.getByLabelText('Repositories to scan');
    const slider = screen.getByLabelText('Repositories to scan (slider)');
    expect(box).toHaveValue(20);
    expect(screen.getByText('≈ 2 min')).toBeInTheDocument();
    expect(screen.getByText('≈ 2 min')).toHaveAttribute('title', 'Measured: 5.4 s per repository over the last 58 self-test scans');

    await userEvent.clear(box);
    await userEvent.type(box, '29');
    expect(slider).toHaveValue('29');
    await userEvent.click(screen.getByRole('button', { name: 'Run self-test' }));
    expect(c.start).toHaveBeenLastCalledWith(29);

    fireEvent.change(slider, { target: { value: '100' } });
    expect(box).toHaveValue(100);
    expect(screen.getByText('≈ 9 min')).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Run self-test' }));
    expect(c.start).toHaveBeenLastCalledWith(100);

    await userEvent.clear(box);
    await userEvent.type(box, '101');
    expect(box).toHaveAttribute('aria-invalid', 'true');
    expect(screen.getByText('1–100')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Run self-test' })).toBeDisabled();
    await userEvent.clear(box);
    await userEvent.type(box, '1');
    expect(screen.getByText('≈ 5 s')).toBeInTheDocument();
  });

  it('caps the size at the eligible pool, and shows no estimate before anything was measured', () => {
    render(<TestRunPanel controls={controls({ settings: null, run: run({ poolSize: 60 }) })} />);
    expect(screen.getByLabelText('Repositories to scan')).toHaveAttribute('max', '60');
    expect(screen.queryByText(/≈/)).toBeNull();
  });

  it('formats estimates in seconds, then minutes', () => {
    expect(formatEstimate(10, 5.4)).toBe('≈ 54 s');
    expect(formatEstimate(0, 5.4)).toBe('≈ 1 s');
    expect(formatEstimate(30, 5.4)).toBe('≈ 3 min');
    expect(formatEstimate(100, 5.4)).toBe('≈ 9 min');
  });

  it('shows a finished run: verdict, totals and one row per repository', () => {
    render(<TestRunPanel controls={controls({ run: run() })} />);
    expect(screen.getByRole('status')).toHaveTextContent(
      '✓ · 1 of 2 repositories scanned · every scan within the 150 MB limit · limit never reached · 0 OOM kills',
    );
    expect(screen.getByText('52 MB / 150 MB')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'gin-gonic/gin' })).toHaveAttribute('href', 'https://github.com/gin-gonic/gin.git');
    expect(screen.getByText('REPO_NOT_FOUND')).toBeInTheDocument();
    expect(screen.queryByText(/a package registry/)).toBeNull();
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
    expect(screen.getByRole('status')).toHaveTextContent('Running · 1 of 3 done · ≈ 11 s left · within the 150 MB limit so far');
    expect(screen.getByText('cloning')).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Cancel' }));
    expect(c.cancel).toHaveBeenCalled();
  });

  it("shows someone else's run without a cancel button, and offers to watch a busy server's run", async () => {
    const watching = render(<TestRunPanel controls={controls({ ownsRun: false, run: run({ state: 'running' }) })} />);
    expect(screen.getByText("Watching another visitor's run")).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Cancel' })).toBeNull();
    watching.unmount();

    const c = controls({ othersRunActive: true, error: 'Another self-test is running on this server right now (one at a time).' });
    render(<TestRunPanel controls={c} />);
    await userEvent.click(screen.getByRole('button', { name: 'Watch it' }));
    expect(c.watchActive).toHaveBeenCalled();
  });

  it('explains registry rate limits as not a service failure', () => {
    const limited = run({ items: [item({ status: 'Failed', error: { code: 'UPSTREAM_RATE_LIMITED', message: '429' } })] });
    render(<TestRunPanel controls={controls({ run: limited })} />);
    expect(screen.getByText(/a package registry \(e.g. Maven Central\) throttled Trivy/)).toBeInTheDocument();
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
