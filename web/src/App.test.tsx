import { act, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { App } from './App';
import { ApiError } from './api/errors';
import type { SystemMemory } from './api/system';
import type { Transport } from './api/types';
import { POLL_INTERVAL_MS } from './hooks/useScanPolling';
import { deferred, fakeApi, type FakeApi, finished, queued, REPO_URL, SCAN_ID, scanning } from './test/fixtures';

let user: ReturnType<typeof userEvent.setup>;

beforeEach(() => {
  vi.useFakeTimers({ shouldAdvanceTime: true });
  user = userEvent.setup({ advanceTimers: (ms) => vi.advanceTimersByTime(ms) });
  window.history.replaceState(null, '', '/');
});
afterEach(() => {
  vi.useRealTimers();
});

async function tick(ms: number): Promise<void> {
  await act(async () => {
    await vi.advanceTimersByTimeAsync(ms);
  });
}

const noMemory = (): Promise<SystemMemory> => Promise.reject(new Error('not available in tests'));

function setup(apis: Partial<Record<Transport, FakeApi>> = {}, loadMemory: (signal: AbortSignal) => Promise<SystemMemory> = noMemory) {
  const rest = apis.rest ?? fakeApi();
  const graphql = apis.graphql ?? fakeApi();
  const createApi = vi.fn((t: Transport) => (t === 'rest' ? rest : graphql));
  const testRunApi = { latest: vi.fn(() => Promise.resolve(null)), get: vi.fn(), start: vi.fn(), cancel: vi.fn() };
  render(<App createApi={createApi} loadMemory={loadMemory} testRunApi={testRunApi} />);
  return { rest, graphql, createApi };
}

async function start(url = REPO_URL): Promise<void> {
  await user.type(screen.getByLabelText('Repository URL'), url);
  await user.click(screen.getByRole('button', { name: 'Start' }));
}

describe('App', () => {
  it('starts a scan, polls until Finished, and shows results', async () => {
    const { rest } = setup();
    rest.startScan.mockResolvedValue({ scanId: SCAN_ID, status: 'Queued', deduplicated: false });
    rest.getScan.mockResolvedValueOnce(queued()).mockResolvedValueOnce(scanning()).mockResolvedValueOnce(finished());

    await start();
    expect(rest.startScan).toHaveBeenCalledWith(REPO_URL);
    expect(window.location.search).toBe(`?scan=${SCAN_ID}`);
    expect(await screen.findByText('Queued')).toBeInTheDocument();
    expect(screen.getByRole('status')).toHaveTextContent('Queued');
    expect(screen.getByRole('button', { name: 'Start' })).toBeDisabled();

    await tick(POLL_INTERVAL_MS);
    expect(screen.getByRole('status')).toHaveTextContent('Scanning · scanning 40%');

    await tick(POLL_INTERVAL_MS);
    expect(screen.getByRole('status')).toHaveTextContent('Finished');
    expect(screen.getByRole('heading', { name: 'Results' })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'CVE-2024-0001' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Start' })).toBeEnabled();
  });

  it('resumes polling from ?scan= on load', async () => {
    window.history.replaceState(null, '', `/?scan=${SCAN_ID}`);
    const rest = fakeApi();
    rest.getScan.mockResolvedValue(scanning({ phase: 'parsing', progressPct: 99 }));
    setup({ rest });
    expect(await screen.findByText('Scanning · parsing 99%')).toBeInTheDocument();
    expect(rest.getScan).toHaveBeenCalledWith(SCAN_ID, { limit: 100, cursor: null }, expect.any(AbortSignal));
  });

  it('"New scan" resets the screen and the URL', async () => {
    window.history.replaceState(null, '', `/?scan=${SCAN_ID}&keep=1`);
    const rest = fakeApi();
    rest.getScan.mockResolvedValue(finished());
    setup({ rest });
    await screen.findByRole('heading', { name: 'Results' });

    await user.click(screen.getByRole('button', { name: 'New scan' }));
    expect(screen.queryByRole('heading', { name: 'Results' })).not.toBeInTheDocument();
    expect(screen.queryByRole('status')).not.toBeInTheDocument();
    expect(window.location.search).toBe('?keep=1');
  });

  it('shows server errors inline and re-enables Start', async () => {
    const { rest } = setup();
    rest.startScan.mockRejectedValue(new ApiError('QUEUE_FULL', 'Scan queue is full, retry later', 429));
    await start();
    expect(await screen.findByRole('alert')).toHaveTextContent('Scan queue is full, retry later');
    expect(screen.getByRole('button', { name: 'Start' })).toBeEnabled();
    expect(window.location.search).toBe('');
  });

  it('disables Start while the request is in flight', async () => {
    const { rest } = setup();
    const pending = deferred<{ scanId: string; status: 'Queued'; deduplicated: boolean }>();
    rest.startScan.mockReturnValue(pending.promise);
    rest.getScan.mockReturnValue(new Promise(() => undefined));
    await start();
    expect(screen.getByRole('button', { name: 'Start' })).toBeDisabled();
    await act(async () => {
      pending.resolve({ scanId: SCAN_ID, status: 'Queued', deduplicated: true });
      await Promise.resolve();
    });
    expect(screen.getByText(/already queued/i)).toBeInTheDocument();
    expect(screen.getByRole('status')).toHaveTextContent('Loading…');
  });

  it('shows a reconnecting hint on transient errors and a terminal error otherwise', async () => {
    window.history.replaceState(null, '', `/?scan=${SCAN_ID}`);
    const rest = fakeApi();
    rest.getScan
      .mockResolvedValueOnce(scanning())
      .mockRejectedValueOnce(new ApiError('NETWORK_ERROR', 'offline', null))
      .mockRejectedValueOnce(new ApiError('NOT_FOUND', 'scan not found', 404));
    setup({ rest });

    await screen.findByText('Scanning · scanning 40%');
    await tick(POLL_INTERVAL_MS);
    expect(screen.getByText('reconnecting…')).toBeInTheDocument();
    await tick(POLL_INTERVAL_MS);
    expect(screen.getByRole('status')).toHaveTextContent('NOT_FOUND: scan not found');
    expect(screen.queryByText('reconnecting…')).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Start' })).toBeEnabled();
  });

  it('switches transport and keeps polling the same scan', async () => {
    window.history.replaceState(null, '', `/?scan=${SCAN_ID}`);
    const rest = fakeApi();
    const graphql = fakeApi();
    rest.getScan.mockResolvedValue(scanning());
    graphql.getScan.mockResolvedValue(finished());
    setup({ rest, graphql });
    await screen.findByText('Scanning · scanning 40%');

    await user.click(screen.getByRole('radio', { name: 'GraphQL' }));
    expect(await screen.findByRole('heading', { name: 'Results' })).toBeInTheDocument();
    expect(graphql.getScan).toHaveBeenCalledWith(SCAN_ID, { limit: 100, cursor: null }, expect.any(AbortSignal));
  });

  it('shows the live memory budget against the real container limit, and draws a finished scan against it', async () => {
    const memory: SystemMemory = { privateMb: 58, heapUsedMb: 24, heapLimitMb: 198, cgroup: { limitMb: 150, currentMb: 67, peakMb: 96 } };
    const { rest } = setup({}, () => Promise.resolve(memory));
    await tick(0);
    expect(screen.getByRole('meter', { name: 'Service memory (live)' })).toHaveAttribute('aria-valuetext', '58 MB of 150 MB');
    expect(screen.getByText(/peak 96 MB · hard limit 150 MB/)).toBeInTheDocument();
    rest.startScan.mockResolvedValue({ scanId: SCAN_ID, status: 'Queued', deduplicated: false });
    rest.getScan.mockResolvedValue(finished());
    await start();
    expect(await screen.findByRole('meter', { name: 'Peak memory during this scan' })).toHaveAttribute('aria-valuemax', '150');
  });

  it('hides the memory panel when the server cannot report memory', async () => {
    setup();
    await tick(0);
    expect(screen.queryByRole('meter')).not.toBeInTheDocument();
  });
});
