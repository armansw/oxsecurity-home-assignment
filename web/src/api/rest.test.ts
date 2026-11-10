import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { jsonResponse, REPO_URL, SCAN_ID } from '../test/fixtures';
import { ApiError } from './errors';
import { RestScanApi } from './rest';

const fetchMock = vi.fn<typeof fetch>();

beforeEach(() => {
  vi.stubGlobal('fetch', fetchMock);
});
afterEach(() => {
  vi.unstubAllGlobals();
  fetchMock.mockReset();
});

const header = { scanId: SCAN_ID, repoUrl: REPO_URL, attempt: 1, createdAt: '2026-11-10T10:00:00.000Z' };
const wireVuln = {
  id: 'CVE-2024-0001',
  pkgName: 'lodash',
  installedVersion: '4.17.20',
  fixedVersion: null,
  severity: 'CRITICAL',
  title: null,
  description: null,
  primaryUrl: null,
  target: 'package-lock.json',
  pkgType: 'npm',
  cvssScore: 9.8,
  publishedDate: null,
};
const wireStats = { reportBytes: 10, vulnerabilitiesScanned: 2, malformedSkipped: 0, durationMs: 5, peakRssMb: 50 };

function lastCall(): { url: string; init: RequestInit } {
  const call = fetchMock.mock.calls.at(-1);
  if (call === undefined) throw new Error('fetch was not called');
  const [input, init] = call;
  return { url: typeof input === 'string' ? input : input instanceof URL ? input.href : input.url, init: init ?? {} };
}

describe('RestScanApi.startScan', () => {
  it('POSTs the repo URL and maps the 202 response', async () => {
    fetchMock.mockResolvedValue(jsonResponse({ scanId: SCAN_ID, status: 'Queued' }, 202));
    const api = new RestScanApi('http://api.test');

    await expect(api.startScan(REPO_URL)).resolves.toEqual({ scanId: SCAN_ID, status: 'Queued', deduplicated: false });
    const { url, init } = lastCall();
    expect(url).toBe('http://api.test/api/scan');
    expect(init.method).toBe('POST');
    expect(init.body).toBe(JSON.stringify({ repoUrl: REPO_URL }));
  });

  it('surfaces the deduplicated flag', async () => {
    fetchMock.mockResolvedValue(jsonResponse({ scanId: SCAN_ID, status: 'Scanning', deduplicated: true }, 202));
    await expect(new RestScanApi().startScan(REPO_URL)).resolves.toMatchObject({ deduplicated: true, status: 'Scanning' });
  });

  it('throws an ApiError built from the error envelope', async () => {
    fetchMock.mockResolvedValue(
      jsonResponse({ error: { code: 'INVALID_REPO_URL', message: 'repoUrl must be a GitHub URL', details: ['host', 3] } }, 400),
    );
    const err = await new RestScanApi().startScan('https://gitlab.com/x/y').catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect(err).toMatchObject({ code: 'INVALID_REPO_URL', message: 'repoUrl must be a GitHub URL', status: 400, details: ['host'] });
  });

  it('maps a network failure to a transient NETWORK_ERROR', async () => {
    fetchMock.mockRejectedValue(new TypeError('Failed to fetch'));
    const err = await new RestScanApi().startScan(REPO_URL).catch((e: unknown) => e);
    expect(err).toMatchObject({ code: 'NETWORK_ERROR', transient: true });
  });
});

describe('RestScanApi.getScan', () => {
  it('always requests a bounded page (limit=100 by default)', async () => {
    fetchMock.mockResolvedValue(jsonResponse({ ...header, status: 'Queued' }));
    await expect(new RestScanApi().getScan(SCAN_ID)).resolves.toEqual({ ...header, status: 'Queued' });
    expect(lastCall().url).toBe(`/api/scan/${SCAN_ID}?limit=100`);
  });

  it('passes the cursor for later pages', async () => {
    fetchMock.mockResolvedValue(jsonResponse({ ...header, status: 'Queued' }));
    await new RestScanApi().getScan(SCAN_ID, { limit: 100, cursor: 'abc=' });
    expect(lastCall().url).toBe(`/api/scan/${SCAN_ID}?limit=100&cursor=abc%3D`);
  });

  it('maps a Scanning response, tolerating null phase/progress', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ ...header, status: 'Scanning', phase: 'cloning', progressPct: 5, startedAt: null }));
    await expect(new RestScanApi().getScan(SCAN_ID)).resolves.toEqual({
      ...header,
      status: 'Scanning',
      phase: 'cloning',
      progressPct: 5,
      startedAt: null,
    });
    fetchMock.mockResolvedValueOnce(jsonResponse({ ...header, status: 'Scanning', phase: null, progressPct: null, startedAt: null }));
    await expect(new RestScanApi().getScan(SCAN_ID)).resolves.toMatchObject({ phase: null, progressPct: null });
  });

  it('maps a Failed response', async () => {
    fetchMock.mockResolvedValue(
      jsonResponse({ ...header, status: 'Failed', error: { code: 'CLONE_FAILED', message: 'nope' }, finishedAt: '2026-11-10T10:01:00Z' }),
    );
    await expect(new RestScanApi().getScan(SCAN_ID)).resolves.toMatchObject({
      status: 'Failed',
      error: { code: 'CLONE_FAILED', message: 'nope' },
      finishedAt: '2026-11-10T10:01:00Z',
    });
  });

  it('maps a Finished page with nextCursor', async () => {
    fetchMock.mockResolvedValue(
      jsonResponse({
        ...header,
        status: 'Finished',
        startedAt: null,
        finishedAt: null,
        criticalCount: 1,
        stats: wireStats,
        criticalVulnerabilities: [wireVuln],
        nextCursor: 'next',
      }),
    );
    const scan = await new RestScanApi().getScan(SCAN_ID);
    expect(scan).toMatchObject({ status: 'Finished', criticalCount: 1, stats: wireStats });
    expect(scan.status === 'Finished' && scan.page).toEqual({ items: [wireVuln], nextCursor: 'next' });
  });

  it('rejects a Finished response that is not paginated (the unbounded stream shape)', async () => {
    fetchMock.mockResolvedValue(
      jsonResponse({ ...header, status: 'Finished', startedAt: null, finishedAt: null, criticalCount: 0, stats: wireStats, criticalVulnerabilities: [] }),
    );
    await expect(new RestScanApi().getScan(SCAN_ID)).rejects.toMatchObject({ code: 'INVALID_RESPONSE', transient: false });
  });

  it.each([
    ['unknown status', { ...header, status: 'Exploded' }],
    ['unknown phase', { ...header, status: 'Scanning', phase: 'warping', progressPct: 1, startedAt: null }],
    ['non-numeric attempt', { ...header, attempt: '1', status: 'Queued' }],
    ['non-string optional field', { ...header, status: 'Scanning', phase: null, progressPct: null, startedAt: 7 }],
    ['non-object body', ['not', 'an', 'object']],
    ['bad vulnerability', { ...header, status: 'Finished', startedAt: null, finishedAt: null, criticalCount: 1, stats: wireStats, criticalVulnerabilities: [{ id: 1 }], nextCursor: null }],
  ])('rejects a malformed response (%s)', async (_label, body) => {
    fetchMock.mockResolvedValue(jsonResponse(body));
    await expect(new RestScanApi().getScan(SCAN_ID)).rejects.toMatchObject({ code: 'INVALID_RESPONSE' });
  });

  it('maps 404 to a non-transient error and 503 to a transient one', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ error: { code: 'NOT_FOUND', message: 'scan not found' } }, 404));
    await expect(new RestScanApi().getScan(SCAN_ID)).rejects.toMatchObject({ code: 'NOT_FOUND', transient: false });
    fetchMock.mockResolvedValueOnce(jsonResponse({ error: { code: 'NOT_READY', message: 'warming up' } }, 503));
    await expect(new RestScanApi().getScan(SCAN_ID)).rejects.toMatchObject({ code: 'NOT_READY', transient: true });
  });

  it('falls back to the HTTP status when the error body is not an envelope', async () => {
    fetchMock.mockResolvedValue(new Response('<html>Bad gateway</html>', { status: 502 }));
    await expect(new RestScanApi().getScan(SCAN_ID)).rejects.toMatchObject({ code: 'HTTP_502', status: 502, transient: true });
  });

  it('propagates aborts untouched', async () => {
    const controller = new AbortController();
    fetchMock.mockImplementation(() => Promise.reject(new DOMException('aborted', 'AbortError')));
    controller.abort();
    await expect(new RestScanApi().getScan(SCAN_ID, undefined, controller.signal)).rejects.toMatchObject({ name: 'AbortError' });
    expect(lastCall().init.signal).toBe(controller.signal);
  });
});
