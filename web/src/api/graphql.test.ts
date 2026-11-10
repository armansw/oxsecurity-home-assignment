import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { jsonResponse, REPO_URL, SCAN_ID } from '../test/fixtures';
import { GET_SCAN_QUERY, GraphqlScanApi, START_SCAN_MUTATION } from './graphql';

const fetchMock = vi.fn<typeof fetch>();

beforeEach(() => {
  vi.stubGlobal('fetch', fetchMock);
});
afterEach(() => {
  vi.unstubAllGlobals();
  fetchMock.mockReset();
});

function sentBody(): unknown {
  const init = fetchMock.mock.calls.at(-1)?.[1];
  if (typeof init?.body !== 'string') throw new Error('no JSON body sent');
  return JSON.parse(init.body);
}

const scanHeader = {
  id: SCAN_ID,
  repoUrl: REPO_URL,
  attempt: 1,
  createdAt: '2026-11-10T10:00:00.000Z',
  phase: null,
  progressPct: null,
  startedAt: null,
  finishedAt: null,
  criticalCount: null,
  stats: null,
  error: null,
  criticalVulnerabilities: null,
};

function node(n: number): Record<string, unknown> {
  return {
    id: `CVE-2024-${String(n).padStart(4, '0')}`,
    cursor: `c${String(n)}`,
    pkgName: 'openssl',
    installedVersion: '1.0',
    fixedVersion: '1.1',
    severity: 'CRITICAL',
    title: 't',
    description: null,
    primaryUrl: null,
    target: 'Dockerfile',
    pkgType: 'debian',
    cvssScore: null,
    publishedDate: null,
  };
}

const stats = { reportBytes: 2048, vulnerabilitiesScanned: 3, malformedSkipped: 1, durationMs: 900, peakMemoryMb: 60 };

describe('GraphqlScanApi.startScan', () => {
  it('sends the startScan mutation and maps the result', async () => {
    fetchMock.mockResolvedValue(jsonResponse({ data: { startScan: { id: SCAN_ID, status: 'Queued' } } }));
    await expect(new GraphqlScanApi('http://api.test').startScan(REPO_URL)).resolves.toEqual({
      scanId: SCAN_ID,
      status: 'Queued',
      deduplicated: false,
    });
    expect(fetchMock.mock.calls.at(-1)?.[0]).toBe('http://api.test/graphql');
    expect(sentBody()).toEqual({ query: START_SCAN_MUTATION, variables: { repoUrl: REPO_URL } });
  });

  it('maps a GraphQL error with extensions.code', async () => {
    fetchMock.mockResolvedValue(
      jsonResponse({ data: null, errors: [{ message: 'repoUrl must be a GitHub URL', extensions: { code: 'INVALID_REPO_URL' } }] }, 400),
    );
    await expect(new GraphqlScanApi().startScan('https://x')).rejects.toMatchObject({
      code: 'INVALID_REPO_URL',
      message: 'repoUrl must be a GitHub URL',
      status: 400,
      transient: false,
    });
  });

  it('defaults the code when extensions are missing (HTTP 200 errors)', async () => {
    fetchMock.mockResolvedValue(jsonResponse({ data: null, errors: [{ message: 'boom' }] }));
    await expect(new GraphqlScanApi().startScan(REPO_URL)).rejects.toMatchObject({ code: 'GRAPHQL_ERROR', status: null });
  });

  it('falls back to the HTTP status when the body carries no GraphQL errors', async () => {
    fetchMock.mockResolvedValueOnce(new Response('gateway down', { status: 504 }));
    await expect(new GraphqlScanApi().startScan(REPO_URL)).rejects.toMatchObject({ code: 'HTTP_504', transient: true });
    fetchMock.mockResolvedValueOnce(jsonResponse({ errors: ['not-an-object'] }, 500));
    await expect(new GraphqlScanApi().startScan(REPO_URL)).rejects.toMatchObject({ code: 'HTTP_500' });
  });
});

describe('GraphqlScanApi.getScan', () => {
  it('queries with first=100 and no cursor by default', async () => {
    fetchMock.mockResolvedValue(jsonResponse({ data: { scan: { ...scanHeader, status: 'Queued' } } }));
    await expect(new GraphqlScanApi().getScan(SCAN_ID)).resolves.toEqual({
      scanId: SCAN_ID,
      repoUrl: REPO_URL,
      attempt: 1,
      createdAt: '2026-11-10T10:00:00.000Z',
      status: 'Queued',
    });
    expect(sentBody()).toEqual({ query: GET_SCAN_QUERY, variables: { id: SCAN_ID, first: 100, after: null } });
  });

  it('maps Scanning and Failed scans to the same shapes as REST', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ data: { scan: { ...scanHeader, status: 'Scanning', phase: 'parsing', progressPct: 90 } } }));
    await expect(new GraphqlScanApi().getScan(SCAN_ID)).resolves.toMatchObject({ status: 'Scanning', phase: 'parsing', progressPct: 90 });
    fetchMock.mockResolvedValueOnce(
      jsonResponse({ data: { scan: { ...scanHeader, status: 'Failed', error: { code: 'TIMEOUT', message: 'took too long' } } } }),
    );
    await expect(new GraphqlScanApi().getScan(SCAN_ID)).resolves.toMatchObject({
      status: 'Failed',
      error: { code: 'TIMEOUT', message: 'took too long' },
    });
  });

  it('derives nextCursor from the last item when a page is full', async () => {
    fetchMock.mockResolvedValue(
      jsonResponse({
        data: { scan: { ...scanHeader, status: 'Finished', criticalCount: 5, stats, criticalVulnerabilities: [node(1), node(2)] } },
      }),
    );
    const scan = await new GraphqlScanApi().getScan(SCAN_ID, { limit: 2, cursor: 'c0' });
    expect(sentBody()).toMatchObject({ variables: { first: 2, after: 'c0' } });
    expect(scan.status === 'Finished' && scan.page.nextCursor).toBe('c2');
    expect(scan.status === 'Finished' && scan.page.items.map((v) => v.id)).toEqual(['CVE-2024-0001', 'CVE-2024-0002']);
    // The wire-only cursor field does not leak into the normalized model.
    expect(scan.status === 'Finished' && scan.page.items[0]).not.toHaveProperty('cursor');
  });

  it('reports no next page when a page is short', async () => {
    fetchMock.mockResolvedValue(
      jsonResponse({ data: { scan: { ...scanHeader, status: 'Finished', criticalCount: 1, stats, criticalVulnerabilities: [node(1)] } } }),
    );
    const scan = await new GraphqlScanApi().getScan(SCAN_ID);
    expect(scan.status === 'Finished' && scan.page).toMatchObject({ nextCursor: null });
  });

  it('turns a null scan into NOT_FOUND', async () => {
    fetchMock.mockResolvedValue(jsonResponse({ data: { scan: null } }));
    await expect(new GraphqlScanApi().getScan(SCAN_ID)).rejects.toMatchObject({ code: 'NOT_FOUND', status: 404, transient: false });
  });

  it('rejects a response without data', async () => {
    fetchMock.mockResolvedValue(jsonResponse({}));
    await expect(new GraphqlScanApi().getScan(SCAN_ID)).rejects.toMatchObject({ code: 'INVALID_RESPONSE' });
  });
});
