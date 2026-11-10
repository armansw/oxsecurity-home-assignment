import { ApiError } from './errors';
import { asArray, asObject, isObject, type JsonObject, optStr, scanView, status, str, vulnerability } from './guards';
import { fetchJson } from './http';
import { PAGE_SIZE, type PageRequest, type ScanApi, type ScanView, type StartScanResult, type VulnerabilityPage } from './types';

const SCAN_FIELDS = `
  id status repoUrl phase progressPct attempt criticalCount createdAt startedAt finishedAt
  error { code message }
  stats { reportBytes vulnerabilitiesScanned malformedSkipped durationMs peakRssMb }
`;

export const GET_SCAN_QUERY = `
  query GetScan($id: ID!, $first: Int!, $after: ID) {
    scan(id: $id) {
      ${SCAN_FIELDS}
      criticalVulnerabilities(first: $first, after: $after) {
        id cursor pkgName installedVersion fixedVersion severity title description
        primaryUrl target pkgType cvssScore publishedDate
      }
    }
  }
`;

export const START_SCAN_MUTATION = `
  mutation StartScan($repoUrl: String!) {
    startScan(repoUrl: $repoUrl) { id status }
  }
`;

export class GraphqlScanApi implements ScanApi {
  constructor(private readonly base = '') {}

  async startScan(repoUrl: string, signal?: AbortSignal): Promise<StartScanResult> {
    const data = await this.request(START_SCAN_MUTATION, { repoUrl }, signal);
    const scan = asObject(data.startScan, 'startScan');
    // The GraphQL schema does not expose deduplication; the mutation simply returns the existing scan.
    return { scanId: str(scan, 'id'), status: status(scan, 'status'), deduplicated: false };
  }

  async getScan(scanId: string, page: PageRequest = { limit: PAGE_SIZE, cursor: null }, signal?: AbortSignal): Promise<ScanView> {
    const data = await this.request(GET_SCAN_QUERY, { id: scanId, first: page.limit, after: page.cursor }, signal);
    if (data.scan === null) throw new ApiError('NOT_FOUND', 'Scan not found.', 404);
    const scan = asObject(data.scan, 'scan');
    return scanView(scan, str(scan, 'id'), () => toPage(scan.criticalVulnerabilities, page.limit));
  }

  private async request(query: string, variables: Readonly<Record<string, unknown>>, signal?: AbortSignal): Promise<JsonObject> {
    const res = await fetchJson(`${this.base}/graphql`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', accept: 'application/json' },
      body: JSON.stringify({ query, variables }),
      signal: signal ?? null,
    });
    const error = firstGraphqlError(res.status, res.body);
    if (error !== null) throw error;
    if (!res.ok) throw new ApiError(`HTTP_${String(res.status)}`, `Request failed with status ${String(res.status)}.`, res.status);
    return asObject(asObject(res.body, 'response').data, 'data');
  }
}

/**
 * GraphQL returns a bare list, so "has more" is inferred: a full page means there may be more,
 * continued after the last item's cursor (at worst one extra, empty, request at the very end).
 */
function toPage(value: unknown, limit: number): VulnerabilityPage {
  const nodes = asArray(value, 'criticalVulnerabilities').map((v, i) => asObject(v, `criticalVulnerabilities[${String(i)}]`));
  const last = nodes.at(-1);
  return {
    items: nodes.map((node, i) => vulnerability(node, `criticalVulnerabilities[${String(i)}]`)),
    nextCursor: nodes.length >= limit && last !== undefined ? str(last, 'cursor') : null,
  };
}

function firstGraphqlError(httpStatus: number, body: unknown): ApiError | null {
  if (!isObject(body) || !Array.isArray(body.errors)) return null;
  const first: unknown = asArray(body.errors, 'errors')[0];
  if (!isObject(first)) return null;
  const message = optStr(first, 'message') ?? 'GraphQL request failed.';
  const extensions = isObject(first.extensions) ? first.extensions : {};
  const code = optStr(extensions, 'code') ?? 'GRAPHQL_ERROR';
  return new ApiError(code, message, httpStatus >= 400 ? httpStatus : null);
}
