import { invalidResponse } from './errors';
import { asArray, asObject, optStr, scanView, status, str, vulnerability } from './guards';
import { errorFromEnvelope, fetchJson } from './http';
import { PAGE_SIZE, type PageRequest, type ScanApi, type ScanView, type StartScanResult } from './types';

export class RestScanApi implements ScanApi {
  constructor(private readonly base = '') {}

  async startScan(repoUrl: string, signal?: AbortSignal): Promise<StartScanResult> {
    const res = await fetchJson(`${this.base}/api/scan`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', accept: 'application/json' },
      body: JSON.stringify({ repoUrl }),
      signal: signal ?? null,
    });
    if (!res.ok) throw errorFromEnvelope(res.status, res.body);
    const obj = asObject(res.body, 'startScan');
    return { scanId: str(obj, 'scanId'), status: status(obj, 'status'), deduplicated: obj.deduplicated === true };
  }

  async getScan(scanId: string, page?: PageRequest, signal?: AbortSignal): Promise<ScanView> {
    const res = await fetchJson(this.scanUrl(scanId, page), {
      headers: { accept: 'application/json' },
      signal: signal ?? null,
    });
    if (!res.ok) throw errorFromEnvelope(res.status, res.body);
    const obj = asObject(res.body, 'scan');
    return scanView(obj, str(obj, 'scanId'), () => {
      if (!('nextCursor' in obj)) throw invalidResponse('nextCursor');
      return {
        items: asArray(obj.criticalVulnerabilities, 'criticalVulnerabilities').map((v, i) =>
          vulnerability(v, `criticalVulnerabilities[${String(i)}]`),
        ),
        nextCursor: optStr(obj, 'nextCursor'),
      };
    });
  }

  /**
   * Always paginated: without `limit` the server streams the complete vulnerability list, which a
   * browser tab has no business holding.
   */
  private scanUrl(scanId: string, page: PageRequest = { limit: PAGE_SIZE, cursor: null }): string {
    const params = new URLSearchParams({ limit: String(page.limit) });
    if (page.cursor !== null) params.set('cursor', page.cursor);
    return `${this.base}/api/scan/${encodeURIComponent(scanId)}?${params.toString()}`;
  }
}
