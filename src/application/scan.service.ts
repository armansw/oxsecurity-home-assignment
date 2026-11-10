import { RequestError, ScanError } from '../domain/errors.js';
import type { ScanStore } from '../domain/ports.js';
import { isScanId, type Scan } from '../domain/scan.js';
import type { StoredVulnerability } from '../domain/vulnerability.js';
import { normalizeRepoUrl } from '../infrastructure/git/repo-url.js';

export interface ScanServiceOptions {
  readonly allowedHosts: readonly string[];
  readonly maxQueued: number;
  /** Nudges an in-process worker so a new scan starts without waiting for the next poll. */
  readonly wake?: () => void;
  /** Optional admission check (e.g. free disk) so the queue does not fill with doomed jobs. */
  readonly checkCapacity?: () => Promise<void>;
}

export interface RequestScanResult {
  readonly scan: Scan;
  /** True when an identical scan was already Queued/Scanning and was returned instead of a new one. */
  readonly deduplicated: boolean;
}

export interface VulnerabilityPage {
  readonly items: readonly StoredVulnerability[];
  readonly nextCursor: string | null;
}

export const MAX_PAGE_SIZE = 1000;

/**
 * Application use cases, shared by the REST controller and the GraphQL resolvers. Transport-agnostic: it
 * speaks domain types and throws RequestError, which each interface maps to its own error format.
 */
export class ScanService {
  constructor(
    private readonly store: ScanStore,
    private readonly opts: ScanServiceOptions,
  ) {}

  async requestScan(rawUrl: string): Promise<RequestScanResult> {
    const normalized = normalizeRepoUrl(rawUrl, this.opts.allowedHosts);
    if (!normalized.ok) throw new RequestError('INVALID_REPO_URL', normalized.reason);

    const existing = this.store.findActiveByRepo(normalized.url);
    if (existing !== undefined) return { scan: existing, deduplicated: true };

    if (this.store.countQueued() >= this.opts.maxQueued) {
      throw new RequestError('QUEUE_FULL', 'Too many scans are queued; retry later');
    }
    if (this.opts.checkCapacity) {
      try {
        await this.opts.checkCapacity();
      } catch (err) {
        if (err instanceof ScanError) throw new RequestError('NOT_READY', err.message);
        throw err;
      }
    }

    const scan = this.store.create(normalized.url);
    this.opts.wake?.();
    return { scan, deduplicated: false };
  }

  getScan(rawId: string): Scan {
    if (!isScanId(rawId)) throw new RequestError('INVALID_SCAN_ID', 'scanId must be a UUID');
    const scan = this.store.findById(rawId);
    if (scan === undefined) throw new RequestError('NOT_FOUND', `Scan ${rawId} not found`);
    return scan;
  }

  /**
   * One keyset page of a finished scan's CRITICAL vulnerabilities, or null while the scan is not Finished
   * (results are only ever exposed once complete — never a partial list).
   */
  listCriticalVulnerabilities(scan: Scan, opts: { limit: number; cursor?: string | null | undefined }): VulnerabilityPage | null {
    if (scan.status !== 'Finished') return null;
    const limit = Math.min(Math.max(Math.trunc(opts.limit), 1), MAX_PAGE_SIZE);
    const afterRowId = opts.cursor == null ? 0 : decodeCursor(opts.cursor);
    // Fetch one extra row to know whether another page exists without a COUNT(*).
    const rows = this.store.listVulnerabilities(scan.id, { afterRowId, limit: limit + 1 });
    const items = rows.slice(0, limit);
    const last = items.at(-1);
    return { items, nextCursor: rows.length > limit && last !== undefined ? encodeCursor(last.rowId) : null };
  }
}

export function encodeCursor(rowId: number): string {
  return Buffer.from(`v1:${rowId}`).toString('base64url');
}

export function decodeCursor(cursor: string): number {
  const decoded = Buffer.from(cursor, 'base64url').toString('utf8');
  const match = /^v1:(\d{1,15})$/.exec(decoded);
  if (match?.[1] === undefined) throw new RequestError('INVALID_CURSOR', 'cursor is not valid');
  return Number(match[1]);
}
