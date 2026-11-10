import http from 'node:http';
import { ScanError, isScanErrorCode } from '../../domain/errors.js';
import type { RepositoryFetcher, Scanner } from '../../domain/ports.js';

export interface RemoteScanAgentOptions {
  /** Base URL of the scanner agent, e.g. http://scanner:3001 */
  readonly url: string;
  readonly token: string;
}

/**
 * Service-side adapter for the scanner agent (SCANNER=remote). Implements the same ports as the in-process git
 * and Trivy adapters, so the processor, queue and stream parser are unchanged: only where git and Trivy run
 * (and whose memory limit they count against) changes.
 *
 * Uses node:http rather than fetch: undici's default 300 s headers timeout would cut off a 20-minute scan.
 * Aborting the job destroys the request; the agent sees the disconnect and kills its child processes.
 */
export class RemoteScanAgent implements RepositoryFetcher, Scanner {
  constructor(private readonly opts: RemoteScanAgentOptions) {}

  async clone(repoUrl: string, destDir: string, signal: AbortSignal): Promise<{ readonly commitSha: string }> {
    const res = await this.post('/internal/clone', { repoUrl, destDir }, signal);
    const commitSha = res.headers['x-commit-sha'];
    if (typeof commitSha !== 'string' || !/^[0-9a-f]{40}([0-9a-f]{24})?$/.test(commitSha)) {
      throw new ScanError('CLONE_FAILED', 'Scanner agent did not report the cloned commit', true);
    }
    return { commitSha };
  }

  async scan(input: Parameters<Scanner['scan']>[0]): Promise<void> {
    const { sourceDir, reportPath, tmpDir, signal } = input;
    await this.post('/internal/scan', { sourceDir, reportPath, tmpDir }, signal);
  }

  async checkAvailable(): Promise<{ ok: boolean; detail: string }> {
    try {
      const res = await this.request('GET', '/readyz', undefined, AbortSignal.timeout(10_000));
      return { ok: res.statusCode === 200, detail: `scanner agent ${this.opts.url} (${String(res.statusCode)})` };
    } catch (err) {
      return { ok: false, detail: `scanner agent ${this.opts.url}: ${err instanceof Error ? err.message : String(err)}` };
    }
  }

  private async post(pathname: string, body: object, signal: AbortSignal): Promise<http.IncomingMessage> {
    let res: http.IncomingMessage;
    try {
      res = await this.request('POST', pathname, body, signal);
    } catch (err) {
      if (signal.aborted) throw signal.reason;
      throw new ScanError('SCANNER_UNAVAILABLE', 'Scanner agent is unreachable', true, { cause: err });
    }
    if (res.statusCode === 204) return res;
    if (res.statusCode === 422) throw errorFromHeaders(res.headers);
    throw new ScanError('SCANNER_FAILED', `Scanner agent answered HTTP ${String(res.statusCode)}`, res.statusCode !== 401 && res.statusCode !== 400);
  }

  private request(method: string, pathname: string, body: object | undefined, signal: AbortSignal): Promise<http.IncomingMessage> {
    const payload = body === undefined ? undefined : JSON.stringify(body);
    return new Promise((resolve, reject) => {
      const req = http.request(
        new URL(pathname, this.opts.url),
        {
          method,
          signal,
          headers: {
            authorization: `Bearer ${this.opts.token}`,
            ...(payload === undefined ? {} : { 'content-type': 'application/json', 'content-length': Buffer.byteLength(payload) }),
          },
        },
        (res) => {
          res.resume(); // outcomes are carried in status + headers; discard any body
          res.on('end', () => {
            resolve(res);
          });
          res.on('error', reject);
        },
      );
      req.on('error', reject);
      req.end(payload);
    });
  }
}

function errorFromHeaders(headers: http.IncomingHttpHeaders): ScanError {
  const code = typeof headers['x-error-code'] === 'string' && isScanErrorCode(headers['x-error-code']) ? headers['x-error-code'] : 'INTERNAL';
  const raw = headers['x-error-message'];
  let message = 'Scanner agent reported a failure';
  if (typeof raw === 'string') {
    try {
      message = decodeURIComponent(raw);
    } catch {
      // keep the generic message
    }
  }
  const retryAfter = Number(headers['x-error-retry-after-ms']);
  return new ScanError(code, message, headers['x-error-retryable'] === 'true', Number.isFinite(retryAfter) && retryAfter > 0 ? { retryAfterMs: retryAfter } : {});
}
