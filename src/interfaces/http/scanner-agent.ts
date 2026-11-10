import path from 'node:path';
import Fastify, { type FastifyBaseLogger, type FastifyInstance, type FastifyReply } from 'fastify';
import { z } from 'zod';
import { ScanError } from '../../domain/errors.js';
import type { RepositoryFetcher, Scanner } from '../../domain/ports.js';
import { normalizeRepoUrl } from '../../infrastructure/git/repo-url.js';
import { CommandError } from '../../infrastructure/process/run-command.js';

/**
 * Internal scanner agent (ROLE=scanner): runs git and Trivy in their own container / cgroup, on the work volume
 * shared with the service. The service's memory limit then covers only the service (API, worker, stream parser),
 * while the scanning tools get their own budget, as in a Kubernetes pod with a separate scanner container.
 *
 * Contract: POST JSON in; the outcome comes back in the status code and headers (no response body to parse).
 *   204                      success (clone: `x-commit-sha` header)
 *   422 + x-error-code/…     classified ScanError (x-error-retryable, x-error-message URI-encoded)
 *   499                      the caller went away; the child processes were killed
 *   401 / 400                bad token / invalid request
 */
export interface ScannerAgentDeps {
  readonly fetcher: RepositoryFetcher;
  readonly scanner: Scanner;
  /** Shared WORK_DIR; every path in a request must be a scan workspace under it. */
  readonly workDir: string;
  readonly token: string;
  readonly allowedHosts: readonly string[];
  readonly logger: FastifyBaseLogger | false;
}

const CloneBody = z.object({ repoUrl: z.string().max(2048), destDir: z.string().max(4096) }).strict();
const ScanBody = z.object({ sourceDir: z.string().max(4096), reportPath: z.string().max(4096), tmpDir: z.string().max(4096) }).strict();

export function buildScannerAgentApp(deps: ScannerAgentDeps): FastifyInstance {
  const app = Fastify({
    ...(deps.logger === false ? { logger: false } : { loggerInstance: deps.logger }),
    bodyLimit: 16 * 1024,
  });

  app.addHook('onRequest', async (request, reply) => {
    if (!request.url.startsWith('/internal/')) return;
    if (request.headers.authorization !== `Bearer ${deps.token}`) await reply.code(401).send();
  });

  app.get('/healthz', () => ({ status: 'ok' }));
  app.get('/readyz', async (_request, reply) => {
    const scanner = await deps.scanner.checkAvailable();
    return reply.code(scanner.ok ? 200 : 503).send({ status: scanner.ok ? 'ready' : 'not_ready', checks: { scanner } });
  });

  app.post('/internal/clone', async (request, reply) => {
    const body = CloneBody.safeParse(request.body);
    if (!body.success) return reply.code(400).send();
    const url = normalizeRepoUrl(body.data.repoUrl, deps.allowedHosts); // defence in depth: re-validate here too
    if (!url.ok || !insideWorkspace(deps.workDir, body.data.destDir)) return reply.code(400).send();
    return run(reply, async (signal) => {
      const { commitSha } = await deps.fetcher.clone(url.url, body.data.destDir, signal);
      void reply.header('x-commit-sha', commitSha);
    });
  });

  app.post('/internal/scan', async (request, reply) => {
    const body = ScanBody.safeParse(request.body);
    if (!body.success) return reply.code(400).send();
    const { sourceDir, reportPath, tmpDir } = body.data;
    if (![sourceDir, reportPath, tmpDir].every((p) => insideWorkspace(deps.workDir, p))) return reply.code(400).send();
    return run(reply, (signal) => deps.scanner.scan({ sourceDir, reportPath, tmpDir, signal }));
  });

  return app;
}

/** Run one job, killing it if the caller disconnects, and translate the outcome into status + headers. */
async function run(reply: FastifyReply, job: (signal: AbortSignal) => Promise<void>): Promise<FastifyReply> {
  const controller = new AbortController();
  const onClose = (): void => {
    if (!reply.sent) controller.abort(new Error('caller disconnected'));
  };
  reply.raw.on('close', onClose);
  try {
    await job(controller.signal);
    return await reply.code(204).send();
  } catch (err) {
    if (controller.signal.aborted || (err instanceof CommandError && err.kind === 'aborted')) return await reply.code(499).send();
    const e = err instanceof ScanError ? err : new ScanError('INTERNAL', 'Scanner agent failed unexpectedly', false, { cause: err });
    if (!(err instanceof ScanError)) reply.log.error({ err }, 'scanner agent job failed');
    if (e.retryAfterMs !== undefined) void reply.header('x-error-retry-after-ms', String(e.retryAfterMs));
    return await reply
      .code(422)
      .header('x-error-code', e.code)
      .header('x-error-retryable', String(e.retryable))
      .header('x-error-message', encodeURIComponent(e.message))
      .send();
  } finally {
    reply.raw.off('close', onClose);
  }
}

/** True only for a path inside WORK_DIR/scan-<id>/ (no traversal, no other directories). */
export function insideWorkspace(workDir: string, candidate: string): boolean {
  const root = path.resolve(workDir);
  const resolved = path.resolve(candidate);
  const rel = path.relative(root, resolved);
  return !rel.startsWith('..') && !path.isAbsolute(rel) && /^scan-[0-9a-f-]{36}(\/|$)/.test(rel);
}
