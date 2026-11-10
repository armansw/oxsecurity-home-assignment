import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { MAX_PAGE_SIZE, type ScanService } from '../../application/scan.service.js';
import type { ScanStore } from '../../domain/ports.js';
import { finishedScanJsonStream } from './scan-json-stream.js';
import { toScanHeaderView, toVulnerabilityDto } from './scan.dto.js';

const StartScanBody = z.object({ repoUrl: z.string().min(1).max(2048) }).strict();
const ScanParams = z.object({ scanId: z.string() });
const ScanQuery = z.object({
  limit: z.coerce.number().int().min(1).max(MAX_PAGE_SIZE).optional(),
  cursor: z.string().max(64).optional(),
});

export interface ScanControllerDeps {
  readonly service: ScanService;
  readonly store: ScanStore;
  readonly responsePageSize: number;
  readonly rateLimitPerMinute: number;
}

/**
 * REST controller: validate → call the service → map to a DTO. No business logic lives here.
 */
export function registerScanRoutes(app: FastifyInstance, deps: ScanControllerDeps): void {
  const { service, store } = deps;

  app.post(
    '/api/scan',
    {
      bodyLimit: 4096,
      config: { rateLimit: { max: deps.rateLimitPerMinute, timeWindow: '1 minute' } },
    },
    async (request, reply) => {
      const { repoUrl } = StartScanBody.parse(request.body);
      const { scan, deduplicated } = await service.requestScan(repoUrl);
      // 202: accepted for asynchronous processing. The work happens in the background worker.
      return reply
        .code(202)
        .header('location', `/api/scan/${scan.id}`)
        .send({ scanId: scan.id, status: scan.status, ...(deduplicated ? { deduplicated: true } : {}) });
    },
  );

  app.get('/api/scan/:scanId', async (request, reply) => {
    const { scanId } = ScanParams.parse(request.params);
    const query = ScanQuery.parse(request.query);
    const scan = service.getScan(scanId);

    // Clients polling for status must never get a cached answer.
    void reply.header('cache-control', 'no-store');

    if (scan.status !== 'Finished') return reply.send(toScanHeaderView(scan));

    if (query.limit !== undefined || query.cursor !== undefined) {
      const page = service.listCriticalVulnerabilities(scan, { limit: query.limit ?? 100, cursor: query.cursor });
      return reply.send({
        ...toScanHeaderView(scan),
        criticalVulnerabilities: (page?.items ?? []).map(toVulnerabilityDto),
        nextCursor: page?.nextCursor ?? null,
      });
    }

    // Default: the full list, streamed at constant memory.
    return reply.type('application/json; charset=utf-8').send(finishedScanJsonStream(scan, store, deps.responsePageSize));
  });
}
