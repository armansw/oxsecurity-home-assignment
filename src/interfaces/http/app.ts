import rateLimit from '@fastify/rate-limit';
import Fastify, { type FastifyBaseLogger, type FastifyInstance } from 'fastify';
import mercurius from 'mercurius';
import type { ScanService } from '../../application/scan.service.js';
import type { ScanStore } from '../../domain/ports.js';
import { buildResolvers } from '../graphql/resolvers.js';
import { schema } from '../graphql/schema.js';
import { registerScanRoutes } from '../rest/scan.controller.js';
import { registerErrorHandling } from './error-handler.js';
import { registerHealthRoutes, type ReadinessProbe } from './health.controller.js';

export interface AppDeps {
  readonly service: ScanService;
  readonly store: ScanStore;
  readonly readiness: ReadinessProbe;
  readonly logger: FastifyBaseLogger | false;
  readonly responsePageSize: number;
  readonly rateLimitPerMinute: number;
  readonly graphiql: boolean;
}

/** Builds the HTTP application (REST + GraphQL on one Fastify instance). No I/O until `listen`. */
export async function buildApp(deps: AppDeps): Promise<FastifyInstance> {
  const app = Fastify({
    ...(deps.logger === false ? { logger: false } : { loggerInstance: deps.logger }),
    bodyLimit: 64 * 1024,
    trustProxy: true,
  });

  registerErrorHandling(app);
  await app.register(rateLimit, { global: false });

  registerHealthRoutes(app, deps.readiness);
  registerScanRoutes(app, {
    service: deps.service,
    store: deps.store,
    responsePageSize: deps.responsePageSize,
    rateLimitPerMinute: deps.rateLimitPerMinute,
  });

  await app.register(mercurius, {
    schema,
    resolvers: buildResolvers(deps.service),
    graphiql: deps.graphiql,
    path: '/graphql',
    // Bound query cost: no deeply nested or oversized queries.
    queryDepth: 6,
  });

  return app;
}
