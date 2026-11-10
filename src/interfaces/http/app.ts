import rateLimit from '@fastify/rate-limit';
import Fastify, { type FastifyBaseLogger, type FastifyInstance, type FastifyRequest } from 'fastify';
import mercurius from 'mercurius';
import type { ScanService } from '../../application/scan.service.js';
import type { ScanStore } from '../../domain/ports.js';
import { buildResolvers } from '../graphql/resolvers.js';
import { schema } from '../graphql/schema.js';
import { registerScanRoutes } from '../rest/scan.controller.js';
import { registerErrorHandling } from './error-handler.js';
import { registerHealthRoutes, type ReadinessProbe } from './health.controller.js';

/** Anything that can render Prometheus text exposition (the PrometheusMetrics adapter). */
export interface MetricsSource {
  readonly contentType: string;
  metrics(): Promise<string>;
}

interface CommonDeps {
  readonly readiness: ReadinessProbe;
  readonly logger: FastifyBaseLogger | false;
  readonly metrics?: MetricsSource | undefined;
  /** Fastify trustProxy: false, true, or addresses/ranges of trusted proxies (e.g. `loopback,uniquelocal`). */
  readonly trustProxy?: boolean | string;
}

export interface AppDeps extends CommonDeps {
  readonly service: ScanService;
  readonly store: ScanStore;
  readonly responsePageSize: number;
  /** Scan-creation limit per client IP, applied to POST /api/scan and to the GraphQL startScan mutation (each). */
  readonly rateLimitPerMinute: number;
  readonly graphiql: boolean;
}

/** Builds the public HTTP application (REST + GraphQL + ops endpoints). No I/O until `listen`. */
export async function buildApp(deps: AppDeps): Promise<FastifyInstance> {
  const app = createServer(deps);
  registerErrorHandling(app);

  // Only scan creation is rate limited, on both transports (each route keeps its own per-IP counter; the queue
  // cap MAX_QUEUED bounds total work regardless). Status polling — the UI polls every 2 s — is not limited: it is
  // a cheap indexed read, and limiting it would throttle legitimate clients first.
  const scanCreationLimit = { max: deps.rateLimitPerMinute, timeWindow: '1 minute' };
  app.addHook('onRoute', (route) => {
    if (route.url === '/graphql' && methodsOf(route.method).includes('POST')) {
      route.config = {
        ...route.config,
        // preHandler: the body is parsed by then, so queries can be told apart from mutations.
        rateLimit: {
          ...scanCreationLimit,
          hook: 'preHandler',
          allowList: (req: FastifyRequest) => !isGraphqlMutation(req.body),
          // Same stable code as every other API error, in GraphQL's own error format.
          errorResponseBuilder: () =>
            new mercurius.ErrorWithProps('Too many scan requests; slow down', { code: 'RATE_LIMITED' }, 429),
        },
      };
    }
  });
  await app.register(rateLimit, { global: false });

  registerOpsRoutes(app, deps);
  registerScanRoutes(app, {
    service: deps.service,
    store: deps.store,
    responsePageSize: deps.responsePageSize,
    rateLimit: scanCreationLimit,
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

/**
 * Ops-only server for a process that serves no API (ROLE=worker): liveness, readiness and metrics, so an
 * orchestrator can probe and scrape the worker like any other pod.
 */
export function buildOpsApp(deps: CommonDeps): FastifyInstance {
  const app = createServer(deps);
  registerErrorHandling(app);
  registerOpsRoutes(app, deps);
  return app;
}

function createServer(deps: CommonDeps): FastifyInstance {
  return Fastify({
    ...(deps.logger === false ? { logger: false } : { loggerInstance: deps.logger }),
    bodyLimit: 64 * 1024,
    trustProxy: deps.trustProxy ?? false,
  });
}

function registerOpsRoutes(app: FastifyInstance, deps: CommonDeps): void {
  registerHealthRoutes(app, deps.readiness);
  const { metrics } = deps;
  if (metrics !== undefined) {
    // Not exposed through the public reverse proxy (see deploy/Caddyfile.snippet); scrape it on the private port.
    app.get('/metrics', async (_request, reply) => reply.type(metrics.contentType).send(await metrics.metrics()));
  }
}

function methodsOf(method: string | readonly string[]): readonly string[] {
  return typeof method === 'string' ? [method] : method;
}

export function isGraphqlMutation(body: unknown): boolean {
  if (typeof body !== 'object' || body === null || !('query' in body) || typeof body.query !== 'string') return false;
  // Strip comments and string literals so neither can fake or hide the operation type.
  const source = body.query.replace(/#[^\n]*/g, '').replace(/"(?:[^"\\]|\\.)*"/g, '""');
  return /^\s*mutation\b/.test(source) || /\}\s*mutation\b/.test(source);
}
