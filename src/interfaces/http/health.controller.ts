import type { FastifyInstance } from 'fastify';

export interface ReadinessCheck {
  readonly ok: boolean;
  readonly detail: string;
}

export type ReadinessProbe = () => Promise<Record<string, ReadinessCheck>>;

const mb = (n: number): number => Math.round(n / (1024 * 1024));

export function registerHealthRoutes(app: FastifyInstance, readiness: ReadinessProbe): void {
  // Liveness: the process is up and the event loop answers. Memory is reported because it is the thing
  // this service is judged on.
  app.get('/healthz', () => {
    const m = process.memoryUsage();
    return {
      status: 'ok',
      uptimeS: Math.round(process.uptime()),
      memoryMb: { rss: mb(m.rss), heapUsed: mb(m.heapUsed), heapTotal: mb(m.heapTotal), external: mb(m.external) },
    };
  });

  // Readiness: dependencies are usable (database, scanner, disk). 503 takes the pod out of rotation.
  app.get('/readyz', async (_request, reply) => {
    const checks = await readiness();
    const ok = Object.values(checks).every((c) => c.ok);
    return reply.code(ok ? 200 : 503).send({ status: ok ? 'ready' : 'not_ready', checks });
  });
}
