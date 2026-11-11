import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import type { TestRunReport, TestRunService } from '../../application/test-run.service.js';
import type { ScanStatus } from '../../domain/scan.js';

const StartBody = z.object({ size: z.number().int().min(1) }).strict();
const RunParams = z.object({ testRunId: z.string() });

export interface TestRunControllerDeps {
  readonly testRuns: TestRunService;
  readonly rateLimit: { readonly max: number; readonly timeWindow: string };
}

export interface TestRunItemDto {
  readonly position: number;
  readonly repoUrl: string;
  readonly language: string;
  readonly sizeMb: number;
  readonly scanId: string;
  /** The scan's status, or `Expired` once the retention janitor has removed it. */
  readonly status: ScanStatus | 'Expired';
  readonly phase: string | null;
  readonly progressPct: number | null;
  readonly criticalCount: number | null;
  readonly vulnerabilitiesScanned: number | null;
  readonly reportBytes: number | null;
  readonly peakMemoryMb: number | null;
  readonly durationMs: number | null;
  readonly error: { readonly code: string; readonly message: string } | null;
}

export interface TestRunDto extends Omit<TestRunReport, 'run'> {
  readonly testRunId: string;
  readonly createdAt: string;
  readonly cancelledAt: string | null;
  readonly poolSize: number;
  readonly items: readonly TestRunItemDto[];
}

/** REST controller for the in-app self-test. Validation and mapping only; the work is in TestRunService. */
export function registerTestRunRoutes(app: FastifyInstance, deps: TestRunControllerDeps): void {
  const { testRuns } = deps;
  const view = (r: TestRunReport): TestRunDto => toTestRunDto(r, testRuns.poolSize);

  app.post('/api/test-runs', { bodyLimit: 1024, config: { rateLimit: { ...deps.rateLimit } } }, async (request, reply) => {
    const { size } = StartBody.parse(request.body);
    const report = await testRuns.start(size);
    return reply.code(202).header('location', `/api/test-runs/${report.run.id}`).send(view(report));
  });

  // Registered before /:testRunId so "latest" is not taken for an id.
  app.get('/api/test-runs/latest', async (_request, reply) => reply.header('cache-control', 'no-store').send(view(await testRuns.latest())));

  app.get('/api/test-runs/:testRunId', async (request, reply) => {
    const { testRunId } = RunParams.parse(request.params);
    return reply.header('cache-control', 'no-store').send(view(await testRuns.get(testRunId)));
  });

  app.post('/api/test-runs/:testRunId/cancel', async (request, reply) => {
    const { testRunId } = RunParams.parse(request.params);
    return reply.send(view(await testRuns.cancel(testRunId)));
  });
}

export function toTestRunDto(report: TestRunReport, poolSize: number): TestRunDto {
  const { run, ...rest } = report;
  return {
    testRunId: run.id,
    createdAt: run.createdAt.toISOString(),
    cancelledAt: run.cancelledAt === null ? null : run.cancelledAt.toISOString(),
    poolSize,
    ...rest,
    items: run.items.map((item) => {
      const scan = item.scan;
      return {
        position: item.position,
        repoUrl: item.repoUrl,
        language: item.language,
        sizeMb: item.sizeMb,
        scanId: item.scanId,
        status: scan === null ? 'Expired' : scan.status,
        phase: scan?.phase ?? null,
        progressPct: scan?.progressPct ?? null,
        criticalCount: scan?.stats?.criticalCount ?? null,
        vulnerabilitiesScanned: scan?.stats?.vulnerabilitiesScanned ?? null,
        reportBytes: scan?.stats?.reportBytes ?? null,
        peakMemoryMb: scan?.stats?.peakMemoryMb ?? null,
        durationMs: scan?.stats?.durationMs ?? null,
        error: scan?.error ?? null,
      };
    }),
  };
}
