import type { FastifyInstance } from 'fastify';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { ScanService } from '../../src/application/scan.service.js';
import type { SqliteScanStore } from '../../src/infrastructure/db/sqlite-scan.store.js';
import { buildApp } from '../../src/interfaces/http/app.js';
import { memoryStore } from '../helpers/index.js';

interface Page {
  scan: {
    criticalCount: number;
    stats: Record<string, number>;
    error: null;
    finishedAt: string;
    criticalVulnerabilities: { id: string; cursor: string }[];
  };
}

interface GqlResponse<T> {
  data: T | null;
  errors?: { message: string; extensions?: { code?: string } }[];
}

const stats = { reportBytes: 5_000_000_000, vulnerabilitiesScanned: 10, criticalCount: 3, malformedSkipped: 0, durationMs: 42, peakRssMb: 97 };
const v = (id: string) => ({
  vulnerabilityId: id, pkgName: 'lodash', installedVersion: '4.17.11', fixedVersion: '4.17.12', severity: 'CRITICAL' as const,
  title: 't', description: 'd', primaryUrl: 'u', target: 'package-lock.json', pkgType: 'npm', cvssScore: 9.8, publishedDate: '2024',
});

describe('GraphQL API', () => {
  let app: FastifyInstance;
  let store: SqliteScanStore;
  beforeEach(async () => {
    store = memoryStore();
    const service = new ScanService(store, { allowedHosts: ['github.com'], maxQueued: 100 });
    app = await buildApp({ service, store, readiness: () => Promise.resolve({}), logger: false, responsePageSize: 10, rateLimitPerMinute: 100, graphiql: true });
  });
  afterEach(async () => {
    await app.close();
    store.close();
  });

  async function gql<T>(query: string, variables: Record<string, unknown> = {}): Promise<GqlResponse<T>> {
    const res = await app.inject({ method: 'POST', url: '/graphql', payload: { query, variables } });
    return res.json<GqlResponse<T>>();
  }

  function finishedScan(ids: string[]): string {
    const scan = store.create(`https://github.com/a/${ids.join('-')}.git`);
    store.claimNext('w');
    store.appendVulnerabilities(scan.id, 'w', ids.map(v));
    store.markFinished(scan.id, 'w', stats);
    return scan.id;
  }

  it('startScan queues a scan', async () => {
    const res = await gql<{ startScan: { id: string; status: string; repoUrl: string; criticalVulnerabilities: null; attempt: number } }>(
      'mutation($u: String!) { startScan(repoUrl: $u) { id status repoUrl attempt criticalVulnerabilities { id } } }',
      { u: 'https://github.com/OWASP/NodeGoat' },
    );
    expect(res.errors).toBeUndefined();
    expect(res.data?.startScan).toMatchObject({ status: 'Queued', repoUrl: 'https://github.com/OWASP/NodeGoat.git', attempt: 0, criticalVulnerabilities: null });
  });

  it('supports the exact query shape from the brief', async () => {
    const id = finishedScan(['CVE-1']);
    const res = await gql<{ scan: unknown }>(`{ scan(id: "${id}") { id status criticalVulnerabilities { id pkgName } } }`);
    expect(res.data?.scan).toEqual({ id, status: 'Finished', criticalVulnerabilities: [{ id: 'CVE-1', pkgName: 'lodash' }] });
  });

  it('exposes stats, timestamps and paginates criticalVulnerabilities by cursor', async () => {
    const id = finishedScan(['A', 'B', 'C']);
    const q = `query($id: ID!, $after: ID) { scan(id: $id) {
      criticalCount createdAt startedAt finishedAt error { code }
      stats { reportBytes vulnerabilitiesScanned malformedSkipped durationMs peakRssMb }
      criticalVulnerabilities(first: 2, after: $after) { id cursor severity cvssScore target pkgType installedVersion fixedVersion }
    } }`;
    const p1 = await gql<Page>(q, { id });
    const { criticalCount: _omitted, ...gqlStats } = stats;
    expect(p1.data?.scan).toMatchObject({ criticalCount: 3, error: null, stats: gqlStats });
    expect(p1.data?.scan.finishedAt).toMatch(/^\d{4}-/);
    expect(p1.data?.scan.criticalVulnerabilities.map((x) => x.id)).toEqual(['A', 'B']);
    const p2 = await gql<Page>(q, { id, after: p1.data?.scan.criticalVulnerabilities[1]?.cursor });
    expect(p2.data?.scan.criticalVulnerabilities.map((x) => x.id)).toEqual(['C']);
  });

  it('returns null for an unknown scan and coded errors for bad input', async () => {
    expect((await gql<{ scan: null }>('{ scan(id: "00000000-0000-4000-8000-000000000000") { id } }')).data).toEqual({ scan: null });
    const badId = await gql('{ scan(id: "nope") { id } }');
    expect(badId.errors?.[0]?.extensions?.code).toBe('INVALID_SCAN_ID');
    const badUrl = await gql('mutation { startScan(repoUrl: "ssh://git@github.com/a/b") { id } }');
    expect(badUrl.errors?.[0]?.extensions?.code).toBe('INVALID_REPO_URL');
    const id = finishedScan(['Z']);
    const badCursor = await gql(`{ scan(id: "${id}") { criticalVulnerabilities(after: "bad") { id } } }`);
    expect(badCursor.errors?.[0]?.extensions?.code).toBe('INVALID_CURSOR');
  });

  it('shows the error only for failed scans and progress while scanning', async () => {
    const scan = store.create('https://github.com/a/failing.git');
    store.claimNext('w');
    store.heartbeat(scan.id, 'w', { phase: 'parsing', progressPct: 30 });
    const running = await gql<{ scan: unknown }>(`{ scan(id: "${scan.id}") { status phase progressPct error { code } criticalCount startedAt finishedAt } }`);
    expect(running.data?.scan).toMatchObject({ status: 'Scanning', phase: 'parsing', progressPct: 30, error: null, criticalCount: null, finishedAt: null });
    store.markFailed(scan.id, 'w', { code: 'DISK_FULL', message: 'disk' });
    const failed = await gql<{ scan: unknown }>(`{ scan(id: "${scan.id}") { status error { code message } } }`);
    expect(failed.data?.scan).toEqual({ status: 'Failed', error: { code: 'DISK_FULL', message: 'disk' } });
  });

  it('rejects overly deep queries', async () => {
    const res = await gql('{ scan(id: "00000000-0000-4000-8000-000000000000") { id } __schema { types { fields { type { fields { type { name } } } } } } }');
    expect(res.errors?.length).toBeGreaterThan(0);
  });
});
