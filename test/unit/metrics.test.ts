import { describe, expect, it } from 'vitest';
import { PrometheusMetrics } from '../../src/infrastructure/metrics/prometheus-metrics.js';
import { buildOpsApp, isGraphqlMutation } from '../../src/interfaces/http/app.js';
import { memoryStore } from '../helpers/index.js';

const stats = { reportBytes: 600 * 1024 * 1024, vulnerabilitiesScanned: 10, criticalCount: 7, malformedSkipped: 0, durationMs: 2000, peakMemoryMb: 97 };

describe('PrometheusMetrics', () => {
  it('records outcomes, peak RSS, report size, criticals and queue depth', async () => {
    const store = memoryStore();
    store.create('a');
    store.create('b');
    const m = new PrometheusMetrics(store, { collectDefaults: false });
    m.recordOutcome('finished', { durationMs: 2000, stats });
    m.recordOutcome('failed', { durationMs: 500, code: 'SCANNER_FAILED' });
    m.recordOutcome('retried', { durationMs: 100, code: 'DISK_FULL' });
    const text = await m.metrics();
    expect(m.contentType).toContain('text/plain');
    expect(text).toContain('code_guardian_scan_outcomes_total{outcome="finished",code="none"} 1');
    expect(text).toContain('code_guardian_scan_outcomes_total{outcome="failed",code="SCANNER_FAILED"} 1');
    expect(text).toContain('code_guardian_critical_vulnerabilities_total 7');
    expect(text).toContain('code_guardian_queue_depth 2');
    expect(text).toContain('code_guardian_scan_peak_memory_bytes_bucket{le="100663296"} 0'); // 96 MiB: 97 MB is above it
    expect(text).toContain('code_guardian_scan_peak_memory_bytes_bucket{le="134217728"} 1');
    expect(text).toContain('code_guardian_report_bytes_count 1');
    store.close();
  });

  it('collects default process metrics when enabled', async () => {
    const store = memoryStore();
    const text = await new PrometheusMetrics(store).metrics();
    expect(text).toContain('code_guardian_process_resident_memory_bytes');
    expect(text).toContain('code_guardian_nodejs_heap_size_used_bytes');
    store.close();
  });
});

describe('buildOpsApp (ROLE=worker)', () => {
  it('serves health, readiness and metrics but no API', async () => {
    const store = memoryStore();
    const metrics = new PrometheusMetrics(store, { collectDefaults: false });
    const app = buildOpsApp({ readiness: () => Promise.resolve({ worker: { ok: true, detail: 'w' } }), metrics, logger: false });
    expect((await app.inject({ method: 'GET', url: '/healthz' })).statusCode).toBe(200);
    expect((await app.inject({ method: 'GET', url: '/readyz' })).json()).toMatchObject({ status: 'ready' });
    const res = await app.inject({ method: 'GET', url: '/metrics' });
    expect(res.statusCode).toBe(200);
    expect(res.body).toContain('code_guardian_queue_depth 0');
    expect((await app.inject({ method: 'POST', url: '/api/scan', payload: {} })).statusCode).toBe(404);
    await app.close();
    store.close();
  });

  it('omits /metrics when no metrics source is configured', async () => {
    const app = buildOpsApp({ readiness: () => Promise.resolve({}), logger: false });
    expect((await app.inject({ method: 'GET', url: '/metrics' })).statusCode).toBe(404);
    await app.close();
  });
});

describe('isGraphqlMutation', () => {
  it.each([
    ['mutation { startScan(repoUrl: "x") { id } }', true],
    ['  mutation Start($u: String!) { startScan(repoUrl: $u) { id } }', true],
    ['query A { scan(id: "1") { id } } mutation B { startScan(repoUrl: "x") { id } }', true],
    ['{ scan(id: "1") { id } }', false],
    ['query Q { scan(id: "mutation { x }") { id } }', false],
    ['# mutation\n{ scan(id: "1") { id } }', false],
    ['query mutationLike { scan(id: "1") { id } }', false],
  ])('%s → %s', (query, expected) => {
    expect(isGraphqlMutation({ query })).toBe(expected);
  });

  it('is false for bodies without a query string', () => {
    for (const body of [undefined, null, 'x', {}, { query: 1 }]) expect(isGraphqlMutation(body)).toBe(false);
  });
});
