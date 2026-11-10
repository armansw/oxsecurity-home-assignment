import { Counter, Gauge, Histogram, Registry, collectDefaultMetrics } from 'prom-client';
import type { ScanMetrics, ScanOutcome, ScanStore } from '../../domain/ports.js';
import type { ScanStats } from '../../domain/scan.js';

const MB = 1024 * 1024;

/**
 * Prometheus adapter for {@link ScanMetrics}. Answers the operational questions this service raises:
 * how close do scans get to the memory limit, how big are reports, how long do scans take, why do they fail,
 * and how deep is the queue. Process metrics (heap, RSS, event-loop lag, GC) come from collectDefaultMetrics.
 */
export class PrometheusMetrics implements ScanMetrics {
  readonly registry = new Registry();
  private readonly outcomes: Counter<'outcome' | 'code'>;
  private readonly duration: Histogram<'outcome'>;
  private readonly peakMemory: Histogram;
  private readonly reportSize: Histogram;
  private readonly criticals: Counter;

  constructor(store: ScanStore, opts: { readonly collectDefaults?: boolean } = {}) {
    const registers = [this.registry];
    if (opts.collectDefaults ?? true) collectDefaultMetrics({ register: this.registry, prefix: 'code_guardian_' });

    this.outcomes = new Counter({
      name: 'code_guardian_scan_outcomes_total',
      help: 'Scan attempts by outcome and error code',
      labelNames: ['outcome', 'code'],
      registers,
    });
    this.duration = new Histogram({
      name: 'code_guardian_scan_duration_seconds',
      help: 'Wall-clock duration of a scan attempt (clone + scan + parse)',
      labelNames: ['outcome'],
      buckets: [1, 5, 15, 30, 60, 120, 300, 600, 1200],
      registers,
    });
    this.peakMemory = new Histogram({
      name: 'code_guardian_scan_peak_memory_bytes',
      help: 'Peak private (anonymous) memory of the service during a finished scan; compare with the container limit',
      buckets: [16, 32, 48, 64, 80, 96, 112, 128, 144, 160].map((n) => n * MB),
      registers,
    });
    this.reportSize = new Histogram({
      name: 'code_guardian_report_bytes',
      help: 'Size of the Trivy JSON report that was stream-parsed',
      buckets: [0.1, 1, 10, 50, 100, 250, 500, 1000, 2000].map((n) => n * MB),
      registers,
    });
    this.criticals = new Counter({
      name: 'code_guardian_critical_vulnerabilities_total',
      help: 'CRITICAL vulnerabilities stored across all finished scans',
      registers,
    });
    new Gauge({
      name: 'code_guardian_queue_depth',
      help: 'Scans waiting in the queue',
      registers,
      collect() {
        this.set(store.countQueued());
      },
    });
  }

  recordOutcome(outcome: ScanOutcome, info: { readonly durationMs: number; readonly code?: string; readonly stats?: ScanStats }): void {
    this.outcomes.inc({ outcome, code: info.code ?? 'none' });
    this.duration.observe({ outcome }, info.durationMs / 1000);
    if (info.stats) {
      this.peakMemory.observe(info.stats.peakMemoryMb * MB);
      this.reportSize.observe(info.stats.reportBytes);
      this.criticals.inc(info.stats.criticalCount);
    }
  }

  get contentType(): string {
    return this.registry.contentType;
  }

  metrics(): Promise<string> {
    return this.registry.metrics();
  }
}
