import { RequestError, ScanError } from '../domain/errors.js';
import type { TestRunStore } from '../domain/ports.js';
import type { MemoryCounters, TestRun, TestRunEntry, TestRunId } from '../domain/test-run.js';
import { normalizeRepoUrl } from '../infrastructure/git/repo-url.js';
import type { CorpusRepo } from './test-corpus.js';

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export interface TestRunServiceOptions {
  readonly corpus: readonly CorpusRepo[];
  readonly allowedHosts: readonly string[];
  /** Largest number of repositories one run may scan. */
  readonly maxSize: number;
  /** Corpus repositories larger than this are left out, so a run finishes in reasonable time. */
  readonly maxRepoMb: number;
  /** Current cgroup counters; null where they cannot be read. */
  readonly readCounters: () => Promise<MemoryCounters | null>;
  readonly wake?: () => void;
  readonly checkCapacity?: () => Promise<void>;
  /** Injected for deterministic tests. */
  readonly random?: () => number;
}

export type TestRunState = 'running' | 'finished' | 'cancelled';

export interface TestRunReport {
  readonly run: TestRun;
  readonly state: TestRunState;
  readonly counts: {
    readonly total: number;
    readonly queued: number;
    readonly scanning: number;
    readonly finished: number;
    readonly failed: number;
    /** Scans already removed by the retention janitor. */
    readonly expired: number;
  };
  readonly totals: { readonly criticalCount: number; readonly vulnerabilitiesScanned: number; readonly reportBytes: number };
  readonly memory: {
    readonly limitMb: number | null;
    /** Highest per-scan peak of private memory among the finished scans. */
    readonly maxScanPeakMb: number | null;
    /** Kernel counters since the run started; null when the cgroup cannot be read. */
    readonly limitHitsDuringRun: number | null;
    readonly oomKillsDuringRun: number | null;
    /** True when no scan came near the limit and the kernel never had to step in; null without a known limit. */
    readonly withinLimit: boolean | null;
  };
}

/**
 * The in-app self-test: scans a sample of the large-repository corpus through the normal queue (as background
 * scans, behind any user scan) and reports, from measurements, whether the service stayed inside its memory limit.
 * One run at a time, so a click cannot pile up work.
 */
export class TestRunService {
  private readonly pool: readonly CorpusRepo[];

  constructor(
    private readonly store: TestRunStore,
    private readonly opts: TestRunServiceOptions,
  ) {
    this.pool = opts.corpus.filter((r) => r.sizeMb <= opts.maxRepoMb && normalizeRepoUrl(r.url, opts.allowedHosts).ok);
  }

  /** How many repositories a run can sample from. */
  get poolSize(): number {
    return this.pool.length;
  }

  async start(size: number): Promise<TestRunReport> {
    if (!Number.isInteger(size) || size < 1 || size > this.opts.maxSize) {
      throw new RequestError('INVALID_TEST_RUN', `size must be an integer from 1 to ${String(this.opts.maxSize)}`);
    }
    const active = this.store.findActive();
    if (active !== undefined) throw new RequestError('TEST_RUN_ACTIVE', `Self-test ${active.id} is still running`);
    if (this.opts.checkCapacity) {
      try {
        await this.opts.checkCapacity();
      } catch (err) {
        if (err instanceof ScanError) throw new RequestError('NOT_READY', err.message);
        throw err;
      }
    }
    const baseline = await this.opts.readCounters();
    const run = this.store.create({ entries: this.sample(size), baseline });
    this.opts.wake?.();
    return this.report(run, baseline);
  }

  async get(rawId: string): Promise<TestRunReport> {
    if (!UUID_RE.test(rawId)) throw new RequestError('INVALID_TEST_RUN', 'testRunId must be a UUID');
    const run = this.store.findById(rawId as TestRunId);
    if (run === undefined) throw new RequestError('NOT_FOUND', `Self-test ${rawId} not found`);
    return this.report(run, await this.opts.readCounters());
  }

  async latest(): Promise<TestRunReport> {
    const run = this.store.findLatest();
    if (run === undefined) throw new RequestError('NOT_FOUND', 'No self-test has been run yet');
    return this.report(run, await this.opts.readCounters());
  }

  async cancel(rawId: string): Promise<TestRunReport> {
    const current = await this.get(rawId);
    this.store.cancel(current.run.id);
    return this.get(rawId);
  }

  /**
   * Random sample, spread across ecosystems: languages take turns, so even a small run covers several package
   * managers instead of, say, ten Go modules.
   */
  private sample(size: number): TestRunEntry[] {
    const random = this.opts.random ?? Math.random;
    const byLanguage = new Map<string, CorpusRepo[]>();
    for (const repo of this.pool) byLanguage.set(repo.language, [...(byLanguage.get(repo.language) ?? []), repo]);
    const queues = shuffle([...byLanguage.values()].map((repos) => shuffle(repos, random)), random);
    const picked: TestRunEntry[] = [];
    while (picked.length < size && queues.some((q) => q.length > 0)) {
      for (const queue of queues) {
        const repo = queue.pop();
        if (repo === undefined || picked.length >= size) continue;
        const normalized = normalizeRepoUrl(repo.url, this.opts.allowedHosts);
        if (normalized.ok) picked.push({ repoUrl: normalized.url, language: repo.language, sizeMb: repo.sizeMb });
      }
    }
    return picked;
  }

  private report(run: TestRun, now: MemoryCounters | null): TestRunReport {
    const scans = run.items.map((i) => i.scan);
    const count = (status: string): number => scans.filter((s) => s?.status === status).length;
    const finished = scans.flatMap((s) => (s?.stats ? [s.stats] : []));
    const counts = {
      total: run.items.length,
      queued: count('Queued'),
      scanning: count('Scanning'),
      finished: count('Finished'),
      failed: count('Failed'),
      expired: scans.filter((s) => s === null).length,
    };
    const state: TestRunState =
      counts.queued + counts.scanning > 0 ? 'running' : run.cancelledAt !== null ? 'cancelled' : 'finished';

    const limitMb = now?.limitMb ?? run.baseline?.limitMb ?? null;
    const maxScanPeakMb = finished.length === 0 ? null : Math.max(...finished.map((s) => s.peakMemoryMb));
    const base = run.baseline;
    const limitHitsDuringRun = base !== null && now !== null ? Math.max(0, now.limitHits - base.limitHits) : null;
    const oomKillsDuringRun = base !== null && now !== null ? Math.max(0, now.oomKills - base.oomKills) : null;
    const withinLimit =
      limitMb === null ? null : (maxScanPeakMb ?? 0) < limitMb && (limitHitsDuringRun ?? 0) === 0 && (oomKillsDuringRun ?? 0) === 0;

    return {
      run,
      state,
      counts,
      totals: {
        criticalCount: sum(finished.map((s) => s.criticalCount)),
        vulnerabilitiesScanned: sum(finished.map((s) => s.vulnerabilitiesScanned)),
        reportBytes: sum(finished.map((s) => s.reportBytes)),
      },
      memory: { limitMb, maxScanPeakMb, limitHitsDuringRun, oomKillsDuringRun, withinLimit },
    };
  }
}

function shuffle<T>(items: T[], random: () => number): T[] {
  for (let i = items.length - 1; i > 0; i -= 1) {
    const j = Math.floor(random() * (i + 1));
    const a = items[i] as T;
    items[i] = items[j] as T;
    items[j] = a;
  }
  return items;
}

function sum(values: readonly number[]): number {
  return values.reduce((a, b) => a + b, 0);
}
