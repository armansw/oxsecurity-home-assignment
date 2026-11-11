import { randomUUID } from 'node:crypto';
import type { Clock, TestRunStore } from '../../domain/ports.js';
import type { MemoryCounters, TestRun, TestRunEntry, TestRunId, TestRunItem } from '../../domain/test-run.js';
import { toScan, type ScanRow } from './sqlite-scan.store.js';
import type { Db } from './sqlite.js';

interface RunRow {
  id: string;
  created_at: number;
  cancelled_at: number | null;
  limit_mb: number | null;
  limit_hits_before: number | null;
  oom_kills_before: number | null;
}

interface ItemRow {
  position: number;
  scan_id: string;
  repo_url: string;
  language: string;
  size_mb: number;
}

const ACTIVE = `EXISTS (SELECT 1 FROM test_run_scans l JOIN scans s ON s.id = l.scan_id
                        WHERE l.run_id = test_runs.id AND s.status IN ('Queued','Scanning'))`;

/** SQLite adapter for {@link TestRunStore}; shares the database (and the scans queue) with SqliteScanStore. */
export class SqliteTestRunStore implements TestRunStore {
  private readonly stmt;

  constructor(
    private readonly db: Db,
    private readonly now: Clock = Date.now,
  ) {
    this.stmt = {
      insertRun: db.prepare<{ id: string; now: number; limitMb: number | null; limitHits: number | null; oomKills: number | null }>(
        `INSERT INTO test_runs (id, created_at, limit_mb, limit_hits_before, oom_kills_before)
         VALUES (@id, @now, @limitMb, @limitHits, @oomKills)`,
      ),
      insertScan: db.prepare<{ id: string; repoUrl: string; now: number }>(
        `INSERT INTO scans (id, repo_url, status, created_at, background) VALUES (@id, @repoUrl, 'Queued', @now, 1)`,
      ),
      insertItem: db.prepare<{ runId: string; position: number; scanId: string; repoUrl: string; language: string; sizeMb: number }>(
        `INSERT INTO test_run_scans (run_id, position, scan_id, repo_url, language, size_mb)
         VALUES (@runId, @position, @scanId, @repoUrl, @language, @sizeMb)`,
      ),
      runById: db.prepare<[string], RunRow>(`SELECT * FROM test_runs WHERE id = ?`),
      latest: db.prepare<[], RunRow>(`SELECT * FROM test_runs ORDER BY created_at DESC, rowid DESC LIMIT 1`),
      active: db.prepare<[], RunRow>(
        `SELECT * FROM test_runs WHERE cancelled_at IS NULL AND ${ACTIVE} ORDER BY created_at DESC LIMIT 1`,
      ),
      items: db.prepare<[string], ItemRow>(
        `SELECT position, scan_id, repo_url, language, size_mb FROM test_run_scans WHERE run_id = ? ORDER BY position`,
      ),
      scans: db.prepare<[string], ScanRow>(
        `SELECT s.* FROM test_run_scans l JOIN scans s ON s.id = l.scan_id WHERE l.run_id = ?`,
      ),
      recentDurations: db.prepare<[number], { d: number }>(
        `SELECT duration_ms AS d FROM scans
          WHERE background = 1 AND status = 'Finished' AND duration_ms IS NOT NULL
          ORDER BY finished_at DESC LIMIT ?`,
      ),
      markCancelled: db.prepare<{ id: string; now: number }>(
        `UPDATE test_runs SET cancelled_at = @now WHERE id = @id AND cancelled_at IS NULL`,
      ),
      cancelQueued: db.prepare<{ id: string; now: number }>(
        `UPDATE scans
            SET status = 'Failed', error_code = 'CANCELLED', error_message = 'The self-test run was cancelled',
                finished_at = @now
          WHERE status = 'Queued' AND id IN (SELECT scan_id FROM test_run_scans WHERE run_id = @id)`,
      ),
    };
  }

  create(input: { readonly entries: readonly TestRunEntry[]; readonly baseline: MemoryCounters | null }): TestRun {
    const id = randomUUID();
    const now = this.now();
    const { baseline } = input;
    this.db.transaction(() => {
      this.stmt.insertRun.run({
        id,
        now,
        limitMb: baseline?.limitMb ?? null,
        limitHits: baseline?.limitHits ?? null,
        oomKills: baseline?.oomKills ?? null,
      });
      input.entries.forEach((entry, position) => {
        const scanId = randomUUID();
        this.stmt.insertScan.run({ id: scanId, repoUrl: entry.repoUrl, now });
        this.stmt.insertItem.run({ runId: id, position, scanId, ...entry });
      });
    })();
    const run = this.findById(id as TestRunId);
    if (run === undefined) throw new Error(`Test run ${id} vanished after insert`);
    return run;
  }

  findById(id: TestRunId): TestRun | undefined {
    return this.load(this.stmt.runById.get(id));
  }

  findLatest(): TestRun | undefined {
    return this.load(this.stmt.latest.get());
  }

  findActive(): TestRun | undefined {
    return this.load(this.stmt.active.get());
  }

  cancel(id: TestRunId): number {
    return this.db.transaction(() => {
      const now = this.now();
      this.stmt.markCancelled.run({ id, now });
      return this.stmt.cancelQueued.run({ id, now }).changes;
    })();
  }

  recentScanDurationsMs(limit: number): number[] {
    return this.stmt.recentDurations.all(limit).map((r) => r.d);
  }

  private load(row: RunRow | undefined): TestRun | undefined {
    if (row === undefined) return undefined;
    const scans = new Map(this.stmt.scans.all(row.id).map((s) => [s.id, toScan(s)]));
    const items: TestRunItem[] = this.stmt.items.all(row.id).map((i) => ({
      position: i.position,
      scanId: i.scan_id,
      repoUrl: i.repo_url,
      language: i.language,
      sizeMb: i.size_mb,
      scan: scans.get(i.scan_id) ?? null,
    }));
    const baseline: MemoryCounters | null =
      row.limit_hits_before === null || row.oom_kills_before === null
        ? null
        : { limitMb: row.limit_mb, limitHits: row.limit_hits_before, oomKills: row.oom_kills_before };
    return {
      id: row.id as TestRunId,
      createdAt: new Date(row.created_at),
      cancelledAt: row.cancelled_at === null ? null : new Date(row.cancelled_at),
      baseline,
      items,
    };
  }
}
