import { randomUUID } from 'node:crypto';
import { LeaseLostError, isScanErrorCode } from '../../domain/errors.js';
import type { Clock, ScanStore } from '../../domain/ports.js';
import {
  SCAN_PHASES,
  SCAN_STATUSES,
  type Scan,
  type ScanFailure,
  type ScanId,
  type ScanPhase,
  type ScanStats,
  type ScanStatus,
} from '../../domain/scan.js';
import type { CriticalVulnerability, StoredVulnerability } from '../../domain/vulnerability.js';
import type { Db } from './sqlite.js';

interface ScanRow {
  id: string;
  repo_url: string;
  status: string;
  phase: string | null;
  progress_pct: number | null;
  attempts: number;
  report_bytes: number | null;
  vulns_scanned: number | null;
  critical_count: number | null;
  malformed_skipped: number | null;
  duration_ms: number | null;
  peak_rss_mb: number | null;
  error_code: string | null;
  error_message: string | null;
  created_at: number;
  started_at: number | null;
  finished_at: number | null;
}

interface VulnerabilityRow {
  row_id: number;
  vulnerability_id: string;
  pkg_name: string;
  installed_version: string | null;
  fixed_version: string | null;
  title: string | null;
  description: string | null;
  primary_url: string | null;
  target: string;
  pkg_type: string | null;
  cvss_score: number | null;
  published_date: string | null;
}

const LEASE = `id = @id AND locked_by = @workerId AND status = 'Scanning'`;

/**
 * SQLite adapter for {@link ScanStore}. The `scans` table is both the state store and the job queue
 * (ADR-1): `status = 'Queued'` rows are the queue, `locked_by` + `heartbeat_at` form a lease.
 */
export class SqliteScanStore implements ScanStore {
  private readonly stmt;

  constructor(
    private readonly db: Db,
    private readonly now: Clock = Date.now,
  ) {
    this.stmt = {
      insert: db.prepare<{ id: string; repoUrl: string; now: number }>(
        `INSERT INTO scans (id, repo_url, status, created_at) VALUES (@id, @repoUrl, 'Queued', @now)`,
      ),
      byId: db.prepare<[string], ScanRow>(`SELECT * FROM scans WHERE id = ?`),
      activeByRepo: db.prepare<[string], ScanRow>(
        `SELECT * FROM scans WHERE repo_url = ? AND status IN ('Queued','Scanning') ORDER BY created_at LIMIT 1`,
      ),
      countQueued: db.prepare<[], { n: number }>(`SELECT COUNT(*) AS n FROM scans WHERE status = 'Queued'`),
      // Single statement: SQLite serialises writers, so two workers can never claim the same row.
      claim: db.prepare<{ workerId: string; now: number }, ScanRow>(
        `UPDATE scans
            SET status = 'Scanning', attempts = attempts + 1, locked_by = @workerId, heartbeat_at = @now,
                started_at = COALESCE(started_at, @now), phase = 'cloning', progress_pct = NULL,
                error_code = NULL, error_message = NULL
          WHERE id = (SELECT id FROM scans WHERE status = 'Queued' AND run_after <= @now
                      ORDER BY created_at, rowid LIMIT 1)
          RETURNING *`,
      ),
      heartbeat: db.prepare<{ id: string; workerId: string; now: number; phase: string | null; setProgress: number; progress: number | null }>(
        `UPDATE scans
            SET heartbeat_at = @now,
                phase = COALESCE(@phase, phase),
                progress_pct = CASE WHEN @setProgress = 1 THEN @progress ELSE progress_pct END
          WHERE ${LEASE}`,
      ),
      holdsLease: db.prepare<{ id: string; workerId: string }, { one: number }>(`SELECT 1 AS one FROM scans WHERE ${LEASE}`),
      clearVulns: db.prepare<[string]>(`DELETE FROM vulnerabilities WHERE scan_id = ?`),
      insertVuln: db.prepare<Record<string, string | number | null>>(
        `INSERT INTO vulnerabilities
           (scan_id, vulnerability_id, pkg_name, installed_version, fixed_version, title, description,
            primary_url, target, pkg_type, cvss_score, published_date)
         VALUES
           (@scanId, @vulnerabilityId, @pkgName, @installedVersion, @fixedVersion, @title, @description,
            @primaryUrl, @target, @pkgType, @cvssScore, @publishedDate)`,
      ),
      finish: db.prepare<Record<string, string | number>>(
        `UPDATE scans
            SET status = 'Finished', phase = NULL, progress_pct = 100, locked_by = NULL, heartbeat_at = NULL,
                report_bytes = @reportBytes, vulns_scanned = @vulnerabilitiesScanned,
                critical_count = @criticalCount, malformed_skipped = @malformedSkipped,
                duration_ms = @durationMs, peak_rss_mb = @peakRssMb, finished_at = @now
          WHERE ${LEASE}`,
      ),
      fail: db.prepare<{ id: string; workerId: string; code: string; message: string; now: number }>(
        `UPDATE scans
            SET status = 'Failed', phase = NULL, progress_pct = NULL, locked_by = NULL, heartbeat_at = NULL,
                error_code = @code, error_message = @message, finished_at = @now
          WHERE ${LEASE}`,
      ),
      requeue: db.prepare<{ id: string; workerId: string; runAfter: number; refund: number }>(
        `UPDATE scans
            SET status = 'Queued', phase = NULL, progress_pct = NULL, locked_by = NULL, heartbeat_at = NULL,
                run_after = @runAfter, attempts = attempts - @refund
          WHERE ${LEASE}`,
      ),
      failStale: db.prepare<{ staleBefore: number; maxAttempts: number; now: number }>(
        `UPDATE scans
            SET status = 'Failed', phase = NULL, progress_pct = NULL, locked_by = NULL, heartbeat_at = NULL,
                error_code = 'WORKER_CRASHED',
                error_message = 'The worker stopped responding (crash or out-of-memory kill) and the retry limit was reached',
                finished_at = @now
          WHERE status = 'Scanning' AND heartbeat_at < @staleBefore AND attempts >= @maxAttempts`,
      ),
      requeueStale: db.prepare<{ staleBefore: number; maxAttempts: number; now: number }>(
        `UPDATE scans
            SET status = 'Queued', phase = NULL, progress_pct = NULL, locked_by = NULL, heartbeat_at = NULL,
                run_after = @now
          WHERE status = 'Scanning' AND heartbeat_at < @staleBefore AND attempts < @maxAttempts`,
      ),
      isScanning: db.prepare<[string], { one: number }>(`SELECT 1 AS one FROM scans WHERE id = ? AND status = 'Scanning'`),
      listVulns: db.prepare<{ id: string; after: number; limit: number }, VulnerabilityRow>(
        `SELECT row_id, vulnerability_id, pkg_name, installed_version, fixed_version, title, description,
                primary_url, target, pkg_type, cvss_score, published_date
           FROM vulnerabilities
          WHERE scan_id = @id AND row_id > @after
          ORDER BY row_id
          LIMIT @limit`,
      ),
      purge: db.prepare<[number]>(`DELETE FROM scans WHERE status IN ('Finished','Failed') AND finished_at < ?`),
    };
  }

  create(repoUrl: string): Scan {
    const id = randomUUID();
    this.stmt.insert.run({ id, repoUrl, now: this.now() });
    return this.mustFind(id);
  }

  findById(id: ScanId): Scan | undefined {
    const row = this.stmt.byId.get(id);
    return row === undefined ? undefined : toScan(row);
  }

  findActiveByRepo(repoUrl: string): Scan | undefined {
    const row = this.stmt.activeByRepo.get(repoUrl);
    return row === undefined ? undefined : toScan(row);
  }

  countQueued(): number {
    return this.stmt.countQueued.get()?.n ?? 0;
  }

  claimNext(workerId: string): Scan | undefined {
    const row = this.stmt.claim.get({ workerId, now: this.now() });
    return row === undefined ? undefined : toScan(row);
  }

  heartbeat(id: ScanId, workerId: string, patch: { phase?: ScanPhase; progressPct?: number | null } = {}): boolean {
    const setProgress = patch.progressPct === undefined ? 0 : 1;
    const res = this.stmt.heartbeat.run({
      id,
      workerId,
      now: this.now(),
      phase: patch.phase ?? null,
      setProgress,
      progress: patch.progressPct ?? null,
    });
    return res.changes === 1;
  }

  clearVulnerabilities(id: ScanId, workerId: string): void {
    this.db.transaction(() => {
      this.assertLease(id, workerId);
      this.stmt.clearVulns.run(id);
    })();
  }

  appendVulnerabilities(id: ScanId, workerId: string, batch: readonly CriticalVulnerability[]): void {
    if (batch.length === 0) return;
    // One transaction per batch: ~500 rows per fsync instead of one, and the lease check is atomic with
    // the insert, so a reclaimed scan can never receive rows from its previous owner.
    this.db.transaction(() => {
      this.assertLease(id, workerId);
      for (const v of batch) {
        this.stmt.insertVuln.run({
          scanId: id,
          vulnerabilityId: v.vulnerabilityId,
          pkgName: v.pkgName,
          installedVersion: v.installedVersion,
          fixedVersion: v.fixedVersion,
          title: v.title,
          description: v.description,
          primaryUrl: v.primaryUrl,
          target: v.target,
          pkgType: v.pkgType,
          cvssScore: v.cvssScore,
          publishedDate: v.publishedDate,
        });
      }
    })();
  }

  markFinished(id: ScanId, workerId: string, stats: ScanStats): boolean {
    const res = this.stmt.finish.run({ id, workerId, now: this.now(), ...stats });
    return res.changes === 1;
  }

  markFailed(id: ScanId, workerId: string, failure: ScanFailure): boolean {
    return this.db.transaction(() => {
      const res = this.stmt.fail.run({ id, workerId, code: failure.code, message: failure.message, now: this.now() });
      // Partial results of a failed attempt are never visible (only Finished scans expose rows); drop them.
      if (res.changes === 1) this.stmt.clearVulns.run(id);
      return res.changes === 1;
    })();
  }

  requeue(id: ScanId, workerId: string, opts: { runAfter: number; refundAttempt: boolean }): boolean {
    const res = this.stmt.requeue.run({ id, workerId, runAfter: opts.runAfter, refund: opts.refundAttempt ? 1 : 0 });
    return res.changes === 1;
  }

  reclaimStale(staleBefore: number, maxAttempts: number): { requeued: number; failed: number } {
    return this.db.transaction(() => {
      const params = { staleBefore, maxAttempts, now: this.now() };
      const failed = this.stmt.failStale.run(params).changes;
      const requeued = this.stmt.requeueStale.run(params).changes;
      return { requeued, failed };
    })();
  }

  isScanning(id: ScanId): boolean {
    return this.stmt.isScanning.get(id) !== undefined;
  }

  listVulnerabilities(id: ScanId, opts: { afterRowId: number; limit: number }): StoredVulnerability[] {
    return this.stmt.listVulns.all({ id, after: opts.afterRowId, limit: opts.limit }).map(toVulnerability);
  }

  purgeFinishedBefore(cutoff: number): number {
    return this.stmt.purge.run(cutoff).changes;
  }

  close(): void {
    if (this.db.open) this.db.close();
  }

  private assertLease(id: ScanId, workerId: string): void {
    if (this.stmt.holdsLease.get({ id, workerId }) === undefined) throw new LeaseLostError(id);
  }

  private mustFind(id: string): Scan {
    const row = this.stmt.byId.get(id);
    if (row === undefined) throw new Error(`Scan ${id} vanished after insert`);
    return toScan(row);
  }
}

function toScan(row: ScanRow): Scan {
  return {
    id: row.id as ScanId,
    repoUrl: row.repo_url,
    status: parseStatus(row.status),
    phase: row.phase === null ? null : parsePhase(row.phase),
    progressPct: row.progress_pct,
    attempts: row.attempts,
    stats:
      row.status === 'Finished'
        ? {
            reportBytes: row.report_bytes ?? 0,
            vulnerabilitiesScanned: row.vulns_scanned ?? 0,
            criticalCount: row.critical_count ?? 0,
            malformedSkipped: row.malformed_skipped ?? 0,
            durationMs: row.duration_ms ?? 0,
            peakRssMb: row.peak_rss_mb ?? 0,
          }
        : null,
    error:
      row.error_code !== null
        ? { code: isScanErrorCode(row.error_code) ? row.error_code : 'INTERNAL', message: row.error_message ?? '' }
        : null,
    createdAt: new Date(row.created_at),
    startedAt: row.started_at === null ? null : new Date(row.started_at),
    finishedAt: row.finished_at === null ? null : new Date(row.finished_at),
  };
}

function toVulnerability(row: VulnerabilityRow): StoredVulnerability {
  return {
    rowId: row.row_id,
    vulnerabilityId: row.vulnerability_id,
    pkgName: row.pkg_name,
    installedVersion: row.installed_version,
    fixedVersion: row.fixed_version,
    severity: 'CRITICAL',
    title: row.title,
    description: row.description,
    primaryUrl: row.primary_url,
    target: row.target,
    pkgType: row.pkg_type,
    cvssScore: row.cvss_score,
    publishedDate: row.published_date,
  };
}

function parseStatus(value: string): ScanStatus {
  const found = SCAN_STATUSES.find((s) => s === value);
  if (found === undefined) throw new Error(`Corrupt scan row: unknown status '${value}'`);
  return found;
}

function parsePhase(value: string): ScanPhase {
  const found = SCAN_PHASES.find((p) => p === value);
  if (found === undefined) throw new Error(`Corrupt scan row: unknown phase '${value}'`);
  return found;
}
