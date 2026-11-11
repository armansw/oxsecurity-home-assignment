import fs from 'node:fs';
import path from 'node:path';
import Database from 'better-sqlite3';

export type Db = Database.Database;

const MIGRATIONS: readonly string[] = [
  `
  CREATE TABLE scans (
    id                TEXT PRIMARY KEY,
    repo_url          TEXT    NOT NULL,
    status            TEXT    NOT NULL CHECK (status IN ('Queued','Scanning','Finished','Failed')),
    phase             TEXT    CHECK (phase IN ('cloning','scanning','parsing')),
    progress_pct      INTEGER,
    attempts          INTEGER NOT NULL DEFAULT 0,
    run_after         INTEGER NOT NULL DEFAULT 0,
    locked_by         TEXT,
    heartbeat_at      INTEGER,
    report_bytes      INTEGER,
    vulns_scanned     INTEGER,
    critical_count    INTEGER,
    malformed_skipped INTEGER,
    duration_ms       INTEGER,
    peak_rss_mb       INTEGER,
    error_code        TEXT,
    error_message     TEXT,
    created_at        INTEGER NOT NULL,
    started_at        INTEGER,
    finished_at       INTEGER
  );
  CREATE INDEX idx_scans_claim  ON scans (status, run_after, created_at);
  CREATE INDEX idx_scans_repo   ON scans (repo_url, status);
  CREATE INDEX idx_scans_lease  ON scans (status, heartbeat_at);

  CREATE TABLE vulnerabilities (
    row_id            INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id           TEXT    NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    vulnerability_id  TEXT    NOT NULL,
    pkg_name          TEXT    NOT NULL,
    installed_version TEXT,
    fixed_version     TEXT,
    title             TEXT,
    description       TEXT,
    primary_url       TEXT,
    target            TEXT    NOT NULL,
    pkg_type          TEXT,
    cvss_score        REAL,
    published_date    TEXT
  );
  CREATE INDEX idx_vulns_scan ON vulnerabilities (scan_id, row_id);
  `,
  `ALTER TABLE scans ADD COLUMN commit_sha TEXT;`,
  // v3: the in-app self-test. Its scans are `background` so a user's own scan is always claimed first and the
  // MAX_QUEUED cap keeps meaning "user scans waiting".
  `
  ALTER TABLE scans ADD COLUMN background INTEGER NOT NULL DEFAULT 0;
  DROP INDEX idx_scans_claim;
  CREATE INDEX idx_scans_claim ON scans (status, background, run_after, created_at);

  CREATE TABLE test_runs (
    id                TEXT PRIMARY KEY,
    created_at        INTEGER NOT NULL,
    cancelled_at      INTEGER,
    limit_mb          INTEGER,
    limit_hits_before INTEGER,
    oom_kills_before  INTEGER
  );
  CREATE INDEX idx_test_runs_created ON test_runs (created_at);

  CREATE TABLE test_run_scans (
    run_id   TEXT    NOT NULL REFERENCES test_runs(id) ON DELETE CASCADE,
    position INTEGER NOT NULL,
    scan_id  TEXT    NOT NULL,
    repo_url TEXT    NOT NULL,
    language TEXT    NOT NULL,
    size_mb  INTEGER NOT NULL,
    PRIMARY KEY (run_id, position)
  );
  CREATE INDEX idx_test_run_scans_scan ON test_run_scans (scan_id);
  `,
];

/**
 * Open (and migrate) the database. WAL lets the API read while the worker writes; the page cache is
 * capped at 4 MB so SQLite's off-heap memory stays small and predictable inside the container.
 */
export function openDatabase(file: string): Db {
  if (file !== ':memory:') fs.mkdirSync(path.dirname(path.resolve(file)), { recursive: true });
  const db = new Database(file);
  db.pragma('journal_mode = WAL');
  db.pragma('synchronous = NORMAL');
  db.pragma('foreign_keys = ON');
  db.pragma('busy_timeout = 5000');
  db.pragma('cache_size = -4000');
  migrate(db);
  return db;
}

function migrate(db: Db): void {
  const current = Number(db.pragma('user_version', { simple: true }));
  for (let v = current; v < MIGRATIONS.length; v += 1) {
    const sql = MIGRATIONS[v];
    if (sql === undefined) break;
    db.transaction(() => {
      db.exec(sql);
      db.pragma(`user_version = ${v + 1}`);
    })();
  }
}
