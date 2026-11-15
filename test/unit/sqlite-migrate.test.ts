import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, describe, expect, it } from 'vitest';
import Database from 'better-sqlite3';
import { migrate, openDatabase, retryWhileBusy } from '../../src/infrastructure/db/sqlite.js';
import { tempDir } from '../helpers/index.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const TSX = path.join(ROOT, 'node_modules/.bin/tsx');
const SQLITE = path.join(ROOT, 'src/infrastructure/db/sqlite.ts');

function openInChild(file: string): Promise<{ code: number | null; stderr: string }> {
  return new Promise((resolve) => {
    const child = spawn(
      TSX,
      ['-e', `import(${JSON.stringify(SQLITE)}).then((m) => { m.openDatabase(${JSON.stringify(file)}).close(); })`],
      { stdio: ['ignore', 'ignore', 'pipe'] },
    );
    let stderr = '';
    child.stderr.on('data', (d: Buffer) => (stderr += d.toString()));
    child.on('close', (code) => {
      resolve({ code, stderr });
    });
  });
}

describe('migrations', () => {
  let dir: string | undefined;
  afterEach(() => {
    if (dir) fs.rmSync(dir, { recursive: true, force: true });
  });

  it('are idempotent on reopen', () => {
    dir = tempDir();
    const file = path.join(dir, 'a.db');
    openDatabase(file).close();
    const db = openDatabase(file);
    expect(Number(db.pragma('user_version', { simple: true }))).toBeGreaterThanOrEqual(3);
    db.close();
  });

  // Split mode: the API and the worker open the same fresh database at once. Both used to see version 0 and the
  // loser crashed with "table scans already exists".
  it('survive several processes migrating one fresh database at the same time', async () => {
    dir = tempDir();
    const file = path.join(dir, 'race.db');
    // Hold the write lock while the children start, so each one reads the schema version before anyone has
    // migrated; then migrate here and release. A child that trusted its early read would now re-run v1 and crash.
    const holder = new Database(file);
    holder.pragma('journal_mode = WAL');
    holder.exec('BEGIN IMMEDIATE');
    const children = Array.from({ length: 3 }, () => openInChild(file));
    await new Promise((r) => setTimeout(r, 3000));
    migrate(holder);
    holder.exec('COMMIT');
    holder.close();

    const results = await Promise.all(children);
    expect(results.map((r) => r.stderr)).toEqual(['', '', '']);
    expect(results.map((r) => r.code)).toEqual([0, 0, 0]);
    const db = openDatabase(file);
    expect(db.prepare(`SELECT COUNT(*) AS n FROM sqlite_master WHERE name = 'test_runs'`).get()).toEqual({ n: 1 });
    db.close();
  }, 30_000);

  // Split mode, one step earlier: switching a fresh database to WAL needs an exclusive lock held by someone else.
  it('wait for the WAL switch while another process holds the fresh database', async () => {
    dir = tempDir();
    const file = path.join(dir, 'wal.db');
    const holder = new Database(file);
    holder.exec('CREATE TABLE t (x)'); // still the default rollback journal: nobody has switched to WAL yet
    holder.exec('BEGIN EXCLUSIVE');
    holder.exec('INSERT INTO t VALUES (1)');
    const children = Array.from({ length: 3 }, () => openInChild(file));
    await new Promise((r) => setTimeout(r, 2000));
    holder.exec('COMMIT');
    holder.close();

    const results = await Promise.all(children);
    expect(results.map((r) => r.stderr)).toEqual(['', '', '']);
    expect(results.map((r) => r.code)).toEqual([0, 0, 0]);
  }, 30_000);
});

// SQLite sometimes answers SQLITE_BUSY at once, skipping the busy handler (deadlock avoidance, WAL recovery); in CI
// run 43060609329 that killed the split-mode worker on open with "database is locked". Opening now retries.
describe('retryWhileBusy', () => {
  const busy = (code = 'SQLITE_BUSY'): Error => Object.assign(new Error('database is locked'), { code });

  it('retries SQLITE_BUSY and its extended codes until the step succeeds', () => {
    const codes = ['SQLITE_BUSY', 'SQLITE_BUSY_RECOVERY', 'SQLITE_BUSY_SNAPSHOT'];
    let calls = 0;
    const result = retryWhileBusy(
      () => {
        const code = codes[calls];
        calls += 1;
        if (code !== undefined) throw busy(code);
        return 'opened';
      },
      1000,
      1,
    );
    expect(result).toBe('opened');
    expect(calls).toBe(4);
  });

  it('rethrows other errors at once', () => {
    let calls = 0;
    const fail = (): never => {
      calls += 1;
      throw Object.assign(new Error('no such table'), { code: 'SQLITE_ERROR' });
    };
    expect(() => retryWhileBusy(fail, 1000, 1)).toThrow('no such table');
    expect(calls).toBe(1);
  });

  it('gives up after the deadline with the last error', () => {
    expect(() =>
      retryWhileBusy(
        () => {
          throw busy();
        },
        30,
        5,
      ),
    ).toThrow('database is locked');
  });
});
