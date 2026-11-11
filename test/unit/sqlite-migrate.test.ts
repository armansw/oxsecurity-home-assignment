import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, describe, expect, it } from 'vitest';
import Database from 'better-sqlite3';
import { migrate, openDatabase } from '../../src/infrastructure/db/sqlite.js';
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
});
