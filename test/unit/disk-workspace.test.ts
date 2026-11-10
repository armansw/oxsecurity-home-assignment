import fs from 'node:fs';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import type { ScanId } from '../../src/domain/scan.js';
import { DiskWorkspace } from '../../src/infrastructure/fs/disk-workspace.js';
import { recordingLogger, tempDir } from '../helpers/index.js';

const ID_A = '11111111-1111-4111-8111-111111111111' as ScanId;
const ID_B = '22222222-2222-4222-8222-222222222222' as ScanId;

describe('DiskWorkspace', () => {
  let base: string;
  beforeEach(() => {
    base = path.join(tempDir(), 'work');
  });
  afterEach(() => {
    fs.rmSync(path.dirname(base), { recursive: true, force: true });
  });

  it('creates a fresh per-scan layout, wiping leftovers of a killed attempt', async () => {
    const ws = new DiskWorkspace(base, 0, recordingLogger());
    const first = await ws.create(ID_A);
    fs.writeFileSync(path.join(first.root, 'stale.txt'), 'x');
    const again = await ws.create(ID_A);
    expect(again).toEqual({
      root: path.join(base, `scan-${ID_A}`),
      repoDir: path.join(base, `scan-${ID_A}`, 'repo'),
      reportPath: path.join(base, `scan-${ID_A}`, 'report.json'),
      tmpDir: path.join(base, `scan-${ID_A}`, 'tmp'),
    });
    expect(fs.existsSync(path.join(again.root, 'stale.txt'))).toBe(false);
    expect(fs.existsSync(again.tmpDir)).toBe(true);
  });

  it('reports free space and enforces the floor', async () => {
    expect(await new DiskWorkspace(base, 0, recordingLogger()).freeBytes()).toBeGreaterThan(0);
    await expect(new DiskWorkspace(base, 0, recordingLogger()).assertFreeSpace()).resolves.toBeUndefined();
    await expect(new DiskWorkspace(base, Number.MAX_SAFE_INTEGER, recordingLogger()).assertFreeSpace()).rejects.toMatchObject({
      code: 'INSUFFICIENT_DISK',
      retryable: true,
    });
  });

  it('removes recursively and never throws', async () => {
    const log = recordingLogger();
    const ws = new DiskWorkspace(base, 0, log);
    const { root } = await ws.create(ID_A);
    await ws.remove(root);
    expect(fs.existsSync(root)).toBe(false);
    await ws.remove(path.join(base, 'does-not-exist'));
    await ws.remove('\0invalid');
    expect(log.entries.some((e) => e.msg === 'workspace cleanup failed')).toBe(true);
  });

  it('removes orphaned workspaces but keeps active ones and unrelated directories', async () => {
    const ws = new DiskWorkspace(base, 0, recordingLogger());
    await ws.create(ID_A);
    await ws.create(ID_B);
    fs.mkdirSync(path.join(base, 'scan-not-a-uuid'));
    fs.mkdirSync(path.join(base, '.trivy-cache'));
    expect(await ws.removeOrphans((id) => id === ID_A)).toBe(2);
    expect(fs.readdirSync(base).sort()).toEqual(['.trivy-cache', `scan-${ID_A}`]);
  });

  it('treats a missing base directory as nothing to clean', async () => {
    expect(await new DiskWorkspace(path.join(base, 'nope'), 0, recordingLogger()).removeOrphans(() => false)).toBe(0);
  });
});
