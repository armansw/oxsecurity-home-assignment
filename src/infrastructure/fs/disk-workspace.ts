import { lstat, mkdir, readdir, rm, statfs } from 'node:fs/promises';
import path from 'node:path';
import { ScanError } from '../../domain/errors.js';
import type { Logger, ScanWorkspace, Workspace } from '../../domain/ports.js';
import { isScanId, type ScanId } from '../../domain/scan.js';
import { baseChildEnv, runCommand } from '../process/run-command.js';

const PREFIX = 'scan-';

/**
 * Per-scan working directories under WORK_DIR:
 *
 *   WORK_DIR/scan-<id>/repo/          the shallow clone (deleted as soon as Trivy finishes)
 *   WORK_DIR/scan-<id>/report.json    the Trivy report (deleted after parsing)
 *   WORK_DIR/scan-<id>/tmp/           TMPDIR for Trivy, so its scratch files are cleaned up with us
 *
 * WORK_DIR must be disk-backed: on tmpfs (or a K8s emptyDir with medium: Memory) every byte of a 500 MB
 * report would be charged to the container's memory cgroup — streaming would not save us from the OOM killer.
 */
export class DiskWorkspace implements Workspace {
  constructor(
    private readonly baseDir: string,
    private readonly minFreeBytes: number,
    private readonly log: Logger,
  ) {}

  async create(id: ScanId): Promise<ScanWorkspace> {
    const root = path.join(this.baseDir, `${PREFIX}${id}`);
    // A previous attempt may have been hard-killed; never reuse its leftovers.
    await rm(root, { recursive: true, force: true });
    const tmpDir = path.join(root, 'tmp');
    await mkdir(tmpDir, { recursive: true, mode: 0o700 });
    return { root, repoDir: path.join(root, 'repo'), reportPath: path.join(root, 'report.json'), tmpDir };
  }

  async freeBytes(): Promise<number> {
    await mkdir(this.baseDir, { recursive: true });
    const s = await statfs(this.baseDir);
    return s.bavail * s.bsize;
  }

  async assertFreeSpace(): Promise<void> {
    const free = await this.freeBytes();
    if (free < this.minFreeBytes) {
      const mb = (n: number): number => Math.floor(n / (1024 * 1024));
      throw new ScanError(
        'INSUFFICIENT_DISK',
        `Not enough free disk space to scan (${mb(free)} MB free, ${mb(this.minFreeBytes)} MB required)`,
        true,
      );
    }
  }

  /**
   * Deletes a file or directory tree with bounded memory.
   *
   * Directories are removed by an `rm -rf` child process, not by `fs.promises.rm`: Node's recursive delete
   * issues one concurrent unlink per directory entry, so a checkout with ~100k files in one directory
   * (microsoft/TypeScript's test baselines) spikes the service's own memory by ~100 MB. Found by the
   * large-repository corpus test, where it OOM-killed a 150 MB container.
   */
  async remove(target: string): Promise<void> {
    try {
      const info = await lstat(target).catch((err: unknown) => {
        if (typeof err === 'object' && err !== null && 'code' in err && err.code === 'ENOENT') return null; // already gone
        throw err;
      });
      if (info === null) return;
      if (!info.isDirectory()) {
        await rm(target, { force: true });
        return;
      }
      await runCommand('rm', {
        args: ['-rf', '--', target],
        env: baseChildEnv(),
        timeoutMs: 30 * 60 * 1000,
        signal: AbortSignal.timeout(31 * 60 * 1000),
        oomScoreAdj: 1000,
      });
    } catch (err) {
      // Never mask the scan's real outcome; the janitor retries orphans later.
      this.log.warn({ err, path: target }, 'workspace cleanup failed');
    }
  }

  async removeOrphans(isActive: (id: ScanId) => boolean): Promise<number> {
    let entries: string[];
    try {
      entries = await readdir(this.baseDir);
    } catch {
      return 0;
    }
    let removed = 0;
    for (const name of entries) {
      if (!name.startsWith(PREFIX)) continue; // e.g. .trivy-cache
      const id = name.slice(PREFIX.length);
      if (isScanId(id) && isActive(id)) continue;
      await this.remove(path.join(this.baseDir, name));
      removed += 1;
    }
    return removed;
  }
}
