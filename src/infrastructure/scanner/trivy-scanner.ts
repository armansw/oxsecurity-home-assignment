import { mkdir, stat, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { ScanError } from '../../domain/errors.js';
import type { Scanner } from '../../domain/ports.js';
import { CommandError, baseChildEnv, isNoSpaceMessage, runCommand } from '../process/run-command.js';

export interface TrivyScannerOptions {
  readonly trivyBin: string;
  readonly timeoutMs: number;
  readonly cacheDir: string;
  /** Client/server mode (ADR-3): the vulnerability DB lives in the server, the client stays small. */
  readonly serverUrl?: string | undefined;
  readonly token?: string | undefined;
  /** Go soft memory limit for the Trivy process, e.g. `48MiB`. */
  readonly goMemLimit: string;
  /** Go GC target percentage (GOGC) for the Trivy process. */
  readonly goGc?: number;
  /**
   * `--offline-scan`: no registry lookups (e.g. Maven Central for parent POMs/BOMs). Deterministic and immune to
   * upstream rate limits, at the cost of not resolving versions inherited from remote POMs.
   */
  readonly offlineScan?: boolean;
  /**
   * Maven repository used in place of every remote repository, through a per-scan settings.xml mirror
   * (`mirrorOf=*`). Pointing it at a mirror of Maven Central avoids repo.maven.apache.org's 429 IP blocks.
   */
  readonly mavenMirror?: string | undefined;
}

/** A Maven settings.xml that routes every repository through one mirror (Trivy honours `<mirrors>`). */
export function mavenSettingsXml(mirrorUrl: string): string {
  const url = mirrorUrl.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  return `<settings><mirrors><mirror><id>code-guardian</id><mirrorOf>*</mirrorOf><url>${url}</url></mirror></mirrors></settings>\n`;
}

/**
 * Runs `trivy fs` against the cloned repository and writes the full JSON report to disk.
 *
 * Note: we intentionally do NOT pass `--severity CRITICAL` (ADR-4). In production you would push the filter
 * down to the scanner; this service is required to filter a huge report in its own stream pipeline.
 */
export class TrivyScanner implements Scanner {
  constructor(private readonly opts: TrivyScannerOptions) {}

  async scan(input: Parameters<Scanner['scan']>[0]): Promise<void> {
    const { sourceDir, reportPath, tmpDir, signal } = input;
    const timeoutSeconds = Math.ceil(this.opts.timeoutMs / 1000);
    const args = [
      'fs',
      '--scanners', 'vuln',
      '--format', 'json',
      '--output', reportPath,
      '--quiet',
      '--no-progress',
      '--parallel', '1',
      '--timeout', `${timeoutSeconds}s`,
      '--cache-dir', this.opts.cacheDir,
    ];
    if (this.opts.offlineScan === true) args.push('--offline-scan');
    if (this.opts.serverUrl !== undefined) {
      args.push('--server', this.opts.serverUrl);
      if (this.opts.token !== undefined) args.push('--token', this.opts.token);
    }
    args.push(sourceDir);

    // Trivy reads Maven mirrors from $HOME/.m2/settings.xml; a per-scan HOME inside the workspace keeps it isolated
    // and is deleted with the workspace.
    let home: string | undefined;
    if (this.opts.mavenMirror !== undefined) {
      home = path.join(tmpDir, 'home');
      await mkdir(path.join(home, '.m2'), { recursive: true });
      await writeFile(path.join(home, '.m2', 'settings.xml'), mavenSettingsXml(this.opts.mavenMirror));
    }

    try {
      await runCommand(this.opts.trivyBin, {
        args,
        // Trivy enforces its own --timeout; ours is the hard backstop.
        timeoutMs: this.opts.timeoutMs + 30_000,
        signal,
        // Under memory pressure the kernel kills Trivy, never the service (classified as SCANNER_KILLED).
        oomScoreAdj: 1000,
        env: baseChildEnv({ GOMEMLIMIT: this.opts.goMemLimit, GOGC: String(this.opts.goGc ?? 50), TMPDIR: tmpDir, HOME: home }),
      });
    } catch (err) {
      throw classifyTrivyError(err);
    }

    try {
      const s = await stat(reportPath);
      if (s.size === 0) throw new ScanError('REPORT_INVALID', 'Trivy produced an empty report');
    } catch (err) {
      if (err instanceof ScanError) throw err;
      throw new ScanError('REPORT_INVALID', 'Trivy exited successfully but produced no report', false, { cause: err });
    }
  }

  async checkAvailable(): Promise<{ ok: boolean; detail: string }> {
    try {
      await runCommand(this.opts.trivyBin, {
        args: ['--version'],
        timeoutMs: 10_000,
        signal: AbortSignal.timeout(15_000),
        env: baseChildEnv(),
      });
      return { ok: true, detail: this.opts.serverUrl === undefined ? 'trivy (standalone)' : 'trivy (client/server)' };
    } catch (err) {
      return { ok: false, detail: err instanceof Error ? err.message : String(err) };
    }
  }
}

export function classifyTrivyError(err: unknown): unknown {
  if (!(err instanceof CommandError)) return err;
  switch (err.kind) {
    case 'aborted':
      return err;
    case 'timeout':
      return new ScanError('SCAN_TIMEOUT', 'Trivy scan timed out', true, { cause: err });
    case 'spawn':
      return new ScanError('SCANNER_UNAVAILABLE', 'Trivy is not installed or not executable', false, { cause: err });
    case 'exit':
      if (isNoSpaceMessage(err.stderrTail)) {
        return new ScanError('DISK_FULL', 'Ran out of disk space while writing the Trivy report', true, { cause: err });
      }
      if (err.signal === 'SIGKILL') {
        // Not killed by us (that path is kind=timeout/aborted): almost always the kernel OOM killer.
        return new ScanError('SCANNER_KILLED', 'Trivy was killed by the system (likely out of memory)', true, { cause: err });
      }
      if (/\b429\b|too many requests/i.test(err.stderrTail)) {
        // e.g. Maven Central rate-limiting POM lookups. Retrying within the block window only burns attempts.
        const retryAfterS = Number(/Retry-After:\s*(\d+)/i.exec(err.stderrTail)?.[1] ?? 600);
        const retryAfterMs = Math.min(Math.max(retryAfterS, 60), 3600) * 1000;
        return new ScanError(
          'UPSTREAM_RATE_LIMITED',
          `A package registry rate-limited Trivy (HTTP 429; it asks to wait ${Math.round(retryAfterMs / 60_000)} min): ${trivyReason(err.stderrTail)}`,
          true,
          { cause: err, retryAfterMs },
        );
      }
      return new ScanError('SCANNER_FAILED', `Trivy exited with code ${String(err.exitCode)}: ${trivyReason(err.stderrTail)}`, true, {
        cause: err,
      });
  }
}

/**
 * The most useful line of Trivy's stderr, made safe for API clients: log prefix and timestamp removed, absolute
 * workspace paths stripped, length capped. The full stderr tail stays in the logs (CommandError.stderrTail).
 */
export function trivyReason(stderr: string): string {
  const lines = stderr.split('\n').map((l) => l.trim()).filter((l) => l.length > 0);
  const line = [...lines].reverse().find((l) => /\b(FATAL|ERROR)\b/.test(l)) ?? lines.at(-1) ?? 'no error output';
  return line
    .replace(/^\S+Z\s+(FATAL|ERROR|WARN|INFO)\s+/, '')
    .replace(/\/\S*\/scan-[0-9a-f-]{36}(\/repo)?\/?/g, '')
    .replace(/\s+/g, ' ')
    .slice(0, 300);
}
