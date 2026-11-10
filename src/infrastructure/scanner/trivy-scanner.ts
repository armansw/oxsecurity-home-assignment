import { stat } from 'node:fs/promises';
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
  /** Go soft memory limit for the Trivy process, e.g. `64MiB`. */
  readonly goMemLimit: string;
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
    if (this.opts.serverUrl !== undefined) {
      args.push('--server', this.opts.serverUrl);
      if (this.opts.token !== undefined) args.push('--token', this.opts.token);
    }
    args.push(sourceDir);

    try {
      await runCommand(this.opts.trivyBin, {
        args,
        // Trivy enforces its own --timeout; ours is the hard backstop.
        timeoutMs: this.opts.timeoutMs + 30_000,
        signal,
        env: baseChildEnv({ GOMEMLIMIT: this.opts.goMemLimit, TMPDIR: tmpDir }),
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
      return new ScanError('SCANNER_FAILED', `Trivy exited with code ${String(err.exitCode)}`, true, { cause: err });
  }
}
