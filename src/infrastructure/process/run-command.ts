import { spawn } from 'node:child_process';
import { writeFile } from 'node:fs/promises';

export type CommandFailureKind = 'spawn' | 'exit' | 'timeout' | 'aborted';

export class CommandError extends Error {
  override readonly name = 'CommandError';

  constructor(
    readonly kind: CommandFailureKind,
    readonly command: string,
    readonly exitCode: number | null,
    readonly signal: NodeJS.Signals | null,
    /** Last few KiB of stderr — enough to classify, never unbounded. */
    readonly stderrTail: string,
    options?: ErrorOptions,
  ) {
    super(`${command} failed (${kind}${exitCode === null ? '' : `, exit ${exitCode}`}${signal ? `, ${signal}` : ''})`, options);
  }

  /** errno code of a spawn failure (e.g. ENOENT when the binary is missing). */
  get errno(): string | undefined {
    const cause: unknown = this.cause;
    return typeof cause === 'object' && cause !== null && 'code' in cause && typeof cause.code === 'string' ? cause.code : undefined;
  }
}

export interface RunOptions {
  readonly args: readonly string[];
  readonly cwd?: string;
  /** Exact environment for the child. The service's own env (tokens, secrets) is deliberately not inherited. */
  readonly env: Readonly<Record<string, string>>;
  readonly timeoutMs: number;
  readonly signal: AbortSignal;
  /** Bytes of stderr to retain. */
  readonly stderrLimit?: number;
  /** Delay between SIGTERM and SIGKILL. */
  readonly killGraceMs?: number;
  /** Capture up to this many bytes of stdout and resolve with it (default: stdout is discarded). */
  readonly captureStdout?: number;
  /**
   * Linux OOM-killer preference for the child (-1000..1000). 1000 makes the kernel kill this child first when
   * the container runs out of memory, so an oversized scan fails on its own instead of taking the service down.
   * Raising a child's score needs no privileges.
   */
  readonly oomScoreAdj?: number;
}

/**
 * Run an external binary safely:
 *  - `spawn` with an argument vector — never a shell, never string interpolation;
 *  - stdout discarded, stderr kept in a bounded tail (child output is a memory risk too);
 *  - own process group (`detached`), so timeout/abort kills the whole tree (git spawns git-remote-https);
 *  - SIGTERM, then SIGKILL after a grace period.
 */
export function runCommand(command: string, opts: RunOptions): Promise<string> {
  const limit = opts.stderrLimit ?? 8 * 1024;
  const killGraceMs = opts.killGraceMs ?? 5000;

  return new Promise<string>((resolve, reject) => {
    if (opts.signal.aborted) {
      reject(new CommandError('aborted', command, null, null, '', { cause: opts.signal.reason }));
      return;
    }

    let stderr = '';
    let stopReason: 'timeout' | 'aborted' | null = null;
    let killTimer: NodeJS.Timeout | undefined;

    const child = spawn(command, [...opts.args], {
      cwd: opts.cwd,
      env: opts.env,
      stdio: ['ignore', opts.captureStdout === undefined ? 'ignore' : 'pipe', 'pipe'],
      detached: true,
      shell: false,
    });

    if (opts.oomScoreAdj !== undefined && child.pid !== undefined && process.platform === 'linux') {
      writeFile(`/proc/${child.pid}/oom_score_adj`, String(opts.oomScoreAdj)).catch(() => {
        // Child already exited, or /proc is unavailable: nothing to protect.
      });
    }

    let stdout = '';
    const stdoutLimit = opts.captureStdout ?? 0;
    child.stdout?.setEncoding('utf8');
    child.stdout?.on('data', (chunk: string) => {
      if (stdout.length < stdoutLimit) stdout = (stdout + chunk).slice(0, stdoutLimit);
    });

    child.stderr?.setEncoding('utf8');
    child.stderr?.on('data', (chunk: string) => {
      stderr += chunk;
      if (stderr.length > limit) stderr = stderr.slice(-limit);
    });

    const killGroup = (sig: NodeJS.Signals): void => {
      if (child.pid === undefined) return;
      try {
        process.kill(-child.pid, sig);
      } catch {
        // Group already gone.
      }
    };

    const stop = (reason: 'timeout' | 'aborted'): void => {
      if (stopReason !== null) return;
      stopReason = reason;
      killGroup('SIGTERM');
      killTimer = setTimeout(() => {
        killGroup('SIGKILL');
      }, killGraceMs);
      killTimer.unref();
    };

    const timer = setTimeout(() => {
      stop('timeout');
    }, opts.timeoutMs);
    const onAbort = (): void => {
      stop('aborted');
    };
    opts.signal.addEventListener('abort', onAbort, { once: true });

    const cleanup = (): void => {
      clearTimeout(timer);
      clearTimeout(killTimer);
      opts.signal.removeEventListener('abort', onAbort);
    };

    child.once('error', (err) => {
      cleanup();
      reject(new CommandError('spawn', command, null, null, stderr, { cause: err }));
    });

    child.once('close', (code, signal) => {
      cleanup();
      if (stopReason !== null) {
        reject(new CommandError(stopReason, command, code, signal, stderr, stopReason === 'aborted' ? { cause: opts.signal.reason } : undefined));
      } else if (code === 0) {
        resolve(stdout);
      } else {
        reject(new CommandError('exit', command, code, signal, stderr));
      }
    });
  });
}

/** Minimal environment for children: enough to find binaries, nothing secret. */
export function baseChildEnv(extra: Readonly<Record<string, string | undefined>> = {}): Record<string, string> {
  const env: Record<string, string> = { PATH: process.env.PATH ?? '/usr/local/bin:/usr/bin:/bin' };
  if (process.env.HOME !== undefined) env.HOME = process.env.HOME;
  for (const [k, v] of Object.entries(extra)) if (v !== undefined) env[k] = v;
  return env;
}

export function isNoSpaceMessage(text: string): boolean {
  return /no space left on device|ENOSPC|disk quota exceeded/i.test(text);
}
