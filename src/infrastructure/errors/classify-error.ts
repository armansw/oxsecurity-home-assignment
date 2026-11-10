import { LeaseLostError, ScanError, ShutdownError } from '../../domain/errors.js';
import { CommandError, isNoSpaceMessage } from '../process/run-command.js';

export type FailureOutcome =
  | { readonly kind: 'shutdown' }
  | { readonly kind: 'lease-lost' }
  | { readonly kind: 'failure'; readonly error: ScanError };

/**
 * The single place where an arbitrary thrown value becomes a scan outcome. Adapters already throw ScanError
 * for failures they understand (git, Trivy, report parsing); this handles what can surface from anywhere —
 * disk exhaustion from fs or SQLite, aborts, lease loss — and treats everything else as INTERNAL.
 */
export function classifyFailure(err: unknown, signal: AbortSignal): FailureOutcome {
  if (err instanceof LeaseLostError || signal.reason instanceof LeaseLostError) return { kind: 'lease-lost' };
  if (err instanceof ShutdownError || signal.reason instanceof ShutdownError) return { kind: 'shutdown' };
  if (err instanceof ScanError) return { kind: 'failure', error: err };
  if (isDiskFull(err)) {
    return { kind: 'failure', error: new ScanError('DISK_FULL', 'The disk filled up while processing the scan', true, { cause: err }) };
  }
  if (err instanceof CommandError && err.kind === 'aborted') return { kind: 'shutdown' };
  return { kind: 'failure', error: new ScanError('INTERNAL', 'Unexpected error while processing the scan', false, { cause: err }) };
}

function isDiskFull(err: unknown): boolean {
  if (typeof err !== 'object' || err === null) return false;
  const code = 'code' in err ? err.code : undefined;
  if (code === 'ENOSPC' || code === 'EDQUOT' || code === 'SQLITE_FULL') return true;
  if (err instanceof Error && isNoSpaceMessage(err.message)) return true;
  return 'cause' in err && err.cause !== err && isDiskFull(err.cause);
}

/** Exponential backoff with ±20 % jitter: base, 4×base, 16×base … */
export function retryDelayMs(attempt: number, baseMs: number, random: () => number = Math.random): number {
  const exp = baseMs * 4 ** Math.max(0, attempt - 1);
  return Math.round(exp * (0.8 + 0.4 * random()));
}
