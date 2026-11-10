import { describe, expect, it } from 'vitest';
import { LeaseLostError, ScanError, ShutdownError, isScanErrorCode } from '../../src/domain/errors.js';
import { classifyFailure, retryDelayMs } from '../../src/infrastructure/errors/classify-error.js';
import { CommandError } from '../../src/infrastructure/process/run-command.js';
import { enospc } from '../helpers/index.js';

const live = new AbortController().signal;
const abortedWith = (reason: unknown) => {
  const c = new AbortController();
  c.abort(reason);
  return c.signal;
};

describe('classifyFailure', () => {
  it('recognises lease loss, from the error or the abort reason', () => {
    expect(classifyFailure(new LeaseLostError('x'), live)).toEqual({ kind: 'lease-lost' });
    expect(classifyFailure(new Error('stream destroyed'), abortedWith(new LeaseLostError('x')))).toEqual({ kind: 'lease-lost' });
  });

  it('recognises shutdown, from the error, the abort reason or an aborted child', () => {
    expect(classifyFailure(new ShutdownError(), live)).toEqual({ kind: 'shutdown' });
    expect(classifyFailure(new Error('x'), abortedWith(new ShutdownError()))).toEqual({ kind: 'shutdown' });
    expect(classifyFailure(new CommandError('aborted', 'git', null, null, ''), live)).toEqual({ kind: 'shutdown' });
  });

  it('passes ScanErrors through', () => {
    const e = new ScanError('SCANNER_FAILED', 'x', true);
    expect(classifyFailure(e, live)).toEqual({ kind: 'failure', error: e });
  });

  it.each([
    ['ENOSPC errno', enospc()],
    ['EDQUOT errno', Object.assign(new Error('quota'), { code: 'EDQUOT' })],
    ['SQLITE_FULL', Object.assign(new Error('database or disk is full'), { code: 'SQLITE_FULL' })],
    ['message only', new Error('write failed: No space left on device')],
    ['nested cause', new Error('outer', { cause: enospc() })],
  ])('maps disk exhaustion (%s) to a retryable DISK_FULL', (_name, err) => {
    const out = classifyFailure(err, live);
    expect(out).toMatchObject({ kind: 'failure', error: { code: 'DISK_FULL', retryable: true } });
  });

  it('maps everything else to a non-retryable INTERNAL', () => {
    for (const err of [new Error('bug'), 'string', null, 42, { code: 7 }]) {
      expect(classifyFailure(err, live)).toMatchObject({ kind: 'failure', error: { code: 'INTERNAL', retryable: false } });
    }
  });
});

describe('retryDelayMs', () => {
  it('grows exponentially with bounded jitter', () => {
    expect(retryDelayMs(1, 1000, () => 0.5)).toBe(1000);
    expect(retryDelayMs(2, 1000, () => 0.5)).toBe(4000);
    expect(retryDelayMs(3, 1000, () => 0.5)).toBe(16_000);
    expect(retryDelayMs(1, 1000, () => 0)).toBe(800);
    expect(retryDelayMs(1, 1000, () => 1)).toBe(1200);
    expect(retryDelayMs(0, 1000, () => 0.5)).toBe(1000);
    expect(retryDelayMs(1, 1000)).toBeGreaterThanOrEqual(800);
  });
});

describe('isScanErrorCode', () => {
  it('validates codes', () => {
    expect(isScanErrorCode('DISK_FULL')).toBe(true);
    expect(isScanErrorCode('NOPE')).toBe(false);
  });
});
