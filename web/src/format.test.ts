import { describe, expect, it } from 'vitest';
import { formatBytes, formatCount, formatDuration } from './format';

describe('format', () => {
  it('formats bytes', () => {
    expect(formatBytes(0)).toBe('0 B');
    expect(formatBytes(1536)).toBe('1.5 KB');
    expect(formatBytes(1_572_864)).toBe('1.5 MB');
    expect(formatBytes(5 * 1024 ** 5)).toBe('5120.0 TB');
  });

  it('formats durations', () => {
    expect(formatDuration(850)).toBe('850 ms');
    expect(formatDuration(12_300)).toBe('12.3 s');
    expect(formatDuration(125_000)).toBe('2m 5s');
  });

  it('formats counts with grouping', () => {
    expect(formatCount(1234567)).toBe('1,234,567');
  });
});
