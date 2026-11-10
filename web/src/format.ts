const BYTE_UNITS = ['B', 'KB', 'MB', 'GB', 'TB'] as const;

/** 1536 -> "1.5 KB" (binary multiples, one decimal above bytes). */
export function formatBytes(bytes: number): string {
  let value = Math.max(0, bytes);
  let unit = 0;
  while (value >= 1024 && unit < BYTE_UNITS.length - 1) {
    value /= 1024;
    unit += 1;
  }
  const label = BYTE_UNITS[unit] ?? 'B';
  return unit === 0 ? `${String(value)} ${label}` : `${value.toFixed(1)} ${label}`;
}

/** 850 -> "850 ms", 12_300 -> "12.3 s", 125_000 -> "2m 5s". */
export function formatDuration(ms: number): string {
  if (ms < 1000) return `${String(Math.round(ms))} ms`;
  if (ms < 60_000) return `${(ms / 1000).toFixed(1)} s`;
  const totalSeconds = Math.round(ms / 1000);
  return `${String(Math.floor(totalSeconds / 60))}m ${String(totalSeconds % 60)}s`;
}

export function formatCount(n: number): string {
  return n.toLocaleString('en-US');
}
