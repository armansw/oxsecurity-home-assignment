const SCAN_PARAM = 'scan';

/** The scan id persisted in `?scan=<id>`, so a refresh resumes polling. */
export function readScanIdFromUrl(): string | null {
  const value = new URLSearchParams(window.location.search).get(SCAN_PARAM);
  return value === null || value === '' ? null : value;
}

export function writeScanIdToUrl(scanId: string | null): void {
  const url = new URL(window.location.href);
  if (scanId === null) url.searchParams.delete(SCAN_PARAM);
  else url.searchParams.set(SCAN_PARAM, scanId);
  window.history.replaceState(window.history.state, '', url);
}
