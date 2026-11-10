import type { ReactElement } from 'react';
import type { ScanView } from '../api/types';

export function statusLabel(scan: ScanView): string {
  switch (scan.status) {
    case 'Queued':
    case 'Finished':
      return scan.status;
    case 'Scanning': {
      const parts = [scan.phase, scan.progressPct === null ? null : `${String(scan.progressPct)}%`].filter(
        (p): p is string => p !== null,
      );
      return parts.length === 0 ? 'Scanning' : `Scanning · ${parts.join(' ')}`;
    }
    case 'Failed':
      return `Failed · ${scan.error.code}: ${scan.error.message}`;
  }
}

export function StatusBadge({ scan }: { readonly scan: ScanView }): ReactElement {
  return (
    <span className={`badge badge--${scan.status.toLowerCase()}`} data-testid="status-badge">
      {statusLabel(scan)}
    </span>
  );
}
