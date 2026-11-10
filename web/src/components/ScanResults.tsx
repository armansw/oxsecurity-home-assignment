import type { ReactElement } from 'react';
import type { FinishedScan, ScanApi, Vulnerability } from '../api/types';
import { formatBytes, formatCount, formatDuration } from '../format';
import { useVulnerabilityPages } from '../hooks/useVulnerabilityPages';
import { MemoryMeter } from './MemoryMeter';

interface ScanResultsProps {
  readonly api: ScanApi;
  readonly scan: FinishedScan;
  /** The service's real memory limit (from the server), to draw this scan's peak against; null if unknown. */
  readonly memoryLimitMb?: number | null;
}

/** Summary + paginated table for a finished scan. Mount with `key={scan.scanId}`. */
export function ScanResults({ api, scan, memoryLimitMb = null }: ScanResultsProps): ReactElement {
  const pages = useVulnerabilityPages(api, scan.scanId, scan.page);

  return (
    <section className="results" aria-labelledby="results-heading">
      <h2 id="results-heading">Results</h2>
      <dl className="summary">
        <Stat label="Critical" value={formatCount(scan.criticalCount)} emphasis={scan.criticalCount > 0} />
        <Stat label="Report size" value={formatBytes(scan.stats.reportBytes)} />
        <Stat label="Vulnerabilities scanned" value={formatCount(scan.stats.vulnerabilitiesScanned)} />
        <Stat label="Duration" value={formatDuration(scan.stats.durationMs)} />
        <Stat label="Peak private memory" value={`${String(scan.stats.peakMemoryMb)} MB`} />
      </dl>
      {memoryLimitMb !== null && (
        <MemoryMeter
          label="Peak memory during this scan"
          usedMb={scan.stats.peakMemoryMb}
          limitMb={memoryLimitMb}
          note={`${formatBytes(scan.stats.reportBytes)} report stream-parsed; the service never held it in memory.`}
        />
      )}

      {pages.items.length === 0 ? (
        <p className="empty">No critical vulnerabilities found. Nice work.</p>
      ) : (
        <div className="table-wrap">
          <table>
            <caption className="visually-hidden">Critical vulnerabilities</caption>
            <thead>
              <tr>
                <th scope="col">ID</th>
                <th scope="col">Package</th>
                <th scope="col">Installed → Fixed</th>
                <th scope="col">CVSS</th>
                <th scope="col">Target</th>
                <th scope="col">Title</th>
              </tr>
            </thead>
            <tbody>
              {pages.items.map((v, i) => (
                // The same CVE can legitimately appear for several packages/targets.
                <VulnerabilityRow key={`${v.id}|${v.pkgName}|${v.target}|${String(i)}`} vulnerability={v} />
              ))}
            </tbody>
          </table>
        </div>
      )}

      <p className="results__footer" aria-live="polite">
        Showing {formatCount(pages.items.length)} of {formatCount(scan.criticalCount)}
      </p>
      {pages.error !== null && (
        <p className="field-error" role="alert">
          Could not load more: {pages.error.message}
        </p>
      )}
      {pages.hasMore && (
        <button type="button" onClick={pages.loadMore} disabled={pages.loading}>
          {pages.loading ? 'Loading…' : 'Load more'}
        </button>
      )}
    </section>
  );
}

function Stat({ label, value, emphasis = false }: { readonly label: string; readonly value: string; readonly emphasis?: boolean }): ReactElement {
  return (
    <div className={emphasis ? 'stat stat--alert' : 'stat'}>
      <dt>{label}</dt>
      <dd>{value}</dd>
    </div>
  );
}

function VulnerabilityRow({ vulnerability: v }: { readonly vulnerability: Vulnerability }): ReactElement {
  return (
    <tr>
      <td>
        {v.primaryUrl === null ? (
          v.id
        ) : (
          <a href={v.primaryUrl} target="_blank" rel="noopener noreferrer">
            {v.id}
          </a>
        )}
      </td>
      <td>{v.pkgName}</td>
      <td className="nowrap">
        {v.installedVersion ?? '?'} → {v.fixedVersion ?? <span className="muted">no fix</span>}
      </td>
      <td>{v.cvssScore === null ? '—' : v.cvssScore.toFixed(1)}</td>
      <td className="break">{v.target}</td>
      <td>{v.title ?? <span className="muted">—</span>}</td>
    </tr>
  );
}
