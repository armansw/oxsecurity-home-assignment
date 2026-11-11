import { type ReactElement, useState } from 'react';
import type { TestRun, TestRunItem } from '../api/testRuns';
import { formatBytes, formatCount, formatDuration } from '../format';
import type { TestRunControls } from '../hooks/useTestRun';

/** Server default for TEST_RUN_MAX_SIZE; a run never exceeds the eligible pool either. */
export const TEST_RUN_MAX_SIZE = 100;
export const TEST_RUN_DEFAULT_SIZE = 20;
/** "≈ 45 s", "≈ 9 min": scans run one at a time, so a run takes about count × the measured time per repository. */
export function formatEstimate(repos: number, secondsPerRepo: number): string {
  const seconds = repos * secondsPerRepo;
  return seconds < 90 ? `≈ ${String(Math.max(1, Math.round(seconds)))} s` : `≈ ${String(Math.round(seconds / 60))} min`;
}

function parseSize(text: string, max: number): number | null {
  if (!/^\d{1,3}$/.test(text)) return null;
  const n = Number(text);
  return n >= 1 && n <= max ? n : null;
}

/**
 * "Run self-test": the live service scans a random sample of the large-repository corpus, one repository at a
 * time and always behind real users' scans, and the panel reports every result against the memory limit.
 */
export function TestRunPanel({ controls }: { readonly controls: TestRunControls }): ReactElement {
  const { run, error, busy, settings } = controls;
  const max = settings?.maxSize ?? Math.min(TEST_RUN_MAX_SIZE, run?.poolSize ?? TEST_RUN_MAX_SIZE);
  const perRepo = settings?.secondsPerRepo ?? null;
  const poolSize = settings?.poolSize ?? run?.poolSize ?? null;
  const [text, setText] = useState(String(TEST_RUN_DEFAULT_SIZE));
  const size = parseSize(text, max);
  const running = run?.state === 'running';

  return (
    <section className="selftest" aria-labelledby="selftest-heading">
      <div className="selftest__header">
        <div>
          <h2 id="selftest-heading">Self-test on real repositories</h2>
          <p className="muted">
            Scans a random sample of the large-repository corpus
            {poolSize !== null && <> ({String(poolSize)} repositories across 9 ecosystems)</>} on this live service and checks
            every scan against the memory limit. Repositories run one at a time, after anyone&apos;s own scans.
          </p>
        </div>
        <div className="selftest__controls">
          {running ? (
            <button type="button" className="secondary" disabled={busy} onClick={controls.cancel}>
              Cancel
            </button>
          ) : (
            <>
              <div className="selftest__size">
                <input
                  type="range"
                  min={1}
                  max={max}
                  value={size ?? TEST_RUN_DEFAULT_SIZE}
                  disabled={busy}
                  aria-label="Repositories to scan (slider)"
                  onChange={(e) => {
                    setText(e.target.value);
                  }}
                />
                <input
                  type="number"
                  inputMode="numeric"
                  min={1}
                  max={max}
                  value={text}
                  disabled={busy}
                  aria-label="Repositories to scan"
                  aria-invalid={size === null}
                  onChange={(e) => {
                    setText(e.target.value);
                  }}
                />
                <span
                  className="muted selftest__eta"
                  title={perRepo === null || settings === null ? undefined : `Measured: ${String(perRepo)} s per repository over the last ${String(settings.basedOnScans)} self-test scans`}
                >
                  {size === null ? `1–${String(max)}` : perRepo === null ? '' : formatEstimate(size, perRepo)}
                </span>
              </div>
              <button
                type="button"
                disabled={busy || size === null}
                onClick={() => {
                  if (size !== null) controls.start(size);
                }}
              >
                Run self-test
              </button>
            </>
          )}
        </div>
      </div>

      {error !== null && (
        <p className="field-error" role="alert">
          {error}
        </p>
      )}
      {run !== null && <RunReport run={run} secondsPerRepo={perRepo} />}
    </section>
  );
}

function RunReport({ run, secondsPerRepo }: { readonly run: TestRun; readonly secondsPerRepo: number | null }): ReactElement {
  const { counts, memory, totals } = run;
  const done = counts.finished + counts.failed + counts.expired;
  const limit = memory.limitMb;
  return (
    <>
      <Verdict run={run} secondsPerRepo={secondsPerRepo} />
      <div
        className="selftest__progress"
        role="progressbar"
        aria-label="Self-test progress"
        aria-valuemin={0}
        aria-valuemax={counts.total}
        aria-valuenow={done}
      >
        <span style={{ width: `${String(counts.total === 0 ? 0 : (done / counts.total) * 100)}%` }} />
      </div>
      <dl className="selftest__stats">
        <Stat label="Scanned" value={`${String(counts.finished)} / ${String(counts.total)}`} />
        <Stat label="Failed" value={String(counts.failed)} />
        <Stat label="Critical found" value={formatCount(totals.criticalCount)} />
        <Stat label="Findings parsed" value={formatCount(totals.vulnerabilitiesScanned)} />
        <Stat label="Reports streamed" value={formatBytes(totals.reportBytes)} />
        <Stat
          label="Highest scan peak"
          value={memory.maxScanPeakMb === null ? '—' : `${String(memory.maxScanPeakMb)} MB${limit === null ? '' : ` / ${String(limit)} MB`}`}
        />
        {memory.limitHitsDuringRun !== null && <Stat label="Limit reached" value={`${String(memory.limitHitsDuringRun)}×`} />}
        {memory.oomKillsDuringRun !== null && <Stat label="OOM kills" value={String(memory.oomKillsDuringRun)} />}
      </dl>
      <div className="table-wrap">
        <table className="selftest__table">
          <thead>
            <tr>
              <th scope="col">Repository</th>
              <th scope="col">Ecosystem</th>
              <th scope="col">Status</th>
              <th scope="col" className="num">
                Critical
              </th>
              <th scope="col">Peak memory</th>
              <th scope="col" className="num">
                Time
              </th>
            </tr>
          </thead>
          <tbody>
            {run.items.map((item) => (
              <Row key={item.position} item={item} limitMb={limit} />
            ))}
          </tbody>
        </table>
      </div>
      {run.items.some((i) => i.error?.code === 'UPSTREAM_RATE_LIMITED') && (
        <p className="hint">
          UPSTREAM_RATE_LIMITED: a package registry (e.g. Maven Central) throttled Trivy. That is the registry, not this
          service; the self-test does not wait out the registry&apos;s back-off.
        </p>
      )}
    </>
  );
}

function Verdict({ run, secondsPerRepo }: { readonly run: TestRun; readonly secondsPerRepo: number | null }): ReactElement {
  const { counts, memory, state } = run;
  const limit = memory.limitMb === null ? '' : ` ${String(memory.limitMb)} MB`;
  if (state === 'running') {
    const done = counts.finished + counts.failed + counts.expired;
    return (
      <p className="selftest__verdict selftest__verdict--running" role="status">
        Running · {done} of {counts.total} done
        {secondsPerRepo !== null && ` · ${formatEstimate(counts.total - done, secondsPerRepo)} left`}
        {memory.withinLimit !== false ? ` · within the${limit} limit so far` : ' · memory limit exceeded'}
      </p>
    );
  }
  const scanned = `${String(counts.finished)} of ${String(counts.total)} repositories scanned`;
  if (memory.withinLimit === false) {
    return (
      <p className="selftest__verdict selftest__verdict--bad" role="status">
        ✕ {scanned} · the memory limit was reached
      </p>
    );
  }
  return (
    <p className={`selftest__verdict selftest__verdict--${state === 'cancelled' ? 'neutral' : 'ok'}`} role="status">
      {state === 'cancelled' ? 'Cancelled' : '✓'} · {scanned}
      {memory.withinLimit === true &&
        ` · every scan within the${limit} limit · limit never reached · ${String(memory.oomKillsDuringRun ?? 0)} OOM kills`}
    </p>
  );
}

function Stat({ label, value }: { readonly label: string; readonly value: string }): ReactElement {
  return (
    <div>
      <dt>{label}</dt>
      <dd>{value}</dd>
    </div>
  );
}

function Row({ item, limitMb }: { readonly item: TestRunItem; readonly limitMb: number | null }): ReactElement {
  const name = item.repoUrl.replace(/^https:\/\/github\.com\//, '').replace(/\.git$/, '');
  return (
    <tr>
      <td className="break">
        <a href={item.repoUrl} target="_blank" rel="noreferrer">
          {name}
        </a>
      </td>
      <td>{item.language}</td>
      <td>
        <span className={`pill pill--${item.status.toLowerCase()}`} title={item.error === null ? undefined : `${item.error.code}: ${item.error.message}`}>
          {item.status === 'Scanning' && item.phase !== null ? item.phase : item.status}
        </span>
        {item.error !== null && <span className="selftest__error">{item.error.code}</span>}
      </td>
      <td className="num">{item.criticalCount === null ? '—' : formatCount(item.criticalCount)}</td>
      <td>
        {item.peakMemoryMb === null ? (
          '—'
        ) : (
          <span className="minibar" title={`${String(item.peakMemoryMb)} MB${limitMb === null ? '' : ` of ${String(limitMb)} MB`}`}>
            {limitMb !== null && (
              <span className="minibar__track" aria-hidden="true">
                <span style={{ width: `${String(Math.min(100, (item.peakMemoryMb / limitMb) * 100))}%` }} />
              </span>
            )}
            {item.peakMemoryMb} MB
          </span>
        )}
      </td>
      <td className="num">{item.durationMs === null ? '—' : formatDuration(item.durationMs)}</td>
    </tr>
  );
}
