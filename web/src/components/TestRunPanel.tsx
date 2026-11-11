import { type ReactElement, useState } from 'react';
import type { TestRun, TestRunItem } from '../api/testRuns';
import { formatBytes, formatCount, formatDuration } from '../format';
import type { TestRunControls } from '../hooks/useTestRun';

export const TEST_RUN_SIZES = [10, 20, 30] as const;

/**
 * "Run self-test": the live service scans a random sample of the large-repository corpus, one repository at a
 * time and always behind real users' scans, and the panel reports every result against the memory limit.
 */
export function TestRunPanel({ controls }: { readonly controls: TestRunControls }): ReactElement {
  const { run, error, busy } = controls;
  const [size, setSize] = useState<number>(TEST_RUN_SIZES[1]);
  const running = run?.state === 'running';

  return (
    <section className="selftest" aria-labelledby="selftest-heading">
      <div className="selftest__header">
        <div>
          <h2 id="selftest-heading">Self-test on real repositories</h2>
          <p className="muted">
            Scans a random sample of the large-repository corpus
            {run !== null && <> ({String(run.poolSize)} repositories across 9 ecosystems)</>} on this live service and checks
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
              <label className="selftest__size">
                <span className="visually-hidden">Repositories to scan</span>
                <select
                  value={size}
                  disabled={busy}
                  onChange={(e) => {
                    setSize(Number(e.target.value));
                  }}
                >
                  {TEST_RUN_SIZES.map((n) => (
                    <option key={n} value={n}>
                      {n} repositories
                    </option>
                  ))}
                </select>
              </label>
              <button
                type="button"
                disabled={busy}
                onClick={() => {
                  controls.start(size);
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
      {run !== null && <RunReport run={run} />}
    </section>
  );
}

function RunReport({ run }: { readonly run: TestRun }): ReactElement {
  const { counts, memory, totals } = run;
  const done = counts.finished + counts.failed + counts.expired;
  const limit = memory.limitMb;
  return (
    <>
      <Verdict run={run} />
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
    </>
  );
}

function Verdict({ run }: { readonly run: TestRun }): ReactElement {
  const { counts, memory, state } = run;
  const limit = memory.limitMb === null ? '' : ` ${String(memory.limitMb)} MB`;
  if (state === 'running') {
    const done = counts.finished + counts.failed + counts.expired;
    return (
      <p className="selftest__verdict selftest__verdict--running" role="status">
        Running · {done} of {counts.total} done
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
  const name = item.repoUrl.replace(/^https:\/\/github\.com\//, '');
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
