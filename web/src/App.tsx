import { type ReactElement, useMemo, useState } from 'react';
import { createScanApi } from './api';
import { toApiError } from './api/errors';
import { isTerminal, type ScanApi, type Transport } from './api/types';
import { fetchSystemMemory, type SystemMemory } from './api/system';
import { MemoryPanel } from './components/MemoryPanel';
import { ScanForm } from './components/ScanForm';
import { ScanResults } from './components/ScanResults';
import { StatusBadge } from './components/StatusBadge';
import { TransportToggle } from './components/TransportToggle';
import { useScanPolling } from './hooks/useScanPolling';
import { useSystemMemory } from './hooks/useSystemMemory';
import { readScanIdFromUrl, writeScanIdToUrl } from './url';

interface AppProps {
  /** Injection point for tests; production uses the real REST/GraphQL clients. */
  readonly createApi?: (transport: Transport) => ScanApi;
  /** Injection point for tests; production polls GET /api/system/memory. */
  readonly loadMemory?: (signal: AbortSignal) => Promise<SystemMemory>;
}

export function App({ createApi = createScanApi, loadMemory = fetchSystemMemory }: AppProps): ReactElement {
  const [transport, setTransport] = useState<Transport>('rest');
  const api = useMemo(() => createApi(transport), [createApi, transport]);

  const [scanId, setScanId] = useState<string | null>(readScanIdFromUrl);
  const [starting, setStarting] = useState(false);
  const [startError, setStartError] = useState<string | null>(null);
  const [deduplicated, setDeduplicated] = useState(false);
  const { scan, error, reconnecting } = useScanPolling(api, scanId);
  const memory = useSystemMemory(loadMemory);
  const memoryLimitMb = memory?.cgroup?.limitMb ?? null;

  const selectScan = (id: string | null): void => {
    setScanId(id);
    writeScanIdToUrl(id);
  };

  const handleStart = (repoUrl: string): void => {
    setStarting(true);
    setStartError(null);
    setDeduplicated(false);
    api
      .startScan(repoUrl)
      .then((result) => {
        selectScan(result.scanId);
        setDeduplicated(result.deduplicated);
      })
      .catch((err: unknown) => {
        setStartError(toApiError(err).message);
      })
      .finally(() => {
        setStarting(false);
      });
  };

  const handleReset = (): void => {
    selectScan(null);
    setStartError(null);
    setDeduplicated(false);
  };

  const pollingActive = scanId !== null && error === null && (scan === null || !isTerminal(scan.status));

  return (
    <main className="app">
      <header className="app__header">
        <h1>Code Guardian</h1>
        <p className="muted">Scan a public GitHub repository for critical vulnerabilities.</p>
      </header>

      {memory !== null && <MemoryPanel memory={memory} />}

      <TransportToggle value={transport} onChange={setTransport} />
      <ScanForm disabled={starting || pollingActive} serverError={startError} onSubmit={handleStart} />

      {scanId !== null && (
        <section className="scan" aria-labelledby="scan-heading">
          <div className="scan__header">
            <h2 id="scan-heading">Scan</h2>
            <button type="button" className="secondary" onClick={handleReset}>
              New scan
            </button>
          </div>
          <p className="scan__meta">
            <code>{scanId}</code>
            {scan !== null && <> · {scan.repoUrl}</>}
          </p>
          {deduplicated && <p className="note">This repository was already queued — showing the existing scan.</p>}
          <div role="status" aria-live="polite" className="scan__status">
            {error !== null ? (
              <span className="field-error">
                {error.code}: {error.message}
              </span>
            ) : scan === null ? (
              <span className="muted">Loading…</span>
            ) : (
              <StatusBadge scan={scan} />
            )}
            {reconnecting && <span className="hint">reconnecting…</span>}
          </div>
        </section>
      )}

      {scan?.status === 'Finished' && <ScanResults key={scan.scanId} api={api} scan={scan} memoryLimitMb={memoryLimitMb} />}
    </main>
  );
}
