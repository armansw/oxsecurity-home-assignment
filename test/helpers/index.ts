import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { getManyValues, isMany, none } from 'stream-chain';
import { jsonParser, type Token } from 'stream-json/parser.js';
import type { Logger, LogFn, RepositoryFetcher, Scanner } from '../../src/domain/ports.js';
import { openDatabase } from '../../src/infrastructure/db/sqlite.js';
import { SqliteScanStore } from '../../src/infrastructure/db/sqlite-scan.store.js';

export interface LogEntry {
  readonly level: string;
  readonly msg: string;
  readonly obj: object;
}

/** In-memory Logger that records entries, so tests can assert on what was logged. */
export function recordingLogger(entries: LogEntry[] = []): Logger & { entries: LogEntry[] } {
  const make =
    (level: string): LogFn =>
    (objOrMsg: object | string, msg?: string) => {
      if (typeof objOrMsg === 'string') entries.push({ level, msg: objOrMsg, obj: {} });
      else entries.push({ level, msg: msg ?? '', obj: objOrMsg });
    };
  const logger: Logger & { entries: LogEntry[] } = {
    entries,
    debug: make('debug'),
    info: make('info'),
    warn: make('warn'),
    error: make('error'),
    child: () => logger,
  };
  return logger;
}

export function tempDir(prefix = 'cg-test-'): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

export function memoryStore(now?: () => number): SqliteScanStore {
  return new SqliteScanStore(openDatabase(':memory:'), now);
}

/** Tokenise a JSON string with the same parser options as production. */
export function tokens(json: string, opts: { flush?: boolean } = {}): Token[] {
  const tokenize = jsonParser({ packValues: true, streamValues: false }) as (v: string | typeof none) => unknown;
  const out: Token[] = [];
  const collect = (r: unknown): void => {
    if (isMany(r)) out.push(...(getManyValues(r) as Token[]));
    else if (r !== none && r !== undefined) out.push(r as Token);
  };
  collect(tokenize(json));
  if (opts.flush ?? true) collect(tokenize(none));
  return out;
}

export interface VulnInput {
  readonly id?: string;
  readonly pkg?: string;
  readonly severity?: string;
  readonly extra?: Record<string, unknown>;
}

export function vuln({ id = 'CVE-2024-0001', pkg = 'lodash', severity = 'CRITICAL', extra = {} }: VulnInput = {}): Record<string, unknown> {
  return {
    VulnerabilityID: id,
    PkgName: pkg,
    InstalledVersion: '1.0.0',
    FixedVersion: '1.0.1',
    Severity: severity,
    Title: `${pkg} issue`,
    Description: 'desc',
    PrimaryURL: `https://avd.aquasec.com/nvd/${id.toLowerCase()}`,
    CVSS: { nvd: { V3Score: 9.8 }, ghsa: { V3Score: 9.1 } },
    PublishedDate: '2024-01-01T00:00:00Z',
    ...extra,
  };
}

export function report(results: readonly Record<string, unknown>[], extra: Record<string, unknown> = {}): string {
  return JSON.stringify({ SchemaVersion: 2, ArtifactName: '.', ...extra, Results: results }, null, 2);
}

export const FAKE_COMMIT = 'a'.repeat(40);

/** Fetcher that "clones" by creating the directory, or fails with the given error. */
export class FakeFetcher implements RepositoryFetcher {
  calls: string[] = [];
  constructor(private readonly behaviour: (url: string, dest: string, signal: AbortSignal) => Promise<void> = mkdirFetch) {}
  async clone(url: string, dest: string, signal: AbortSignal): Promise<{ readonly commitSha: string }> {
    this.calls.push(url);
    await this.behaviour(url, dest, signal);
    return { commitSha: FAKE_COMMIT };
  }
}

async function mkdirFetch(_url: string, dest: string): Promise<void> {
  await fs.promises.mkdir(dest, { recursive: true });
  await fs.promises.writeFile(path.join(dest, 'package-lock.json'), '{}');
}

/** Scanner that writes a fixed report, or runs a custom behaviour. */
export class FakeScanner implements Scanner {
  calls = 0;
  constructor(private readonly behaviour: (input: Parameters<Scanner['scan']>[0]) => Promise<void>) {}
  static writing(json: string): FakeScanner {
    return new FakeScanner(async ({ reportPath }) => {
      await fs.promises.writeFile(reportPath, json);
    });
  }
  async scan(input: Parameters<Scanner['scan']>[0]): Promise<void> {
    this.calls += 1;
    await this.behaviour(input);
  }
  checkAvailable(): Promise<{ ok: boolean; detail: string }> {
    return Promise.resolve({ ok: true, detail: 'fake' });
  }
}

export function enospc(): NodeJS.ErrnoException {
  return Object.assign(new Error('ENOSPC: no space left on device, write'), { code: 'ENOSPC' });
}

/** Write an executable shell script (used to stand in for git / trivy binaries). */
export function fakeBinary(dir: string, name: string, script: string): string {
  const file = path.join(dir, name);
  fs.writeFileSync(file, `#!/bin/sh\n${script}\n`, { mode: 0o755 });
  return file;
}

export async function waitFor(predicate: () => boolean, timeoutMs = 5000, stepMs = 10): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!predicate()) {
    if (Date.now() > deadline) throw new Error('waitFor: condition not met in time');
    await new Promise((r) => setTimeout(r, stepMs));
  }
}
