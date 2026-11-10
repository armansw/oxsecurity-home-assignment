import { Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { SyncedFileWriteStream } from '../fs/synced-write-stream.js';

export type FixtureLayout = 'single-result' | 'many-results';

export interface FixtureOptions {
  readonly path: string;
  readonly sizeMb: number;
  /** Fraction of vulnerabilities that are CRITICAL, 0..1. Distributed evenly and deterministically. */
  readonly criticalRatio: number;
  /**
   * single-result: every finding inside Results[0] — the worst case for parsers that stream at the
   *   Results[] level, and the realistic shape of a huge monorepo lockfile.
   * many-results: a new Result every `resultSize` findings.
   */
  readonly layout?: FixtureLayout;
  readonly resultSize?: number;
  readonly signal?: AbortSignal;
}

export interface FixtureSummary {
  readonly bytes: number;
  readonly total: number;
  readonly critical: number;
}

const SEVERITIES = ['HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'] as const;
const LOREM =
  'A crafted payload can trigger prototype pollution, leading to denial of service or remote code execution ' +
  'when attacker-controlled input reaches the vulnerable merge routine. Upgrade to the fixed version. ';

/**
 * Writes a synthetic, Trivy-shaped, pretty-printed JSON report of roughly `sizeMb` megabytes.
 *
 * The generator is itself memory-flat: content is produced lazily by a generator and written through
 * `pipeline()`, which honours backpressure, so only one ~64 KiB chunk exists at a time. The file is written
 * with periodic fdatasync so dirty page cache stays bounded inside a memory cgroup (see SyncedFileWriteStream).
 */
export async function writeFixtureReport(opts: FixtureOptions): Promise<FixtureSummary> {
  const counts = { bytes: 0, total: 0, critical: 0 };
  const targetBytes = Math.max(1, Math.floor(opts.sizeMb * 1024 * 1024));
  const layout = opts.layout ?? 'single-result';
  const resultSize = opts.resultSize ?? 1000;

  function* chunks(): Generator<string> {
    let buf = header();
    let resultIndex = 0;
    let inResult = 0;
    buf += openResult(resultIndex);

    while (counts.bytes + buf.length < targetBytes || counts.total === 0) {
      if (layout === 'many-results' && inResult === resultSize) {
        resultIndex += 1;
        inResult = 0;
        buf += `\n      ]\n    },\n${openResult(resultIndex)}`;
      }
      const i = counts.total;
      const critical = Math.floor((i + 1) * opts.criticalRatio) > Math.floor(i * opts.criticalRatio);
      const severity = critical ? 'CRITICAL' : (SEVERITIES[i % SEVERITIES.length] ?? 'LOW');
      buf += (inResult === 0 ? '\n' : ',\n') + vulnerability(i, severity);
      counts.total += 1;
      inResult += 1;
      if (critical) counts.critical += 1;

      if (buf.length >= 64 * 1024) {
        counts.bytes += Buffer.byteLength(buf);
        yield buf;
        buf = '';
      }
    }
    buf += '\n      ]\n    }\n  ]\n}\n';
    counts.bytes += Buffer.byteLength(buf);
    yield buf;
  }

  await pipeline(Readable.from(chunks()), new SyncedFileWriteStream(opts.path), opts.signal ? { signal: opts.signal } : {});
  return { ...counts };
}

function header(): string {
  return [
    '{',
    '  "SchemaVersion": 2,',
    '  "CreatedAt": "2026-01-01T00:00:00.000Z",',
    '  "ArtifactName": ".",',
    '  "ArtifactType": "filesystem",',
    '  "Metadata": {',
    '    "ImageConfig": { "architecture": "", "created": "0001-01-01T00:00:00Z", "os": "", "rootfs": { "type": "", "diff_ids": null }, "config": {} }',
    '  },',
    '  "Results": [',
  ].join('\n');
}

function openResult(index: number): string {
  // A Packages array before Vulnerabilities, as Trivy emits it: must be walked and skipped, never built.
  const packages = Array.from({ length: 3 }, (_, p) =>
    JSON.stringify({ ID: `pkg-${index}-${p}@1.0.${p}`, Name: `pkg-${index}-${p}`, Version: `1.0.${p}` }),
  ).join(',\n        ');
  return [
    '    {',
    `      "Target": "packages/app-${index}/package-lock.json",`,
    '      "Class": "lang-pkgs",',
    '      "Type": "npm",',
    `      "Packages": [\n        ${packages}\n      ],`,
    '      "Vulnerabilities": [',
  ].join('\n');
}

function vulnerability(i: number, severity: string): string {
  const id = `CVE-${2000 + (i % 26)}-${String(10000 + i)}`;
  const pkg = `package-${i % 5000}`;
  const v = {
    VulnerabilityID: id,
    VendorIDs: [`GHSA-${(i * 7919).toString(36).padStart(4, 'x')}-fixt-ure0`],
    PkgID: `${pkg}@1.${i % 10}.${i % 7}`,
    PkgName: pkg,
    PkgIdentifier: { PURL: `pkg:npm/${pkg}@1.${i % 10}.${i % 7}`, UID: (i * 2654435761).toString(16) },
    InstalledVersion: `1.${i % 10}.${i % 7}`,
    FixedVersion: `1.${(i % 10) + 1}.0`,
    Status: 'fixed',
    SeveritySource: 'ghsa',
    PrimaryURL: `https://avd.aquasec.com/nvd/${id.toLowerCase()}`,
    DataSource: { ID: 'ghsa', Name: 'GitHub Security Advisory npm', URL: 'https://github.com/advisories?query=type%3Areviewed+ecosystem%3Anpm' },
    Title: `${pkg}: prototype pollution in merge (${id})`,
    Description: LOREM.repeat(3).trim(),
    Severity: severity,
    CweIDs: ['CWE-1321'],
    VendorSeverity: { ghsa: 4, nvd: 4 },
    CVSS: {
      ghsa: { V3Vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', V3Score: 9.8 },
      nvd: { V3Vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', V3Score: 9.1 + (i % 7) / 10 },
    },
    References: [`https://github.com/advisories/${id}`, `https://nvd.nist.gov/vuln/detail/${id}`],
    PublishedDate: '2024-01-01T00:00:00Z',
    LastModifiedDate: '2025-01-01T00:00:00Z',
  };
  return JSON.stringify(v, null, 2).replace(/^/gm, '        ');
}
