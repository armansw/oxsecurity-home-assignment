import type { Scanner } from '../../domain/ports.js';
import { writeFixtureReport } from './fixture-report.js';

/**
 * Scanner used to prove the memory claim end-to-end (SCANNER=fixture): instead of running Trivy it writes a
 * synthetic Trivy-shaped report of `sizeMb` megabytes. The repository is still really cloned, and the report
 * still flows through the exact production path: worker → stream parser → store → status API.
 */
export class FixtureScanner implements Scanner {
  constructor(private readonly opts: { readonly sizeMb: number; readonly criticalRatio: number }) {}

  async scan(input: Parameters<Scanner['scan']>[0]): Promise<void> {
    await writeFixtureReport({
      path: input.reportPath,
      sizeMb: this.opts.sizeMb,
      criticalRatio: this.opts.criticalRatio,
      signal: input.signal,
    });
  }

  checkAvailable(): Promise<{ ok: boolean; detail: string }> {
    return Promise.resolve({ ok: true, detail: `fixture (${this.opts.sizeMb} MB synthetic report)` });
  }
}
