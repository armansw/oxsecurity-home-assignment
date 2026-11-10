import fs from 'node:fs';
import path from 'node:path';
import { Writable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { afterAll, describe, expect, it } from 'vitest';
import { CriticalVulnerabilityExtractor } from '../../src/infrastructure/report/critical-vulnerability-extractor.js';
import { buildParseStage } from '../../src/infrastructure/report/stream-report-processor.js';
import { writeFixtureReport } from '../../src/infrastructure/scanner/fixture-report.js';
import { tempDir } from '../helpers/index.js';

const dir = tempDir();
afterAll(() => {
  fs.rmSync(dir, { recursive: true, force: true });
});

async function parse(file: string): Promise<{ targets: Set<string>; critical: number; scanned: number }> {
  const extractor = new CriticalVulnerabilityExtractor();
  const targets = new Set<string>();
  await pipeline(
    fs.createReadStream(file, 'utf8'),
    buildParseStage(extractor, 1024 * 1024),
    new Writable({
      objectMode: true,
      write(v: { target: string }, _e, cb) {
        targets.add(v.target);
        cb();
      },
    }),
  );
  return { targets, critical: extractor.stats.critical, scanned: extractor.stats.scanned };
}

describe('writeFixtureReport', () => {
  it('writes a valid single-result report of the requested size with exact counts', async () => {
    const file = path.join(dir, 'single.json');
    const summary = await writeFixtureReport({ path: file, sizeMb: 1, criticalRatio: 0.25 });
    expect(summary.bytes).toBe(fs.statSync(file).size);
    expect(summary.bytes).toBeGreaterThanOrEqual(1024 * 1024);
    expect(summary.bytes).toBeLessThan(1.1 * 1024 * 1024);
    expect(summary.critical).toBe(Math.floor(summary.total * 0.25));
    const parsed = await parse(file);
    expect(parsed).toMatchObject({ critical: summary.critical, scanned: summary.total });
    expect(parsed.targets).toEqual(new Set(['packages/app-0/package-lock.json']));
  });

  it('supports a many-results layout', async () => {
    const file = path.join(dir, 'many.json');
    const summary = await writeFixtureReport({ path: file, sizeMb: 0.5, criticalRatio: 1, layout: 'many-results', resultSize: 50 });
    const parsed = await parse(file);
    expect(parsed.critical).toBe(summary.total);
    expect(parsed.targets.size).toBe(Math.ceil(summary.total / 50));
  });

  it('always writes at least one vulnerability and supports a zero ratio', async () => {
    const file = path.join(dir, 'tiny.json');
    const summary = await writeFixtureReport({ path: file, sizeMb: 0.000001, criticalRatio: 0 });
    expect(summary).toMatchObject({ total: 1, critical: 0 });
    expect((await parse(file)).scanned).toBe(1);
  });

  it('honours an abort signal', async () => {
    const c = new AbortController();
    c.abort(new Error('stop'));
    await expect(writeFixtureReport({ path: path.join(dir, 'aborted.json'), sizeMb: 50, criticalRatio: 0.1, signal: c.signal })).rejects.toThrow();
  });
});
