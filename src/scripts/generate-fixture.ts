/**
 * Generate a synthetic Trivy report on disk, e.g. for manual testing:
 *   node dist/scripts/generate-fixture.js --out /tmp/report.json --size-mb 600 --critical-ratio 0.05
 */
import { parseArgs } from 'node:util';
import { writeFixtureReport } from '../infrastructure/scanner/fixture-report.js';

const { values } = parseArgs({
  options: {
    out: { type: 'string', default: 'fixtures/trivy-report.json' },
    'size-mb': { type: 'string', default: '600' },
    'critical-ratio': { type: 'string', default: '0.05' },
    layout: { type: 'string', default: 'single-result' },
  },
});

const summary = await writeFixtureReport({
  path: values.out,
  sizeMb: Number(values['size-mb']),
  criticalRatio: Number(values['critical-ratio']),
  layout: values.layout === 'many-results' ? 'many-results' : 'single-result',
});
process.stdout.write(`${values.out}: ${JSON.stringify(summary)}\n`);
