import fs from 'node:fs';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { readMemoryCounters, readSmallTextFile, readSystemMemory } from '../../src/infrastructure/process/system-memory.js';
import { tempDir } from '../helpers/index.js';

const MiB = 1024 * 1024;
const linux = process.platform === 'linux';

describe('readSystemMemory', () => {
  let root: string | undefined;
  afterEach(() => {
    if (root) fs.rmSync(root, { recursive: true, force: true });
  });

  async function fakeCgroup(files: Record<string, string>): Promise<string> {
    root = tempDir();
    const self = (await readSmallTextFile('/proc/self/cgroup')) ?? '0::/';
    const rel = /^0::(\/.*)$/m.exec(self)?.[1] ?? '/';
    const dir = path.join(root, rel);
    fs.mkdirSync(dir, { recursive: true });
    for (const [name, value] of Object.entries(files)) fs.writeFileSync(path.join(dir, name), value);
    return root;
  }

  it('reports process, heap and V8 limit figures', async () => {
    const m = await readSystemMemory('/nonexistent');
    expect(m.privateMb).toBeGreaterThan(0);
    expect(m.heapUsedMb).toBeGreaterThan(0);
    expect(m.heapLimitMb).toBeGreaterThan(m.heapUsedMb);
    expect(m.cgroup).toBeNull();
  });

  it.runIf(linux)('reads the service cgroup: limit, current incl. cache, peak', async () => {
    const r = await fakeCgroup({ 'memory.max': `${150 * MiB}\n`, 'memory.current': `${67 * MiB}\n`, 'memory.peak': `${96 * MiB}\n` });
    expect((await readSystemMemory(r)).cgroup).toEqual({ limitMb: 150, currentMb: 67, peakMb: 96 });
  });

  it.runIf(linux)('treats "max" as unlimited and tolerates kernels without memory.peak', async () => {
    const r = await fakeCgroup({ 'memory.max': 'max\n', 'memory.current': `${10 * MiB}\n` });
    expect((await readSystemMemory(r)).cgroup).toEqual({ limitMb: null, currentMb: 10, peakMb: null });
  });

  it.runIf(linux)('reads memory.events counters and the limit', async () => {
    const r = await fakeCgroup({
      'memory.max': `${150 * MiB}\n`,
      'memory.events': 'low 0\nhigh 0\nmax 3\noom 1\noom_kill 1\noom_group_kill 0\n',
    });
    expect(await readMemoryCounters(r)).toEqual({ limitMb: 150, limitHits: 3, oomKills: 1 });
  });

  it('returns null counters without a cgroup', async () => {
    expect(await readMemoryCounters('/nonexistent')).toBeNull();
  });

  it('returns null for missing files', async () => {
    expect(await readSmallTextFile('/definitely/not/here')).toBeNull();
  });
});
