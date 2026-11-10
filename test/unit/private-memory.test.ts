import { describe, expect, it } from 'vitest';
import { privateMemoryBytes } from '../../src/infrastructure/process/private-memory.js';

describe('privateMemoryBytes', () => {
  it('reports anonymous memory: positive, and below RSS on Linux (which also counts shared code pages)', async () => {
    const priv = await privateMemoryBytes();
    expect(priv).toBeGreaterThan(1024 * 1024);
    if (process.platform === 'linux') expect(priv).toBeLessThan(process.memoryUsage.rss());
  });
});
