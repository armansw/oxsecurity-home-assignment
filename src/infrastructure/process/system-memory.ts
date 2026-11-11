import { open } from 'node:fs/promises';
import v8 from 'node:v8';
import type { MemoryCounters } from '../../domain/test-run.js';
import { privateMemoryBytes } from './private-memory.js';

export interface CgroupMemory {
  /** Hard limit (memory.max); null when unlimited. */
  readonly limitMb: number | null;
  /** Everything charged to the cgroup now, page cache included (memory.current). */
  readonly currentMb: number;
  /** Highest value of currentMb since the cgroup was created (memory.peak), when the kernel provides it. */
  readonly peakMb: number | null;
}

export interface SystemMemory {
  /** This process's private (anonymous) memory. */
  readonly privateMb: number;
  readonly heapUsedMb: number;
  /** V8's heap ceiling (reflects --max-old-space-size). */
  readonly heapLimitMb: number;
  /** The service's own cgroup (container / systemd unit), or null where cgroup v2 is unavailable. */
  readonly cgroup: CgroupMemory | null;
}

const MB = 1024 * 1024;
const mb = (bytes: number): number => Math.round(bytes / MB);

/** Live memory figures for the UI's "fits the limit" proof. Every value is measured, none is configured. */
export async function readSystemMemory(cgroupRoot = '/sys/fs/cgroup'): Promise<SystemMemory> {
  const heap = v8.getHeapStatistics();
  return {
    privateMb: mb(await privateMemoryBytes()),
    heapUsedMb: mb(heap.used_heap_size),
    heapLimitMb: mb(heap.heap_size_limit),
    cgroup: await readCgroup(cgroupRoot),
  };
}

async function readCgroup(root: string): Promise<CgroupMemory | null> {
  const dir = await cgroupDir(root);
  if (dir === null) return null;
  const current = await readSmallTextFile(`${dir}/memory.current`);
  if (current === null) return null;
  const peak = await readSmallTextFile(`${dir}/memory.peak`);
  return {
    limitMb: await readLimitMb(dir),
    currentMb: mb(Number(current)),
    peakMb: peak === null ? null : mb(Number(peak)),
  };
}

/**
 * The cgroup's lifetime memory events (limit reached, OOM kills) and its limit, or null without cgroup v2.
 * The self-test records them when a run starts and reports the difference.
 */
export async function readMemoryCounters(cgroupRoot = '/sys/fs/cgroup'): Promise<MemoryCounters | null> {
  const dir = await cgroupDir(cgroupRoot);
  if (dir === null) return null;
  const events = await readSmallTextFile(`${dir}/memory.events`);
  if (events === null) return null;
  const counter = (name: string): number => Number(new RegExp(`^${name} (\\d+)$`, 'm').exec(events)?.[1] ?? 0);
  return { limitMb: await readLimitMb(dir), limitHits: counter('max'), oomKills: counter('oom_kill') };
}

async function cgroupDir(root: string): Promise<string | null> {
  if (process.platform !== 'linux') return null;
  // cgroup v2: "0::/system.slice/code-guardian.service" (systemd) or "0::/" (a container's own namespace).
  const self = await readSmallTextFile('/proc/self/cgroup');
  const rel = self === null ? undefined : /^0::(\/.*)$/m.exec(self)?.[1];
  if (rel === undefined) return null;
  return `${root}${rel === '/' ? '' : rel}`;
}

async function readLimitMb(dir: string): Promise<number | null> {
  const max = (await readSmallTextFile(`${dir}/memory.max`))?.trim();
  return max === undefined || max === 'max' ? null : mb(Number(max));
}

/** Reads a tiny kernel file through a file handle (no readFile). Returns null when it does not exist. */
export async function readSmallTextFile(path: string): Promise<string | null> {
  let handle;
  try {
    handle = await open(path, 'r');
    const buf = Buffer.alloc(4096);
    const { bytesRead } = await handle.read(buf, 0, buf.length, 0);
    return buf.toString('utf8', 0, bytesRead);
  } catch {
    return null;
  } finally {
    await handle?.close();
  }
}
