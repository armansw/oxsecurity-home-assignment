import { open } from 'node:fs/promises';

/**
 * Private (anonymous) memory of this process in bytes: heap, buffers and native allocations, the memory the
 * process itself owns. Unlike RSS it excludes file-backed pages such as the Node binary's code, which are shared
 * with other processes and reclaimable, so it is the honest figure to compare with a container limit.
 *
 * Linux: `RssAnon` from /proc/self/status (read through a small file handle: no readFile). Elsewhere: RSS.
 */
export async function privateMemoryBytes(): Promise<number> {
  if (process.platform !== 'linux') return process.memoryUsage.rss();
  let handle;
  try {
    handle = await open('/proc/self/status', 'r');
    const buf = Buffer.alloc(8192);
    const { bytesRead } = await handle.read(buf, 0, buf.length, 0);
    const kb = /^RssAnon:\s+(\d+)\s+kB/m.exec(buf.toString('utf8', 0, bytesRead))?.[1];
    return kb === undefined ? process.memoryUsage.rss() : Number(kb) * 1024;
  } catch {
    return process.memoryUsage.rss();
  } finally {
    await handle?.close();
  }
}
