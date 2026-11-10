import { open, type FileHandle } from 'node:fs/promises';
import { Writable } from 'node:stream';

/**
 * A file Writable that calls `fdatasync` every `syncEveryBytes`, bounding the amount of *dirty* page cache.
 *
 * Why this exists: inside a memory cgroup (docker `mem_limit`), page cache is charged to the container. Clean
 * pages are reclaimable, but dirty pages must be written back first. Writing hundreds of MB faster than the
 * disk flushes them fills the cgroup with unreclaimable dirty pages, and the kernel OOM-kills the process even
 * though its heap is tiny. Observed in CI: a 600 MB write in a 200 MB container was killed with anon-rss 46 MB
 * (`gfp_mask=GFP_HIGHUSER_MOVABLE|__GFP_WRITE`). Syncing periodically caps dirty data at ~`syncEveryBytes`.
 */
export class SyncedFileWriteStream extends Writable {
  private handle: FileHandle | undefined;
  private unsynced = 0;

  constructor(
    private readonly path: string,
    private readonly syncEveryBytes = 8 * 1024 * 1024,
  ) {
    super({ highWaterMark: 64 * 1024, decodeStrings: true });
  }

  override _construct(callback: (error?: Error | null) => void): void {
    open(this.path, 'w').then(
      (fh) => {
        this.handle = fh;
        callback();
      },
      (err: unknown) => {
        callback(toError(err));
      },
    );
  }

  override _write(chunk: Buffer, _encoding: BufferEncoding, callback: (error?: Error | null) => void): void {
    this.writeChunk(chunk).then(
      () => {
        callback();
      },
      (err: unknown) => {
        callback(toError(err));
      },
    );
  }

  override _final(callback: (error?: Error | null) => void): void {
    this.sync().then(
      () => {
        callback();
      },
      (err: unknown) => {
        callback(toError(err));
      },
    );
  }

  override _destroy(error: Error | null, callback: (error?: Error | null) => void): void {
    const fh = this.handle;
    this.handle = undefined;
    if (fh === undefined) {
      callback(error);
      return;
    }
    fh.close().then(
      () => {
        callback(error);
      },
      () => {
        callback(error);
      },
    );
  }

  private async writeChunk(chunk: Buffer): Promise<void> {
    const fh = this.requireHandle();
    let offset = 0;
    while (offset < chunk.length) {
      const { bytesWritten } = await fh.write(chunk, offset);
      offset += bytesWritten;
    }
    this.unsynced += chunk.length;
    if (this.unsynced >= this.syncEveryBytes) await this.sync();
  }

  private async sync(): Promise<void> {
    if (this.unsynced === 0) return;
    await this.requireHandle().datasync();
    this.unsynced = 0;
  }

  private requireHandle(): FileHandle {
    if (this.handle === undefined) throw new Error('file is not open');
    return this.handle;
  }
}

function toError(err: unknown): Error {
  return err instanceof Error ? err : new Error(String(err));
}
