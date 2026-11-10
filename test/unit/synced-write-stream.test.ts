import fs from 'node:fs';
import path from 'node:path';
import { Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { afterAll, describe, expect, it, vi } from 'vitest';
import { SyncedFileWriteStream } from '../../src/infrastructure/fs/synced-write-stream.js';
import { tempDir, waitFor } from '../helpers/index.js';

const dir = tempDir();
afterAll(() => {
  fs.rmSync(dir, { recursive: true, force: true });
});

describe('SyncedFileWriteStream', () => {
  it('writes all bytes and fdatasyncs every syncEveryBytes', async () => {
    const file = path.join(dir, 'a.bin');
    const stream = new SyncedFileWriteStream(file, 1000);
    const syncSpy = vi.spyOn(stream as unknown as { sync: () => Promise<void> }, 'sync');
    const chunks = Array.from({ length: 10 }, (_, i) => Buffer.alloc(300, i));
    await pipeline(Readable.from(chunks), stream);
    expect(fs.statSync(file).size).toBe(3000);
    // after 1200, 2400 bytes (≥1000 each time) + final flush of the remaining 600
    expect(syncSpy).toHaveBeenCalledTimes(3);
  });

  it('accepts strings and skips the final sync when nothing is pending', async () => {
    const file = path.join(dir, 'b.txt');
    await pipeline(Readable.from(['hello ', 'world']), new SyncedFileWriteStream(file, 11));
    expect(fs.statSync(file).size).toBe(11);
  });

  it('fails when the file cannot be opened', async () => {
    await expect(pipeline(Readable.from(['x']), new SyncedFileWriteStream(path.join(dir, 'missing', 'c.txt')))).rejects.toMatchObject({ code: 'ENOENT' });
  });

  it('closes the file when destroyed mid-stream', async () => {
    const file = path.join(dir, 'd.txt');
    const stream = new SyncedFileWriteStream(file);
    const err = new Error('stop');
    const source = new Readable({ read() { this.push('data'); this.destroy(err); } });
    await expect(pipeline(source, stream)).rejects.toBe(err);
    expect(stream.destroyed).toBe(true);
  });

  it('reports write failures', async () => {
    const stream = new SyncedFileWriteStream(path.join(dir, 'e.txt'));
    const internals = stream as unknown as { handle?: { write: () => Promise<never> } };
    await waitFor(() => internals.handle !== undefined);
    const handle = internals.handle!;
    handle.write = () => Promise.reject(Object.assign(new Error('no space'), { code: 'ENOSPC' }));
    await expect(pipeline(Readable.from(['x']), stream)).rejects.toMatchObject({ code: 'ENOSPC' });
  });
});
