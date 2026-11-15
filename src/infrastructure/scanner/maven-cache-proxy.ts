import { randomUUID } from 'node:crypto';
import { createReadStream, createWriteStream } from 'node:fs';
import { mkdir, readdir, rename, rm, stat, utimes } from 'node:fs/promises';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import path from 'node:path';
import { Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import type { ReadableStream as WebReadableStream } from 'node:stream/web';
import type { Logger } from '../../domain/ports.js';

export interface MavenCacheProxyOptions {
  /** The Maven repository behind the cache, e.g. Google's Maven Central mirror. */
  readonly upstream: string;
  readonly dir: string;
  /** Oldest files are evicted once the cache grows past this (down to 80 % of it). */
  readonly maxBytes: number;
  readonly log: Logger;
  readonly upstreamTimeoutMs?: number;
  readonly fetchImpl?: typeof fetch;
}

/** Released POMs never change once published (Maven Central forbids it), so they are cached without expiry. */
export function isCacheable(repoPath: string): boolean {
  return repoPath.endsWith('.pom') && !repoPath.includes('SNAPSHOT');
}

/** A repository path we are willing to forward and store: plain segments only, no traversal, no query. */
export function safeRepoPath(urlPath: string): string | null {
  let p: string;
  try {
    p = decodeURIComponent(urlPath);
  } catch {
    return null;
  }
  if (!/^\/[A-Za-z0-9._+\-/]+$/.test(p)) return null;
  const segments = p.slice(1).split('/');
  if (segments.some((s) => s === '' || s === '.' || s === '..')) return null;
  return segments.join('/');
}

/**
 * A local, caching Maven repository for Trivy. Trivy resolves a Java project's parent POMs and BOMs one HTTP request
 * at a time and keeps nothing between scans, so a large Maven project re-downloads the same few thousand POMs on
 * every scan (JeecgBoot: 13.5 min). Trivy's settings.xml mirror points here; released POMs are served from disk after
 * the first scan, everything else passes straight through to the upstream repository (status, Retry-After and all).
 *
 * Bodies are streamed to a temporary file and renamed into place, so memory stays flat and a half-written file is
 * never served. Concurrent misses for one path share a single download.
 */
export class MavenCacheProxy {
  private server: http.Server | undefined;
  /** Downloads in progress; each resolves to whether the file was stored. */
  private readonly inflight = new Map<string, Promise<boolean>>();
  private sizeBytes = 0;
  private pruning: Promise<void> | undefined;
  private readonly upstream: string;
  private readonly fetchImpl: typeof fetch;

  constructor(private readonly opts: MavenCacheProxyOptions) {
    this.upstream = opts.upstream.endsWith('/') ? opts.upstream : `${opts.upstream}/`;
    this.fetchImpl = opts.fetchImpl ?? fetch;
  }

  /** Listen on a random loopback port; resolves to the repository URL to give Trivy. */
  async start(): Promise<string> {
    await mkdir(this.opts.dir, { recursive: true });
    for (const e of await readdir(this.opts.dir)) {
      if (e.startsWith('.tmp-')) await rm(path.join(this.opts.dir, e), { force: true }); // left by a hard kill
    }
    this.sizeBytes = await directorySize(this.opts.dir);
    const server = http.createServer((req, res) => {
      void this.handle(req, res);
    });
    this.server = server;
    await new Promise<void>((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', () => {
        resolve();
      });
    });
    server.unref();
    const { port } = server.address() as AddressInfo;
    this.opts.log.info({ port, cachedMb: Math.round(this.sizeBytes / 1048576) }, 'maven cache proxy listening');
    return `http://127.0.0.1:${String(port)}/maven2/`;
  }

  async close(): Promise<void> {
    const server = this.server;
    if (server === undefined) return;
    this.server = undefined;
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => {
      resolve();
    }));
  }

  private async handle(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    const url = req.url ?? '/';
    const repoPath = url.startsWith('/maven2/') && !url.includes('?') ? safeRepoPath(url.slice('/maven2'.length)) : null;
    if ((req.method !== 'GET' && req.method !== 'HEAD') || repoPath === null) {
      res.writeHead(repoPath === null ? 400 : 405).end();
      return;
    }
    try {
      if (!isCacheable(repoPath)) {
        await this.forward(await this.fetchUpstream(repoPath, req.method === 'HEAD' ? 'HEAD' : 'GET'), req, res);
      } else if (!(await this.serveCached(repoPath, req, res))) {
        await this.miss(repoPath, req, res);
      }
    } catch (err) {
      this.opts.log.warn({ err, path: repoPath }, 'maven cache proxy request failed');
      if (!res.headersSent) res.writeHead(502);
      res.end();
    }
  }

  private fileFor(repoPath: string): string {
    return path.join(this.opts.dir, ...repoPath.split('/'));
  }

  private async serveCached(repoPath: string, req: http.IncomingMessage, res: http.ServerResponse): Promise<boolean> {
    const file = this.fileFor(repoPath);
    let size: number;
    try {
      size = (await stat(file)).size;
    } catch {
      return false;
    }
    const now = new Date();
    void utimes(file, now, now).catch(() => undefined); // recency for eviction
    res.writeHead(200, { 'content-type': 'text/xml', 'content-length': size, 'x-cache': 'HIT' });
    if (req.method === 'HEAD') {
      res.end();
      return true;
    }
    await pipeline(createReadStream(file), res);
    return true;
  }

  /**
   * A cacheable file that is not on disk yet. One upstream request per miss: a 200 is stored and then served from
   * disk; anything else (404, 429 + Retry-After, 5xx) is forwarded as is, so upstream sees no extra traffic. Requests
   * for the same file meanwhile wait for that download instead of starting their own.
   */
  private async miss(repoPath: string, req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    const pending = this.inflight.get(repoPath);
    if (pending !== undefined) {
      if ((await pending) && (await this.serveCached(repoPath, req, res))) return;
      await this.forward(await this.fetchUpstream(repoPath, req.method === 'HEAD' ? 'HEAD' : 'GET'), req, res);
      return;
    }
    let settle: (stored: boolean) => void = () => undefined;
    this.inflight.set(repoPath, new Promise<boolean>((resolve) => (settle = resolve)));
    let stored = false;
    try {
      const upstream = await this.fetchUpstream(repoPath, 'GET');
      if (upstream.status !== 200 || upstream.body === null) {
        await this.forward(upstream, req, res);
        return;
      }
      await this.store(repoPath, upstream.body as WebReadableStream<Uint8Array>);
      stored = true;
    } finally {
      settle(stored);
      this.inflight.delete(repoPath);
    }
    if (!(await this.serveCached(repoPath, req, res))) throw new Error('cached file disappeared'); // evicted at once
  }

  private async store(repoPath: string, body: WebReadableStream<Uint8Array>): Promise<void> {
    const file = this.fileFor(repoPath);
    const tmp = path.join(this.opts.dir, `.tmp-${randomUUID()}`);
    await mkdir(path.dirname(file), { recursive: true });
    try {
      await pipeline(Readable.fromWeb(body), createWriteStream(tmp));
      const { size } = await stat(tmp);
      await rename(tmp, file);
      this.sizeBytes += size;
    } catch (err) {
      await rm(tmp, { force: true });
      throw err;
    }
    if (this.sizeBytes > this.opts.maxBytes) void this.prune();
  }

  /** Relay an upstream response: status, the headers a Maven client uses, and the body (streamed). */
  private async forward(upstream: Response, req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    const headers: Record<string, string> = { 'x-cache': 'MISS' };
    for (const name of ['content-type', 'content-length', 'retry-after', 'last-modified', 'etag']) {
      const v = upstream.headers.get(name);
      if (v !== null) headers[name] = v;
    }
    res.writeHead(upstream.status, headers);
    if (upstream.body === null || req.method === 'HEAD') {
      await upstream.body?.cancel();
      res.end();
      return;
    }
    await pipeline(Readable.fromWeb(upstream.body as WebReadableStream<Uint8Array>), res);
  }

  private fetchUpstream(repoPath: string, method: 'GET' | 'HEAD'): Promise<Response> {
    return this.fetchImpl(`${this.upstream}${repoPath}`, {
      method,
      redirect: 'follow',
      signal: AbortSignal.timeout(this.opts.upstreamTimeoutMs ?? 30_000),
    });
  }

  /** Evict least recently used files until the cache is back under 80 % of its limit. One pass at a time. */
  prune(): Promise<void> {
    this.pruning ??= (async () => {
      try {
        const files = await listFiles(this.opts.dir);
        files.sort((a, b) => a.mtimeMs - b.mtimeMs);
        let total = files.reduce((n, f) => n + f.size, 0);
        const target = this.opts.maxBytes * 0.8;
        for (const f of files) {
          if (total <= target) break;
          await rm(f.path, { force: true });
          total -= f.size;
        }
        this.sizeBytes = total;
      } catch (err) {
        this.opts.log.warn({ err }, 'maven cache prune failed');
      } finally {
        this.pruning = undefined;
      }
    })();
    return this.pruning;
  }
}

interface FileEntry {
  readonly path: string;
  readonly size: number;
  readonly mtimeMs: number;
}

async function listFiles(dir: string): Promise<FileEntry[]> {
  const out: FileEntry[] = [];
  const entries = await readdir(dir, { withFileTypes: true, recursive: true });
  for (const e of entries) {
    if (!e.isFile()) continue;
    const p = path.join(e.parentPath, e.name);
    try {
      const s = await stat(p);
      out.push({ path: p, size: s.size, mtimeMs: s.mtimeMs });
    } catch {
      // removed meanwhile
    }
  }
  return out;
}

async function directorySize(dir: string): Promise<number> {
  return (await listFiles(dir)).reduce((n, f) => n + f.size, 0);
}
