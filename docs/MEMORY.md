# Memory design

The service must process a 500 MB+ Trivy report in a container of about 200 MB, under `node --max-old-space-size=150`. This document explains where memory goes, why it is bounded, and how that is verified.

## The pipeline

```
fs.createReadStream(report, { encoding: 'utf8', highWaterMark: 256 KiB })
  └─► stream-chain [ jsonParser (sync tokenizer) ─► CriticalVulnerabilityExtractor ]   one Duplex, fused
        └─► VulnerabilityBatchWriter (objectMode Writable, highWaterMark 64) ─► SQLite, 500 rows / txn
```

All of it is wired with `stream/promises.pipeline` and an `AbortSignal`. That gives three guarantees:

- **Backpressure end to end.** When SQLite is slow, the writer's buffer fills, the chain stops reading, and the file stream pauses.
- **Teardown on any error or abort.** No half-open file descriptors, and no zombie stages.
- **First-error semantics.** The scan fails with the actual cause.

## What each stage holds

| Stage | Holds at most | Bounded by |
|---|---|---|
| read stream | one 256 KiB chunk (as a string) | `highWaterMark` |
| tokenizer | the current partial token; one packed string or number | `maxPackedLength` = 1 MiB, `maxDepth` = 64 |
| extractor | a stack of `{kind, key}` frames + **one** vulnerability object | nesting depth; size of one finding (a few KB) |
| writer | ≤ 64 queued findings + ≤ 500 in the current batch | `highWaterMark`, `BATCH_SIZE` |
| SQLite | 4 MB page cache, off-heap | `PRAGMA cache_size = -4000` |

None of these grows with report size. That is the whole point.

## The six memory traps

### 1. The single-result trap

Trivy groups findings per target:

```jsonc
{ "Results": [ { "Target": "package-lock.json", "Packages": [ … ], "Vulnerabilities": [ {…}, {…}, … ] } ] }
```

A 500 MB report from a large monorepo lockfile is typically **one** `Results[0]` object. The common streaming answer, `StreamArray` over `Results`, emits each *element* of `Results` fully assembled. With one element, that means assembling the entire 500 MB object, so it OOMs exactly like `JSON.parse`, only more slowly.

`CriticalVulnerabilityExtractor` walks the token stream with a small stack. It recognises the exact position `Results[i].Vulnerabilities[j]`. Only there does it start a short-lived `Assembler` for one object, which is validated with zod and then dropped. `Packages`, `Metadata`, nested `Vulnerabilities` keys elsewhere, and non-critical findings are walked token by token and never built. The OOM harness uses this worst-case layout by default.

### 2. The accumulate-in-an-array trap

Even a perfect streaming parser OOMs if it does `criticals.push(v)` for the whole scan: 30 % critical in 500 MB is 150 MB of objects. Findings leave the process in 500-row transactions as they are found.

### 3. The egress trap

Serving the result as `reply.send({ ..., criticalVulnerabilities: allRows })` re-materialises the result set, twice: rows plus the JSON string. `GET /api/scan/:id` instead returns a `Readable` built from a generator. The generator yields the header and then one keyset page (`row_id > ?`, 500 rows) at a time. `Readable.from` pulls the next page only when the socket drains, so a slow client holds one page. No SQLite cursor stays open between pages, so the worker is never blocked by a reader. GraphQL and the UI use explicit pagination, with page size capped at 1000.

### 4. The tmpfs trap

On tmpfs, or a Kubernetes `emptyDir` with `medium: Memory`, every byte written counts toward the container's memory cgroup. A 500 MB report on tmpfs OOM-kills a 200 MB container *no matter how well the parser streams*. `WORK_DIR` is a disk-backed named volume in compose. On Kubernetes, use a disk-backed `emptyDir` (no `medium: Memory`) with a `sizeLimit`, or a PVC. Reading a file on disk does fill the page cache, but those pages are clean and reclaimable, so the kernel drops them under pressure instead of killing the process.

### 5. The child-process trap

`mem_limit` applies to the container's cgroup: Node **plus** `git` **plus** Trivy. The phases are sequential (clone, then scan, then parse), and worker concurrency is 1, so their peaks do not stack. Trivy measured on NodeGoat:

| Mode | Peak RSS | Anonymous | File-backed |
|---|---|---|---|
| standalone | 142 MB | 32 MB | 88 MB |
| client (`--server`) | 128 MB | 27 MB | 87 MB |

The file-backed part is mostly the 176 MB binary and the memory-mapped vulnerability DB. It is reclaimable, which is why RSS overstates real pressure. The decisive difference is that standalone mode downloads, decompresses and mmaps a **1.7 GB** database inside the container. In Docker the DB lives in the Trivy server sidecar. Trivy also runs with `GOMEMLIMIT=64MiB` (Go soft heap limit) and `--parallel 1`. If an extreme repository still exceeds the budget, the kernel kills Trivy (`SIGKILL`). The service classifies that as `SCANNER_KILLED` (retryable) instead of dying itself. In the split deployment, the API container is unaffected either way.

One caveat. Trivy marshals its report from an in-memory structure, so producing a *genuinely* 500 MB report needs far more than 200 MB inside Trivy itself. At that scale, Trivy runs outside the constrained pod (a scan job or a bigger sidecar) and hands over the file. The constraint this service is built for, and what the assignment tests, is *consuming* such a report. The fixture scanner models exactly that hand-over.

**Measured outcome on large repositories.** With git and Trivy inside a 150 MB cap shared with the service, kubernetes either stalled the API under memory throttling or got Trivy OOM-killed. systemd's default `OOMPolicy=stop` then stopped the whole service. The service now (a) spawns git and Trivy with `oom_score_adj=1000`, so they are always the OOM killer's choice, (b) runs with `OOMPolicy=continue`, and (c) in the default Compose and live topologies, delegates git and Trivy to a separate scanner container (ADR-8). Result: the service peaks at 129 MiB including page cache on the same repositories, without ever reaching the 150 MiB limit.

### 6. The dirty-page-cache trap (found by CI)

Page cache is charged to the container's memory cgroup. Clean pages are reclaimable; **dirty** pages are not reclaimable until they have been written back. The first CI run of the 600 MB fixture inside the 200 MB container was OOM-killed while *writing* the report. The kernel log showed:

```
libuv-worker invoked oom-killer: gfp_mask=…(GFP_HIGHUSER_MOVABLE|__GFP_WRITE), order=3
Memory cgroup out of memory: Killed process (node) anon-rss:46372kB, file-rss:55168kB
```

The heap was 46 MB. The cgroup was full of dirty pages that the runner's disk had not flushed yet. The same run passed on a host with a faster disk, which makes this an environment-dependent failure that is easy to miss. The fix is `SyncedFileWriteStream`, which calls `fdatasync` every 8 MB so unflushed data stays bounded. Reading is unaffected: pages read from disk are clean and are dropped under pressure. A local run under an equivalent cgroup (`MemoryMax=200M`, no swap) shows the shape. Anonymous memory peaked at 75 MB. Total cgroup usage sat at the 200 MB limit throughout, made up of reclaimable cache, with `oom_kill 0`.

## Other bounded buffers

- **Child output.** stdout is ignored and stderr is a ring buffer of 8 KiB. A chatty Trivy cannot grow the heap.
- **Request bodies.** 4 KiB on `POST /api/scan`, and 64 KiB globally.
- **Single values in a report.** Over 1 MiB, the report is rejected (`REPORT_INVALID`). This bounds memory for *malicious* reports, not just well-formed ones.
- **Stored descriptions.** Truncated to 4 KiB.

## Throughput

The stream-json `parser()` entry point wraps the tokenizer in an async generator: one `await` per token, and parse errors thrown lazily. The pipeline uses the synchronous core `jsonParser` instead, fused with the extractor in one `stream-chain` stage. UTF-8 chunk boundaries are handled by the read stream's `encoding: 'utf8'` decoder, which is covered by tests feeding 1-character chunks of multibyte text. This took the 600 MB parse from 76 s to 25 s (8 → 24 MB/s), measured with the process capped at 60 % of one CPU.

## Verification

| Check | Command | Result |
|---|---|---|
| 600 MB single-Result report, 150 MB heap | `npm run oom:check` | peak heapUsed **47 MB**, peak RSS 130 MB, 14,041/14,041 CRITICAL stored |
| every finding CRITICAL (store + egress path) | `node --max-old-space-size=150 dist/scripts/oom-check.js --size-mb 300 --critical-ratio 1` | runs in CI |
| whole service in the 200 MB container | `docker compose -f docker-compose.yml -f docker-compose.oom.yml up -d` + `./scripts/e2e-docker.sh --fixture` | CI `docker-e2e`: Finished, `OOMKilled=false`, empty workspace |
| real Trivy in the 200 MB container | `docker compose up -d` + `./scripts/e2e-docker.sh` | CI `docker-e2e` |
| forbidden APIs absent | ESLint rule + CI grep | enforced |

Heap use samples during the 600 MB run stayed between 18 and 39 MB from 10 % to 90 % progress. They oscillate with GC and do not trend upward with bytes read.
