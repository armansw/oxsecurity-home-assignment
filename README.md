# Code Guardian

Node.js + TypeScript service that wraps Trivy: clones a GitHub repo, **stream-parses** the JSON report, keeps only `CRITICAL` findings, deletes the clone and report, and serves results over REST and GraphQL. The service runs within 150 MB, page cache included.

[![CI](https://github.com/armansw/oxsecurity-home-assignment/actions/workflows/ci.yml/badge.svg)](https://github.com/armansw/oxsecurity-home-assignment/actions/workflows/ci.yml) · **Live:** https://oxhometask.armstep.com · **Video:** [docs/demo.mp4](docs/demo.mp4) (34 s)

## Proof

| Run | Result |
|---|---|
| 600 MB report, all findings in one `Results[0]`, `node --max-old-space-size=150` | peak heap **47 MB**, 14,041/14,041 CRITICAL stored, 25 s |
| Same report, whole service in Docker `mem_limit: 200m` / `150m`, no swap (CI) | Finished, `OOMKilled=false`, peak 97 / 94 MiB |
| Real Trivy scan of [armansw/NodeGoat](https://github.com/armansw/NodeGoat) in the 200 MB container (CI) | Finished, 12 CRITICAL |
| [Large repositories](#large-repositories) (next.js, vscode, kubernetes, …), service capped at **150 MB**, every CRITICAL checked against Trivy | 7/7 exact; peak **94 MiB incl. cache**, limit never reached, 0 OOM kills |
| [152-repository corpus](#large-repositories) (9 ecosystems), burst-submitted, 8 parallel CI shards, service at **150 MB** | **152/152** exact (793 CRITICAL of 15,631 findings); peak **96 MiB incl. cache**, limit never reached, 0 OOM kills ([run](https://github.com/armansw/oxsecurity-home-assignment/actions/runs/42893164579)) |

`fs.readFile` and `JSON.parse` are banned across `src/` by ESLint and a CI grep.

## Run

```bash
./run.sh            # needs only bash, git, tar, curl → UI http://localhost:5173, API http://localhost:3000
```

Missing Node (≥ 22.12) or Trivy is downloaded, checksum-verified, into a local `.cg-env/`, with no root and no global installs. Other commands: `./run.sh docker | test | oom-check | doctor | clean`. On Windows, use WSL2 or Docker.

| Alternative | Command |
|---|---|
| Docker (200 MB app, Trivy sidecar, UI on :8080) | `docker compose up --build` |
| The brief's self-test | `npm ci && npm run build && node --max-old-space-size=150 dist/index.js` (needs `git` + `trivy`) |
| Memory proof | `npm run oom:check` |

## API

```bash
curl -X POST localhost:3000/api/scan -H 'content-type: application/json' \
     -d '{"repoUrl":"https://github.com/armansw/NodeGoat"}'      # → 202 {"scanId":"…","status":"Queued"}
curl localhost:3000/api/scan/<scanId>                            # → Queued | Scanning | Finished | Failed
```

- **Finished** responses include `criticalVulnerabilities`, the full list, streamed at constant memory. `?limit=&cursor=` returns one page.
- **GraphQL** at `/graphql`: `startScan(repoUrl)` and `scan(id) { id status criticalVulnerabilities { … } }`, using the brief's exact types (GraphiQL at `/graphiql`).
- **Errors** use one envelope, `{"error":{"code","message"}}`. A failed scan carries a stable code: `REPO_NOT_FOUND`, `SCANNER_FAILED`, `DISK_FULL`, ….
- **Ops:** `/healthz`, `/readyz`, `/metrics` (Prometheus, including peak RSS per scan), `/api/system/memory` (live memory against the real limit).
- **Self-test:** `POST /api/test-runs {"size":1..100}` scans a random sample of the corpus below (repositories ≤ 500 MB, spread across ecosystems) on the running service; `GET /api/test-runs/latest` reports each scan's result and peak memory, plus the kernel's limit-hit and OOM-kill counters for the run. One run at a time; its scans queue behind users' scans. The UI's **Run self-test** button drives it.

## How it stays within memory

```
createReadStream ─► stream-json tokenizer ─► token-level extractor ─► 500-row SQLite batches
                    (fused in one stream-chain stage: one vulnerability in memory at a time)
```

Six traps, each closed and explained in [docs/MEMORY.md](docs/MEMORY.md):

1. **One giant `Results[0]`.** Streaming whole results would still build that object.
2. **Collecting results in an array.**
3. **`JSON.stringify` of the response.**
4. **A tmpfs workspace.**
5. **Trivy and git sharing the memory limit.** They now run in their own scanner container.
6. **Dirty page cache.** CI caught an OOM kill while the heap was only 46 MB.

## Design

- **Layers:** `interfaces` (REST, GraphQL) → `application` (ScanService, ScanProcessor) → `domain` (types, ports) ← `infrastructure` (SQLite, git, Trivy, streams). The `worker/` claims jobs.
- **Topology:** the service container (API, worker, stream parser) and a `scanner` container (`ROLE=scanner`: git + Trivy, own memory budget) share the work volume. A huge repo can't starve or OOM-kill the service. `node dist/index.js` alone still runs everything in-process.
- **Queue:** SQLite is both the state store and a durable job queue. It provides atomic claims, leases with fencing, retries with backoff, and recovery from crashes or OOM kills. Nothing else to run.
- **Every failure ends** in `Failed` with a stable code, or in a retry. The clone and report are always deleted. [Error table](docs/ARCHITECTURE.md#error-taxonomy).
- **Security:**
  - the URL allow-list blocks SSRF, `file://` and option injection;
  - git and Trivy run without a shell, in a minimal environment;
  - single values over 1 MiB in a report are rejected, so hostile reports can't exhaust memory;
  - scan creation is rate-limited on both REST and GraphQL;
  - the container runs non-root with all capabilities dropped.

Decisions and trade-offs: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). Deployment (systemd + Caddy, same 200 MB limit): [deploy/](deploy/README.md).

## Tests

226 backend and 75 frontend tests (~99 % line coverage), plus CI end-to-end runs:

- Docker at 200 MB and at 150 MB;
- the web image and its nginx proxy;
- the split API and worker containers;
- `./run.sh` from scratch on Linux and macOS.

## Large repositories

`scripts/large_repos_e2e.py` scans each repository in [test/large/repos.txt](test/large/repos.txt) through the running service. It then independently runs Trivy on **the same commit**, against the same DB, and parses that report with Python's `json`, which shares no code with ours. The test requires:

- **an exact match** of every CRITICAL finding and of the total finding count;
- **no OOM kill;**
- **an empty workspace;**
- **a ready service** afterwards.

CI runs the 7 repositories on `main` and nightly. It runs the [152-repository corpus](test/large/corpus.tsv) weekly and on demand: 8 parallel shards, each submitting all of its repositories at once. The corpus is built by `scripts/build_corpus.py` from the GitHub API: large, popular repositories across npm, Go, Python, Rust, Ruby, PHP, Java and .NET.

Corpus run, 2026-11-10 ([GitHub Actions](https://github.com/armansw/oxsecurity-home-assignment/actions/runs/42893164579)): **152/152 passed**. That's 15,631 findings, of which 793 CRITICAL, all matched exactly. The service container held 150 MiB hard: peak 96 MiB including page cache, the limit reached 0 times, 0 OOM kills. Two earlier runs found and fixed real issues: an unbounded recursive delete in Node, Maven Central rate limits, and a harness that perturbed the container it measured. See the git log.

Live deployment, service hard-capped at 150 MB (`MemoryMax=150M`, no swap, no soft limit), strict mode, 2026-11-10:

| Repository | Findings | CRITICAL (service / Trivy) | Report | Time |
|---|---|---|---|---|
| armansw/NodeGoat | 93 | 12 / 12 | 0.55 MB | 3 s |
| snyk-labs/nodejs-goof | 241 | 37 / 37 | 1.18 MB | 3 s |
| vercel/next.js | 378 | 15 / 15 | 3.41 MB | 21 s |
| microsoft/vscode | 75 | 4 / 4 | 1.16 MB | 21 s |
| grafana/grafana | 26 | 0 / 0 | 2.78 MB | 21 s |
| kubernetes/kubernetes | 10 | 0 / 0 | 0.89 MB | 39 s |
| getsentry/sentry | 15 | 0 / 0 | 0.55 MB | 12 s |

Service memory over the whole run: peak **94 MiB including page cache** against the 150 MiB limit. The limit was reached 0 times, with 0 OOM kills.

## Configuration

All environment variables are optional and validated at boot. See [.env.example](.env.example).
