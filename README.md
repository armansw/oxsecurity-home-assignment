# Code Guardian

Node.js + TypeScript service that wraps Trivy: clones a GitHub repo, **stream-parses** the JSON report, keeps only `CRITICAL` findings, deletes the clone and report, and serves results over REST and GraphQL. Built to run in a 200 MB container.

[![CI](https://github.com/armansw/oxsecurity-home-assignment/actions/workflows/ci.yml/badge.svg)](https://github.com/armansw/oxsecurity-home-assignment/actions/workflows/ci.yml) · **Live:** https://oxhometask.armstep.com · **Video:** [docs/demo.mp4](docs/demo.mp4) (34 s)

## Proof

| Run | Result |
|---|---|
| 600 MB report, all findings in one `Results[0]`, `node --max-old-space-size=150` | peak heap **47 MB**, 14,041/14,041 CRITICAL stored, 25 s |
| Same report, whole service in Docker `mem_limit: 200m` / `150m`, no swap (CI) | Finished, `OOMKilled=false`, peak 97 / 94 MiB |
| Real Trivy scan of [armansw/NodeGoat](https://github.com/armansw/NodeGoat) in the 200 MB container (CI) | Finished, 12 CRITICAL |
| [Large repositories](#large-repositories) (next.js, vscode, kubernetes, …), every CRITICAL checked against Trivy | see table below |

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
- **Ops:** `/healthz`, `/readyz`, `/metrics` (Prometheus, including peak RSS per scan).

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
5. **Trivy and git sharing the memory limit.**
6. **Dirty page cache.** CI caught an OOM kill while the heap was only 46 MB.

## Design

- **Layers:** `interfaces` (REST, GraphQL) → `application` (ScanService, ScanProcessor) → `domain` (types, ports) ← `infrastructure` (SQLite, git, Trivy, streams). The `worker/` claims jobs.
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

CI runs it nightly and on `main`.

<!-- LARGE-REPOS-RESULTS -->

## Configuration

All environment variables are optional and validated at boot. See [.env.example](.env.example).
