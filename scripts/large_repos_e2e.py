#!/usr/bin/env python3
"""
Large-repository end-to-end verification for Code Guardian.

For every repository in the corpus it:
  1. submits the repo to the RUNNING service (POST /api/scan) and polls until a terminal status;
  2. fetches the service's full, streamed result (GET /api/scan/:id, unpaginated);
  3. independently computes the ground truth: checks out the exact commit the service scanned, runs Trivy with
     the same flags against the same Trivy server (same vulnerability DB), and parses the report with Python's
     json module, an implementation that shares no code with the service;
  4. asserts the CRITICAL findings match exactly (as a multiset) and the total finding count matches;
  5. asserts the memory/cleanup invariants: no OOM kill, cgroup peak under the limit, empty workspace, and the
     service still ready afterwards.

Usage (against a docker compose stack, as in CI):
  python3 scripts/large_repos_e2e.py --api http://localhost:3000 --trivy-server http://localhost:4954 \
      --trivy-token change-me-local-token --container "$(docker compose ps -q app)"
Usage (against a systemd deployment):
  python3 scripts/large_repos_e2e.py --api http://127.0.0.1:8795 --trivy-server http://127.0.0.1:4954 \
      --trivy-token "$TRIVY_TOKEN" --cgroup /sys/fs/cgroup/system.slice/code-guardian.service \
      --work-dir /var/lib/private/code-guardian/work

Exit status is non-zero if any check fails. A Markdown summary is appended to $GITHUB_STEP_SUMMARY when set.
"""
from __future__ import annotations

import argparse
import collections
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request

TERMINAL = {"Finished", "Failed"}


def http_json(method: str, url: str, body: dict | None = None, timeout: int = 120) -> dict:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={"content-type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as res:
        return json.loads(res.read())


def run(cmd: list[str], cwd: str | None = None, timeout: int = 3600, env: dict | None = None) -> str:
    out = subprocess.run(cmd, cwd=cwd, timeout=timeout, env=env, check=True, capture_output=True, text=True)
    return out.stdout


def scan_with_service(api: str, repo: str, timeout_s: int) -> dict:
    started = time.time()
    created = http_json("POST", f"{api}/api/scan", {"repoUrl": repo})
    assert created.get("status") == "Queued", f"POST should answer Queued, got {created}"
    scan_id = created["scanId"]
    last_phase = None
    while True:
        head = http_json("GET", f"{api}/api/scan/{scan_id}?limit=1")
        phase = (head["status"], head.get("phase"))
        if phase != last_phase:
            print(f"    {time.time() - started:6.1f}s  {head['status']}{' · ' + head['phase'] if head.get('phase') else ''}", flush=True)
            last_phase = phase
        if head["status"] in TERMINAL:
            break
        if time.time() - started > timeout_s:
            raise TimeoutError(f"scan {scan_id} did not finish within {timeout_s}s")
        time.sleep(3)
    full = http_json("GET", f"{api}/api/scan/{scan_id}", timeout=600) if head["status"] == "Finished" else head
    full["_wall_s"] = round(time.time() - started, 1)
    return full


def ground_truth(repo: str, sha: str, args: argparse.Namespace, scratch: str) -> dict:
    src = os.path.join(scratch, "src")
    report = os.path.join(scratch, "report.json")
    os.makedirs(src)
    run(["git", "init", "-q", src])
    run(["git", "-C", src, "fetch", "-q", "--depth", "1", repo, sha], timeout=1800)
    run(["git", "-C", src, "checkout", "-q", "FETCH_HEAD"])
    # Identical flags to src/infrastructure/scanner/trivy-scanner.ts (client/server mode).
    run(
        [args.trivy_bin, "fs", "--scanners", "vuln", "--format", "json", "--output", report, "--quiet",
         "--no-progress", "--parallel", "1", "--timeout", "1800s", "--cache-dir", os.path.join(scratch, "cache"),
         *(["--offline-scan"] if args.trivy_offline else []),
         "--server", args.trivy_server, "--token", args.trivy_token, src],
        timeout=2400,
    )
    size = os.path.getsize(report)
    with open(report, encoding="utf-8") as fh:
        data = json.load(fh)
    total = 0
    critical: collections.Counter = collections.Counter()
    for result in data.get("Results") or []:
        for v in result.get("Vulnerabilities") or []:
            total += 1
            if v.get("Severity") == "CRITICAL":
                critical[(v["VulnerabilityID"], v["PkgName"], v.get("InstalledVersion") or "", result.get("Target") or "")] += 1
    return {"total": total, "critical": critical, "report_bytes": size}


def service_criticals(full: dict) -> collections.Counter:
    c: collections.Counter = collections.Counter()
    for v in full.get("criticalVulnerabilities", []):
        c[(v["id"], v["pkgName"], v.get("installedVersion") or "", v.get("target") or "")] += 1
    return c


class CgroupReader:
    """Reads the service's cgroup v2 files, directly (systemd) or through `docker exec` (container)."""

    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.host_dir = args.cgroup
        if args.container and not self.host_dir:
            # Read the container's cgroup from the HOST: `docker exec` would start a runc process inside the
            # container's own cgroup on every sample and perturb the very memory being measured (it once
            # triggered an OOM kill in a 150 MB container).
            full_id = run(["docker", "inspect", "-f", "{{.Id}}", args.container]).strip()
            for candidate in (f"/sys/fs/cgroup/system.slice/docker-{full_id}.scope", f"/sys/fs/cgroup/docker/{full_id}"):
                if os.path.exists(os.path.join(candidate, "memory.events")):
                    self.host_dir = candidate
                    break
        print(f"cgroup source: {self.host_dir or 'docker exec (fallback)'}")

    def read(self, name: str) -> str:
        if self.host_dir:
            with open(os.path.join(self.host_dir, name), encoding="utf-8") as fh:
                return fh.read()
        return run(["docker", "exec", self.args.container, "cat", f"/sys/fs/cgroup/{name}"], timeout=30)

    def events(self) -> dict:
        return {k: int(v) for k, v in (line.split() for line in self.read("memory.events").splitlines())}

    def usage(self) -> tuple[int, int]:
        """(total incl. page cache, working set = total - inactive_file), the value Kubernetes evicts on."""
        current = int(self.read("memory.current"))
        stat = dict(line.split() for line in self.read("memory.stat").splitlines())
        return current, current - int(stat.get("inactive_file", 0))


class Sampler(threading.Thread):
    """Samples total and working-set memory while a scan runs."""

    def __init__(self, reader: CgroupReader, interval: float) -> None:
        super().__init__(daemon=True)
        self.reader, self.interval = reader, interval
        self.peak_total = self.peak_ws = 0
        self._halt = threading.Event()

    def run(self) -> None:
        while not self._halt.is_set():
            try:
                total, ws = self.reader.usage()
                self.peak_total, self.peak_ws = max(self.peak_total, total), max(self.peak_ws, ws)
            except (OSError, subprocess.SubprocessError, ValueError):
                pass
            self._halt.wait(self.interval)

    def stop(self) -> None:
        self._halt.set()
        self.join()


def memory_state(args: argparse.Namespace) -> dict:
    """Peak memory + OOM evidence for the service's container or systemd cgroup."""
    state: dict = {}
    if args.container:
        inspect = json.loads(run(["docker", "inspect", args.container]))[0]
        state["oom_killed"] = inspect["State"]["OOMKilled"]
        state["restarts"] = inspect["RestartCount"]
        state["running"] = inspect["State"]["Running"]
        state["limit_mb"] = inspect["HostConfig"]["Memory"] // (1024 * 1024)
        if not state["running"]:
            return state
        listing = run(["docker", "exec", args.container, "sh", "-c", "ls -A /work | grep '^scan-' || true"])
        state["leftover_workspaces"] = len([line for line in listing.splitlines() if line.strip()])
    elif args.cgroup:
        def read(name: str) -> str:
            with open(os.path.join(args.cgroup, name), encoding="utf-8") as fh:
                return fh.read()
        events = dict(line.split() for line in read("memory.events").splitlines())
        state["oom_killed"] = int(events.get("oom_kill", "0")) > 0
        state["peak_mb"] = int(read("memory.peak")) // (1024 * 1024)
        limit = read("memory.max").strip()
        state["limit_mb"] = None if limit == "max" else int(limit) // (1024 * 1024)
        if args.work_dir:
            state["leftover_workspaces"] = len([n for n in os.listdir(args.work_dir) if n.startswith("scan-")])
    return state


def load_repos(path: str) -> list[str]:
    """repos.txt (one URL per line) or corpus.tsv (URL in the first column); '#' starts a comment."""
    repos = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            first = line.split("#")[0].strip().split("\t")[0].strip()
            if first:
                repos.append(first)
    return repos


def verify(full: dict, repo: str, args: argparse.Namespace) -> tuple[dict, list[str]]:
    """Compare one finished service result with the independent Trivy ground truth."""
    row: dict = {"status": full["status"], "commit": full.get("commitSha"), "wall_s": full.get("_wall_s")}
    problems: list[str] = []
    if full["status"] != "Finished":
        problems.append(f"service status {full['status']}: {full.get('error')}")
        return row, problems
    stats = full["stats"]
    row.update(scanned=stats["vulnerabilitiesScanned"], critical=full["criticalCount"],
               report_mb=round(stats["reportBytes"] / 1048576, 2), peak_rss_mb=stats["peakMemoryMb"])
    if len(full["criticalVulnerabilities"]) != full["criticalCount"]:
        problems.append("streamed list length != criticalCount")
    if not full.get("commitSha"):
        problems.append("no commitSha recorded")
        return row, problems
    if args.no_verify:
        return row, problems
    scratch = tempfile.mkdtemp(prefix="cg-large-")
    try:
        truth = ground_truth(repo, full["commitSha"], args, scratch)
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    row.update(truth_scanned=truth["total"], truth_critical=sum(truth["critical"].values()))
    if truth["total"] != stats["vulnerabilitiesScanned"]:
        problems.append(f"vulnerabilitiesScanned {stats['vulnerabilitiesScanned']} != trivy {truth['total']}")
    mine = service_criticals(full)
    if mine != truth["critical"]:
        missing, extra = truth["critical"] - mine, mine - truth["critical"]
        problems.append(f"CRITICAL mismatch: {sum(missing.values())} missing, {sum(extra.values())} extra "
                        f"(e.g. {list(missing or extra)[:2]})")
    return row, problems


def run_burst(repos: list[str], args: argparse.Namespace) -> dict[str, dict]:
    """Submit every repository at once, then poll all of them until each reaches a terminal status."""
    started = time.time()
    ids: dict[str, str] = {}
    for repo in repos:
        created = http_json("POST", f"{args.api}/api/scan", {"repoUrl": repo})
        if created.get("status") != "Queued":
            raise AssertionError(f"POST should answer Queued, got {created}")
        ids[repo] = created["scanId"]
    print(f"submitted {len(ids)} scans in {time.time() - started:.1f}s (all Queued)", flush=True)
    done: dict[str, dict] = {}
    while len(done) < len(ids):
        if time.time() - started > args.timeout * max(1, len(ids)):
            raise TimeoutError(f"burst did not finish: {len(done)}/{len(ids)} done")
        for repo, scan_id in ids.items():
            if repo in done:
                continue
            head = http_json("GET", f"{args.api}/api/scan/{scan_id}?limit=1")
            if head["status"] in TERMINAL:
                full = http_json("GET", f"{args.api}/api/scan/{scan_id}", timeout=600) if head["status"] == "Finished" else head
                full["_wall_s"] = round(time.time() - started, 1)
                done[repo] = full
                print(f"  [{len(done):>3}/{len(ids)}] {head['status']:<8} {repo}  "
                      f"critical={full.get('criticalCount', '–')}  t={full['_wall_s']}s", flush=True)
        time.sleep(5)
    return done


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--api", default="http://localhost:3000")
    p.add_argument("--repos", default=os.path.join(os.path.dirname(__file__), "..", "test", "large", "repos.txt"),
                   help="repos.txt or corpus.tsv")
    p.add_argument("--only", nargs="*", help="subset of repo URLs to run")
    p.add_argument("--shard", help="run shard i of n, e.g. 2/6 (1-based)")
    p.add_argument("--limit", type=int, help="first N repositories (after sharding)")
    p.add_argument("--burst", action="store_true", help="submit all repositories at once instead of one by one")
    p.add_argument("--no-verify", action="store_true", help="skip the independent Trivy ground truth")
    p.add_argument("--trivy-server", required=True)
    p.add_argument("--trivy-token", required=True)
    p.add_argument("--trivy-bin", default="trivy")
    p.add_argument("--trivy-offline", action="store_true", help="the service runs with TRIVY_OFFLINE_SCAN=true; match it")
    p.add_argument("--container", help="docker container id of the service (for OOM/peak/workspace checks)")
    p.add_argument("--cgroup", help="cgroup v2 directory of the service (systemd deployment)")
    p.add_argument("--work-dir", help="service WORK_DIR (with --cgroup) to check for leftover workspaces")
    p.add_argument("--timeout", type=int, default=3600, help="per-repo scan timeout in seconds")
    p.add_argument("--json-out", help="write raw results here")
    p.add_argument("--strict-limit", action="store_true",
                   help="also fail if total memory INCLUDING page cache ever reached the hard limit (memory.events max)")
    args = p.parse_args()

    repos = load_repos(args.repos)
    if args.only:
        repos = [r for r in repos if r in args.only] or args.only
    if args.shard:
        i, n = (int(x) for x in args.shard.split("/"))
        repos = repos[i - 1::n]
    if args.limit:
        repos = repos[: args.limit]

    reader = CgroupReader(args) if (args.container or args.cgroup) else None
    limit_mb = None
    if reader:
        raw = reader.read("memory.max").strip()
        limit_mb = None if raw == "max" else int(raw) // 1048576
        high = reader.read("memory.high").strip()
        print(f"cgroup memory.max={limit_mb} MiB memory.high={'none' if high == 'max' else str(int(high) // 1048576) + ' MiB'}")

    before = reader.events() if reader else {}
    sampler = Sampler(reader, 0.25) if reader else None
    if sampler:
        sampler.start()

    results: list[dict] = []
    run_problems: list[str] = []
    try:
        if args.burst:
            finished = run_burst(repos, args)
        else:
            finished = {}
            for repo in repos:
                print(f"\n== {repo}", flush=True)
                try:
                    finished[repo] = scan_with_service(args.api, repo, args.timeout)
                except Exception as exc:  # noqa: BLE001
                    finished[repo] = {"status": "Error", "error": f"{type(exc).__name__}: {exc}"}
    except Exception as exc:  # noqa: BLE001
        run_problems.append(f"{type(exc).__name__}: {exc}")
        finished = locals().get("finished", {})
    finally:
        if sampler:
            sampler.stop()

    # Memory verdict for the whole run: kernel counters are exact, sampling only reports peaks.
    after: dict | None = None
    if reader and sampler:
        try:
            after = reader.events()
        except (OSError, subprocess.SubprocessError) as exc:
            run_problems.append(f"service cgroup disappeared (container died?): {exc}")
    if reader and sampler and after is not None:
        hit_max = after.get("max", 0) - before.get("max", 0)
        kills = after.get("oom_kill", 0) - before.get("oom_kill", 0)
        mem = {"limit_mb": limit_mb, "total_peak_mb": sampler.peak_total // 1048576, "ws_peak_mb": sampler.peak_ws // 1048576,
               "hit_limit_events": hit_max, "high_events": after.get("high", 0) - before.get("high", 0), "oom_kills": kills}
        print(f"\nmemory: {mem}")
        if kills:
            run_problems.append(f"{kills} OOM kill(s) in the service cgroup")
        if limit_mb and mem["ws_peak_mb"] >= limit_mb:
            run_problems.append(f"working set reached the limit ({mem['ws_peak_mb']} MiB)")
        if args.strict_limit and hit_max:
            run_problems.append(f"total memory incl. page cache hit the {limit_mb} MiB limit {hit_max}x")
    else:
        mem = {}
    state = memory_state(args)
    if args.container and not state.get("running", True):
        run_problems.append("service container is not running")
    if state.get("oom_killed"):
        run_problems.append("service was OOM-killed")
    if state.get("restarts"):
        run_problems.append(f"container restarted {state['restarts']}x")
    if state.get("leftover_workspaces"):
        run_problems.append(f"{state['leftover_workspaces']} workspace(s) left behind")
    try:
        ready = http_json("GET", f"{args.api}/readyz")
        if ready.get("status") != "ready":
            run_problems.append(f"service not ready afterwards: {ready}")
    except urllib.error.URLError as exc:
        run_problems.append(f"service unreachable afterwards: {exc}")

    print("\nverifying against independent Trivy runs…" if not args.no_verify else "", flush=True)
    for repo in repos:
        full = finished.get(repo, {"status": "Missing"})
        try:
            row, problems = verify(full, repo, args)
        except Exception as exc:  # noqa: BLE001
            row, problems = {"status": full.get("status")}, [f"{type(exc).__name__}: {exc}"]
        row.update(repo=repo, ok=not problems, problems=problems)
        results.append(row)
        print(f"  {'PASS' if not problems else 'FAIL'}  {repo}" + ("" if not problems else "  ← " + "; ".join(problems)), flush=True)

    passed = sum(1 for r in results if r["ok"])
    header = "| Repository | Commit | Result | Findings | CRITICAL (service / Trivy) | Report | Worker RSS | Time |"
    lines = [header, "|" + "---|" * 8]
    for r in results:
        lines.append(
            f"| {r['repo'].removeprefix('https://github.com/')} | `{(r.get('commit') or '')[:10]}` | "
            f"{'PASS' if r['ok'] else 'FAIL'} | {r.get('scanned', '–')} | {r.get('critical', '–')} / {r.get('truth_critical', '–')} | "
            f"{r.get('report_mb', '–')} MB | {r.get('peak_rss_mb', '–')} MB | {r.get('wall_s', '–')} s |")
    summary = (f"**{passed}/{len(results)} repositories passed.** Memory over the whole run: "
               f"limit {mem.get('limit_mb', '–')} MiB, peak total incl. cache {mem.get('total_peak_mb', '–')} MiB, "
               f"peak working set {mem.get('ws_peak_mb', '–')} MiB, hard-limit hits {mem.get('hit_limit_events', '–')}, "
               f"OOM kills {mem.get('oom_kills', '–')}.")
    table = "\n".join(lines)
    print("\n" + summary + "\n\n" + table)
    for problem in run_problems:
        print(f"  ✗ run: {problem}")
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as fh:
            fh.write(f"## Large repositories{' (shard ' + args.shard + ')' if args.shard else ''}\n\n{summary}\n\n{table}\n")
    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as fh:
            json.dump({"memory": mem, "run_problems": run_problems, "results": results}, fh, indent=2, default=str)
    return 1 if run_problems or passed < len(results) else 0


if __name__ == "__main__":
    sys.exit(main())
