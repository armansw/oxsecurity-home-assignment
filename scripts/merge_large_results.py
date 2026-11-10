#!/usr/bin/env python3
"""Merge per-shard results of scripts/large_repos_e2e.py into one report (Markdown to stdout / $GITHUB_STEP_SUMMARY).

  python3 scripts/merge_large_results.py results/*.json
"""
from __future__ import annotations

import json
import os
import sys


def main(paths: list[str]) -> int:
    shards = []
    for p in sorted(paths):
        with open(p, encoding="utf-8") as fh:
            shards.append((os.path.basename(os.path.dirname(p)) or p, json.load(fh)))
    rows = [r for _, s in shards for r in s["results"]]
    passed = sum(1 for r in rows if r["ok"])
    mems = [s["memory"] for _, s in shards if s.get("memory")]
    problems = [(name, p) for name, s in shards for p in s.get("run_problems", [])]
    findings = sum(r.get("scanned") or 0 for r in rows)
    criticals = sum(r.get("critical") or 0 for r in rows)
    limit = max((m.get("limit_mb") or 0 for m in mems), default=0)
    peak_total = max((m.get("total_peak_mb") or 0 for m in mems), default=0)
    peak_ws = max((m.get("ws_peak_mb") or 0 for m in mems), default=0)
    hits = sum(m.get("hit_limit_events") or 0 for m in mems)
    kills = sum(m.get("oom_kills") or 0 for m in mems)

    out = [
        "## Large-repository corpus: merged result",
        "",
        f"**{passed}/{len(rows)} repositories passed** across {len(shards)} shards, each with every repository submitted at once. "
        f"{findings:,} findings scanned, {criticals:,} CRITICAL, each one matched against an independent Trivy run.",
        "",
        "| Memory (service container) | Value |",
        "|---|---|",
        f"| Hard limit | {limit} MiB |",
        f"| Peak total, page cache included (max over shards) | {peak_total} MiB |",
        f"| Peak working set (max over shards) | {peak_ws} MiB |",
        f"| Times the hard limit was reached | {hits} |",
        f"| OOM kills | {kills} |",
        "",
    ]
    failed = [r for r in rows if not r["ok"]]
    if failed or problems:
        out += ["### Failures", ""]
        out += [f"- `{r['repo']}`: {'; '.join(r['problems'])}" for r in failed]
        out += [f"- shard `{name}`: {p}" for name, p in problems]
        out.append("")
    out += ["<details><summary>All repositories</summary>", "",
            "| Repository | Result | Findings | CRITICAL (service / Trivy) | Report | Time |", "|---|---|---|---|---|---|"]
    for r in sorted(rows, key=lambda r: r["repo"].lower()):
        out.append(f"| {r['repo'].removeprefix('https://github.com/')} | {'PASS' if r['ok'] else 'FAIL'} | {r.get('scanned', '–')} | "
                   f"{r.get('critical', '–')} / {r.get('truth_critical', '–')} | {r.get('report_mb', '–')} MB | {r.get('wall_s', '–')} s |")
    out += ["", "</details>"]
    text = "\n".join(out) + "\n"
    sys.stdout.write(text)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as fh:
            fh.write(text)
    return 0 if passed == len(rows) and not problems else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
