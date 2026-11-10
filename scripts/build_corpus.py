#!/usr/bin/env python3
"""
Builds test/large/corpus.tsv: a reproducible set of large, popular GitHub repositories across the ecosystems
Trivy's filesystem scanner understands, for the large-repository load test (scripts/large_repos_e2e.py).

  GITHUB_TOKEN=$(gh auth token) python3 scripts/build_corpus.py            # writes test/large/corpus.tsv

Selection per ecosystem: GitHub search by primary language, sorted by stars, not archived, not a fork,
repository size above a floor (big repos are the point) and below a ceiling (keeps CI disk bounded).
"""
from __future__ import annotations

import datetime
import json
import os
import sys
import time
import urllib.parse
import urllib.request

# language, how many, min stars, min size (MB, whole history)
PLAN = [
    ("TypeScript", 25, 15000, 100),
    ("JavaScript", 20, 15000, 50),
    ("Go", 25, 10000, 50),
    ("Python", 25, 10000, 50),
    ("Rust", 15, 8000, 30),
    ("Ruby", 10, 4000, 30),
    ("PHP", 10, 4000, 30),
    ("Java", 10, 8000, 50),
    ("C#", 10, 5000, 50),
]
MAX_SIZE_MB = 4000
ALWAYS = [  # deliberately vulnerable / assignment targets: guaranteed CRITICAL findings
    ("https://github.com/armansw/NodeGoat", "JavaScript"),
    ("https://github.com/snyk-labs/nodejs-goof", "JavaScript"),
]


def search(language: str, min_stars: int, min_size_mb: int, page: int) -> list[dict]:
    q = f"language:{language} stars:>{min_stars} size:>{min_size_mb * 1024} archived:false fork:false"
    url = "https://api.github.com/search/repositories?" + urllib.parse.urlencode(
        {"q": q, "sort": "stars", "order": "desc", "per_page": 100, "page": page})
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "code-guardian-corpus"}
    if os.environ.get("GITHUB_TOKEN"):
        headers["Authorization"] = f"Bearer {os.environ['GITHUB_TOKEN']}"
    with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=60) as res:
        return json.loads(res.read())["items"]


def main() -> int:
    out = os.path.join(os.path.dirname(__file__), "..", "test", "large", "corpus.tsv")
    rows: list[tuple[str, str, int, int]] = []
    seen = set()
    for url, lang in ALWAYS:
        rows.append((url, lang, 0, 0))
        seen.add(url.lower())
    for language, count, min_stars, min_size in PLAN:
        picked = 0
        for page in (1, 2):
            for item in search(language, min_stars, min_size, page):
                size_mb = item["size"] // 1024
                if picked >= count or size_mb > MAX_SIZE_MB or item["html_url"].lower() in seen:
                    continue
                rows.append((item["html_url"], language, size_mb, item["stargazers_count"]))
                seen.add(item["html_url"].lower())
                picked += 1
            if picked >= count:
                break
            time.sleep(2)  # search API rate limit
        print(f"{language:<11} {picked} repositories", file=sys.stderr)
        time.sleep(2)

    with open(out, "w", encoding="utf-8") as fh:
        fh.write(f"# Generated {datetime.date.today().isoformat()} by scripts/build_corpus.py: {len(rows)} repositories.\n")
        fh.write("# url\tlanguage\tsize_mb\tstars\n")
        for url, lang, size_mb, stars in rows:
            fh.write(f"{url}\t{lang}\t{size_mb}\t{stars}\n")
    print(f"wrote {out}: {len(rows)} repositories", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
