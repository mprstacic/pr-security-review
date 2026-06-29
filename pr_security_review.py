#!/usr/bin/env python3
"""
PR Security Reviewer - Week 1 core (Days 1-2)
=============================================
Fetches a GitHub pull request's changed files, runs Semgrep against them,
and prints the findings as JSON.

This is the local-first foundation. In Days 3-4 you'll add:
  - Claude triage (severity / false-positive call / fix suggestion)
  - posting the result back as a PR review comment
...both slot in at the marked seams near the bottom of main().

Setup (night one - only Semgrep needs installing):
    pip install semgrep             # the SAST engine
    export GITHUB_TOKEN=ghp_xxx     # fine-grained PAT, read access to the repo

Run against any accessible PR:
    python pr_security_review.py --repo OWNER/NAME --pr 42
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path

GITHUB_API = "https://api.github.com"
API_VERSION = "2022-11-28"


def _gh(url: str, token: str, accept: str = "application/vnd.github+json") -> bytes:
    """Minimal authenticated GET against the GitHub REST API (stdlib only)."""
    req = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": accept,
            "X-GitHub-Api-Version": API_VERSION,
            "User-Agent": "pr-security-reviewer",
        },
    )
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.read()
    except urllib.error.HTTPError as e:
        sys.exit(f"GitHub API error {e.code} for {url}: {e.read().decode(errors='replace')}")


def get_pr(repo: str, pr: int, token: str) -> dict:
    return json.loads(_gh(f"{GITHUB_API}/repos/{repo}/pulls/{pr}", token))


def get_changed_files(repo: str, pr: int, token: str) -> list[dict]:
    """Changed files in the PR. NOTE: capped at 100; add paging if a PR exceeds that."""
    raw = _gh(f"{GITHUB_API}/repos/{repo}/pulls/{pr}/files?per_page=100", token)
    return json.loads(raw)


def fetch_file_at(repo: str, path: str, ref: str, token: str) -> bytes | None:
    """Raw bytes of a file at a given commit SHA, or None if it can't be fetched."""
    url = f"{GITHUB_API}/repos/{repo}/contents/{path}?ref={ref}"
    try:
        return _gh(url, token, accept="application/vnd.github.raw")
    except SystemExit:
        return None  # submodule, symlink, or too-large file - skip it


def materialize_changed_files(repo: str, pr_data: dict, files: list[dict],
                              token: str, dest: Path) -> list[str]:
    """Write the PR's changed (non-removed) files into `dest`, preserving paths."""
    head_sha = pr_data["head"]["sha"]
    written: list[str] = []
    for f in files:
        if f.get("status") == "removed":
            continue
        path = f["filename"]
        content = fetch_file_at(repo, path, head_sha, token)
        if content is None:
            continue
        out = dest / path
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(content)
        written.append(path)
    return written


def run_semgrep(target: Path) -> dict:
    """Run Semgrep with the auto config and return parsed JSON results."""
    proc = subprocess.run(
        ["semgrep", "scan", "--config", "auto", "--json", "--quiet", str(target)],
        capture_output=True,
        text=True,
    )
    if proc.returncode not in (0, 1):  # 1 == findings present, still valid
        sys.exit(f"Semgrep failed (exit {proc.returncode}):\n{proc.stderr}")
    return json.loads(proc.stdout or "{}")


def summarize(results: dict) -> list[dict]:
    """Flatten Semgrep output into the shape Claude will triage in Days 3-4."""
    findings = []
    for r in results.get("results", []):
        findings.append({
            "check_id": r.get("check_id"),
            "path": r.get("path"),
            "line": r.get("start", {}).get("line"),
            "severity": r.get("extra", {}).get("severity"),
            "message": r.get("extra", {}).get("message"),
            "code": r.get("extra", {}).get("lines"),
        })
    return findings


def main() -> None:
    ap = argparse.ArgumentParser(description="Run Semgrep over a GitHub PR's changed files.")
    ap.add_argument("--repo", required=True, help="owner/name")
    ap.add_argument("--pr", required=True, type=int, help="pull request number")
    args = ap.parse_args()

    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        sys.exit("Set GITHUB_TOKEN (a fine-grained PAT with read access to the repo).")

    pr_data = get_pr(args.repo, args.pr, token)
    files = get_changed_files(args.repo, args.pr, token)

    with tempfile.TemporaryDirectory() as tmp:
        target = Path(tmp)
        written = materialize_changed_files(args.repo, pr_data, files, token, target)
        if not written:
            print(json.dumps({"changed_files": 0, "findings": []}, indent=2))
            return
        results = run_semgrep(target)

    findings = summarize(results)
    print(json.dumps({
        "repo": args.repo,
        "pr": args.pr,
        "head_sha": pr_data["head"]["sha"],
        "scanned_files": written,
        "finding_count": len(findings),
        "findings": findings,
    }, indent=2))

    # -- Day 3-4 seam #1: triage --------------------------------------------
    # triaged = triage_with_claude(findings, files)   # severity / FP call / fix
    #
    # -- Day 3-4 seam #2: post review ---------------------------------------
    # post_pr_review(args.repo, args.pr, pr_data["head"]["sha"], triaged, token)


if __name__ == "__main__":
    main()
