#!/usr/bin/env python3
"""
PR Security Reviewer - Week 1 (Days 1-4)
========================================
1. Fetches a GitHub pull request's changed files
2. Runs Semgrep against them (SAST)
3. Has Claude triage each finding: true/false positive, severity, fix
4. Posts (or dry-runs) a summary security review comment back on the PR

Setup:
    pip install semgrep anthropic
    export GITHUB_TOKEN=ghp_xxx        # fine-grained PAT.
                                       #   read: Contents + Pull requests
                                       #   write: Pull requests  (only needed for --post)
    export ANTHROPIC_API_KEY=sk-xxx    # used by the triage step

Dry run (prints the review it WOULD post - iterate on triage here):
    python pr_security_review.py --repo OWNER/NAME --pr 42

Actually post the review comment to the PR:
    python pr_security_review.py --repo OWNER/NAME --pr 42 --post
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path

GITHUB_API = "https://api.github.com"
API_VERSION = "2022-11-28"
ANTHROPIC_MODEL = "claude-sonnet-4-6"  # swap to claude-opus-4-8 for deeper reasoning, or haiku for cost


# ---------------------------------------------------------------------------
# GitHub REST helpers (stdlib only)
# ---------------------------------------------------------------------------
def _gh(url: str, token: str, accept: str = "application/vnd.github+json") -> bytes:
    """Authenticated GET against the GitHub REST API."""
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


def _gh_post(url: str, token: str, payload: dict) -> dict:
    """Authenticated POST against the GitHub REST API."""
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
        method="POST",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": API_VERSION,
            "User-Agent": "pr-security-reviewer",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        sys.exit(f"GitHub API error {e.code} posting review: {e.read().decode(errors='replace')}")


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


# ---------------------------------------------------------------------------
# Semgrep
# ---------------------------------------------------------------------------
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
    """Flatten Semgrep output into the shape Claude will triage."""
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


# ---------------------------------------------------------------------------
# Claude triage  (Day 3-4 seam #1)
# ---------------------------------------------------------------------------
TRIAGE_SYSTEM = """You are a senior application security engineer reviewing the \
output of a Semgrep SAST scan on a pull request.

Semgrep findings are CANDIDATES, not confirmed vulnerabilities. Many are false \
positives or low-impact. Judge each one against the actual code shown.

For every finding, return an object with:
- "index": the finding's index (integer, copied from the input)
- "is_true_positive": boolean - is this a real, exploitable issue in this context?
- "severity": one of "critical", "high", "medium", "low", "info"
- "rationale": 1-3 sentences explaining why it is or isn't a real issue here
- "suggested_fix": a concrete, code-level remediation (or "" if not a true positive)

Respond with ONLY a JSON array of these objects. No prose, no markdown fences."""


def _extract_json_array(text: str) -> list[dict]:
    """Pull a JSON array out of the model response, tolerating stray fences/prose."""
    text = text.strip()
    text = re.sub(r"^```(?:json)?|```$", "", text, flags=re.MULTILINE).strip()
    start, end = text.find("["), text.rfind("]")
    if start == -1 or end == -1:
        raise ValueError(f"No JSON array in model response:\n{text[:500]}")
    return json.loads(text[start:end + 1])


def triage_with_claude(findings: list[dict]) -> list[dict]:
    """Ask Claude to triage findings; return findings enriched with triage fields."""
    if not findings:
        return []
    if not os.environ.get("ANTHROPIC_API_KEY"):
        sys.exit("Set ANTHROPIC_API_KEY for the triage step.")
    try:
        from anthropic import Anthropic
    except ImportError:
        sys.exit("Triage needs the Anthropic SDK: pip install anthropic")

    indexed = [{"index": i, **f} for i, f in enumerate(findings)]
    client = Anthropic()
    resp = client.messages.create(
        model=ANTHROPIC_MODEL,
        max_tokens=4096,
        system=TRIAGE_SYSTEM,
        messages=[{"role": "user", "content": json.dumps(indexed, indent=2)}],
    )
    text = "".join(b.text for b in resp.content if b.type == "text")
    triage = {t["index"]: t for t in _extract_json_array(text)}

    enriched = []
    for i, f in enumerate(findings):
        t = triage.get(i, {})
        enriched.append({
            **f,
            "is_true_positive": t.get("is_true_positive", True),
            "triaged_severity": t.get("severity", f.get("severity", "info")),
            "rationale": t.get("rationale", ""),
            "suggested_fix": t.get("suggested_fix", ""),
        })
    return enriched


# ---------------------------------------------------------------------------
# Render + post review  (Day 3-4 seam #2)
# ---------------------------------------------------------------------------
_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def render_review_body(enriched: list[dict]) -> str:
    """Build the markdown body of the PR review comment."""
    confirmed = sorted(
        [f for f in enriched if f.get("is_true_positive")],
        key=lambda f: _SEV_ORDER.get(f.get("triaged_severity", "info"), 9),
    )
    likely_fp = [f for f in enriched if not f.get("is_true_positive")]

    lines = ["## Automated security review", ""]
    lines.append(f"Scanned with Semgrep, triaged by `{ANTHROPIC_MODEL}`.")
    lines.append(f"**{len(confirmed)} issue(s) worth attention** "
                 f"+ {len(likely_fp)} likely false positive(s).")
    lines.append("")

    if not confirmed:
        lines.append("No confirmed issues in the changed files. ")
    for f in confirmed:
        sev = f.get("triaged_severity", "info").upper()
        lines.append(f"### [{sev}] `{f['path']}:{f.get('line')}`")
        lines.append(f"_{f.get('check_id')}_")
        lines.append("")
        if f.get("rationale"):
            lines.append(f.get("rationale"))
            lines.append("")
        if f.get("suggested_fix"):
            lines.append("**Suggested fix:**")
            lines.append(f"```\n{f['suggested_fix']}\n```")
            lines.append("")

    if likely_fp:
        lines.append("<details><summary>Likely false positives (triaged out)</summary>")
        lines.append("")
        for f in likely_fp:
            reason = f.get("rationale", "")
            lines.append(f"- `{f['path']}:{f.get('line')}` - {f.get('check_id')}: {reason}")
        lines.append("")
        lines.append("</details>")

    lines.append("")
    lines.append("<sub>Automated review - verify before acting.</sub>")
    return "\n".join(lines)


def post_pr_review(repo: str, pr: int, head_sha: str, body: str, token: str) -> str:
    """Post a single summary review comment on the PR. Returns the review URL."""
    url = f"{GITHUB_API}/repos/{repo}/pulls/{pr}/reviews"
    result = _gh_post(url, token, {"commit_id": head_sha, "body": body, "event": "COMMENT"})
    return result.get("html_url", "(posted)")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> None:
    ap = argparse.ArgumentParser(description="AI-assisted security review of a GitHub PR.")
    ap.add_argument("--repo", required=True, help="owner/name")
    ap.add_argument("--pr", required=True, type=int, help="pull request number")
    ap.add_argument("--post", action="store_true",
                    help="post the review to the PR (default: dry run, print only)")
    args = ap.parse_args()

    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        sys.exit("Set GITHUB_TOKEN (fine-grained PAT; Pull requests: write needed for --post).")

    pr_data = get_pr(args.repo, args.pr, token)
    files = get_changed_files(args.repo, args.pr, token)

    with tempfile.TemporaryDirectory() as tmp:
        target = Path(tmp)
        written = materialize_changed_files(args.repo, pr_data, files, token, target)
        if not written:
            print("No scannable changed files in this PR.")
            return
        results = run_semgrep(target)

    findings = summarize(results)
    enriched = triage_with_claude(findings)
    body = render_review_body(enriched)

    if args.post:
        review_url = post_pr_review(args.repo, args.pr, pr_data["head"]["sha"], body, token)
        print(f"Posted review: {review_url}")
    else:
        print("=== DRY RUN - review that would be posted ===\n")
        print(body)


if __name__ == "__main__":
    main()
