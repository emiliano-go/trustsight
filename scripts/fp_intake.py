#!/usr/bin/env python3
"""Validate a GitHub false-positive issue and post the intake checklist.

The issue body is parsed as text, never executed.  The comment names the
missing evidence, if any, and points at the triage pipeline.  This script
does not run ``fp_triage`` itself: that stays a maintainer or agent action,
so an untrusted issue cannot trigger network work on its own.
"""

from __future__ import annotations

import json
import os
import re
import sys
import urllib.error
import urllib.request

MARKER = "<!-- fp-intake -->"
SLUG_RE = re.compile(r"\b\d{4}-\d{2}-\d{2}/\d{6}(?:-[A-Za-z0-9_-]+)?\b")

# Form heading -> the name the checklist uses.
FIELDS = {
    "what kind of report is this?": "kind",
    "trustsight version": "version",
    "aur package": "package",
    "feed alert url": "alert_url",
    "rule id": "rule_id",
    "what trustsight reported": "reported",
    "why this is a bad rule trigger": "why",
    "pkgbuild or diff": "pkgbuild",
    "command or mode": "command",
    "config fingerprint": "config_fingerprint",
}
REQUIRED = ("kind", "version", "package", "rule_id", "reported", "why", "pkgbuild")

KIND_LABELS = {
    "bad rule trigger (malicious false positive)": "false-positive",
    "correct finding, wrong weight or severity (overweighted)": "overweighted",
    "real finding about a packager practice (benign false positive)": "benign-practice",
}


def _label(value: str) -> str:
    text = re.sub(r"\s*\(optional\)\s*$", "", value.strip(), flags=re.I)
    return re.sub(r"\s+", " ", text).strip().lower()


def parse_body(body: str) -> dict[str, str]:
    """Split an issue-form body on its ``### Label`` headings."""
    sections: dict[str, list[str]] = {}
    current = None
    for line in body.splitlines():
        match = re.match(r"^###\s+(.+?)\s*$", line)
        if match:
            current = _label(match.group(1))
            sections.setdefault(current, [])
            continue
        if current is not None:
            sections[current].append(line)
    parsed = {}
    for heading, lines in sections.items():
        key = FIELDS.get(heading)
        if key:
            parsed[key] = "\n".join(lines).strip()
    return parsed


def _missing(fields: dict[str, str]) -> list[str]:
    missing = []
    for key in REQUIRED:
        value = fields.get(key, "").strip()
        if not value or value in {"_No response_", "No response"}:
            missing.append(key)
    return missing


def _slug(fields: dict[str, str]) -> str:
    match = SLUG_RE.search(fields.get("alert_url", ""))
    if match:
        return match.group(0)
    match = SLUG_RE.search("\n".join(fields.values()))
    return match.group(0) if match else ""


def _comment(fields: dict[str, str], missing: list[str], slug: str) -> str:
    present = {
        "kind": "kind",
        "version": "version",
        "package": "package",
        "rule_id": "rule id",
        "reported": "report JSON",
        "why": "why the trigger is wrong",
        "pkgbuild": "PKGBUILD or diff",
    }
    lines = [MARKER, "### False-positive intake", ""]
    for key, label in present.items():
        lines.append(f"- [{' ' if key in missing else 'x'}] {label}")
    lines.append(
        f"- [{' ' if not slug else 'x'}] feed alert slug"
        + (f": `{slug}`" if slug else " (optional)"))
    lines.append("")
    if missing:
        names = ", ".join(present[key] for key in missing)
        lines.append(f"**Needs information:** {names}.")
        lines.append("")
        lines.append(
            "Edit the issue to add the missing fields. The template is "
            "[False positive]"
            "(https://github.com/emiliano-go/trustsight/issues/new"
            "?template=false_positive.yml).")
    else:
        lines.append(
            "**The required evidence is present.** A maintainer can run "
            "`python -m harness fp_triage --alert-slug <slug>` over the "
            "alert, or let the feed-driven triage agent pick it up.")
        if not slug:
            lines.append(
                "No alert slug was found, so the agent cannot fetch the exact "
                "alert. The package and rule id are enough to start.")
    lines.extend([
        "",
        "The pipeline is described in "
        "[Tuning False Positives](https://docs.trustsight.org/guides/"
        "tuning-false-positives/#what-happens-after-you-report).",
    ])
    return "\n".join(lines)


class GitHub:
    def __init__(self, token: str, repo: str):
        self.token = token
        self.repo = repo
        self.base = os.environ.get("GITHUB_API_URL", "https://api.github.com")

    def request(self, method: str, path: str, data=None):
        body = json.dumps(data).encode() if data is not None else None
        req = urllib.request.Request(
            f"{self.base}/repos/{self.repo}{path}",
            method=method,
            data=body,
            headers={
                "Authorization": f"Bearer {self.token}",
                "Accept": "application/vnd.github+json",
                "Content-Type": "application/json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        with urllib.request.urlopen(req, timeout=30) as response:
            return json.loads(response.read() or b"null")

    def upsert_comment(self, number: int, body: str) -> None:
        for comment in self.request("GET", f"/issues/{number}/comments?per_page=100"):
            if MARKER in comment.get("body", ""):
                self.request("PATCH", f"/issues/comments/{comment['id']}",
                             {"body": body})
                return
        self.request("POST", f"/issues/{number}/comments", {"body": body})

    def add_labels(self, number: int, labels: list[str]) -> None:
        try:
            self.request("POST", f"/issues/{number}/labels", {"labels": labels})
        except urllib.error.HTTPError as exc:
            if exc.code != 422:
                raise

    def remove_label(self, number: int, label: str) -> None:
        try:
            self.request("DELETE", f"/issues/{number}/labels/{label}")
        except urllib.error.HTTPError as exc:
            if exc.code != 404:
                raise


def main() -> int:
    token = os.environ.get("GITHUB_TOKEN")
    repo = os.environ.get("GITHUB_REPOSITORY")
    event_path = os.environ.get("GITHUB_EVENT_PATH")
    if not token or not repo or not event_path:
        print("GITHUB_TOKEN, GITHUB_REPOSITORY and GITHUB_EVENT_PATH are required",
              file=sys.stderr)
        return 2

    with open(event_path, encoding="utf-8") as fh:
        event = json.load(fh)
    issue = event.get("issue") or {}
    number = issue.get("number")
    body = issue.get("body") or ""
    if not number:
        print("event carries no issue", file=sys.stderr)
        return 2

    fields = parse_body(body)
    missing = _missing(fields)
    slug = _slug(fields)
    gh = GitHub(token, repo)
    gh.upsert_comment(number, _comment(fields, missing, slug))

    kind = fields.get("kind", "").strip().lower()
    labels = ["false-positive"]
    kind_label = KIND_LABELS.get(kind)
    if kind_label and kind_label not in labels:
        labels.append(kind_label)
    if missing:
        labels.append("needs-info")
        gh.add_labels(number, labels)
        gh.remove_label(number, "fp-intake-ok")
    else:
        labels.append("fp-intake-ok")
        gh.add_labels(number, labels)
        gh.remove_label(number, "needs-info")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
