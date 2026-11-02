#!/usr/bin/env python3
"""Provenance screen for corpus candidates and corpus diffs.

A benign corpus is a negative control: importing a package or a diff that is
already on a known-bad list turns the corpus into a measurement of the
incident.  The screen runs twice, on purpose:

  * at build time, over candidate package names and their commits;
  * in CI, over every reconstructed diff's URLs, hashes and declared paths.

Both runs record what they checked and how many they excluded, so a silent
pass is distinguishable from a skipped screen.

Usage:
    python scripts/corpus_provenance.py --check-lock tests/fixtures/corpus.lock
    python scripts/corpus_provenance.py --check-corpus tests/fixtures/benign-corpus
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from trustsight.iocs import compile_ioc_pattern, normalize as normalize_ioc  # noqa: E402

DATA = ROOT / "data"
URL_RE = re.compile(r"https?://[^\s'\"<>)\]]+", re.I)


def _digest(paths: list[Path]) -> str:
    h = hashlib.sha256()
    for path in sorted(paths):
        h.update(path.name.encode())
        h.update(path.read_bytes())
    return h.hexdigest()


def load_indicators(data_dir: Path = DATA) -> dict:
    """Load package/hash/domain/pattern/path indicators from the committed data."""
    packages: set[str] = set()
    hashes: set[str] = set()
    domains: set[str] = set()
    paths: set[str] = set()
    patterns: list[tuple[str, re.Pattern]] = []
    sources: list[Path] = []

    for path in sorted((data_dir / "aur-compromised").rglob("*.tsv")):
        sources.append(path)
        lines = path.read_text(errors="replace").splitlines()
        if not lines:
            continue
        header = lines[0].split("\t")
        cols = {name: i for i, name in enumerate(header)}
        for line in lines[1:]:
            cells = line.split("\t")
            for field in ("package", "name"):
                idx = cols.get(field)
                if idx is not None and idx < len(cells) and cells[idx].strip():
                    if cells[idx].strip().lower() != field:
                        packages.add(cells[idx].strip().lower())
            idx = cols.get("malicious_commit")
            if idx is not None and idx < len(cells):
                digest = normalize_ioc("hash", cells[idx].strip())
                if digest:
                    hashes.add(digest)

    for path in sorted((data_dir / "iocs").glob("*.json")):
        if path.name == "example.json":
            continue
        sources.append(path)
        for entry in json.loads(path.read_text()):
            kind = str(entry.get("type") or "")
            value = normalize_ioc(kind, entry.get("value"))
            if not value:
                continue
            if kind == "package":
                packages.add(value)
            elif kind == "hash":
                hashes.add(value)
            elif kind == "domain":
                domains.add(value)
            elif kind == "file_path":
                paths.add(value)
            elif kind == "pkgbuild_pattern":
                compiled = compile_ioc_pattern(value)
                if compiled:
                    patterns.append((value, compiled))

    watchlist = data_dir / "watchlist" / "official.json"
    if watchlist.exists():
        sources.append(watchlist)
        doc = json.loads(watchlist.read_text())
        for name in (doc.get("packages") or {}):
            packages.add(str(name).lower())

    return {
        "packages": packages,
        "hashes": hashes,
        "domains": domains,
        "paths": paths,
        "patterns": patterns,
        "sources": sources,
        "source_sha256": _digest(sources),
    }


def package_excluded(name: str, indicators: dict) -> str | None:
    if str(name).lower() in indicators["packages"]:
        return "package indicator"
    return None


def commit_excluded(sha: str, indicators: dict) -> str | None:
    digest = normalize_ioc("hash", sha)
    if digest and digest in indicators["hashes"]:
        return "malicious commit hash"
    return None


def text_excluded(text: str, indicators: dict) -> list[str]:
    """Return the first matching indicator descriptions in *text*."""
    hits: list[str] = []
    lowered = text.lower()
    for digest in indicators["hashes"]:
        if digest.lower() in lowered:
            hits.append(f"hash {digest}")
    for url in URL_RE.findall(text):
        try:
            host = (urlsplit(url).hostname or "").lower().rstrip(".")
        except ValueError:
            continue
        if host in indicators["domains"]:
            hits.append(f"domain {host}")
    for value in indicators["paths"]:
        if value in text:
            hits.append(f"path {value}")
    for source, compiled in indicators["patterns"]:
        if compiled.search(text):
            hits.append(f"pattern {source}")
    return hits


def screen_lock(lock_path: Path, indicators: dict) -> dict:
    lock = json.loads(lock_path.read_text())
    excluded = []
    for entry in lock.get("entries", []):
        reason = package_excluded(entry["pkg"], indicators)
        if reason is None:
            for sha in (entry.get("old_sha"), entry.get("new_sha")):
                reason = commit_excluded(str(sha), indicators)
                if reason:
                    break
        if reason:
            excluded.append({
                "pkg": entry["pkg"], "stratum": entry.get("stratum"),
                "reason": reason,
            })
    return {
        "checked": len(lock.get("entries", [])),
        "excluded": excluded,
        "excluded_of": f"{len(excluded)} of {len(lock.get('entries', []))} candidates",
        "indicator_source_sha256": indicators["source_sha256"],
    }


def screen_corpus(corpus: Path, indicators: dict) -> dict:
    excluded = []
    files = sorted(corpus.rglob("*.diff"))
    for path in files:
        pkg = path.name.split("__", 1)[0]
        reason = package_excluded(pkg, indicators)
        hits = text_excluded(path.read_text(errors="replace"), indicators)
        if reason or hits:
            excluded.append({
                "file": path.name,
                "package": pkg,
                "reason": reason or "; ".join(hits[:3]),
            })
    return {
        "checked": len(files),
        "excluded": excluded,
        "excluded_of": f"{len(excluded)} of {len(files)} diffs",
        "indicator_source_sha256": indicators["source_sha256"],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Corpus provenance screen")
    parser.add_argument("--data", type=Path, default=DATA)
    parser.add_argument("--lock", type=Path)
    parser.add_argument("--corpus", type=Path)
    parser.add_argument("--json", type=Path)
    args = parser.parse_args()
    if not args.lock and not args.corpus:
        parser.error("pass --lock and/or --corpus")

    indicators = load_indicators(args.data)
    report = {}
    if args.lock:
        report["lock"] = screen_lock(args.lock, indicators)
    if args.corpus:
        report["corpus"] = screen_corpus(args.corpus, indicators)
    text = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.json:
        args.json.write_text(text)
    print(text, end="")

    failures = sum(len(part["excluded"]) for part in report.values())
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
