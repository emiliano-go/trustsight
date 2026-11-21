#!/usr/bin/env python3
"""Report the maintainer coverage of an AUR metadata snapshot and seed.

Read-only.  The audit is the Phase 0 gate for a seed expansion: it shows
how many package bases the metadata covers, how many have an authoritative
maintainer, and how many seed rows are active versus comment aliases.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "src"))

import generate_seed  # noqa: E402


def audit(metadata_path: Path, seed_dir: Path | None = None) -> dict:
    index, digest = generate_seed.load_metadata(metadata_path)
    entries = list(index.values())
    result = {
        "metadata": str(metadata_path),
        "metadata_sha256": digest,
        "package_bases": len(index),
        "entries": len(entries),
        "with_maintainer": sum(1 for e in entries if e.get("Maintainer")),
        "orphan": sum(1 for e in entries if not e.get("Maintainer")),
    }
    if seed_dir is not None:
        path = seed_dir / "trustsight-seed-v2" / "maintainers.jsonl"
        rows = [json.loads(line) for line in path.read_text().splitlines()
                if line.strip()]
        result["seed_rows"] = len(rows)
        result["seed_active"] = sum(
            1 for row in rows if int(row.get("package_count", 0)) > 0)
        result["seed_aliases"] = sum(
            1 for row in rows if int(row.get("package_count", 0)) == 0)
        result["seed_sources"] = dict(
            Counter(row.get("source", "") for row in rows))
        result["seed_bytes"] = path.stat().st_size
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--metadata", type=Path, required=True)
    parser.add_argument("--seed-dir", type=Path, default=None)
    args = parser.parse_args(argv)
    try:
        result = audit(args.metadata, args.seed_dir)
    except (OSError, ValueError) as exc:
        print(f"seed coverage audit: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
