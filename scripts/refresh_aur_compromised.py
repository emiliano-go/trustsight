"""Refresh the Atomic Arch compromise exposure list from MIT upstream data.

Network-using and opt-in: this is a curator's tool, never run in CI or by a
test.  It downloads the MIT-licensed `jasonherald/atomic-arch-check` data files
and regenerates `packages.tsv` and `spam-packages.tsv` in the incident
directory.  Only MIT sources are merged; GPL and unlicensed trackers are
deliberately excluded (see the directory README).

Usage::

    python scripts/refresh_aur_compromised.py --check
    python scripts/refresh_aur_compromised.py --apply
"""

from __future__ import annotations

import argparse
import csv
import io
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "data" / "aur-compromised" / "atomic-arch-2026-06"
BASE = "https://raw.githubusercontent.com/jasonherald/atomic-arch-check/main/data"

_MALWARE = {"compromised-packages.tsv": "wave1-2",
            "compromised-packages-wave3.tsv": "wave3"}
_SPAM = "aur-spam-2026-06.tsv"
_RANK = {"primary-source": 3, "single-source": 2}


def _fetch(name: str) -> str:
    with urllib.request.urlopen(f"{BASE}/{name}", timeout=30) as response:
        return response.read().decode("utf-8", errors="replace")


def _merge(rows: dict[str, dict]) -> str:
    lines = ["package\twaves\tconfidence\tsources"]
    for name in sorted(rows):
        rec = rows[name]
        lines.append("\t".join([
            name,
            ",".join(sorted(rec["waves"])),
            rec["confidence"] or "single-source",
            ",".join(sorted(rec["sources"])),
        ]))
    return "\n".join(lines) + "\n"


def build() -> tuple[str, str]:
    records: dict[str, dict] = {}
    for filename, wave in _MALWARE.items():
        for row in csv.DictReader(io.StringIO(_fetch(filename)), delimiter="\t"):
            name = (row.get("name") or "").strip()
            if not name:
                continue
            rec = records.setdefault(name, {"waves": set(), "confidence": "", "sources": set()})
            rec["waves"].add(wave)
            confidence = (row.get("confidence") or "").strip()
            if _RANK.get(confidence, 0) > _RANK.get(rec["confidence"], 0):
                rec["confidence"] = confidence
            for source in (row.get("sources") or "").split(","):
                if source.strip():
                    rec["sources"].add(source.strip())
    spam = _fetch(_SPAM)
    return _merge(records), (spam if spam.endswith("\n") else spam + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--check", action="store_true", help="report changes, write nothing")
    group.add_argument("--apply", action="store_true", help="write the files")
    args = parser.parse_args()

    try:
        packages, spam = build()
    except OSError as exc:
        print(f"refresh failed (network): {exc}", file=sys.stderr)
        return 2

    targets = {"packages.tsv": packages, "spam-packages.tsv": spam}
    changed = [name for name, text in targets.items()
               if (OUT / name).read_text(encoding="utf-8") != text]
    if args.check:
        print("would change: " + (", ".join(changed) if changed else "nothing"))
        return 0
    for name, text in targets.items():
        (OUT / name).write_text(text, encoding="utf-8")
    print("wrote: " + ", ".join(sorted(targets)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
