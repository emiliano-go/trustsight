"""ChangeDelta parity runner (spec §1).

The change summary, the change report and the rules must read the same
document-derived facts.  This runner replays the locked benign corpus and
asserts, for every diff, that ``ChangeDelta`` reproduces exactly the
facts the summary machinery reads from the same text: host gained/lost
sets, the checksum classification, the local source-file names, and the
dict round-trip.  A migration that makes one surface re-derive a fact
differently fails here instead of drifting quietly.

Usage:

    uv run python tests/harness/change_parity.py [--sample N]
"""

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT / "src"))

from trustsight.changes import ChangeDelta, _host  # noqa: E402
from trustsight.differ import (  # noqa: E402
    _post_diff_lines,
    _pre_diff_lines,
    change_delta,
    extract_urls_from_diff,
    local_source_names,
)


def replay(sample: int = 1) -> list[str]:
    """The names of corpus diffs whose delta disagrees with the reference."""
    corpus = ROOT / "tests" / "fixtures" / "benign-corpus"
    mismatches: list[str] = []
    paths = sorted(corpus.glob("*.diff"))[::sample]
    for path in paths:
        text = path.read_text(encoding="utf-8", errors="replace")
        delta = change_delta(text)
        reference = extract_urls_from_diff(text)
        added = {_host(u) for u in reference.added_urls if _host(u)}
        removed = {_host(u) for u in reference.removed_urls if _host(u)}
        local = (
            local_source_names("\n".join(_post_diff_lines(text)))
            - local_source_names("\n".join(_pre_diff_lines(text)))
        )
        if (
            set(delta.hosts_gained) != added - removed
            or set(delta.hosts_lost) != removed - added
            or delta.checksum_behavior != reference.checksum_behavior
            or set(delta.local_sources_gained) != local
            or ChangeDelta.from_dict(delta.to_dict()) != delta
        ):
            mismatches.append(path.name)
    return mismatches


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sample", type=int, default=1,
                        help="take every Nth corpus diff (default: all)")
    args = parser.parse_args()
    mismatches = replay(sample=max(1, args.sample))
    if mismatches:
        for name in mismatches:
            print(f"MISMATCH {name}")
        print(f"{len(mismatches)} mismatching diff(s)")
        return 1
    print("change parity: all diffs agree")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
