"""ChangeDelta parity runner.

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
import multiprocessing
import os
import sys
from concurrent.futures import ProcessPoolExecutor
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


def _default_jobs() -> int:
    """The worker count a CLI run uses unless told otherwise."""
    return max(1, min(8, os.cpu_count() or 1))


def _resolve_jobs(jobs: int | None) -> int:
    """One worker unless a caller asks for more.

    Direct library callers (the tests) stay serial; the CLI passes
    :func:`_default_jobs` so a corpus run uses the machine.
    """
    if jobs is None or int(jobs) <= 0:
        return 1
    return max(1, int(jobs))


def _check(path_str: str) -> str | None:
    """The diff's name if its delta disagrees with the reference, else None.

    Each diff is independent, so this is the whole unit of work: a fork
    pool maps it over the corpus in ``replay``.
    """
    path = Path(path_str)
    text = path.read_text(encoding="utf-8", errors="replace")
    delta = change_delta(text)
    reference = extract_urls_from_diff(text)
    # Declared upstreams (`url=`) and documentation sources are not fetched
    # build inputs; `ChangeDelta` excludes them from the host sets, so the
    # reference must too.
    declared = set(reference.declared_urls)
    added = {_host(u) for u in reference.added_urls
             if u not in declared and _host(u)}
    removed = {_host(u) for u in reference.removed_urls
               if u not in declared and _host(u)}
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
        return path.name
    return None


def replay(sample: int = 1, jobs: int | None = None) -> list[str]:
    """The names of corpus diffs whose delta disagrees with the reference."""
    corpus = ROOT / "tests" / "fixtures" / "benign-corpus"
    paths = sorted(corpus.glob("*.diff"))[::sample]
    workers = _resolve_jobs(jobs)
    if workers <= 1:
        names = [_check(str(path)) for path in paths]
    else:
        context = multiprocessing.get_context("fork")
        with ProcessPoolExecutor(
            max_workers=workers, mp_context=context
        ) as pool:
            names = list(pool.map(_check, [str(p) for p in paths],
                                  chunksize=16))
    return [name for name in names if name]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sample", type=int, default=1,
                        help="take every Nth corpus diff (default: all)")
    parser.add_argument("--jobs", type=int, default=_default_jobs(),
                        help="worker processes (default: min(8, CPUs))")
    args = parser.parse_args()
    mismatches = replay(sample=max(1, args.sample), jobs=args.jobs)
    if mismatches:
        for name in mismatches:
            print(f"MISMATCH {name}")
        print(f"{len(mismatches)} mismatching diff(s)")
        return 1
    print("change parity: all diffs agree")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
