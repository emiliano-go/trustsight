"""Measure the analysis hot path without changing behaviour.

Modes:

    corpus   scan the fetched benign corpus (serial, cProfile)
    package  scan one diff file (serial, cProfile)
    metadata parse the stored AUR metadata snapshot
    watch    run one full-AUR cycle (requires cached clones; offline)

The output is a baseline, not a gate.  Use it before and after an
optimization on the same machine and corpus.
"""

from __future__ import annotations

import argparse
import cProfile
import json
import pstats
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT))

import calibration_gates as gates  # noqa: E402


def _print_profile(profiler: cProfile.Profile, limit: int) -> None:
    stats = pstats.Stats(profiler)
    stats.strip_dirs().sort_stats("cumulative").print_stats(limit)


def _corpus(args) -> None:
    corpus = args.corpus or (gates.FIXTURES / "benign-corpus")
    if not corpus.is_dir():
        raise SystemExit(
            f"corpus not found at {corpus}; fetch it with the calibration asset"
        )
    profiler = cProfile.Profile()
    started = time.perf_counter()
    profiler.enable()
    rows = gates.scan_corpus(corpus, sample=args.sample, jobs=1)
    profiler.disable()
    elapsed = time.perf_counter() - started
    print(f"corpus={corpus} sample={args.sample} rows={len(rows)} "
          f"elapsed={elapsed:.2f}s per_row={elapsed / max(1, len(rows)):.4f}s")
    _print_profile(profiler, args.limit)


def _package(args) -> None:
    from trustsight.analysis import scan_diff
    from trustsight.config import load_config, load_rules

    path = Path(args.diff)
    if not path.is_file():
        raise SystemExit(f"diff not found: {path}")
    text = path.read_text(errors="replace")
    package = args.package or path.name.split("__")[0]
    profiler = cProfile.Profile()
    started = time.perf_counter()
    with gates.shipped_config():
        profiler.enable()
        fact = scan_diff(text, rules=load_rules(), config=load_config(),
                         package_name=package)
        profiler.disable()
    elapsed = time.perf_counter() - started
    print(f"package={package} diff={path} elapsed={elapsed:.4f}s "
          f"score={fact.final_score}")
    _print_profile(profiler, args.limit)


def _metadata(args) -> None:
    from trustsight.config import CONFIG_DIR

    path = Path(args.snapshot) if args.snapshot else (
        CONFIG_DIR / "full-aur-meta.json")
    if not path.is_file():
        raise SystemExit(f"metadata snapshot not found: {path}")
    raw = path.read_text(encoding="utf-8")
    started = time.perf_counter()
    data = json.loads(raw)
    elapsed = time.perf_counter() - started
    print(f"snapshot={path} bytes={len(raw):,} packages={len(data):,} "
          f"parse={elapsed:.2f}s")
    if args.engine != "stdlib":
        try:
            import ijson  # type: ignore
        except ImportError:
            print("ijson is not installed; skipping the streaming comparison")
            return
        started = time.perf_counter()
        count = sum(1 for _ in ijson.items(raw.encode("utf-8"), "item"))
        elapsed = time.perf_counter() - started
        print(f"ijson packages={count:,} parse={elapsed:.2f}s")


def _watch(args) -> None:
    from trustsight.full_aur import run_baseline_build

    profiler = cProfile.Profile()
    started = time.perf_counter()
    profiler.enable()
    result = run_baseline_build(json_output=False)
    profiler.disable()
    elapsed = time.perf_counter() - started
    print(f"watch cycle elapsed={elapsed:.2f}s processed={getattr(result, 'processed', '?')}")
    _print_profile(profiler, args.limit)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="mode", required=True)

    corpus = sub.add_parser("corpus", help="scan the fetched benign corpus")
    corpus.add_argument("--corpus", type=Path, default=None)
    corpus.add_argument("--sample", type=int, default=1)
    corpus.add_argument("--limit", type=int, default=30)
    corpus.set_defaults(func=_corpus)

    package = sub.add_parser("package", help="scan one diff file")
    package.add_argument("--diff", required=True)
    package.add_argument("--package", default="")
    package.add_argument("--limit", type=int, default=30)
    package.set_defaults(func=_package)

    metadata = sub.add_parser("metadata", help="parse the metadata snapshot")
    metadata.add_argument("--snapshot", default=None)
    metadata.add_argument("--engine", choices=("stdlib", "ijson"),
                          default="stdlib")
    metadata.set_defaults(func=_metadata)

    watch = sub.add_parser("watch", help="run one full-AUR cycle")
    watch.add_argument("--limit", type=int, default=30)
    watch.set_defaults(func=_watch)

    args = parser.parse_args(argv)
    args.func(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
