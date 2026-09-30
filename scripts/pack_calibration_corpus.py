#!/usr/bin/env python3
"""Pack the calibration corpus into the CI asset.

The corpus is not committed (``*.diff`` is gitignored), and rebuilding it
from ``corpus.lock`` is not byte-stable across git versions: the same lock
reconstructed to different bytes in CI than on the maintainer's machine,
and two corpora that differ in a handful of diffs measure different benign
flag rates (7.8 vs 7.9), which fails the published-figures gate.

So the corpus ships as a release asset, the same answer the seed channel
already gives: CI downloads ``baseline-benign-corpus.tar.gz`` from the
channel release, extracts it, and verifies the extracted bytes against the
``corpus_content_sha256`` recorded in ``tests/fixtures/baseline.json``.
The asset is CI-only: the tool never downloads it, so it is unsigned; the
committed hash in baseline.json is the integrity anchor.

Usage:

    python scripts/pack_calibration_corpus.py            # dist/baseline-benign-corpus.tar.gz
    python scripts/pack_calibration_corpus.py --check    # verify the corpus matches baseline.json only

The pack refuses to run over a corpus whose content hash does not match
baseline.json: shipping a drifted corpus would bless the drift.
"""

import argparse
import gzip
import hashlib
import io
import json
import sys
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "fixtures"
CORPUS = FIXTURES / "benign-corpus"
BASELINE = FIXTURES / "baseline.json"
ASSET_NAME = "baseline-benign-corpus.tar.gz"

# Same fixed epoch as build_release_tarball.py: the asset's bytes must not
# depend on when or by whom it was packed.
FIXED_MTIME = 0


def corpus_content_hash(corpus: Path) -> str:
    """SHA-256 over the sorted concatenation of all diff file bytes.

    Byte-for-byte the helper in ``build_corpus.py``/``rebaseline.py``; the
    three must agree because the value is compared against
    ``corpus_content_sha256`` in ``baseline.json``.
    """
    h = hashlib.sha256()
    for dp in sorted(corpus.rglob("*.diff")):
        h.update(dp.read_bytes())
    return h.hexdigest()


def recorded_hash(baseline: Path) -> str:
    return json.loads(baseline.read_text(encoding="utf-8"))["corpus_content_sha256"]


def pack(corpus: Path, out: Path) -> str:
    """Write the deterministic tarball and return its sha256."""
    files = sorted(corpus.rglob("*.diff"))
    buffer = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", compresslevel=9,
                       fileobj=buffer, mtime=FIXED_MTIME) as gz:
        with tarfile.open(fileobj=gz, mode="w") as tar:
            for path in files:
                info = tar.gettarinfo(str(path), arcname=path.name)
                info.mtime = FIXED_MTIME
                info.uid = info.gid = 0
                info.uname = info.gname = ""
                with open(path, "rb") as fh:
                    tar.addfile(info, fh)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(buffer.getvalue())
    return hashlib.sha256(buffer.getvalue()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--corpus", type=Path, default=CORPUS)
    parser.add_argument("--baseline", type=Path, default=BASELINE)
    parser.add_argument("--out", type=Path, default=ROOT / "dist" / ASSET_NAME)
    parser.add_argument("--check", action="store_true",
                        help="verify the corpus matches baseline.json and stop")
    args = parser.parse_args()

    if not args.corpus.is_dir():
        print(f"corpus not found: {args.corpus}", file=sys.stderr)
        return 1

    content = corpus_content_hash(args.corpus)
    recorded = recorded_hash(args.baseline)
    if content != recorded:
        print(
            f"corpus content sha256 {content} does not match baseline.json "
            f"{recorded}; refusing to pack a drifted corpus",
            file=sys.stderr,
        )
        return 1
    n = len(list(args.corpus.rglob("*.diff")))
    print(f"corpus: {n} diffs, content sha256 {content} (matches baseline.json)")

    if args.check:
        return 0

    digest = pack(args.corpus, args.out)
    print(f"asset:  {args.out}")
    print(f"asset sha256 {digest}")
    print(f"upload: gh release upload <baseline-tag> {args.out} --clobber")
    return 0


if __name__ == "__main__":
    sys.exit(main())
