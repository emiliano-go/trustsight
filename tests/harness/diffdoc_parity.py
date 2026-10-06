"""Projection regression lock for the typed diff core.

The parse decisions - file attribution, side, both line numbers, hunk
arithmetic - are frozen as a per-diff digest over ``DiffDoc.files`` and
``DiffDoc.lines``.  A change that alters the parse fails until the baseline
is deliberately regenerated with ``--write``, which also pins the locked
corpus by its ``corpus_content_sha256``.  (The cross-walker comparison this
file used to run became self-referential once the legacy readers were
migrated onto ``DiffDoc``.)

    uv run python tests/harness/diffdoc_parity.py --write tests/fixtures/diffdoc-projections.json.gz
    uv run python tests/harness/diffdoc_parity.py --check tests/fixtures/diffdoc-projections.json.gz

The default test suite runs a sampled variant
(``tests/test_diffdoc_parity.py``); the calibration CI job runs this whole.
"""

import argparse
import gzip
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT / "src"))

from trustsight.diffdoc import parse_diff  # noqa: E402

FIXTURES = ROOT / "tests" / "fixtures"
BASELINE = FIXTURES / "diffdoc-projections.json.gz"
SCHEMA = 1


def iter_diff_paths(sample: int = 1):
    """Every corpus diff, benign first, then the labelled malicious ones.

    ``sample`` thins whole packages uniformly (every *sample*-th diff in
    the sorted walk), the same convention ``calibration_gates.scan_corpus``
    uses, so a sampled run is a subset of the full one, never a different
    one.
    """
    paths: list[Path] = []
    benign = FIXTURES / "benign-corpus"
    if benign.exists():
        paths.extend(sorted(benign.rglob("*.diff")))
    malicious = FIXTURES / "malicious"
    if malicious.exists():
        paths.extend(sorted(malicious.rglob("*.diff")))
    for index, path in enumerate(paths, start=1):
        if sample > 1 and index % sample:
            continue
        yield path


def projection_digest(text: str) -> str:
    """A short digest of the parse, stable across runs and platforms.

    ``tokenizer_version`` and the schema are deliberately excluded: they
    change with the tokenizer, not with the parse, and a tokenizer edit that
    does not move the parse must not force a re-baseline.
    """
    data = parse_diff(text).to_dict()
    payload = json.dumps(
        {"files": data["files"], "lines": data["lines"]},
        sort_keys=True, separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode()).hexdigest()[:16]


def corpus_content_sha() -> str:
    """The locked corpus's content hash, from the committed baseline."""
    return json.loads(
        (FIXTURES / "baseline.json").read_text(encoding="utf-8")
    )["corpus_content_sha256"]


def replay(sample: int = 1) -> dict:
    """The baseline document for the corpus: sha pin plus per-diff digests."""
    projections = {
        str(path.relative_to(FIXTURES)): projection_digest(
            path.read_text(errors="replace")
        )
        for path in iter_diff_paths(sample=sample)
    }
    return {
        "schema": SCHEMA,
        "corpus_content_sha256": corpus_content_sha(),
        "projections": projections,
    }


def compare(baseline: dict, current: dict) -> list[str]:
    """Human-readable differences: corpus pin, missing, new, changed."""
    failures: list[str] = []
    if baseline.get("schema") != SCHEMA:
        failures.append(
            f"baseline schema {baseline.get('schema')!r} != {SCHEMA}"
        )
    if baseline.get("corpus_content_sha256") != current["corpus_content_sha256"]:
        failures.append(
            "corpus mismatch: baseline built from "
            f"{baseline.get('corpus_content_sha256')}, current corpus is "
            f"{current['corpus_content_sha256']}"
        )
    old = baseline.get("projections", {})
    new = current["projections"]
    for name in sorted(set(old) | set(new)):
        if name not in new:
            failures.append(f"{name}: in the baseline, absent from the corpus")
        elif name not in old:
            failures.append(f"{name}: new diff not in the baseline")
        elif old[name] != new[name]:
            failures.append(
                f"{name}: projection {old[name]} -> {new[name]}"
            )
    return failures


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--write", metavar="PATH")
    group.add_argument("--check", metavar="PATH")
    parser.add_argument("--sample", type=int, default=1)
    args = parser.parse_args(argv)

    current = replay(sample=args.sample)
    if args.write:
        Path(args.write).write_bytes(
            gzip.compress(json.dumps(current, sort_keys=True).encode())
        )
        print(
            f"diffdoc projections: wrote {len(current['projections'])} "
            f"digests to {args.write}"
        )
        return 0

    with gzip.open(args.check, "rt") as handle:
        baseline = json.load(handle)
    failures = compare(baseline, current)
    for failure in failures[:200]:
        print(f"PARITY FAIL {failure}")
    print(
        f"diffdoc projections: {len(current['projections'])} diffs, "
        f"{len(failures)} mismatched"
    )
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
