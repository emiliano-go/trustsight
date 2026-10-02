"""Finding-level parity runner for the typed-core migration.

Phase 1 moves diff readers off their own text walks onto
:class:`~trustsight.diffdoc.DiffDoc` projections.  The projection gate
(``diffdoc_parity.py``) proves the parse; this runner proves the
*findings*: replay the locked benign corpus and the labelled malicious
fixtures through ``scan_diff`` and compare every emitted finding, so a
migration that changes what fires, where it points, or what it weighs
fails loudly instead of drifting the published figures.

Usage:

    uv run python tests/harness/finding_parity.py --write BASELINE.json
    uv run python tests/harness/finding_parity.py --check BASELINE.json [--sample N]

The baseline is taken on the pre-migration tree and checked after each
migration step.  It is a migration tool, not a permanent artifact: it
retires with the last legacy walker.
"""

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

import calibration_gates as gates  # noqa: E402


def replay(sample: int = 1) -> list[dict]:
    """Every corpus diff's findings, benign then malicious, in a stable order."""
    results: list[dict] = []
    corpus = gates.FIXTURES / "benign-corpus"
    if corpus.exists():
        for row in gates.scan_corpus(corpus, sample=sample):
            results.append({
                "kind": "benign",
                "package": row["package"],
                "name": row["path"].name,
                "score": row["score"],
                "entries": row["entries"],
            })
    malicious = gates.FIXTURES / "malicious"
    if malicious.exists():
        # scan_malicious returns labels, not findings, so the replay here
        # repeats its walk and keeps the full entries.
        gates.ensure_default_configs()
        config = gates.load_config()
        rules = gates.load_rules()
        for group in sorted(p for p in malicious.iterdir() if p.is_dir()):
            for path in sorted(group.glob("*.diff")):
                fact = gates.scan_diff(
                    path.read_text(errors="replace"), rules=rules,
                    config=config, package_name=path.stem, seen_urls={})
                results.append({
                    "kind": "malicious",
                    "package": group.name,
                    "name": path.name,
                    "score": fact.final_score,
                    "entries": [
                        {"rule_id": e.rule_id, "severity": e.severity,
                         "weight": e.weight, "params": e.params or {}}
                        for e in fact.score_breakdown
                    ],
                })
    return results


def compare(baseline: list[dict], current: list[dict]) -> list[str]:
    """The finding-level differences between two replays."""
    failures: list[str] = []
    if len(baseline) != len(current):
        failures.append(
            f"replay size differs: baseline={len(baseline)} current={len(current)}"
        )
        return failures
    for old, new in zip(baseline, current):
        key = (old["kind"], old["package"], old["name"])
        if key != (new["kind"], new["package"], new["name"]):
            failures.append(f"order drift: {key} vs {(new['kind'], new['package'], new['name'])}")
            continue
        if old["score"] != new["score"] or old["entries"] != new["entries"]:
            failures.append(
                f"{key}: score {old['score']} -> {new['score']}; "
                f"entries {old['entries']} -> {new['entries']}"
            )
    return failures


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--write", metavar="PATH")
    group.add_argument("--check", metavar="PATH")
    parser.add_argument("--sample", type=int, default=1)
    args = parser.parse_args(argv)

    results = replay(sample=args.sample)
    if args.write:
        Path(args.write).write_text(json.dumps(results, indent=1))
        print(f"finding parity: wrote {len(results)} replays to {args.write}")
        return 0

    baseline = json.loads(Path(args.check).read_text())
    failures = compare(baseline, results)
    for failure in failures[:50]:
        print(f"PARITY FAIL {failure}")
    print(
        f"finding parity: {len(results)} replays checked, "
        f"{len(failures)} mismatched"
    )
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
