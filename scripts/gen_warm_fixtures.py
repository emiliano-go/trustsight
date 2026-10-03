"""Generate the warm D-series fixtures (corpus-dependent rules).

D001/D002 answer from the dependency corpus, and the main gates run cold by
design: an unseeded install must not make every dependency look novel.  The
evasion and synthetic corpora therefore cannot label a fixture for D001
(the shape would fail its label no matter how well the parser works), so the
warm half lives in its own category and its own context.

Each fixture is scanned twice here, exactly as ``gate_d_series_warm`` scans
it: once with the committed corpus seeded, where the label must pass, and
once cold, where D001/D002 must stay silent.  A fixture that fired cold
would mean the cold-start guard broke, which is a security property and not
just a label.

Usage:
    python scripts/gen_warm_fixtures.py [--out tests/fixtures/malicious/warm]
"""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from calibration_gates import (  # noqa: E402
    _fixture_failures,
    shipped_config,
    warm_dependency_corpus,
)
from trustsight.analysis import scan_diff  # noqa: E402
from trustsight.config import ensure_default_configs, load_config  # noqa: E402
from trustsight.rules import load_rules  # noqa: E402

FIXTURES: list[dict] = []


def add(name: str, body: str, **expect) -> None:
    FIXTURES.append({"name": name, "diff_text": body, "expect": expect})


def diff(*added: str, context: str = "pkgname=demo\npkgver=1.0") -> str:
    """A one-file unified diff whose hunk adds *added*."""
    ctx = context.splitlines()
    plus = "\n".join("+" + line for line in added)
    return (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n"
        f"@@ -1,{len(ctx)} +1,{len(ctx) + len(added)} @@\n"
        + "".join(f" {line}\n" for line in ctx)
        + plus
        + "\n"
    )


add("D001-depends-plus-eq",
    diff("depends+=('totally-unknown-backdoor')"),
    description="A dependency appended with += that the warm corpus has "
                "never seen. D001 fires only when the corpus is loaded, and "
                "the cold scan of the same fixture must stay silent, which "
                "is the half the evasion corpus cannot test",
    must_fire=["D001"], min_score=25)


def _scan(path: Path, config, rules) -> dict:
    fact = scan_diff(path.read_text(errors="replace"), rules=rules,
                     config=config, package_name=path.stem, seen_urls={})
    return {
        "name": path.name,
        "score": fact.final_score,
        "fired": {e.rule_id for e in fact.score_breakdown},
        "scored": {
            e.rule_id for e in fact.score_breakdown
            if e.weight != 0 or e.severity == "FATAL"
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate warm D-series fixtures")
    parser.add_argument("--out", type=Path,
                        default=Path(__file__).resolve().parent.parent
                        / "tests" / "fixtures" / "malicious" / "warm")
    args = parser.parse_args()

    args.out.mkdir(parents=True, exist_ok=True)

    expected: dict = {}
    failures: list[str] = []

    with warm_dependency_corpus():
        ensure_default_configs()
        config = load_config()
        rules = load_rules()

        for fx in FIXTURES:
            fname = fx["name"] + ".diff"
            fpath = args.out / fname
            fpath.write_text(fx["diff_text"])

            result = _scan(fpath, config, rules)
            entry = {k: fx["expect"][k] for k in ("description", "must_fire", "min_score")
                     if k in fx["expect"]}
            result["expected"] = entry
            failures.extend(_fixture_failures(result))
            expected[fname] = entry

    # The cold half of the same contract: with no corpus, the guard must
    # keep D001/D002 silent.  Firing here would be the cold-start failure.
    with shipped_config():
        ensure_default_configs()
        config = load_config()
        rules = load_rules()

        for fx in FIXTURES:
            result = _scan(args.out / (fx["name"] + ".diff"), config, rules)
            cold = {"D001", "D002"} & result["fired"]
            if cold:
                failures.append(
                    f"{fx['name']}.diff: {sorted(cold)} fired on the cold database"
                )

    expected = {k: expected[k] for k in sorted(expected)}
    with open(args.out / "expected.json", "w", encoding="utf-8") as f:
        json.dump(expected, f, indent=2, sort_keys=True, ensure_ascii=False)
        f.write("\n")

    for fname in sorted(expected):
        print(f"  {fname}")

    if failures:
        print(f"\nFAILURES ({len(failures)}):", file=sys.stderr)
        for failure in failures:
            print(f"  {failure}", file=sys.stderr)
        return 1
    print(f"\n{len(FIXTURES)} warm fixture(s) fire warm and stay silent cold.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
