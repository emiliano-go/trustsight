"""Derive the R->H rename mapping, once, from the pre-rename catalog.

The split is by *mechanism*, not by number: a rule whose id appears in
``rules.toml`` is a regex rule and keeps its ``R`` prefix; every other id in
the catalog is emitted from code and becomes an ``H`` rule.  Both sides are
read from the build rather than typed out, because a hand-written list of
ninety-five ids is a second list that has to agree with the catalog, and the
whole point of the exercise is that ``R`` should mean something checkable.

Run before the rename to produce the mapping::

    python scripts/rule_id_mapping.py --write

That writes ``scripts/rule_id_map.json``, which is the single source of
truth for everything downstream: the database migration, the changelog
table, the test rewrite and the documentation pass all read it rather than
re-deriving.  After the rename the derivation no longer works - the catalog
holds ``H`` ids by then - so the artifact is committed and this script
refuses to overwrite it with a different result.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ARTIFACT = Path(__file__).resolve().parent / "rule_id_map.json"

sys.path.insert(0, str(ROOT / "src"))


def derive() -> dict[str, str]:
    """The mapping, from the catalog and the shipped rule set.

    Ordered by the current number so the new numbering preserves the old
    relative order.  That is not cosmetic: it keeps ranges of related rules
    adjacent, and it makes the mapping table readable as a diff of one
    sequence into another rather than a permutation.
    """
    from trustsight.categories import RULE_CATEGORIES
    from trustsight.config import shipped_rules

    catalog = {rid for rid in RULE_CATEGORIES if rid.startswith("R")}
    regex_rules = {rule["id"] for rule in shipped_rules() if rule["id"].startswith("R")}

    stranded = regex_rules - catalog
    if stranded:
        raise SystemExit(
            f"rules.toml declares ids the catalog does not know: {sorted(stranded)}")

    programmatic = sorted(catalog - regex_rules, key=lambda rid: int(rid[1:]))
    return {old: f"H{index:03d}" for index, old in enumerate(programmatic, start=1)}


def load() -> dict[str, str]:
    """The committed mapping.  Every consumer downstream reads this."""
    if not ARTIFACT.exists():
        raise SystemExit(f"no mapping at {ARTIFACT}; run with --write first")
    return json.loads(ARTIFACT.read_text())


def as_markdown(mapping: dict[str, str]) -> str:
    """The changelog table: four column-pairs, ordered down then across."""
    items = sorted(mapping.items(), key=lambda kv: int(kv[0][1:]))
    columns = 4
    rows = -(-len(items) // columns)
    lines = ["| Old | New | Old | New | Old | New | Old | New |",
             "|---|---|---|---|---|---|---|---|"]
    for row in range(rows):
        cells = []
        for column in range(columns):
            index = column * rows + row
            cells.extend([f"`{items[index][0]}`", f"`{items[index][1]}`"]
                         if index < len(items) else ["", ""])
        lines.append("| " + " | ".join(cells) + " |")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true",
                        help="derive and write the artifact")
    parser.add_argument("--markdown", action="store_true",
                        help="print the changelog table from the artifact")
    args = parser.parse_args(argv)

    if args.write:
        mapping = derive()
        if ARTIFACT.exists():
            existing = load()
            if existing != mapping:
                raise SystemExit(
                    f"{ARTIFACT.name} already exists and differs from the "
                    "derivation. The mapping is frozen once published: a "
                    "second, different mapping would silently renumber rules "
                    "that databases, baselines and fixtures already name.")
        ARTIFACT.write_text(json.dumps(mapping, indent=2, sort_keys=True) + "\n")
        print(f"{len(mapping)} ids -> {ARTIFACT}")
        return 0

    mapping = load()
    if args.markdown:
        print(as_markdown(mapping))
        return 0
    for old, new in sorted(mapping.items(), key=lambda kv: int(kv[0][1:])):
        print(f"{old} -> {new}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
