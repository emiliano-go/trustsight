#!/usr/bin/env python3
"""Generate docs/reference/threat-coverage.md from the shipped registry."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

OUT = ROOT / "docs" / "reference" / "threat-coverage.md"

HEADER = """<!-- description: Generated coverage map: every shipped rule, its layer, claim category, CWE, weight state and known gap. -->
<!-- generated: threat-coverage -->

# Threat coverage

This page is generated from the shipped registry by
`scripts/build_threat_coverage.py`. It is a map of what the rules claim, not a
claim of complete coverage.

| Rule | Name | Vector | Stage | Category | Layer | Severity | Weight | CWE | Boundary |
|---|---|---|---|---|---|---|---|---|---|
"""


def _rows() -> list[str]:
    from trustsight.anergy import entries
    from trustsight.categories import category_of
    from trustsight.config import load_config
    from trustsight.layers import layer_of
    from trustsight.analysis.composition import _STAGE_OF
    from trustsight.registry import REGISTRY
    from trustsight.rule_metadata import cwe_of

    rules = REGISTRY.all()
    ledger = entries()
    weights = load_config().get("severity_weights", {})
    rows = []
    for rule in sorted(rules, key=lambda r: r.sort_key):
        rule_id = rule.id
        row = {"name": rule.name, "severity": rule.severity}
        entry = ledger.get(rule_id)
        category = category_of(rule_id)
        layer = layer_of(rule_id)
        severity = str(row.get("severity", ""))
        if entry is not None and entry.status == "anergic":
            weight = "0 (anergic)"
            boundary = "calibration"
        elif entry is not None and entry.weight is not None:
            # A promoted rule may still carry an explicit 0: that is the
            # reviewed "report-only, never score" decision, not a severity
            # weight.
            weight = str(entry.weight)
            boundary = "calibration" if entry.weight == 0 else "promoted"
        else:
            weight = str(weights.get(severity, 0))
            boundary = "boundary" if rule_id.startswith("W") else ""
        rows.append(
            f"| {rule_id} | {row.get('name', '')} | "
            f"{rule.capability or ''} | {_STAGE_OF.get(rule_id, '')} | "
            f"{category.value if category else ''} | "
            f"{layer.value if layer else ''} | {severity} | {weight} | "
            f"{cwe_of(rule_id)} | {boundary} |"
        )
    return rows


def render() -> str:
    return HEADER + "\n".join(_rows()) + "\n"


def main() -> int:
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(render(), encoding="utf-8")
    print(f"wrote {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
