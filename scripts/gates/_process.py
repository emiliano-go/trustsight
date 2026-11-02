"""Gates for the two-signal process, not for a detection mechanism.

Two claims live here:

* a rule listed as anergic is visible but cannot score; and
* a rule that stopped being anergic carries the release and changelog bullet
  that recorded its measured outcome.

Both are deterministic and corpus-free: they read the shipped ledger and the
shipped scorer, so they fail before a release rather than after a bad one.
"""

from __future__ import annotations

import tomllib
from scripts.gates._core import ROOT, Gate

__all__ = [
    "gate_anergic_promotions_are_changelogged",
    "gate_anergic_rules_never_score",
]


def _changelog_section(text: str, version: str) -> str:
    marker = f"## [{version}]"
    start = text.find(marker)
    if start < 0:
        return ""
    nxt = text.find("\n## [", start + len(marker))
    return text[start:] if nxt < 0 else text[start:nxt]


def gate_anergic_rules_never_score() -> Gate:
    """An anergic rule is reported at weight 0 whatever severity it declares.

    The ledger is the second-signal state, so a rule in it that still scores
    is the exact failure the state exists to prevent: an uncalibrated rule
    quietly moving a verdict.
    """
    name = "anergic rules never score"
    try:
        from trustsight.anergy import ANERGIC, entries
        from trustsight.config import DEFAULT_CONFIG
        from trustsight.schema import NoveltyContext
        from trustsight.scoring import calculate_score

        config = tomllib.loads(DEFAULT_CONFIG)
        ledger = entries()
    except Exception as exc:  # noqa: BLE001 - a broken ledger is a failed gate
        return Gate(name, False, 0, f"could not load the ledger: {exc}")
    checked = 0
    problems: list[str] = []
    for rule_id, row in ledger.items():
        if row.status != ANERGIC:
            continue
        checked += 1
        if not (row.signal and row.since and row.promotion):
            problems.append(f"{rule_id}: signal/since/promotion must be named")
        finding = {
            "rule_id": rule_id,
            "name": f"anergy probe {rule_id}",
            "severity": "MEDIUM",
            "category": "temporal",
            "match": "anergy probe",
        }
        _, breakdown, _ = calculate_score(
            [finding], {}, NoveltyContext(), config=config)
        rows = [row for row in breakdown if row.rule_id == rule_id]
        if not rows:
            problems.append(f"{rule_id}: no score entry produced")
        elif any(row.weight != 0 for row in rows):
            problems.append(f"{rule_id}: scored {rows[0].weight}, expected 0")
    return Gate(name, not problems, {"checked": checked}, "; ".join(problems))


def gate_anergic_promotions_are_changelogged() -> Gate:
    """A promoted rule names the release and the changelog bullet that carried it.

    Promotion is the moment an uncalibrated detector starts moving verdicts.
    It is allowed, but it is never silent: the ledger's ``promoted_in`` must
    resolve to a changelog section naming the rule and its measured outcome.
    """
    name = "anergic promotions are changelogged"
    try:
        from trustsight.anergy import promoted_entries

        path = ROOT / "docs" / "changelog.md"
        text = path.read_text(encoding="utf-8") if path.exists() else ""
        promoted = promoted_entries()
    except Exception as exc:  # noqa: BLE001 - a broken ledger is a failed gate
        return Gate(name, False, 0, f"could not read the ledger: {exc}")
    problems: list[str] = []
    for row in promoted:
        if not row.promoted_in:
            problems.append(f"{row.rule_id}: promoted without promoted_in")
            continue
        if not row.changelog:
            problems.append(f"{row.rule_id}: promoted without a changelog anchor")
            continue
        section = _changelog_section(text, row.promoted_in)
        if not section:
            problems.append(
                f"{row.rule_id}: no changelog section for {row.promoted_in}")
            continue
        if row.rule_id not in section:
            problems.append(
                f"{row.rule_id}: absent from the {row.promoted_in} changelog section")
    return Gate(name, not problems, {"promoted": len(promoted)}, "; ".join(problems))
