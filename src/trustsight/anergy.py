"""The standing anergy ledger: rules held at weight 0 pending a second signal.

A new detection ships report-only until the benign corpus calibrates it
(``docs/standards.md``).  This module is that state made explicit: a shipped
rule listed here contributes weight 0 whatever severity it declares, and the
release gate refuses to score it silently.

An entry is removed only by promotion.  Promotion records the release and the
changelog bullet that carried the measured outcome, so ``trustsight admin
anergic`` and the release gate read one source rather than two.

The ledger changes what the instrument scores, so it is part of
``config_fingerprint``: promoting a rule is a different instrument by design
(B1).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from importlib.resources import files

__all__ = [
    "ANERGIC",
    "PROMOTED",
    "AnergyEntry",
    "anergic_ids",
    "entries",
    "entry",
    "is_anergic",
    "ledger_section",
    "promoted_entries",
]

ANERGIC = "anergic"
PROMOTED = "promoted"
_STATUSES = frozenset({ANERGIC, PROMOTED})


@dataclass(frozen=True, slots=True)
class AnergyEntry:
    """One rule's anergy state and the evidence that closes it."""

    rule_id: str
    status: str
    signal: str
    since: str
    promotion: str
    promoted_in: str = ""
    changelog: str = ""
    #: Decided score weight once a human has adjudicated the rule.  ``None``
    #: means undecided (severity weight applies on promotion); ``0`` is the
    #: explicit "report-only, never score" decision.
    weight: int | None = None
    decided_in: str = ""

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "status": self.status,
            "signal": self.signal,
            "since": self.since,
            "promotion": self.promotion,
            "promoted_in": self.promoted_in,
            "changelog": self.changelog,
            "weight": self.weight,
            "decided_in": self.decided_in,
        }


def _load() -> dict[str, AnergyEntry]:
    data = files("trustsight").joinpath("anergy.json").read_text(encoding="utf-8")
    raw = json.loads(data)
    rules = raw.get("rules") if isinstance(raw, dict) else None
    if not isinstance(rules, dict):
        raise RuntimeError("anergy.json must carry a 'rules' object")
    out: dict[str, AnergyEntry] = {}
    for rule_id, row in rules.items():
        if not isinstance(row, dict):
            raise RuntimeError(f"anergy entry {rule_id!r} is not an object")
        status = str(row.get("status") or ANERGIC)
        if status not in _STATUSES:
            raise RuntimeError(f"anergy entry {rule_id!r} has unknown status {status!r}")
        weight = row.get("weight")
        if weight is not None and (isinstance(weight, bool)
                                   or not isinstance(weight, int)
                                   or weight < 0):
            raise RuntimeError(
                f"anergy entry {rule_id!r} has invalid weight {weight!r}")
        out[str(rule_id)] = AnergyEntry(
            rule_id=str(rule_id),
            status=status,
            signal=str(row.get("signal") or ""),
            since=str(row.get("since") or ""),
            promotion=str(row.get("promotion") or ""),
            promoted_in=str(row.get("promoted_in") or ""),
            changelog=str(row.get("changelog") or ""),
            weight=weight,
            decided_in=str(row.get("decided_in") or ""),
        )
    return out


_ENTRIES: dict[str, AnergyEntry] | None = None


def entries() -> dict[str, AnergyEntry]:
    """Every ledger entry, keyed by rule id, in stable order."""
    global _ENTRIES
    if _ENTRIES is None:
        _ENTRIES = dict(sorted(_load().items()))
    return dict(_ENTRIES)


def entry(rule_id: str | None) -> AnergyEntry | None:
    """The ledger entry for *rule_id*, or ``None``."""
    if not rule_id:
        return None
    return entries().get(str(rule_id))


def is_anergic(rule_id: str | None) -> bool:
    """True when *rule_id* must contribute weight 0."""
    row = entry(rule_id)
    return row is not None and row.status == ANERGIC


def anergic_ids() -> list[str]:
    """Sorted ids currently held at weight 0."""
    return sorted(rid for rid, row in entries().items() if row.status == ANERGIC)


def promoted_entries() -> list[AnergyEntry]:
    """Sorted entries that were promoted, with the release that carried them."""
    return [row for _, row in sorted(entries().items()) if row.status == PROMOTED]


def ledger_section() -> dict:
    """The anergy section the coverage ledger and the CLI both render."""
    return {rid: row.to_dict() for rid, row in entries().items()}
