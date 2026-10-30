"""Ownership and maintainer-transition temporal emitters."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ._temporal_common import _cluster, _last_modified, _threshold

if TYPE_CHECKING:
    from .temporal_engine import HistorySnapshot


def _known_maintainers(old_meta: dict) -> set[str]:
    """Every maintainer the previous snapshot knew of."""
    known: set[str] = set()
    for entry in old_meta.values():
        maintainer = (entry.get("Maintainer") or "").strip().lower()
        if maintainer:
            known.add(maintainer)
    return known


def _ownership_transition_findings(snapshot: HistorySnapshot) -> list[dict]:
    """H044 - a package changed maintainer this cycle, and H026 with it."""
    old_meta = snapshot.old_meta
    transitions = snapshot.transitions
    out: list[dict] = []
    known = _known_maintainers(old_meta or {})
    for name, (old_m, new_m) in sorted(transitions.items()):
        if not new_m:
            continue
        out.append(_cluster(
            "H044",
            "Ownership Transition",
            f"maintainer of {name} changed from '{old_m or 'orphan'}' to '{new_m}'",
            [name],
            severity="MEDIUM",
            category="maintainer",
            old=old_m,
            new=new_m,
        ))
        if new_m not in known:
            out.append(_cluster(
                "H026",
                "New Maintainer Without Prior History",
                f"maintainer of {name} changed to '{new_m}', who maintained "
                f"no package in the previous snapshot",
                [name],
                severity="HIGH",
                category="maintainer",
                previous_maintainer=old_m,
                current_maintainer=new_m,
            ))
    return out


def _adopt_then_modify_findings(snapshot: HistorySnapshot) -> list[dict]:
    """H074 - adopt-then-immediately-modify (fires on the first package)."""
    new_meta, old_meta = snapshot.new_meta, snapshot.old_meta
    transitions, now = snapshot.transitions, snapshot.now
    window_s = _threshold("h074", "window_days", 14) * 86400
    by_maintainer: dict[str, list[str]] = {}
    for name, (old_m, new_m) in transitions.items():
        if not new_m:
            continue
        old_v = (old_meta.get(name) or {}).get("Version")
        new_v = (new_meta.get(name) or {}).get("Version")
        if old_v == new_v:
            continue
        lm = _last_modified(new_meta.get(name))
        if lm is not None and now and (now - lm) > window_s:
            continue
        by_maintainer.setdefault(new_m, []).append(name)
    out: list[dict] = []
    for maintainer, members in by_maintainer.items():
        out.append(_cluster(
            "H074",
            "Adopt-then-Modify",
            f"maintainer {maintainer} adopted and immediately modified "
            f"{len(members)} package(s)",
            sorted(members),
            severity="MEDIUM",
            category="maintainer",
            maintainer=maintainer,
        ))
    return out
