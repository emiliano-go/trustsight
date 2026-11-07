"""History-backed campaign signals that span more than one observation.

Every emitter is pure: the caller supplies the current cycle and bounded
history feeds on a ``HistorySnapshot``-like value.  Missing history means no
finding; malformed measurements are never coerced into evidence.
"""

from __future__ import annotations

from datetime import datetime, timezone
from itertools import islice
import math
from typing import TYPE_CHECKING

from ..analysis.payload_signals import SHARED_PAYLOAD_RULES
from ..deps import is_related_package, normalize_dependency
from ._temporal_common import _cluster, _threshold

if TYPE_CHECKING:
    from .temporal_engine import HistorySnapshot

__all__ = [
    "_delayed_adoption_findings",
    "_dormant_takeover_findings",
    "_dependency_redirection_findings",
    "_reappearance_findings",
    "_trust_erosion_findings",
]

_MAX_PACKAGES = 4096
_MAX_HISTORY = 256
_MAX_RULES = 128
_MAX_DEPENDENCIES = 128
_MAX_PROVIDES = 128
_DEP_FIELDS = ("depends_added", "makedepends_added", "checkdepends_added")
_PRECURSOR_RULES = frozenset({
    "H024", "H078", "H091", "H092", "H047",
    "H049", "H054", "H057", "H064", "D004",
})
_TERMINAL_RULES = SHARED_PAYLOAD_RULES | frozenset({"S009", "S010", "S011"})


def _mapping(value) -> dict:
    return value if isinstance(value, dict) else {}


def _sequence(value, cap: int):
    if value is None or isinstance(value, (str, bytes, dict)):
        return ()
    try:
        return tuple(islice(value, cap))
    except TypeError:
        return ()


def _number(value, default: float = 0.0) -> float:
    try:
        result = float(value)
    except (TypeError, ValueError, OverflowError):
        return default
    return result if math.isfinite(result) else default


def _timestamp(value) -> float | None:
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        try:
            parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            pass
        else:
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            try:
                result = parsed.timestamp()
            except (OverflowError, OSError, ValueError):
                return None
            return result if math.isfinite(result) else None
    if isinstance(value, bool) or value is None:
        return None
    result = _number(value, float("nan"))
    return result if math.isfinite(result) else None


def _packages(index) -> list[str]:
    return sorted(str(name) for name in _mapping(index))[:_MAX_PACKAGES]


def _rules(detail: dict) -> set[str]:
    return {
        str(rule) for rule in _sequence(detail.get("rules"), _MAX_RULES)
        if str(rule)
    }


def _iso_time(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, timezone.utc).isoformat()


def _delayed_adoption_findings(snapshot: HistorySnapshot) -> list[dict]:
    """T008: a payload appears well after an earlier maintainer adoption."""
    now = _timestamp(snapshot.now)
    if now is None:
        return []
    delay_days = max(0.0, _number(
        _threshold("t008", "min_delay_days", 14), 14.0))
    detail_index = _mapping(snapshot.detail)
    transitions = _mapping(snapshot.transitions)
    history_index = _mapping(snapshot.maintainer_transitions)
    out: list[dict] = []
    for name in _packages(detail_index):
        if name in transitions:
            continue
        rules = sorted(_rules(_mapping(detail_index[name])) & SHARED_PAYLOAD_RULES)
        if not rules:
            continue
        adoptions: list[tuple[float, dict]] = []
        for row in _sequence(history_index.get(name), _MAX_HISTORY):
            row = _mapping(row)
            if row.get("property_key", "maintainer") != "maintainer":
                continue
            observed = _timestamp(row.get("observed_at"))
            if observed is not None:
                adoptions.append((observed, row))
        if not adoptions:
            continue
        adopted, row = max(adoptions, key=lambda item: item[0])
        if now - adopted < delay_days * 86400:
            continue
        detail = _mapping(detail_index[name])
        maintainer = str(
            detail.get("maintainer") or row.get("new_value") or "")
        out.append(_cluster(
            "T008",
            "Delayed Payload Adoption",
            f"{name} gained payload rule(s) {', '.join(rules)} "
            f"{(now - adopted) / 86400:.1f} days after maintainer adoption",
            [name],
            severity="INFO",
            category="temporal",
            adoption_date=str(row.get("observed_at") or _iso_time(adopted)),
            adoption_timestamp=adopted,
            rules=rules,
            maintainer=maintainer,
            delay_days=round((now - adopted) / 86400, 3),
        ))
    return out


def _dormant_takeover_findings(snapshot: HistorySnapshot) -> list[dict]:
    """T009: a dormant, measurably exposed package changes owner."""
    now = _timestamp(snapshot.now)
    if now is None:
        return []
    dormant_days = max(0.0, _number(
        _threshold("t009", "dormant_days", 180), 180.0))
    min_votes = max(0.0, _number(_threshold("t009", "min_votes", 100), 100.0))
    min_popularity = max(0.0, _number(
        _threshold("t009", "min_popularity", 1.0), 1.0))
    min_dependents = max(0, int(_number(
        _threshold("t009", "min_dependents", 10), 10.0)))
    old_meta = _mapping(snapshot.old_meta)
    new_meta = _mapping(snapshot.new_meta)
    reverse: dict[str, set[str]] = {}
    for dependent, targets in _mapping(snapshot.edges).items():
        for target in _sequence(targets, _MAX_DEPENDENCIES):
            reverse.setdefault(str(target), set()).add(str(dependent))
    out: list[dict] = []
    for name, change in sorted(_mapping(snapshot.transitions).items()):
        try:
            old_maintainer, new_maintainer = change
        except (TypeError, ValueError):
            continue
        if not new_maintainer or old_maintainer == new_maintainer:
            continue
        modified = _timestamp(_mapping(old_meta.get(name)).get("LastModified"))
        if modified is None or now - modified <= dormant_days * 86400:
            continue
        entry = _mapping(new_meta.get(name))
        votes = _number(entry.get("NumVotes"))
        popularity = _number(entry.get("Popularity"))
        dependents = len(reverse.get(name, ()))
        if not (votes >= min_votes or popularity >= min_popularity
                or dependents >= min_dependents):
            continue
        measures = []
        if votes >= min_votes:
            measures.append(f"NumVotes={votes:g}")
        if popularity >= min_popularity:
            measures.append(f"Popularity={popularity:g}")
        if dependents >= min_dependents:
            measures.append(f"direct_dependents={dependents}")
        dormant_for = (now - modified) / 86400
        out.append(_cluster(
            "T009",
            "High-Value Dormant Takeover",
            f"{name} was dormant for {dormant_for:.1f} days before adoption; "
            + ", ".join(measures),
            [name],
            severity="INFO",
            category="temporal",
            previous_maintainer=old_maintainer,
            current_maintainer=new_maintainer,
            last_modified=modified,
            dormant_days=round(dormant_for, 3),
            num_votes=votes,
            popularity=popularity,
            direct_dependents=dependents,
            qualifying_measures=measures,
        ))
    return out


def _unique_providers(meta: dict) -> dict[str, str]:
    candidates: dict[str, set[str]] = {}
    for name in _packages(meta):
        entry = _mapping(meta[name])
        for provided in _sequence(entry.get("Provides"), _MAX_PROVIDES):
            alias = normalize_dependency(str(provided))
            if alias and alias != name:
                candidates.setdefault(alias, set()).add(name)
    return {
        alias: next(iter(names)) for alias, names in candidates.items()
        if len(names) == 1
    }


def _dependency_redirection_findings(snapshot: HistorySnapshot) -> list[dict]:
    """T010: new dependencies point at a newly added or adopted target."""
    new_meta = _mapping(snapshot.new_meta)
    changes = _mapping(snapshot.changes)
    transitions = _mapping(snapshot.transitions)
    aliases = _unique_providers(new_meta)
    grouped: dict[str, dict[str, set[str]]] = {}
    dependency_names: dict[str, set[str]] = {}
    detail_index = _mapping(snapshot.detail)
    for name in _packages(detail_index):
        dependency_changes = _mapping(
            _mapping(detail_index[name]).get("dependency_changes"))
        for field in _DEP_FIELDS:
            for raw in _sequence(dependency_changes.get(field), _MAX_DEPENDENCIES):
                normalized = normalize_dependency(str(raw))
                target = normalized if normalized in new_meta else aliases.get(normalized)
                if not target or target == name:
                    continue
                current_transition = transitions.get(target)
                adopted = bool(
                    isinstance(current_transition, (list, tuple))
                    and len(current_transition) == 2
                    and current_transition[1]
                )
                if changes.get(target) != "added" and not adopted:
                    continue
                source_base = str(_mapping(new_meta.get(name)).get("PackageBase") or name)
                target_base = str(_mapping(new_meta.get(target)).get("PackageBase") or target)
                if source_base == target_base or is_related_package(name, target_base):
                    continue
                grouped.setdefault(target, {}).setdefault(name, set()).add(field)
                dependency_names.setdefault(target, set()).add(normalized)
    out: list[dict] = []
    for target in sorted(grouped):
        sources = grouped[target]
        members = sorted(sources)
        fields = sorted({field for values in sources.values() for field in values})
        out.append(_cluster(
            "T010",
            "Dependency Redirection",
            f"{len(members)} package(s) added dependencies on recently "
            f"added or adopted target {target}",
            members,
            severity="INFO",
            category="dependency",
            target=target,
            dependency_names=sorted(dependency_names[target]),
            fields=fields,
            target_status=("added" if changes.get(target) == "added" else "adopted"),
        ))
    return out


def _reappearance_findings(snapshot: HistorySnapshot) -> list[dict]:
    """T011: a package currently marked added has an earlier removal row."""
    new_meta = _mapping(snapshot.new_meta)
    events_index = _mapping(snapshot.package_cycle_events)
    out: list[dict] = []
    for name, status in sorted(_mapping(snapshot.changes).items()):
        if status != "added":
            continue
        removals: list[tuple[float, dict]] = []
        for row in _sequence(events_index.get(name), _MAX_HISTORY):
            row = _mapping(row)
            if str(row.get("status") or "").lower() != "removed":
                continue
            # cycle_time is a logical cycle ordinal, never a Unix timestamp.
            cycle_time = _number(row.get("cycle_time"), float("nan"))
            if math.isfinite(cycle_time):
                removals.append((cycle_time, row))
        if not removals:
            continue
        _removed_cycle, removal = max(removals, key=lambda item: item[0])
        entry = _mapping(new_meta.get(name))
        maintainer = str(entry.get("Maintainer") or "")
        first_submitted = entry.get("FirstSubmitted")
        out.append(_cluster(
            "T011",
            "Package Reappearance",
            f"{name} reappeared after removal cycle "
            f"{removal.get('cycle_time')}; current maintainer "
            f"{maintainer or 'unknown'}, FirstSubmitted={first_submitted!r}",
            [name],
            severity="INFO",
            category="temporal",
            removal_cycle=removal.get("cycle_time"),
            removal_maintainer=removal.get("maintainer"),
            maintainer=maintainer,
            first_submitted=first_submitted,
        ))
    return out


def _trust_erosion_findings(snapshot: HistorySnapshot) -> list[dict]:
    """T012: an earlier integrity/provenance precursor precedes a payload."""
    detail_index = _mapping(snapshot.detail)
    history_index = _mapping(snapshot.prior_rule_history)
    out: list[dict] = []
    for name in _packages(detail_index):
        terminal = sorted(_rules(_mapping(detail_index[name])) & _TERMINAL_RULES)
        if not terminal:
            continue
        seen: set[str] = set()
        sequence: list[dict] = []
        for row in _sequence(history_index.get(name), _MAX_HISTORY):
            row = _mapping(row)
            history_id = str(row.get("history_id") or "")
            if not history_id or history_id in seen:
                continue
            seen.add(history_id)
            precursor = sorted(_rules(row) & _PRECURSOR_RULES)
            if precursor:
                sequence.append({
                    "history_id": history_id,
                    "timestamp": row.get("timestamp"),
                    "rules": precursor,
                })
        if not sequence:
            continue
        precursor_rules = sorted({rule for row in sequence for rule in row["rules"]})
        history_ids = [row["history_id"] for row in sequence]
        out.append(_cluster(
            "T012",
            "Trust Erosion Sequence",
            f"{name} has precursor rule(s) {', '.join(precursor_rules)} "
            f"before current terminal rule(s) {', '.join(terminal)}",
            [name],
            severity="INFO",
            category="temporal",
            precursor_rules=precursor_rules,
            precursor_history_ids=history_ids,
            precursor_sequence=sequence,
            terminal_rules=terminal,
        ))
    return out
