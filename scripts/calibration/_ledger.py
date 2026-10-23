"""Per-rule corpus coverage: the control panel for corpus expansion.

Every catalog id must land in exactly one state:

``measured``          fires on at least one benign source (cold diff corpus,
                      history corpus, warm replay, manifest corpus, artifact
                      corpus, or a labelled benign fixture).
``zero_fire``         runnable on the cold corpus but no benign diff fires it.
``cold_only``         needs observation history or warm state a cold diff
                      replay cannot provide.
``adversarial_only``  an evasion/sabotage detector whose benign floor is the
                      refusal floor; it is measured by its attack fixtures.

The ledger is data, not prose.  ``rebaseline.py`` writes it from the same scan
that produces the score baseline, so the two cannot describe different
corpora, and the calibration job uploads it as an artifact.
"""

from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from trustsight.contract import pseudo_rule_ids, rule_ids
from trustsight.registry import REGISTRY

from calibration._core import CLASS_C_RULES, CLASS_D_RULES

#: Rules whose finding needs state a stateless diff replay does not carry.
COLD_ONLY_RULES = frozenset(
    CLASS_C_RULES | CLASS_D_RULES | {
        # Temporal engine instances (per-package, cycle and graph scope).
        "H020", "H021", "H022", "H028", "H037", "H044", "H045", "H046",
        "H047", "H048", "H049", "H050", "H051", "H052", "H053", "H054",
        "H055", "H057", "H058", "H059", "H060", "H061", "H073", "H074",
        "H086", "H087", "H088",
        # Dependency and correlation families; D003-D005 are cold, D001/D002
        # are the warm half of the pair.
        "D001", "D002",
        # Correlation, meta, temporal and artifact families.
        *{f"G{n:03d}" for n in range(1, 15)},
        *{f"M{n:03d}" for n in range(1, 7)},
        *{f"T{n:03d}" for n in range(1, 8)},
        *{f"A{n:03d}" for n in range(1, 9)},
    }
)

#: Families measured by their own attack corpora, not by benign packaging.
ADVERSARIAL_SERIES = frozenset({"S", "X"})

#: Sources that count as benign coverage.  ``malicious`` is the only source
#: whose fires say nothing about the benign floor.
ADVERSARIAL_SOURCES = frozenset({"malicious"})

#: Status of a disposition.  ``deferred`` is a ratified gap with a scheduled
#: plan; ``resolved`` means the plan has been applied and the expectation must
#: now agree with the ledger.
DISPOSITION_STATUSES = frozenset({"deferred", "resolved"})

#: Plans a deferred expectation may carry.  The gate fails when a new
#: expectation appears without one.
DISPOSITION_PLANS = frozenset({
    "add_benign_shape",
    "add_history_or_warm",
    "add_artifact_or_manifest",
    "attack_only",
    "not_measurable",
    "expectation_wrong",
    "weight_zero",
    "unverifiable",
    "pseudo",
    "known_false_positive",
})


def _severity(rule_id: str) -> str:
    try:
        return (REGISTRY.resolve(rule_id).severity or "").upper()
    except Exception:
        return ""


def adversarial_only(rule_id: str) -> bool:
    """An evasion/sabotage detector, or a critical regex rule with no benign floor."""
    if rule_id[:1] in ADVERSARIAL_SERIES:
        return True
    return rule_id[:1] == "R" and _severity(rule_id) in {"CRITICAL", "FATAL"}


@dataclass
class Observation:
    """One source's view of the corpus."""

    source: str
    #: rule id -> number of diffs/cycles/manifests it fired in
    fires: dict[str, int] = field(default_factory=dict)
    #: rule id -> stratum names exercising it
    strata: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))
    total: int = 0


def observation_from_rows(rows: Iterable[dict], source: str) -> Observation:
    """Build an observation from scan rows, history rows, or artifact findings.

    Accepts the two shapes the harnesses already emit: scan rows with
    ``entries`` (or ``fired``) and a ``stratum``/``package``, and plain
    rule-id lists.
    """
    obs = Observation(source=source)
    for row in rows:
        obs.total += 1
        rules = set(row.get("fired") or [])
        for entry in row.get("entries") or ():
            rules.add(entry["rule_id"] if isinstance(entry, dict) else entry)
        stratum = row.get("stratum")
        for rule_id in rules:
            obs.fires[rule_id] = obs.fires.get(rule_id, 0) + 1
            if stratum:
                obs.strata[rule_id].add(stratum)
    return obs


def _reason(rule_id: str, state: str, expected: list[str]) -> str:
    if state == "measured":
        return ""
    if state == "cold_only":
        return ("needs observation history or warm state; measured by the "
                "history/warm replay when available")
    if state == "adversarial_only":
        return ("adversarial-only detection; its benign floor is the refusal "
                "floor, and its fixtures are the labelled attack corpus")
    if expected:
        return "no benign shape in the locked corpus; expected from " + ", ".join(expected)
    return "no benign shape in the locked corpus yet; add a shape stratum, never a rule-targeted sample"


def build_ledger(
    observations: Iterable[Observation],
    *,
    expected: dict[str, list[str]] | None = None,
    dispositions: dict[str, dict] | None = None,
    corpus_sha256: str = "",
    version: str = "",
) -> dict:
    """Return the committed ledger document.

    *expected* maps rule id -> strata that are supposed to exercise it, from
    ``strata.toml``'s ``expected_rules`` fields.  It is advisory: a mismatch is
    reported by the ledger audit, never silently hidden.

    *dispositions* maps rule id -> a reviewed plan for a rule that is not yet
    benign-measured.  The coverage gate fails when an expected rule has no
    disposition, so a silent gap cannot survive a corpus change.
    """
    expected = expected or {}
    dispositions = dispositions or {}
    by_rule: dict[str, dict] = {}
    all_ids = list(rule_ids()) + list(pseudo_rule_ids())

    for rule_id in all_ids:
        sources: dict[str, dict] = {}
        total = 0
        strata: set[str] = set()
        for obs in observations:
            fires = obs.fires.get(rule_id, 0)
            if not fires:
                continue
            total += fires
            strata.update(obs.strata.get(rule_id, ()))
            sources[obs.source] = {
                "fires": fires,
                "strata": sorted(obs.strata.get(rule_id, ())),
            }
        if total:
            state = "measured"
        elif rule_id in COLD_ONLY_RULES:
            state = "cold_only"
        elif adversarial_only(rule_id):
            state = "adversarial_only"
        else:
            state = "zero_fire"
        is_pseudo = rule_id in set(pseudo_rule_ids())
        benign_sources = sorted(
            src for src in sources if src not in ADVERSARIAL_SOURCES)
        benign_strata = sorted({
            stratum
            for src in benign_sources
            for stratum in sources[src]["strata"]
        })
        expected_strata = sorted(expected.get(rule_id, []))
        if is_pseudo:
            benign_state = "pseudo"
        elif benign_sources:
            benign_state = "fire"
        elif state in {"cold_only", "adversarial_only"}:
            benign_state = state
        elif total:
            benign_state = "malicious_only"
        else:
            benign_state = "zero_fire"
        by_rule[rule_id] = {
            "id": rule_id,
            "uid": REGISTRY.uid_of(rule_id) if not is_pseudo else None,
            "series": rule_id[:1],
            "pseudo": is_pseudo,
            "state": state,
            "fires": total,
            "strata": sorted(strata),
            "benign_sources": benign_sources,
            "benign_strata": benign_strata,
            "benign_state": benign_state,
            "expected_strata": expected_strata,
            "expected_met": bool(benign_sources),
            "expected_strata_met": sorted(
                set(expected_strata) & set(benign_strata)),
            "disposition": dispositions.get(rule_id),
            "sources": sources,
            "reason": _reason(rule_id, state, expected_strata),
        }

    counts: dict[str, int] = defaultdict(int)
    for row in by_rule.values():
        counts[row["state"]] += 1
    return {
        "version": version or "1",
        "corpus_content_sha256": corpus_sha256,
        "catalog_size": len(all_ids),
        "counts": dict(sorted(counts.items())),
        "rules": dict(sorted(by_rule.items())),
    }


def expected_from_strata(strata: dict) -> dict[str, list[str]]:
    """Flatten ``strata.toml``'s per-stratum expected rule lists."""
    out: dict[str, list[str]] = defaultdict(list)
    for name, cfg in (strata.get("strata") or {}).items():
        for rule_id in cfg.get("expected_rules") or ():
            out[str(rule_id)].append(name)
    return {rule_id: sorted(set(names)) for rule_id, names in out.items()}


def unmet_expectations(ledger: dict, expected: dict[str, list[str]] | None = None,
                       *, require_stratum: bool = False) -> dict[str, dict]:
    """Name every expectation the ledger does not meet.

    The default is the ratchet the CI gate enforces: an expected rule must be
    exercised by at least one benign source.  ``require_stratum=True`` is the
    stricter review view: the rule must also fire in the stratum that declared
    the expectation.  Both are reported so a corpus expansion can distinguish
    "not measured at all" from "measured somewhere else".
    """
    expected = expected or {
        rid: row.get("expected_strata") or []
        for rid, row in (ledger.get("rules") or {}).items()
        if row.get("expected_strata")
    }
    out: dict[str, dict] = {}
    for rule_id, names in sorted(expected.items()):
        row = (ledger.get("rules") or {}).get(rule_id)
        if row is None:
            out[rule_id] = {"reason": "missing", "expected": sorted(names)}
            continue
        if not row.get("benign_sources"):
            out[rule_id] = {
                "reason": "no_benign_source",
                "expected": sorted(names),
                "benign_state": row.get("benign_state"),
            }
            continue
        if require_stratum:
            fired = set(row.get("benign_strata") or [])
            missing = sorted(set(names) - fired)
            if missing:
                out[rule_id] = {
                    "reason": "wrong_stratum",
                    "expected": sorted(names),
                    "missing_strata": missing,
                    "fired_in": sorted(fired),
                }
    return out


def ledger_audit(before: dict, after: dict, expected: dict[str, list[str]] | None = None) -> dict:
    """Compare two ledgers; name rows a stratum was expected to move.

    ``moved`` is every rule whose fires or state changed.  ``unexpected`` is a
    move with no stratum naming it in *expected*; ``unmoved`` is an expectation
    that the new corpus did not move.
    """
    expected = expected or {}
    old = before.get("rules", {})
    new = after.get("rules", {})
    moved = {
        rid: {
            "before": {"state": old.get(rid, {}).get("state"), "fires": old.get(rid, {}).get("fires", 0)},
            "after": {"state": new.get(rid, {}).get("state"), "fires": new.get(rid, {}).get("fires", 0)},
        }
        for rid in sorted(set(old) | set(new))
        if (old.get(rid, {}).get("state"), old.get(rid, {}).get("fires", 0))
        != (new.get(rid, {}).get("state"), new.get(rid, {}).get("fires", 0))
    }
    unexpected = [rid for rid in moved if rid not in expected]
    unmoved = [rid for rid in expected if rid not in moved]
    return {
        "moved": moved,
        "unexpected": unexpected,
        "unmoved_expectations": sorted(unmoved),
    }


def write_ledger(path: Path, ledger: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(ledger, indent=2, sort_keys=True) + "\n")
