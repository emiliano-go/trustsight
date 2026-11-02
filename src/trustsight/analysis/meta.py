"""M-series: meta / confluence.

The only series whose input is other rules' outputs: predicates over the
finding multiset after the ownership resolver, so no line is double-counted.
Constitutional rules: M never lowers a score, M only escalates, and every M
rule must pass the cluster-rate gate before its threshold ships.

v1 ships the two predicates with a concrete, testable shape:

* **M001 - Claim Contradicted By Structure** (HIGH).  The recipe's declared
  practices (the P ledger) contradict a structural finding in the same run:
  it declares checksums while H091 reports the arrays do not cover every
  source, or it declares GPG verification while H024 reports it removed.
  "The recipe lying about its own practices" is only visible from the
  profile, because only M reads both surfaces.
* **M002 - Weak Signal Across Layers** (weight 0, annotation).  Three or
  more distinct assurance layers fired, each below the alert bar.  An
  attacker spreading weak signals across layers is only visible from the
  layer profile.  The escalation the spec describes is deferred until the
  cluster-rate gate is measured on the corpus; v1 reports the span.
* **M003 - Composition Not Owned Elsewhere** (weight 0, annotation).  The
  H098/X007 cluster predicate, generalized: two or more distinct capability
  families co-occur while neither owner rule fired (they may be disabled).
  The composition is never lost.

M never changes a finding's evidence; it names the inputs that composed.
"""

from __future__ import annotations

from ..coverage import note_stage_failure

__all__ = [
    "m_series_findings",
    "claim_contradictions",
    "cofire_absence",
    "campaign_reactivation_notes",
    "weak_layer_span",
    "alert_volume_finding",
]

#: (claim id, contradicting finding, message) for M001.  The claim is a P
#: finding the run's declared facts imply; the finding is a structural fact
#: that contradicts it.  The pairing is data, not another conditional.
_CONTRADICTIONS: tuple[tuple[str, str, str], ...] = (
    ("P001", "H091",
     "the recipe declares checksums (P001) while H091 reports the checksum "
     "arrays do not cover every source"),
    ("P002", "H024",
     "the recipe declares GPG verification (P002) while H024 reports the "
     "verification removed"),
    ("P005", "H101",
     "a source is pinned to a commit (P005) while H101 reports the pinning "
     "lost"),
    ("P007", "H099",
     "a source is hosted on a trusted forge (P007) while H099 reports the "
     "host swapped under a kept local name"),
    ("P009", "H066",
     "the recipe declares a prebuilt deliverable (P009) while H066 reports "
     "an ELF binary committed to the repository outside source=()"),
)


def _thresholds(config) -> dict:
    return (config or {}).get("thresholds", {})


def claim_contradictions(triggered: list[dict], claims=None) -> list[dict]:
    """M001: a declared practice contradicted by a structural finding.

    *claims* is the set of P-series ids the run's declared facts imply
    (:func:`trustsight.scoring.declared_claims`).  ``None`` means "assume
    every claim is present", which keeps the pre-ledger callers working; a
    supplied set means the contradiction must actually be declared.
    """
    from ..findings import stamp

    ids = {r.get("rule_id") for r in triggered}
    out: list[dict] = []
    for claim, finding, message in _CONTRADICTIONS:
        if finding not in ids:
            continue
        if claims is not None and claim not in claims:
            continue
        out.append(stamp({
            "rule_id": "M001",
            "name": "Claim Contradicted By Structure",
            "severity": "HIGH", "category": "meta",
            "match": message,
            "params": {"claim": claim, "contradicted_by": finding},
        }))
    return out


def cofire_absence(triggered: list[dict], pairs) -> list[str]:
    """M004: a tool-health check, never a package finding (family 4).

    *pairs* is an iterable of ``(precursor_rule, expected_rule)``.  When the
    precursor fired but the expected rule did not, the construct that
    historically co-fires appeared without its rule - a sign the rule broke
    or was evaded in a known shape.  The result is a list of human-readable
    health notes for the harness/calibration, deliberately **not** added to
    the package finding set (a hit means the tool, not the package, needs
    attention).
    """
    ids = {r.get("rule_id") for r in (triggered or ()) if isinstance(r, dict)}
    notes: list[str] = []
    for precursor, expected in pairs or ():
        if precursor in ids and expected not in ids:
            notes.append(
                f"{precursor} fired without expected co-fire {expected}")
    return notes


def licensor_absent(triggered: list[dict], rules: list[dict]) -> list[dict]:
    """M005: a licensed rule fired and none of its declared licensors did.

    The mirror of escalation licensing.  A rule that declares
    ``escalates_when`` was written expecting a partner signal; if it fired
    alone, that is a **tool-health** observation - the detector travelled
    without its usual company - not evidence about the package.  Weight 0,
    routed to the harness, never scored.
    """
    fired = {r.get("rule_id") for r in (triggered or ()) if isinstance(r, dict)}
    by_id = {
        str(r.get("id", "")): r
        for r in (rules or ()) if isinstance(r, dict)
    }
    out: list[dict] = []
    for rule in triggered or ():
        if not isinstance(rule, dict):
            continue
        rid = str(rule.get("rule_id", ""))
        licensors = _as_list((by_id.get(rid, {}) or {}).get("escalates_when"))
        if licensors and not (set(licensors) & fired):
            out.append({
                "rule_id": "M005",
                "name": "Licensor Absent On Licensed Shape",
                "severity": "INFO", "category": "meta",
                "match": (f"{rid} fired without its licensor(s): "
                          f"{', '.join(str(x) for x in licensors)}"),
                "params": {"rule": rid,
                           "licensors": ", ".join(str(x) for x in licensors)},
            })
    return out


def _cofire_pairs() -> list[tuple[str, str]]:
    """Expected co-fire pairs from ``[thresholds] cofire_pairs`` (may be empty).

    Each entry is ``[precursor, expected]``: a construct whose rule fired but
    whose historical partner did not flags the *instrument*, not the package.
    Ships empty until a pair is measured, so M004 stays quiet rather than
    guessing at coincidences.
    """
    try:
        from ..config import load_thresholds

        raw = load_thresholds().get("cofire_pairs", [])
    except Exception:  # noqa: BLE001 - an unreadable threshold set is no pairs
        note_stage_failure("thresholds-unreadable")
        raw = []
    pairs: list[tuple[str, str]] = []
    for entry in raw or ():
        if isinstance(entry, (list, tuple)) and len(entry) == 2:
            pairs.append((str(entry[0]), str(entry[1])))
    return pairs


def m_tool_health(
    triggered: list[dict], rules: list[dict] | None = None,
) -> list[dict]:
    """M004 + M005: instrument health, never the package's finding set.

    Kept separate from :func:`m_series_findings` on purpose: these describe
    the *tool*, and feeding them into the package's breakdown would let a
    detector-health note move a verdict.  They ride on the fact's
    ``cofire_health`` and are consumed by the harness/calibration.

    M004 reads the expected co-fire pairs; M005 reads the rules' own
    ``escalates_when`` declarations.  M006 (campaign re-activation pressure)
    is cycle-level instrument state with no per-package input, so it never
    rides ``cofire_health``: the cycle reports it on the log via
    :func:`trustsight.full_aur.pipeline._report_reactivation_pressure`.
    """
    out: list[dict] = []
    for note in cofire_absence(triggered, _cofire_pairs()):
        out.append({
            "rule_id": "M004", "name": "Expected Co-fire Absent",
            "severity": "INFO", "category": "meta",
            "match": note, "params": {"detail": note},
        })
    out.extend(licensor_absent(triggered, rules or []))
    return out


def campaign_reactivation_notes(pressure: list[dict] | None) -> list[dict]:
    """M006: a campaign class that re-armed faster than the interval allows.

    A campaign is instrument state, and a class that re-arms far too often
    (the same G-rule id corroborating a campaign over and over in a short
    window) is the tool churning, not a package misbehaving.  The spec routes
    this to a tool-health signal rather than letting it pass in silence.
    Weight 0; it never joins the package's finding set.
    """
    out: list[dict] = []
    for entry in pressure or ():
        if not isinstance(entry, dict):
            continue
        source = str(entry.get("source", "") or "campaign")
        campaign_id = str(entry.get("campaign_id", ""))
        count = entry.get("count", 0)
        span = entry.get("span", 0)
        interval = entry.get("min_interval", 0)
        note = (f"{source} campaign {campaign_id} re-armed {count} time(s) "
                f"over {span} observation(s), below the {interval}-observation "
                f"interval")
        out.append({
            "rule_id": "M006", "name": "Campaign Re-armed Too Often",
            "severity": "INFO", "category": "meta",
            "match": note,
            "params": {"campaign_id": campaign_id, "source": source,
                       "count": count, "span": span, "min_interval": interval},
        })
    return out


def weak_layer_span(triggered: list[dict], config) -> list[dict]:
    """M002: three or more layers fired, none above the alert bar."""
    from ..findings import stamp
    from ..layers import layer_of

    threshold = int(_thresholds(config).get("m002", {}).get("min_layers", 3))
    strong = any(
        r.get("severity") in ("FATAL", "CRITICAL", "HIGH") for r in triggered
    )
    if strong:
        return []
    layers = {
        layer_of(str(r.get("rule_id", ""))) for r in triggered
        if r.get("rule_id")
    }
    layers.discard(None)
    if len(layers) < threshold:
        return []
    named = ", ".join(sorted(layer.value for layer in layers))
    return [stamp({
        "rule_id": "M002",
        "name": "Weak Signal Across Layers",
        "severity": "MEDIUM", "category": "meta",
        "weight_override": 0,
        "match": (f"{len(layers)} distinct layers fired with no strong "
                  f"signal: {named}"),
        "params": {"layers": len(layers), "which": named},
    })]


#: The capability families the crossfire/naming clusters own.  M003 fires
#: only when a composition exists that neither owner recorded.
_CLUSTER_OWNERS = ("H098", "X007", "H027")


def composition_not_owned(triggered: list[dict], config) -> list[dict]:
    """M003: a capability composition neither H098, X007 nor H027 owns."""
    from ..findings import stamp

    ids = {r.get("rule_id") for r in triggered}
    if ids & set(_CLUSTER_OWNERS):
        return []
    families = {
        r.get("category") for r in triggered
        if r.get("category") and r.get("category") not in ("meta", "unverifiable")
    }
    if len(families) < 2:
        return []
    named = ", ".join(sorted(families))
    return [stamp({
        "rule_id": "M003",
        "name": "Composition Not Owned Elsewhere",
        "severity": "MEDIUM", "category": "meta",
        "weight_override": 0,
        "match": (f"{len(families)} capability families co-occurred with no "
                  f"cluster rule: {named}"),
        "params": {"families": len(families), "which": named},
    })]


def m_series_findings(triggered: list[dict], config=None, claims=None) -> list[dict]:
    """All M-series findings for a completed rule set (post-resolution).

    *claims* is the P-series claim set the run declared, so M001 joins the
    real ledger rather than firing on rule presence alone.
    """
    out: list[dict] = []
    out.extend(claim_contradictions(triggered, claims))
    out.extend(weak_layer_span(triggered, config))
    out.extend(composition_not_owned(triggered, config))
    return out


#: Rule ids that render even at weight 0 (kept in sync with
#: ``reporting.ALWAYS_SHOWN_ANNOTATIONS``).  The alert-volume count must see
#: the same set the renderer does, or the cap and the count disagree.
_ALWAYS_SHOWN = frozenset({"H043", "H065"})


def _as_list(value) -> list[str]:
    """A declared rule-id list as strings; a bare string is one value."""
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    try:
        return [str(v) for v in value]
    except TypeError:
        return []


def _renders(rule: dict, weights: dict) -> bool:
    """True when *rule* appears in the rendered finding list."""
    if not isinstance(rule, dict):
        return False
    rid = str(rule.get("rule_id") or "")
    severity = str(rule.get("severity") or "")
    if rid.startswith("W") or rid in _ALWAYS_SHOWN:
        return True
    if severity in ("FATAL", "CRITICAL"):
        return True
    weight = rule.get("weight_override", weights.get(severity, 0))
    try:
        return int(weight or 0) > 0
    except (TypeError, ValueError, OverflowError):
        return False


def alert_volume_finding(triggered: list[dict], config=None) -> dict | None:
    """W010: the terminal render was capped (superantigen control).

    A campaign that makes every package moderately noisy trains a reviewer
    to skim - the attack is the raised noise floor, not any single finding.
    Past ``[alerts] max_rendered_findings`` the terminal groups the
    remainder; this weight-0 boundary records that the sensor was
    **saturated, not missing**, so ``forbids_clean`` stays False.  The
    per-band counts travel with it, so grouping never drops content
    silently (B5): the JSON is unfiltered and this names what it grouped.

    Volume is never evidence about any one package, so the rule carries no
    weight and is not a finding about the package - it is a statement about
    the run.
    """
    alerts = (config or {}).get("alerts", {}) or {}
    try:
        cap = int(alerts.get("max_rendered_findings", 50) or 0)
    except (TypeError, ValueError, OverflowError):
        cap = 50
    if cap <= 0:
        return None
    weights = (config or {}).get("severity_weights", {}) or {}
    rendered = [rule for rule in triggered if _renders(rule, weights)]
    if len(rendered) <= cap:
        return None
    by_severity: dict[str, int] = {}
    for rule in rendered[cap:]:
        severity = str(rule.get("severity", "") or "INFO")
        by_severity[severity] = by_severity.get(severity, 0) + 1
    from ..findings import stamp

    grouped = len(rendered) - cap
    return stamp({
        "rule_id": "W010", "name": "Alert Volume Capped",
        "severity": "INFO", "category": "unverifiable",
        "match": (f"{len(rendered)} findings; the terminal shows the first "
                  f"{cap} and groups {grouped} more"),
        "params": {"rendered": len(rendered), "shown": cap,
                   "grouped": grouped, "by_severity": by_severity},
    })
