"""M-series: meta / confluence (Addendum 5 §6.5).

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

__all__ = [
    "m_series_findings",
    "claim_contradictions",
    "cofire_absence",
    "weak_layer_span",
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
    """M004: a tool-health check, never a package finding (§6.5 family 4).

    *pairs* is an iterable of ``(precursor_rule, expected_rule)``.  When the
    precursor fired but the expected rule did not, the construct that
    historically co-fires appeared without its rule - a sign the rule broke
    or was evaded in a known shape.  The result is a list of human-readable
    health notes for the harness/calibration, deliberately **not** added to
    the package finding set (a hit means the tool, not the package, needs
    attention).
    """
    ids = {r.get("rule_id") for r in triggered}
    notes: list[str] = []
    for precursor, expected in pairs or ():
        if precursor in ids and expected not in ids:
            notes.append(
                f"{precursor} fired without expected co-fire {expected}")
    return notes


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
