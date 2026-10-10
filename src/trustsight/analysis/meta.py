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

__all__ = ["m_series_findings", "claim_contradictions", "weak_layer_span"]


def _thresholds(config) -> dict:
    return (config or {}).get("thresholds", {})


def claim_contradictions(triggered: list[dict]) -> list[dict]:
    """M001: a declared practice contradicted by a structural finding."""
    from ..findings import stamp

    ids = {r.get("rule_id") for r in triggered}
    out: list[dict] = []
    if "H091" in ids:
        out.append(stamp({
            "rule_id": "M001",
            "name": "Claim Contradicted By Structure",
            "severity": "HIGH", "category": "meta",
            "match": ("the recipe declares checksums (P001) while H091 reports "
                      "the checksum arrays do not cover every source"),
            "params": {"claim": "P001", "contradicted_by": "H091"},
        }))
    if "H024" in ids:
        out.append(stamp({
            "rule_id": "M001",
            "name": "Claim Contradicted By Structure",
            "severity": "HIGH", "category": "meta",
            "match": ("the recipe declares GPG verification (P002) while H024 "
                      "reports the verification removed"),
            "params": {"claim": "P002", "contradicted_by": "H024"},
        }))
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


def m_series_findings(triggered: list[dict], config=None) -> list[dict]:
    """All M-series findings for a completed rule set (post-resolution)."""
    out: list[dict] = []
    out.extend(claim_contradictions(triggered))
    out.extend(weak_layer_span(triggered, config))
    out.extend(composition_not_owned(triggered, config))
    return out
