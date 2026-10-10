"""The assurance layers: which point of an attacker's trajectory a rule guards.

Addendum 5 introduces a second axis over the rule taxonomy.  ``category``
(:mod:`trustsight.categories`) answers *what kind of claim* a rule makes;
``layer`` answers *where on the path from repository text to a running
machine* the rule's evidence sits.  The two are independent by design: a
finding carries the layer where it *caught*, not the layer it protects, so
an evasion-shape rule caught at L4 still reports L4 even though the payload
it would have shielded lives at L3.

The mapping is data, not code: a per-series default with a small table of
per-rule overrides for the handful of rules whose mechanism diverges from
their series.  Every rule that appears in :data:`RULE_CATEGORIES` has
exactly one layer; :func:`layer_of` is the single lookup every consumer
(validation, the report profile, the harness telemetry) shares, so no two
surfaces can disagree about a rule's layer.

L0 (tool integrity) and L9 (artifact reality) are deliberately absent: L0
is the release process rather than a rule, and L9 is the optional build
lane, which is not part of the static core.
"""

from __future__ import annotations

from enum import StrEnum

__all__ = [
    "GAP_BLINDED_LAYERS",
    "LAYER_ORDER",
    "RULE_LAYER_OVERRIDES",
    "SERIES_LAYER",
    "Layer",
    "blinded_layers",
    "layer_of",
    "layer_profile",
    "layers_traversed",
    "minimum_layer_cut",
    "rules_in_layer",
]


class Layer(StrEnum):
    """The attacker's trajectory through the onion (Addendum 5 §1)."""

    L1 = "L1"
    L2 = "L2"
    L3 = "L3"
    L4 = "L4"
    L5 = "L5"
    L6 = "L6"
    L7 = "L7"
    L8 = "L8"

    @property
    def name_text(self) -> str:
        """Human-readable layer name."""
        return _NAMES[self]


_NAMES: dict[Layer, str] = {
    Layer.L1: "Structural coherence",
    Layer.L2: "Readability",
    Layer.L3: "Payload signature",
    Layer.L4: "Evasion shape",
    Layer.L5: "Behavioral suspicion",
    Layer.L6: "Ecosystem memory",
    Layer.L7: "Known indicators",
    Layer.L8: "Campaign correlation",
}

#: The trajectory order, outermost-first: L1 is "does the change hang
#: together", L8 is "do other packages tell the same story".
LAYER_ORDER: tuple[Layer, ...] = (
    Layer.L1, Layer.L2, Layer.L3, Layer.L4, Layer.L5, Layer.L6, Layer.L7, Layer.L8,
)

#: Default layer by series prefix (Addendum 5 §2).  A series that is not
#: listed (M, whose findings fire *at* their inputs' layer) has no default.
SERIES_LAYER: dict[str, Layer] = {
    "R": Layer.L3,
    "C": Layer.L1,
    "D": Layer.L6,
    "S": Layer.L3,
    "X": Layer.L4,
    "H": Layer.L5,
    "T": Layer.L6,
    "G": Layer.L8,
    "E": Layer.L4,
    "I": Layer.L7,
    "P": Layer.L1,
    "W": Layer.L2,
}

#: Per-rule overrides of the series default.  Three groups:
#:
#: * the refusal family X026/X027 fires at the readability boundary (the
#:   constructor cannot read the line) rather than as an evasion shape;
#: * the observational H rules read stored history, so they belong to the
#:   ecosystem-memory layer even though they are filed in H;
#: * H056 is an indicator match, so it belongs with the I mechanism.
RULE_LAYER_OVERRIDES: dict[str, Layer] = {
    "X026": Layer.L2,
    "X027": Layer.L2,
    "H020": Layer.L6,
    "H021": Layer.L6,
    "H022": Layer.L6,
    "H026": Layer.L6,
    "H028": Layer.L6,
    "H037": Layer.L6,
    "H044": Layer.L6,
    "H045": Layer.L6,
    "H046": Layer.L6,
    "H056": Layer.L7,
    "H058": Layer.L6,
    "H060": Layer.L6,
    "H073": Layer.L6,
    "H074": Layer.L6,
    "H086": Layer.L6,
    "H088": Layer.L6,
}


def _series_of(rule_id: str) -> str:
    return rule_id[:1].upper() if rule_id else ""


def layer_of(rule_id: str) -> Layer | None:
    """The one layer owning *rule_id*, or ``None`` for a non-rule id.

    An override wins over the series default; an id whose series has no
    default (M) returns ``None`` rather than guessing.  Reserved and
    unknown ids return ``None`` for the same reason
    :func:`trustsight.categories.category_of` does: a caller reads ids out
    of stored findings, and an id that is no longer a rule is a fact about
    the data.
    """
    from .categories import RULE_CATEGORIES

    rule_id = rule_id.upper()
    if rule_id not in RULE_CATEGORIES:
        return None
    override = RULE_LAYER_OVERRIDES.get(rule_id)
    if override is not None:
        return override
    return SERIES_LAYER.get(_series_of(rule_id))


def rules_in_layer(layer: Layer) -> list[str]:
    """Sorted rule ids assigned to *layer*."""
    from .categories import RULE_CATEGORIES

    return sorted(rid for rid in RULE_CATEGORIES if layer_of(rid) is layer)


#: Which layers a coverage gap can blind (Addendum 5 §3).
#:
#: A gap is bounded evidence: content the run did not read.  "Unreadable" is
#: reserved for the layers that actually depend on the missing evidence, so a
#: truncated diff does not make ecosystem memory (L6) look unread when the
#: history read completed.  Anything not listed blinds every layer - the
#: fail-safe direction, since claiming a layer passed on an unexplained gap is
#: the dangerous error.
_ALL_LAYERS: frozenset[Layer] = frozenset(LAYER_ORDER)

GAP_BLINDED_LAYERS: dict[str, frozenset[Layer]] = {
    # History / corpus reads only.
    "parent_baseline": frozenset({Layer.L6}),
    "history_truncated": frozenset({Layer.L6}),
    "deps_not_scanned": frozenset({Layer.L3, Layer.L6}),
    # A value the tokenizer could not resolve reads as "not seen" to the
    # structural, readability and payload layers.
    "unresolved_source": frozenset({Layer.L1, Layer.L2, Layer.L3, Layer.L4}),
    "unresolved_parse_time": frozenset({Layer.L1, Layer.L2, Layer.L3, Layer.L4}),
    "unpinned_build_deps": frozenset({Layer.L3, Layer.L6}),
    # File content not read at all (structure + payload).
    "tree_not_analyzed": frozenset({Layer.L1, Layer.L3}),
    "snapshot_refused": frozenset({Layer.L1, Layer.L3}),
    "companion_truncated": frozenset({Layer.L1, Layer.L3}),
    "binary_metadata": frozenset({Layer.L1, Layer.L3}),
    "partial_file_analysis": frozenset({Layer.L1, Layer.L3}),
    "noextract_suppressed": frozenset({Layer.L1, Layer.L3}),
}


def layers_traversed(triggered) -> dict:
    """The harness telemetry for one attempt (Addendum 5 §4).

    Returns ``{"traversed": [...], "stopped": layer | None}``: the ordered
    layers the attempt passed, and the layer that stopped it (the
    outermost - lowest-index - layer whose rules fired).  A bypass caught
    no rule, so it traversed every layer and stopped at none.
    """
    fired = {
        layer for layer in (
            layer_of(str(entry.get("rule_id", ""))) for entry in triggered or ()
        ) if layer is not None
    }
    if not fired:
        return {"traversed": [layer.value for layer in LAYER_ORDER],
                "stopped": None}
    stopped = min(fired, key=LAYER_ORDER.index)
    return {
        "traversed": [layer.value for layer in LAYER_ORDER[:LAYER_ORDER.index(stopped)]],
        "stopped": stopped.value,
    }


def minimum_layer_cut(attempts) -> int | None:
    """The smallest layer-set intersection that stops every recorded attempt.

    *attempts* is an iterable of ``{"stopped": layer|None, "traversed": [...]}``.
    A minimum cut is a set of layers that intersects every attempt's
    traverse-or-stop path.  Computed by greedy set cover over each layer:
    for each candidate layer, how many attempts it would stop (its ``stopped``
    equals the layer, or the layer is in the attempt's traversed set).  The
    reported number is the smallest covering set size, or ``None`` when there
    are no attempts.  v1 is the reported metric; the gate is a follow-on.
    """
    attempts = list(attempts)
    if not attempts:
        return None
    uncovered = set(range(len(attempts)))
    chosen = 0
    # Each layer covers attempts whose path passes through it.
    coverage: dict[str, set[int]] = {}
    for layer in LAYER_ORDER:
        cover = {
            i for i, a in enumerate(attempts)
            if a.get("stopped") == layer.value
            or layer.value in (a.get("traversed") or ())
        }
        coverage[layer.value] = cover
    while uncovered:
        best = max(coverage.values(), key=lambda c: len(c & uncovered), default=set())
        if not (best & uncovered):
            # An attempt with no covered layer (malformed) cannot be cut.
            break
        uncovered -= best
        chosen += 1
    return chosen


def blinded_layers(gaps) -> frozenset[Layer]:
    """The layers a run's coverage gaps leave unexercised."""
    blinded: set[Layer] = set()
    for gap in gaps or ():
        blinded |= GAP_BLINDED_LAYERS.get(str(gap), _ALL_LAYERS)
    return frozenset(blinded)


def layer_profile(fact, findings) -> dict[str, dict]:
    """The report's ``layers`` object (Addendum 5 §3).

    Per layer, ``{"status", "name", "findings"}``.  ``fired`` when a
    finding in that layer is present; otherwise ``passed`` when the run was
    fully read, or ``unreadable`` when a coverage gap or a truncated diff
    means the layer was not fully exercised.  A finding carries the layer
    where it caught, so this is a projection over the finding set, never a
    re-derivation.
    """
    by_layer: dict[Layer, list[str]] = {layer: [] for layer in LAYER_ORDER}
    for finding in findings:
        layer = layer_of(str(finding.get("rule_id", "")))
        if layer is not None:
            by_layer[layer].append(str(finding.get("rule_id", "")))

    gaps = list(getattr(fact, "coverage_gaps", ()) or ())
    # ``diff_truncated``/``scan_truncated`` are also surfaced as flags in
    # case a caller did not thread them into the gap list; either form
    # blinds everything.
    if getattr(fact, "diff_truncated", False):
        gaps.append("diff_truncated")
    if getattr(fact, "scan_truncated", False):
        gaps.append("scan_truncated")
    blinded = blinded_layers(gaps)
    return {
        layer.value: {
            "name": layer.name_text,
            "status": ("fired" if by_layer[layer]
                       else "unreadable" if layer in blinded
                       else "passed"),
            "findings": by_layer[layer],
        }
        for layer in LAYER_ORDER
    }
