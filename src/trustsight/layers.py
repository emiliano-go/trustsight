"""The assurance layers: which kind of evidence a rule represents.

``category`` (:mod:`trustsight.categories`) answers *what kind of claim* a
rule makes; ``layer`` groups that claim's finding by the kind of evidence it
represents.  A layer is not a stage in an attacker's path and not a second
mechanism axis: a finding carries the layer where it *caught*, not the layer
it protects, so an evasion-shape rule caught at L4 still reports L4 even
though the payload it would have shielded lives at L3.  Nor is it fully
independent of the series: the mapping is a per-series default with a small
table of per-rule overrides for the handful of rules whose mechanism diverges
from their series.

Every rule that appears in :data:`RULE_CATEGORIES` has
exactly one layer; :func:`layer_of` is the single lookup every consumer
(validation, the report profile, the harness telemetry) shares, so no two
surfaces can disagree about a rule's layer.

L0 (tool integrity) and L9 (artifact reality) are deliberately absent: L0
is the release process rather than a rule, and L9 is the optional build
lane, which is not part of the static core.
"""

from __future__ import annotations

import itertools
from enum import StrEnum

__all__ = [
    "GAP_BLINDED_LAYERS",
    "LAYER_ORDER",
    "LAYER_VALUES",
    "RULE_LAYER_OVERRIDES",
    "SERIES_LAYER",
    "Layer",
    "blinded_layers",
    "bypass_count",
    "exact_minimum_cut",
    "layer_of",
    "layer_profile",
    "layers_fully_bypassed",
    "minimum_layer_cut",
    "observed_layers",
    "parse_overrides",
    "resilience_distribution",
    "rules_in_layer",
    "single_layer_failure",
]


class Layer(StrEnum):
    """The kind of evidence a finding represents.

    A layer groups findings by the evidence category they belong to - the
    name answers "what kind of check produced this", not "how far an attacker
    got".  The L1-L8 identifiers are stable labels for those categories; they
    are not, by themselves, a claim about sequential attacker progress.
    """

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

#: The layer order, broadest-first: L1 is "does the change hang together",
#: L8 is "do other packages tell the same story".
LAYER_ORDER: tuple[Layer, ...] = (
    Layer.L1, Layer.L2, Layer.L3, Layer.L4, Layer.L5, Layer.L6, Layer.L7, Layer.L8,
)

# Default layer by series prefix. A series that is not
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
    "U": Layer.L3,
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
#:
# The spec's own H099-H103 layer rows referred to the
# *proposed* rules, which re-filed as C014-C017 and which
#: are L1 by the C-series default.  The live H099/H101/H103 are different,
#: unrelated rules; they are structural-coherence violations and are pinned to
#: L1 here so the profile does not read them as generic L5 suspicion.
RULE_LAYER_OVERRIDES: dict[str, Layer] = {
    "X026": Layer.L2,
    "X027": Layer.L2,
    "H099": Layer.L1,   # source host swapped under a kept local name
    "H101": Layer.L1,   # source pinning lost
    "H103": Layer.L1,   # metadata and recipe disagree
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
    # U007/U008 are federation-fed indicator matches (the signed
    # `upstream_repo` feed), so they belong with the indicator mechanism
    # rather than L3.  U009 reads a committed-file shape, so it is L1.
    "U007": Layer.L7,
    "U008": Layer.L7,
    "U009": Layer.L1,
}


def _series_of(rule_id: str) -> str:
    return rule_id[:1].upper() if rule_id else ""


#: The closed set of layer values a config override may name.
LAYER_VALUES: frozenset[str] = frozenset(layer.value for layer in LAYER_ORDER)


def parse_overrides(config) -> dict[str, Layer]:
    """The validated ``[layers]`` overrides from *config*, ``{}`` by default.

    A layer override is a ``[layers]`` table mapping a rule id to ``L1``..``L8``.
    An entry naming an unknown rule or an out-of-range layer is dropped rather
    than guessed: the set is closed, and a bad override must not move a rule
    off it.  The security gate ``layer overrides stay within the closed set``
    pins that dropping behaviour.
    """
    from .categories import RULE_CATEGORIES

    raw = (config or {}).get("layers") or {}
    overrides: dict[str, Layer] = {}
    if not isinstance(raw, dict):
        return overrides
    for rule_id, value in raw.items():
        key = str(rule_id).upper()
        text = str(value).upper()
        if text not in LAYER_VALUES or key not in RULE_CATEGORIES:
            continue
        overrides[key] = Layer(text)
    return overrides


def layer_of(rule_id: str, overrides: dict[str, Layer] | None = None) -> Layer | None:
    """The one layer owning *rule_id*, or ``None`` for a non-rule id.

    Precedence: a config override (``[layers]``), then the shipped per-rule
    override, then the series default.  An id whose series has no default (M)
    returns ``None`` rather than guessing; reserved and unknown ids return
    ``None`` for the same reason :func:`trustsight.categories.category_of`
    does - a caller reads ids out of stored findings, and an id that is no
    longer a rule is a fact about the data.
    """
    from .categories import RULE_CATEGORIES

    rule_id = rule_id.upper()
    if rule_id not in RULE_CATEGORIES:
        return None
    if overrides and rule_id in overrides:
        return overrides[rule_id]
    override = RULE_LAYER_OVERRIDES.get(rule_id)
    if override is not None:
        return override
    return SERIES_LAYER.get(_series_of(rule_id))


def rules_in_layer(layer: Layer, overrides: dict[str, Layer] | None = None) -> list[str]:
    """Sorted rule ids assigned to *layer*."""
    from .categories import RULE_CATEGORIES

    return sorted(
        rid for rid in RULE_CATEGORIES if layer_of(rid, overrides) is layer)


# Which layers a coverage gap can blind.
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


def observed_layers(triggered, overrides: dict[str, Layer] | None = None) -> dict:
    """Which evidence categories fired on one harness attempt.

    Returns ``{"fired": [...], "fully_bypassed": bool}``: the layer ids whose
    rules actually fired, in evidence-category order.  This is a projection
    of the fired rule layers, **not** an observed traversal - the earlier
    ``traversed``/``stopped`` shape inferred a prefix, which made every path
    contain L1 and the minimum cut structurally one.

    *overrides* are the ``[layers]`` config overrides, so harness telemetry
    agrees with the report/verdict/CLI surfaces when an operator moves a
    rule.
    """
    fired = sorted(
        {layer for layer in (
            layer_of(str(entry.get("rule_id", "")), overrides)
            for entry in triggered or ()
        ) if layer is not None},
        key=LAYER_ORDER.index,
    )
    return {"fired": [layer.value for layer in fired],
            "fully_bypassed": not fired}


def minimum_layer_cut(attempts) -> int | None:
    """Exact smallest set of layers that covers every caught attempt.

    *attempts* is an iterable of ``{"fired": [...], "fully_bypassed": bool}``.
    A layer covers an attempt when it is one of the layers that fired for it.
    The minimum cut is the smallest set of layers covering every caught
    attempt; a fully-bypassed attempt (nothing fired) is uncuttable, so any
    bypass makes the cut undefined - reported separately by
    :func:`bypass_count`.  Enumerated exactly over the 2**8 layer subsets,
    not greedily.  ``None`` when there are no attempts.
    """
    paths = [p for p in (attempts or ()) if p]
    if not paths:
        return None
    caught = [set(p.get("fired") or ()) for p in paths]
    if any(not fired for fired in caught):
        return None  # an attempt fired nothing; no layer set can cover it
    layers = [layer.value for layer in LAYER_ORDER]
    for size in range(1, len(layers) + 1):
        for combo in itertools.combinations(layers, size):
            chosen = set(combo)
            if all(chosen & fired for fired in caught):
                return size
    return len(layers)


def single_layer_failure(paths) -> dict[str, int]:
    """Attempts that bypass if one layer's detector family is disabled.

    For each layer, the count of caught attempts whose *only* fired layer is
    that layer - disable it and they pass.  This is the empirical "does one
    layer's failure reopen a path" question the path-intersection metric
    could not answer.
    """
    out: dict[str, int] = {}
    for path in paths or ():
        fired = [lit for lit in (path.get("fired") or ()) if lit]
        if len(fired) == 1:
            out[fired[0]] = out.get(fired[0], 0) + 1
    return dict(sorted(out.items()))


def bypass_count(paths) -> int:
    """Attempts that fired no rule at all."""
    return sum(1 for p in (paths or ()) if p and p.get("fully_bypassed"))


#: Remediation T2: the honest replacement for `aligned_hole_depth` - the
#: number of attempts no evidence category caught.  Same value as
#: :func:`bypass_count`; the second name is the one the plan and the report
#: use.
layers_fully_bypassed = bypass_count


def resilience_distribution(paths) -> dict[int, int]:
    """How many evidence categories caught each caught attempt.

    Remediation T2: the measured distribution that replaces the "minimum cut
    >= 2" target.  A histogram over caught attempts of the number of distinct
    categories that fired; an attempt caught by a single category is one
    regression from a bypass, and a campaign whose mass sits at ``1`` is
    fragile regardless of its minimum cut.  Bypassed attempts are not counted
    here (see :func:`layers_fully_bypassed`).
    """
    out: dict[int, int] = {}
    for path in paths or ():
        if not path or path.get("fully_bypassed"):
            continue
        fired = len({lit for lit in (path.get("fired") or ()) if lit})
        if fired:
            out[fired] = out.get(fired, 0) + 1
    return dict(sorted(out.items()))


#: The exact cut, under the name the remediation plan uses.  See
#: :func:`minimum_layer_cut`.
exact_minimum_cut = minimum_layer_cut


def blinded_layers(gaps) -> frozenset[Layer]:
    """The layers a run's coverage gaps leave unexercised."""
    blinded: set[Layer] = set()
    for gap in gaps or ():
        blinded |= GAP_BLINDED_LAYERS.get(str(gap), _ALL_LAYERS)
    return frozenset(blinded)


def layer_profile(fact, findings, *, correlation_ran: bool = False,
                  overrides: dict[str, Layer] | None = None) -> dict[str, dict]:
    """The report's ``layers`` object.

    Per layer, ``{"status", "name", "findings"}``.  ``fired`` when a
    finding in that layer is present; otherwise ``passed`` when the run was
    fully read, or ``unreadable`` when a coverage gap or a truncated diff
    means the layer was not fully exercised.  A finding carries the layer
    where it caught, so this is a projection over the finding set, never a
    re-derivation.
    """
    by_layer: dict[Layer, list[str]] = {layer: [] for layer in LAYER_ORDER}
    for finding in findings:
        if finding.get("present_before"):
            continue
        layer = layer_of(str(finding.get("rule_id", "")), overrides)
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
    # L8 (campaign correlation) is exercised when the collective pass ran.
    # The flag is threaded from the corpus cycle, but an L8 finding in the
    # set proves correlation ran regardless, so a report rendered from a
    # stored row still shows L8 honestly rather than permanently
    # "not applicable".
    correlation_ran = (
        bool(correlation_ran)
        or bool(getattr(fact, "correlation_ran", False))
        or bool(by_layer[Layer.L8])
    )
    return {
        layer.value: {
            "name": layer.name_text,
            # Two independent dimensions: what was detected, and how far the
            # evidence could be assessed.  A finding must not hide that the
            # same layer was also unread (the review's report fix).
            "detection": "fired" if by_layer[layer] else "none",
            "coverage": _layer_coverage(layer, blinded, correlation_ran),
            # Derived, kept for one release for back-compat consumers: the
            # coarser of the two (fired wins; then not-exercised; then
            # incomplete; else passed).
            "status": _layer_status(layer, by_layer[layer], blinded,
                                    correlation_ran),
            "findings": by_layer[layer],
        }
        for layer in LAYER_ORDER
    }


def _layer_coverage(layer, blinded, correlation_ran: bool) -> str:
    """How far the layer's evidence could be assessed.

    ``not_applicable`` for L8 outside a correlation run (the input does not
    exist there); ``incomplete`` when a coverage gap blinds the layer;
    ``complete`` otherwise.
    """
    if layer is Layer.L8 and not correlation_ran:
        return "not_applicable"
    if layer in blinded:
        return "incomplete"
    return "complete"


def _layer_status(layer, findings, blinded, correlation_ran: bool) -> str:
    """One layer's derived status, kept for one release.

    A finding carries the layer where it caught.  This collapses the
    ``detection`` and ``coverage`` dimensions into the earlier single field:
    ``fired`` if detected, else ``not_exercised`` (L8 outside a correlation
    run), ``unreadable`` if incomplete, else ``passed``.
    """
    if findings:
        return "fired"
    if layer is Layer.L8 and not correlation_ran:
        return "not_exercised"
    if layer in blinded:
        return "unreadable"
    return "passed"
