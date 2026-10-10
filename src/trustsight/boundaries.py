"""The unified analysis-boundary model (Addendum 2, W1).

A boundary is one property of the *input* that limits what the analysis
could conclude: a truncated diff, an unreadable script, a registry the
build will consult at run time, an assignment the tokenizer refused.  Two
surfaces already describe these - the ``coverage_gaps`` list (which forbids
a clean verdict) and the weight-0 W-series findings (which render the same
fact to a reader) - and they were kept in agreement only by convention.

This module makes them one object.  :func:`boundaries_from_fact` is the
single derivation; :func:`forbids_clean` is the view the verdict reads; and
the W rules are the renderings.  v1 is additive: the report gains a
``boundaries`` array while ``coverage_gaps`` and the W findings stay for one
release (the migration contract), and the verdict is unchanged by
construction because :func:`forbids_clean` equals ``bool(coverage_gaps)``.
"""

from __future__ import annotations

from dataclasses import dataclass

__all__ = [
    "AnalysisBoundary",
    "BoundaryKind",
    "boundary_kind_for_gap",
    "boundary_kind_for_w_rule",
    "boundaries_from_fact",
    "forbids_clean",
]


class BoundaryKind(str):
    """The category of a boundary.  Strings, not an enum member per gap:
    the same kind is reached by a coverage gap, a W rule, or both."""

    TRUNCATED = "truncated"
    UNREADABLE_FILE = "unreadable_file"
    UNREADABLE_TREE = "unreadable_tree"
    PARTIAL_FILE = "partial_file"
    UNRESOLVED = "unresolved"
    UNPINNED_DEPS = "unpinned_deps"
    NO_HISTORY = "no_history"
    ANALYSIS_INCOMPLETE = "analysis_incomplete"
    REGISTRY_RESOLUTION = "registry_resolution"
    BUILD_ONLY_PATH = "build_only_path"


#: Coverage-gap id -> boundary kind.  Kept in step with ``coverage.GAPS``.
_GAP_KIND: dict[str, str] = {
    "diff_truncated": BoundaryKind.TRUNCATED,
    "scan_truncated": BoundaryKind.TRUNCATED,
    "partial_hunk": BoundaryKind.TRUNCATED,
    "line_truncated": BoundaryKind.TRUNCATED,
    "tree_not_analyzed": BoundaryKind.UNREADABLE_TREE,
    "snapshot_refused": BoundaryKind.UNREADABLE_TREE,
    "companion_truncated": BoundaryKind.UNREADABLE_FILE,
    "binary_metadata": BoundaryKind.UNREADABLE_FILE,
    "partial_file_analysis": BoundaryKind.PARTIAL_FILE,
    "unresolved_source": BoundaryKind.UNRESOLVED,
    "unresolved_parse_time": BoundaryKind.UNRESOLVED,
    "unpinned_build_deps": BoundaryKind.UNPINNED_DEPS,
    "deps_not_scanned": BoundaryKind.UNPINNED_DEPS,
    "parent_baseline": BoundaryKind.NO_HISTORY,
    "history_truncated": BoundaryKind.NO_HISTORY,
    "ruleset_drifted": BoundaryKind.ANALYSIS_INCOMPLETE,
    "stage_degraded": BoundaryKind.ANALYSIS_INCOMPLETE,
    "noextract_suppressed": BoundaryKind.UNREADABLE_FILE,
}

#: W-rule id -> boundary kind.  The W series is the rendering face of the
#: same facts; W002 is a registry the build consults at run time, the rest
#: are code/files the analysis did not read.
_W_RULE_KIND: dict[str, str] = {
    "W001": BoundaryKind.UNREADABLE_FILE,
    "W002": BoundaryKind.REGISTRY_RESOLUTION,
    "W003": BoundaryKind.UNREADABLE_FILE,
    "W004": BoundaryKind.UNREADABLE_FILE,
    "W005": BoundaryKind.UNREADABLE_FILE,
    "W006": BoundaryKind.BUILD_ONLY_PATH,
}


def boundary_kind_for_gap(gap: str) -> str | None:
    return _GAP_KIND.get(str(gap))


def boundary_kind_for_w_rule(rule_id: str) -> str | None:
    return _W_RULE_KIND.get(str(rule_id))


@dataclass(frozen=True)
class AnalysisBoundary:
    """One limit on the analysis, with both of its renderings.

    ``gap`` is the coverage-gap id when the fact forbid a clean verdict
    (empty for a W-only boundary); ``w_rule`` is the W-series rule id when a
    finding renders it (empty for a gap with no W shape).  ``kind`` is the
    shared category, which is why the two faces cannot disagree.
    """

    kind: str
    gap: str = ""
    w_rule: str = ""
    detail: str = ""

    @property
    def forbids_clean(self) -> bool:
        """True when this boundary blocks an unflagged verdict."""
        return bool(self.gap)

    def to_dict(self) -> dict:
        return {
            "kind": self.kind,
            "gap": self.gap,
            "w_rule": self.w_rule,
            "detail": self.detail,
            "forbids_clean": self.forbids_clean,
        }


def boundaries_from_fact(fact) -> list[AnalysisBoundary]:
    """Every boundary of *fact*, one per gap and one per W finding.

    Stable order: gaps first (their order is the coverage layer's stable
    order), then W renderings that carry no corresponding gap.
    """
    out: list[AnalysisBoundary] = []
    for gap in getattr(fact, "coverage_gaps", ()) or ():
        kind = boundary_kind_for_gap(gap)
        if kind is None:
            continue
        out.append(AnalysisBoundary(kind=kind, gap=str(gap)))
    seen_rules = {b.w_rule for b in out if b.w_rule}
    for entry in getattr(fact, "score_breakdown", ()) or ():
        rule_id = str(getattr(entry, "rule_id", ""))
        if not rule_id.startswith("W") or rule_id in seen_rules:
            continue
        kind = boundary_kind_for_w_rule(rule_id)
        if kind is None:
            kind = BoundaryKind.UNREADABLE_FILE
        detail = str(getattr(entry, "reason", "") or "")
        out.append(AnalysisBoundary(kind=kind, w_rule=rule_id, detail=detail))
        seen_rules.add(rule_id)
    return out


def forbids_clean(boundaries) -> bool:
    """The verdict's view: any boundary with a gap blocks a clean verdict.

    Equal to ``bool(coverage_gaps)`` by construction, which is what keeps
    the dual-emit migration verdict-identical.
    """
    return any(b.forbids_clean for b in boundaries)
