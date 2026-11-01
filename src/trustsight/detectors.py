"""Detector metadata: mechanism, evidence source, and shared dependencies.

A layer says *what kind of evidence* a finding represents.  Two rules in
different series can look independent and still share a failure mode - the
same tokenizer, parser, history database, or corpus.  Different algorithms
are a starting point, not proof of independence; shared dependencies must be
named so common-mode failure is visible.

This registry holds that metadata per series (the granularity at which
dependencies actually differ) and derives it per rule.  It is the source the
intake review and the documentation read; the security gate
``every rule names its shared dependencies`` fails if a rule's series has no
entry.
"""

from __future__ import annotations

__all__ = [
    "SERIES_MECHANISM",
    "SERIES_EVIDENCE",
    "SERIES_DEPENDENCIES",
    "RULE_METADATA_OVERRIDES",
    "DetectorMetadata",
    "detector_metadata",
    "series_of",
]

#: How a series reaches its conclusion.
SERIES_MECHANISM: dict[str, str] = {
    "R": "regex pattern match",
    "C": "structural invariant over parsed documents",
    "D": "dependency-graph walk",
    "S": "sabotage-pattern match",
    "X": "evasion/refusal analysis",
    "H": "behavioral heuristic",
    "T": "historical observation",
    "G": "cross-package correlation",
    "E": "distribution/entropy statistic",
    "I": "external indicator membership",
    "M": "predicate over other findings",
    "A": "built-artifact inspection",
    "U": "committed-manifest parse",
    "P": "declared-practice record",
    "W": "analysis-boundary report",
}

#: The information the series needs to reach its conclusion.
SERIES_EVIDENCE: dict[str, str] = {
    "R": "diff text",
    "C": "parsed recipe/diff documents",
    "D": "dependency corpus",
    "S": "diff text",
    "X": "diff text and tokenizer refusals",
    "H": "diff text and analysis modules",
    "T": "stored observation history",
    "G": "the set of recent analyses",
    "E": "added diff text",
    "I": "signed indicator baselines",
    "M": "the finding set",
    "A": "the built-package manifest",
    "U": "committed manifest files",
    "P": "recipe declarations",
    "W": "coverage-gap records",
}

#: The shared infrastructure each series depends on.  A weakness here is a
#: common-mode failure across every rule in the series (and across series
#: that share an entry), so it is named rather than assumed away.
SERIES_DEPENDENCIES: dict[str, frozenset[str]] = {
    "R": frozenset({"tokenizer", "rules.toml"}),
    "C": frozenset({"recipedoc", "diffdoc"}),
    "D": frozenset({"dependency_corpus", "deps"}),
    "S": frozenset({"tokenizer", "lexer"}),
    "X": frozenset({"tokenizer", "crossfire", "refusals"}),
    "H": frozenset({"tokenizer", "analysis_modules"}),
    "T": frozenset({"observation_db"}),
    "G": frozenset({"corpus_db", "cycle_records"}),
    "E": frozenset({"tokenizer", "diffdoc"}),
    "I": frozenset({"ioc_baseline"}),
    "M": frozenset({"finding_set"}),
    "A": frozenset({"artifact_manifest"}),
    "U": frozenset({"manifests", "tree_walk", "diffdoc"}),
    "P": frozenset({"recipedoc", "diffdoc"}),
    "W": frozenset({"coverage"}),
}


#: Per-rule overrides.  A rule whose id prefix no longer matches its
#: mechanism gets its metadata here rather than a renumber (rule ids are
#: immutable): H056 is the *indicator* mechanism under an H id, so its
#: mechanism, evidence and shared dependencies are the I-series facts, not
#: the H-series ones.  Without this the registry would call an exact
#: external-list match a "behavioral heuristic" and hide the indicator
#: list and keyring it actually depends on.
RULE_METADATA_OVERRIDES: dict[str, dict] = {
    # T004/T005 are filed in T for identity but read the diff, not stored
    # history: naming "historical observation" would overstate the evidence.
    "T004": {
        "mechanism": "missing-self diff predicate",
        "evidence": "parsed recipe/diff documents",
        "shared_dependencies": ["recipedoc", "diffdoc"],
    },
    "T005": {
        "mechanism": "missing-self diff predicate",
        "evidence": "parsed recipe/diff documents",
        "shared_dependencies": ["recipedoc", "diffdoc"],
    },
    "H056": {
        "mechanism": "external indicator membership",
        "evidence": "signed indicator baselines",
        "shared_dependencies": ["ioc_baseline", "keyring"],
    },
}


def series_of(rule_id: str) -> str:
    return (rule_id[:1].upper() if rule_id else "")


class DetectorMetadata(dict):
    """A rule's detector metadata, as a plain dict for serialisation."""


def detector_metadata(rule_id: str) -> DetectorMetadata | None:
    """Mechanism, subject, evidence source and shared dependencies of a rule.

    ``subject`` is the rule's category (what it looks for); ``mechanism`` and
    ``evidence`` are the series-level facts, with a per-rule override for a
    rule whose mechanism no longer matches its id series;
    ``shared_dependencies`` is the infrastructure whose failure would blind
    every rule in the series.  ``None`` for an id this build does not ship.
    """
    from .categories import category_of

    category = category_of(rule_id)
    if category is None:
        return None
    series = series_of(rule_id)
    metadata = {
        "rule_id": rule_id.upper(),
        "series": series,
        "subject": category.value,
        "mechanism": SERIES_MECHANISM.get(series, series),
        "evidence": SERIES_EVIDENCE.get(series, ""),
        "shared_dependencies": sorted(SERIES_DEPENDENCIES.get(series, ())),
    }
    metadata.update(RULE_METADATA_OVERRIDES.get(rule_id.upper(), {}))
    return DetectorMetadata(metadata)
