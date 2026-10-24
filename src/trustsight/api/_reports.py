"""Internal projections from analysis facts to the public API result objects."""

from __future__ import annotations
from dataclasses import replace
from typing import Optional, Sequence
from ._models import AcknowledgedUrl, ClusterFinding, CycleReport, FileChange, Finding, Progress, ProgressHook, Report, SuppressedRule

__all__ = ['COVERAGE_GAP_REASONS', '_LazyGapReasons', '_body_source', '_clean', '_cycle_report', '_evaluate_fact', '_file_changes', '_findings_from_breakdown', '_findings_from_evaluation', '_gap_reasons', '_hook', '_report_from_fact', '_report_from_result', '_suppressed']

def _gap_reasons() -> dict:
    from ..coverage import GAP_REASONS

    return dict(GAP_REASONS)

class _LazyGapReasons(dict):
    """``COVERAGE_GAP_REASONS`` without importing coverage at module import."""

    def _load(self):
        if not dict.__len__(self):
            self.update(_gap_reasons())
        return self

    def __getitem__(self, key):
        return dict.__getitem__(self._load(), key)

    def __contains__(self, key):
        # `in` is the natural way to test a "gap identifier -> reason" table;
        # without this it consulted the not-yet-loaded dict and lied.
        return dict.__contains__(self._load(), key)

    def get(self, key, default=None):
        return dict.get(self._load(), key, default)

    def __iter__(self):
        return dict.__iter__(self._load())

    def __len__(self):
        return dict.__len__(self._load())

    def items(self):
        return dict.items(self._load())

    def keys(self):
        return dict.keys(self._load())

    def values(self):
        return dict.values(self._load())

COVERAGE_GAP_REASONS = _LazyGapReasons()

def _hook(callback: Optional[ProgressHook]):
    """Adapt a ``Progress`` hook to the engine's ``(cur, total, phase)`` form."""
    if callback is None:
        return None

    def _cb(current: int, total: int, phase: str) -> None:
        callback(Progress(current=current, total=total, phase=phase))

    return _cb

def _findings_from_breakdown(fact) -> tuple[Finding, ...]:
    return _findings_from_evaluation(_evaluate_fact(fact))

def _findings_from_evaluation(evaluated: dict) -> tuple[Finding, ...]:
    return tuple(
        Finding(
            rule_id=row["rule_id"],
            severity=row["severity"],
            weight=row["weight"],
            description=row["description"],
            file=row["file"],
            line=row["line"],
            template=row["template"],
            evidence=row["evidence"],
            techniques=tuple(row.get("techniques") or ()),
        )
        for row in evaluated["findings"]
    )

def _evaluate_fact(fact) -> dict:
    from ..reporting import evaluate_fact

    return evaluate_fact(fact)

def _suppressed(rows: Sequence[dict]) -> tuple[SuppressedRule, ...]:
    return tuple(
        SuppressedRule(
            rule_id=r.get("rule_id", ""),
            severity=r.get("severity", ""),
            override_reason=r.get("override_reason", ""),
            override_package=r.get("override_package"),
        )
        for r in rows or ()
    )

def _file_changes(rows: Sequence[dict]) -> tuple[FileChange, ...]:
    return tuple(
        FileChange(path=r.get("path", ""), status=r.get("status", ""))
        for r in rows or ()
    )

def _body_source(evaluated: dict, *, row: Optional[dict]) -> dict:
    """The evaluated dict as ``report_body`` wants it.

    ``failed`` lives on a review row rather than on a fact - a fact exists
    only when the analysis produced one - so it is folded in here. Nothing
    else is transformed: the whole point is that one dict feeds every
    surface.
    """
    source = dict(evaluated)
    source.pop("fact", None)
    if row is not None:
        source["failed"] = bool(row.get("failed", False))
    source.setdefault("failed", False)
    return source

def _clean(value):
    """`safe_text.clean`, preserving ``None`` and the empty string."""
    from ..safe_text import clean

    return clean(value) if value else value

def _report_from_fact(fact) -> Report:
    """Build a Report from an internal PackageFact."""
    evaluated = _evaluate_fact(fact)
    findings = _findings_from_evaluation(evaluated)
    raw = evaluated["raw"]

    return Report(
        package=evaluated["package"],
        old_version=evaluated["old_version"],
        new_version=evaluated["new_version"],
        old_commit=evaluated["old_commit"],
        new_commit=evaluated["new_commit"],
        score=evaluated["score"],
        risk=evaluated["risk"],
        risk_label=evaluated["risk_label"],
        verdict=evaluated["verdict"],
        findings=findings,
        suppressed=_suppressed(evaluated["suppressed_rules"]),
        acknowledged_urls=tuple(
            AcknowledgedUrl(url=r.get("url", ""), reason=r.get("reason", ""))
            for r in evaluated.get("acknowledged_urls", ())
        ),
        changes=tuple(evaluated["changes"]),
        coverage_gaps=tuple(evaluated["coverage_gaps"]),
        coverage_gaps_carried=tuple(evaluated.get("coverage_gaps_carried", ())),
        change=dict(evaluated.get("change", {}) or {}),
        unresolved_assignments=tuple(
            evaluated.get("unresolved_assignments", ())),
        partial_files=tuple(evaluated.get("partial_files", ())),
        resolution_coverage=dict(evaluated.get("resolution_coverage", {}) or {}),
        layers=dict(evaluated.get("layers", {}) or {}),
        boundaries=tuple(evaluated.get("boundaries", ()) or ()),
        file_changes=_file_changes(evaluated["file_changes"]),
        diff_shape_fp=fact.diff_shape_fp or "",
        added_urls=tuple(fact.source_changes.added_urls),
        removed_urls=tuple(fact.source_changes.removed_urls),
        source_buckets=dict(fact.source_buckets),
        checksum_behavior=fact.source_changes.checksum_behavior,
        resolved_commands=tuple(fact.execution_changes.resolved_commands),
        # Both are attacker-chosen strings that arrive from a PKGBUILD
        # comment or an AUR record and leave through `Report`. The CLI
        # renderer cleans what it prints, but an API consumer printing a
        # maintainer name raw would render whatever escape sequence the
        # name carries - and the fix belongs where the fact becomes a
        # report, not in one of the things that reads it.
        maintainer=_clean(fact.current_maintainer),
        previous_maintainer=_clean(fact.previous_maintainer),
        maintainer_changed=fact.maintainer_changed,
        dependency_changes={k: sorted(v) for k, v in fact.dependency_changes.items()},
        dependencies=tuple(getattr(fact, "dependencies", ())),
        depth_truncated=bool(getattr(fact, "depth_truncated", False)),
        required_by=tuple(raw.get("required_by", ()) if raw else ()),
        ioc_matches=tuple(getattr(fact, "ioc_matches", ()) or ()),
        indicators=tuple(getattr(fact, "ioc_matches", ()) or ()),
        scan_truncated=bool(getattr(fact, "scan_truncated", False)),
        first_seen=fact.first_seen,
        comparison_base=getattr(fact, "comparison_base", ""),
        is_trivial=evaluated["is_trivial"],
        diff_truncated=evaluated["diff_truncated"],
        tree_analyzed=fact.tree_analyzed,
        version_comparison=evaluated["version_comparison"],
        cached=bool(getattr(fact, "cached", False)),
        cached_at=getattr(fact, "cached_at", "") or "",
        adapter=fact.adapter,
        review_profile=evaluated["review_profile"],
        review_threshold=evaluated["review_threshold"],
        config_fingerprint=evaluated["config_fingerprint"],
        _raw=raw,
        _evaluated=_body_source(evaluated, row=None),
    )

def _report_from_result(row: dict) -> Report:
    """Build a Report from a review-engine result dict.

    When the row carries the underlying fact, the report is built from it,
    so a report from ``review`` and one from ``inspect`` describe the same
    package identically.  The versions still come from the row: ``review``
    compares what pacman has installed against what the AUR advertises,
    which is not the same pair the fact holds.
    """
    fact = row.get("_verbose_fact")
    if fact is not None:
        report = _report_from_fact(fact)
        raw = dict(report._raw)
        raw["old_version"] = row.get("old_version", "")
        raw["new_version"] = row.get("new_version", "")
        evaluated = dict(report._evaluated)
        evaluated["old_version"] = row.get("old_version", "")
        evaluated["new_version"] = row.get("new_version", "")
        evaluated["failed"] = bool(row.get("failed", False))
        # `--deps` is a property of the run, not of the fact: the fact knows
        # what this package depends on, and the row knows who depends on it.
        evaluated["required_by"] = list(row.get("required_by", ()))
        raw["required_by"] = list(row.get("required_by", ()))
        return replace(
            report,
            old_version=row.get("old_version", ""),
            new_version=row.get("new_version", ""),
            required_by=tuple(row.get("required_by", ())),
            _raw=raw,
            _evaluated=evaluated,
        )

    from ..reporting import evaluate_review_row

    evaluated = evaluate_review_row(row)
    findings = _findings_from_evaluation(evaluated)
    raw = evaluated["raw"]
    return Report(
        package=evaluated["package"],
        old_version=evaluated["old_version"],
        new_version=evaluated["new_version"],
        score=evaluated["score"],
        risk=evaluated["risk"],
        risk_label=evaluated["risk_label"],
        verdict=evaluated["verdict"],
        findings=findings,
        suppressed=_suppressed(evaluated["suppressed_rules"]),
        acknowledged_urls=tuple(
            AcknowledgedUrl(url=r.get("url", ""), reason=r.get("reason", ""))
            for r in evaluated.get("acknowledged_urls", ())
        ),
        changes=tuple(evaluated["changes"]),
        coverage_gaps=tuple(evaluated["coverage_gaps"]),
        coverage_gaps_carried=tuple(evaluated.get("coverage_gaps_carried", ())),
        change=dict(evaluated.get("change", {}) or {}),
        unresolved_assignments=tuple(
            evaluated.get("unresolved_assignments", ())),
        partial_files=tuple(evaluated.get("partial_files", ())),
        resolution_coverage=dict(evaluated.get("resolution_coverage", {}) or {}),
        layers=dict(evaluated.get("layers", {}) or {}),
        boundaries=tuple(evaluated.get("boundaries", ()) or ()),
        file_changes=_file_changes(evaluated["file_changes"]),
        diff_shape_fp=evaluated.get("diff_shape_fp", "") or "",
        first_seen=evaluated["first_seen"],
        comparison_base=evaluated.get("comparison_base", ""),
        is_trivial=evaluated["is_trivial"],
        diff_truncated=evaluated["diff_truncated"],
        version_comparison=evaluated["version_comparison"],
        cached=bool(evaluated.get("cached", False)),
        cached_at=evaluated.get("cached_at", "") or "",
        required_by=tuple(evaluated.get("required_by", ())),
        review_profile=evaluated["review_profile"],
        review_threshold=evaluated["review_threshold"],
        _raw=raw,
        _evaluated=_body_source(evaluated, row=row),
    )

def _cycle_report(result) -> CycleReport:
    return CycleReport(
        added=result.added,
        changed=result.changed,
        removed=result.removed,
        processed=result.processed,
        bootstrap=result.bootstrap,
        backfilling=result.backfilling,
        elapsed=result.elapsed,
        flagged=tuple((name, score) for name, score in result.flagged),
        over_threshold=tuple((name, score) for name, score in result.over_threshold),
        ioc_hits=tuple(result.ioc_hits),
        cluster_findings=tuple(
            ClusterFinding(
                rule_id=f.get("rule_id", ""),
                name=f.get("name", ""),
                severity=f.get("severity", ""),
                match=f.get("match", ""),
                members=tuple(f.get("params", {}).get("members", ())),
            )
            for f in result.cluster_findings
        ),
        new_alerts=tuple((p, r) for p, r in result.new_alerts),
    )
