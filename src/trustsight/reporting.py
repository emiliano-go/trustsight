"""Shared semantic result assembly for the CLI and public API.

This module intentionally does not render terminal output.  It owns the
meaning of an evaluation: score, risk, coverage, findings, suppression and
verdict.  The CLI and API are presentation adapters over these values.
"""

from __future__ import annotations

from typing import Any, Sequence


def finding_rows(fact) -> list[dict]:
    """Return the findings exposed by the CLI and API for *fact*."""
    from .verdict import _render

    rows = []
    for entry in fact.score_breakdown:
        if entry.weight > 0 or entry.severity in ("FATAL", "CRITICAL"):
            rows.append({
                "rule_id": entry.rule_id,
                "file": entry.file,
                "line": entry.line,
                "description": _render(entry, fact),
                "template": entry.template,
                "evidence": dict(entry.evidence) if entry.evidence else {},
                "severity": entry.severity,
                "weight": entry.weight,
            })
    return rows


def suppressed_rows(fact) -> list[dict]:
    """Return suppressed rules as visible, non-scoring audit data."""
    return [dict(row) for row in (fact.suppressed_rules or ())]


def is_trivial(fact, findings: Sequence[dict] | None = None) -> bool:
    """Apply the shared trivial-update definition."""
    if not fact.diff_summary.files_changed:
        return True
    for finding in findings if findings is not None else finding_rows(fact):
        if finding.get("rule_id") not in ("C002",):
            return False
    return True


def evaluate_fact(fact) -> dict[str, Any]:
    """Build the canonical semantic result for an internal ``PackageFact``.

    The returned values are plain data for adapters.  In particular, risk is
    taken from the analysis band and never derived from the numeric score.
    """
    from .coverage import describe as describe_coverage
    from .schema import fact_to_dict
    from .scoring import verdict_label, verdict_level
    from .verdict import fallback_verdict

    findings = finding_rows(fact)
    verdict = fallback_verdict(fact)
    coverage_note = describe_coverage(fact.coverage_gaps)
    if coverage_note:
        verdict = f"{coverage_note} {verdict}"

    raw = fact_to_dict(fact)
    raw.update({
        "verdict": verdict,
        "risk_label": verdict_label(fact),
        "version_comparison": fact.version_comparison,
    })
    return {
        "package": fact.package_name,
        "old_version": fact.old_version,
        "new_version": fact.new_version,
        "old_commit": fact.old_commit,
        "new_commit": fact.new_commit,
        "score": fact.final_score,
        "risk": verdict_level(fact),
        "risk_label": verdict_label(fact),
        "verdict": verdict,
        "findings": findings,
        "suppressed_rules": suppressed_rows(fact),
        "changes": list(fact.changes),
        "coverage_gaps": list(fact.coverage_gaps),
        "file_changes": list(fact.diff_summary.file_changes),
        "first_seen": fact.first_seen,
        "diff_truncated": fact.diff_truncated,
        "version_comparison": fact.version_comparison,
        "is_trivial": is_trivial(fact, findings),
        "ioc_matches": list(fact.ioc_matches),
        "config_fingerprint": raw.get("config_fingerprint", ""),
        "raw": raw,
        "fact": fact,
    }


def evaluate_review_row(row: dict) -> dict[str, Any]:
    """Normalize a review-engine row when no underlying fact is attached."""
    findings = [dict(finding) for finding in row.get("findings", ())]
    raw = {
        "package_name": row["package"],
        "old_version": row.get("old_version", ""),
        "new_version": row.get("new_version", ""),
        "final_score": row.get("score", 0),
        "risk": row.get("risk", ""),
        "risk_label": row.get("risk_label", ""),
        "verdict": row.get("verdict", ""),
        "first_seen": row.get("first_seen", False),
        "is_trivial": row.get("is_trivial", False),
        "diff_truncated": row.get("diff_truncated", False),
        "changes": list(row.get("changes", ())),
        "coverage_gaps": list(row.get("coverage_gaps", ())),
        "version_comparison": row.get("version_comparison", ""),
        "file_changes": list(row.get("file_changes", ())),
        "score_breakdown": findings,
        "suppressed_rules": list(row.get("suppressed_rules", ())),
    }
    return {
        "package": row["package"],
        "old_version": row.get("old_version", ""),
        "new_version": row.get("new_version", ""),
        "old_commit": "",
        "new_commit": "",
        "score": row.get("score") or 0,
        "risk": row.get("risk", ""),
        "risk_label": row.get("risk_label") or row.get("risk", ""),
        "verdict": row.get("verdict", ""),
        "findings": findings,
        "suppressed_rules": list(row.get("suppressed_rules", ())),
        "changes": list(row.get("changes", ())),
        "coverage_gaps": list(row.get("coverage_gaps", ())),
        "file_changes": list(row.get("file_changes", ())),
        "first_seen": row.get("first_seen", False),
        "diff_truncated": row.get("diff_truncated", False),
        "version_comparison": row.get("version_comparison", ""),
        "is_trivial": row.get("is_trivial", False),
        "ioc_matches": list(row.get("ioc_matches", ())),
        "config_fingerprint": row.get("config_fingerprint", ""),
        "raw": raw,
        "fact": None,
    }
