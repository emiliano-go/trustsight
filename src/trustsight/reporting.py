"""Shared semantic result assembly for the CLI and public API.

This module intentionally does not render terminal output.  It owns the
meaning of an evaluation: score, risk, coverage, findings, suppression and
verdict.  The CLI and API are presentation adapters over these values.
"""

from __future__ import annotations

from typing import Any, Sequence


#: Weight-0 findings that are shown anyway.
#:
#: The filter below keeps findings that carry score, which is right for a
#: rule that claims a *line*: a weight-0 line-rule is a note about
#: something already counted. These two are not about a line. R089 says
#: the diff holds a staged attack chain and R117 says a line the reader is
#: about to judge was reconstructed rather than read - each changes how
#: every other finding should be read, and both were computed and then
#: dropped before anyone saw them.
#:
#: Computing and hiding is the worst of the three options; the other two
#: are to show them or to stop computing them.
ALWAYS_SHOWN_ANNOTATIONS = frozenset({"R089", "R117"})


def finding_rows(fact) -> list[dict]:
    """Return the findings exposed by the CLI and API for *fact*."""
    from .verdict import _render

    rows = []
    for entry in fact.score_breakdown:
        if (entry.weight > 0
                or entry.severity in ("FATAL", "CRITICAL")
                or entry.rule_id in ALWAYS_SHOWN_ANNOTATIONS
                # The W series is weight-0 by construction and useless
                # unless shown: its whole content is "something ran that
                # nobody read", which is a statement to a reader and not a
                # component of any number.
                or entry.rule_id.startswith("W")):
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
    from .review_policy import review_policy
    from .verdict import fallback_verdict

    findings = finding_rows(fact)
    verdict = fallback_verdict(fact)
    coverage_note = describe_coverage(fact.coverage_gaps)
    if coverage_note:
        verdict = f"{coverage_note} {verdict}"

    raw = fact_to_dict(fact)
    policy = review_policy()
    raw.update({
        "verdict": verdict,
        "risk_label": verdict_label(fact),
        "review_profile": policy.name,
        "review_threshold": policy.threshold,
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
        "review_profile": policy.name,
        "review_threshold": policy.threshold,
        "flagged": policy.flagged(fact.final_score),
        "verdict": verdict,
        "findings": findings,
        "suppressed_rules": suppressed_rows(fact),
        "changes": list(fact.changes),
        "coverage_gaps": list(fact.coverage_gaps),
        "file_changes": list(fact.diff_summary.file_changes),
        "first_seen": fact.first_seen,
        "diff_truncated": fact.diff_truncated,
        "scan_truncated": fact.scan_truncated,
        "version_comparison": fact.version_comparison,
        "is_trivial": is_trivial(fact, findings),
        "ioc_matches": list(fact.ioc_matches),
        "dependencies": list(getattr(fact, "dependencies", ())),
        "depth_truncated": bool(getattr(fact, "depth_truncated", False)),
        # `review --deps` reverses the relationship this report describes:
        # the subject is a dependency and the interesting fact is which
        # packages require it. Empty on an ordinary review, where the
        # subject is the thing that was asked for.
        "required_by": list(raw.get("required_by", ())),
        "config_fingerprint": raw.get("config_fingerprint", ""),
        "raw": raw,
        "fact": fact,
    }


#: Keys every machine-readable body carries, whatever surface produced it.
#: A consumer written against one JSON path works against all of them, and a
#: key that exists on one and not another is a difference in *information*
#: rather than in form, which is what parity forbids.
REPORT_KEYS = (
    "package",
    "old_version",
    "new_version",
    "old_commit",
    "new_commit",
    "version_comparison",
    "verdict",
    "findings",
    "file_changes",
    "changes",
    "coverage_gaps",
    "suppressed_rules",
    "ioc_matches",
    "first_seen",
    "is_trivial",
    "diff_truncated",
    "scan_truncated",
    "failed",
    "fully_vetted",
    "dependencies",
    "depth_truncated",
    "required_by",
    "config_fingerprint",
    "review_profile",
    "review_threshold",
    "flagged",
)

#: The aggregate verdict numbers.  Withheld unless the caller asks, because
#: the default output is evidence and not a headline: a number invites a
#: decision the tool is not entitled to make.  The CLI asks with ``--score``
#: or ``--risk``; the API asks with ``include_score=True``.
SCORE_KEYS = ("score", "risk", "risk_label")

#: The full scored breakdown, including per-entry weights.  Verbose only, on
#: every surface: a weight is score information, so it travels with the
#: score rather than in the default body.
VERBOSE_KEYS = ("score_breakdown",)

# Fields of a finding that are evidence rather than arithmetic.  ``weight``
# is deliberately absent: it belongs to VERBOSE_KEYS with the breakdown.
_FINDING_FIELDS = ("rule_id", "severity", "file", "line", "description",
                   "template", "evidence")


def _ioc_row(match) -> dict:
    """An IOC match as plain data, from either an object or a dict."""
    if isinstance(match, dict):
        return dict(match)
    return {
        "type": match.type,
        "value": match.value,
        "source": match.source,
        "confidence": match.confidence,
        "provenance": match.provenance,
        "campaign": match.campaign,
        "added": match.added,
        "surface": match.surface,
        "line": match.line,
        "expired": match.expired,
    }


def report_body(
    evaluated: dict[str, Any],
    *,
    include_score: bool = False,
    verbose: bool = False,
) -> dict[str, Any]:
    """The one machine-readable body, for every JSON surface there is.

    ``review --json``, ``inspect --json`` and the API's ``to_dict()`` all
    return this.  They used to each build their own: three key sets, two
    naming conventions (``package`` against ``package_name``, ``score``
    against ``final_score``), and the API body carried no ``findings`` at
    all while claiming in its docstring to be what the CLI writes.  A
    consumer could therefore be written against one path and silently miss
    evidence on another, which is the same class of defect as a coverage
    gap that never reaches the report.

    The split between the three groups is the model's own: evidence is
    always present, the aggregate numbers are available on request, and the
    arithmetic behind them is verbose.  Presentation may differ between a
    terminal and a dict; *information* may not.
    """
    from .review_policy import review_policy

    policy = review_policy()
    findings = [
        {field: finding.get(field) for field in _FINDING_FIELDS}
        for finding in evaluated.get("findings", ())
    ]
    body = {
        "package": evaluated.get("package", ""),
        "old_version": evaluated.get("old_version", ""),
        "new_version": evaluated.get("new_version", ""),
        "old_commit": evaluated.get("old_commit", ""),
        "new_commit": evaluated.get("new_commit", ""),
        "version_comparison": evaluated.get("version_comparison", ""),
        "verdict": evaluated.get("verdict", ""),
        "findings": findings,
        "file_changes": list(evaluated.get("file_changes", ())),
        # B7: what moved, whether or not a rule matched.
        "changes": list(evaluated.get("changes", ())),
        # B2: never dropped, on any path.
        "coverage_gaps": list(evaluated.get("coverage_gaps", ())),
        # B5: unconditional.  A suppression behind a verbosity flag looks
        # exactly like a rule that never matched.
        "suppressed_rules": [dict(r) for r in evaluated.get("suppressed_rules", ())],
        "ioc_matches": [_ioc_row(m) for m in evaluated.get("ioc_matches", ())],
        "first_seen": bool(evaluated.get("first_seen", False)),
        "is_trivial": bool(evaluated.get("is_trivial", False)),
        "diff_truncated": bool(evaluated.get("diff_truncated", False)),
        "scan_truncated": bool(evaluated.get("scan_truncated", False)),
        # A consumer gating on `findings == []` must be able to tell "clean"
        # from "not vetted".
        "failed": bool(evaluated.get("failed", False)),
        # And from "vetted as far as it could be read". `failed` covers an
        # analysis that *raised*; this covers one that finished having seen
        # only part of the change. Both produce `findings: []` and a score
        # of zero, and a CI job had no field distinguishing either from a
        # package that is genuinely clean. It is derived from
        # `coverage_gaps`, which was already here - but a consumer should
        # not have to know that an empty list is the only safe reading of
        # a verdict.
        "fully_vetted": not evaluated.get("coverage_gaps", ()),
        # Each dependency is its own analysis with its own score, so these
        # are results and not a component of this package's number.
        "dependencies": [
            d.to_dict() if hasattr(d, "to_dict") else dict(d)
            for d in evaluated.get("dependencies", ())
        ],
        "depth_truncated": bool(evaluated.get("depth_truncated", False)),
        "required_by": [str(n) for n in evaluated.get("required_by", ())],
        "config_fingerprint": evaluated.get("config_fingerprint", ""),
        "review_profile": evaluated.get("review_profile", policy.name),
        "review_threshold": evaluated.get("review_threshold", policy.threshold),
        "flagged": bool(evaluated.get("flagged", False)),
    }
    if include_score:
        body["score"] = evaluated.get("score", 0)
        body["risk"] = evaluated.get("risk", "")
        body["risk_label"] = evaluated.get("risk_label", "") or evaluated.get("risk", "")
    if verbose:
        raw = evaluated.get("raw") or {}
        body["score_breakdown"] = list(raw.get("score_breakdown", ()))
    return body


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
        "scan_truncated": row.get("scan_truncated", False),
        "changes": list(row.get("changes", ())),
        "coverage_gaps": list(row.get("coverage_gaps", ())),
        "version_comparison": row.get("version_comparison", ""),
        "file_changes": list(row.get("file_changes", ())),
        "score_breakdown": findings,
        "suppressed_rules": list(row.get("suppressed_rules", ())),
    }
    from .review_policy import review_policy

    policy = review_policy()
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
        "required_by": list(row.get("required_by", ())),
        "coverage_gaps": list(row.get("coverage_gaps", ())),
        "file_changes": list(row.get("file_changes", ())),
        "first_seen": row.get("first_seen", False),
        "diff_truncated": row.get("diff_truncated", False),
        "scan_truncated": row.get("scan_truncated", False),
        "version_comparison": row.get("version_comparison", ""),
        "is_trivial": row.get("is_trivial", False),
        "ioc_matches": list(row.get("ioc_matches", ())),
        "dependencies": list(row.get("dependencies", ())),
        "depth_truncated": bool(row.get("depth_truncated", False)),
        "config_fingerprint": row.get("config_fingerprint", ""),
        "review_profile": policy.name,
        "review_threshold": policy.threshold,
        "flagged": policy.flagged(row.get("score") or 0),
        "raw": raw,
        "fact": None,
    }
