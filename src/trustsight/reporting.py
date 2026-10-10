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
#: something already counted. These two are not about a line. H043 says
#: the diff holds a staged attack chain and H065 says a line the reader is
#: about to judge was reconstructed rather than read - each changes how
#: every other finding should be read, and both were computed and then
#: dropped before anyone saw them.
#:
#: Computing and hiding is the worst of the three options; the other two
#: are to show them or to stop computing them.
ALWAYS_SHOWN_ANNOTATIONS = frozenset({"H043", "H065"})


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


def _indexed_unresolved(fact) -> list[str]:
    """Unresolved-source lines with their ``unresolved_assignments`` index.

    Spec §8: a gap that depended on a refused assignment cross-references
    the structured list entry by index, so the reader can move between the
    two without re-matching text.
    """
    rows = getattr(fact, "unresolved_assignments", ()) or ()
    index_by_line = {
        str(row.get("line", "")).strip()[:200]: i
        for i, row in enumerate(rows)
    }
    out: list[str] = []
    for line in getattr(fact, "unresolved_sources", ()) or ():
        key = line.strip()[:200]
        index = index_by_line.get(key)
        out.append(f"{line} (unresolved_assignments[{index}])"
                   if index is not None else line)
    return out


def evaluate_fact(fact) -> dict[str, Any]:
    """Build the canonical semantic result for an internal ``PackageFact``.

    The returned values are plain data for adapters.  In particular, risk is
    taken from the analysis band and never derived from the numeric score.
    """
    from .boundaries import boundaries_from_fact
    from .coverage import describe as describe_coverage
    from .layers import layer_profile
    from .review_policy import review_policy
    from .schema import fact_to_dict
    from .scoring import verdict_label, verdict_level
    from .verdict import fallback_verdict

    findings = finding_rows(fact)
    verdict = fallback_verdict(fact)
    coverage_note = describe_coverage(
        fact.coverage_gaps,
        carried=getattr(fact, "carried_coverage_gaps", ()),
        details={
            "unresolved_source": _indexed_unresolved(fact),
            "partial_hunk": getattr(fact, "partial_hunks", ()),
            "partial_file_analysis": getattr(fact, "partial_files", ()),
        },
    )
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
        # The fact path must carry what report_body reads: the review-row
        # path already set this, so omitting it here made the surfaces
        # disagree (B11).  raw is fact_to_dict(fact), which has the value.
        "comparison_base": raw.get("comparison_base", ""),
        "score": fact.final_score,
        "risk": verdict_level(fact),
        "risk_label": verdict_label(fact),
        "review_profile": policy.name,
        "review_threshold": policy.threshold,
        "flagged": policy.flagged(fact.final_score),
        "verdict": verdict,
        "findings": findings,
        # Addendum 5 §3: the layer profile, additive.  A finding carries
        # the layer where it caught, so this is a projection of `findings`.
        "layers": layer_profile(fact, findings),
        "suppressed_rules": suppressed_rows(fact),
        "acknowledged_urls": [dict(row) for row in (fact.acknowledged_urls or ())],
        "changes": list(fact.changes),
        "coverage_gaps": list(fact.coverage_gaps),
        "coverage_gaps_carried": list(getattr(fact, "carried_coverage_gaps", ())),
        # Addendum 2 W1: the unified boundary model, additive.  The same
        # facts as coverage_gaps + the W renderings, one object.
        "boundaries": [b.to_dict() for b in boundaries_from_fact(fact)],
        # Spec §1: the typed change-as-data object, additive to the body.
        "change": dict(getattr(fact, "change", {}) or {}),
        # Spec §8 v1: the structured boundary of analysis.
        "unresolved_assignments": [
            dict(a) for a in getattr(fact, "unresolved_assignments", ()) or ()
        ],
        # Spec §9: install scripts read only in part.
        "partial_files": list(getattr(fact, "partial_files", ()) or ()),
        # Addendum 2 R1: tokenizer resolution coverage, with the rule-level
        # pointer: a resolved-target R-rule that fired zero times beside
        # unresolved lines points at X026 (the refusal family).
        "resolution_coverage": _resolution_coverage_rows(fact),
        "file_changes": list(fact.diff_summary.file_changes),
        "first_seen": fact.first_seen,
        "diff_truncated": fact.diff_truncated,
        "scan_truncated": fact.scan_truncated,
        "version_comparison": fact.version_comparison,
        "is_trivial": is_trivial(fact, findings),
        "ioc_matches": list(fact.ioc_matches),
        # Addendum 5 §6.4: the indicator tier, promoted.  Same facts as
        # `ioc_matches`, exposed as the first-class I-series surface.
        "indicators": list(fact.ioc_matches),
        "dependencies": list(getattr(fact, "dependencies", ())),
        "depth_truncated": bool(getattr(fact, "depth_truncated", False)),
        # Served from the recorded analysis rather than freshly computed
        # (#20); both False/"" on a fresh run.
        "cached": bool(getattr(fact, "cached", False)),
        "cached_at": getattr(fact, "cached_at", "") or "",
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
    "layers",
    "file_changes",
    "changes",
    "coverage_gaps",
    "coverage_gaps_carried",
    "boundaries",
    "change",
    "unresolved_assignments",
    "partial_files",
    "resolution_coverage",
    "suppressed_rules",
    "acknowledged_urls",
    "ioc_matches",
    "indicators",
    "first_seen",
    "comparison_base",
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
    "cached",
    "cached_at",
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
        # Addendum 5 §3: the layer profile, additive.
        "layers": dict(evaluated.get("layers", {}) or {}),
        "file_changes": list(evaluated.get("file_changes", ())),
        # B7: what moved, whether or not a rule matched.
        "changes": list(evaluated.get("changes", ())),
        # B2: never dropped, on any path.
        "coverage_gaps": list(evaluated.get("coverage_gaps", ())),
        # #19: the subset of those gaps unchanged since the previous review.
        "coverage_gaps_carried": list(evaluated.get("coverage_gaps_carried", ())),
        # Addendum 2 W1: the unified boundary list, additive.
        "boundaries": [
            dict(b) for b in evaluated.get("boundaries", ()) or ()
        ],
        # Spec §1: ChangeDelta.to_dict(), additive.
        "change": dict(evaluated.get("change", {}) or {}),
        # Spec §8 v1: the structured unresolved list, additive.
        "unresolved_assignments": [
            dict(a) for a in evaluated.get("unresolved_assignments", ()) or ()
        ],
        # Spec §9: install scripts the diff showed only in part.
        "partial_files": [str(p) for p in evaluated.get("partial_files", ())],
        # Addendum 2 R1: tokenizer resolution coverage, additive.
        "resolution_coverage": dict(
            evaluated.get("resolution_coverage", {}) or {}),
        # B5: unconditional.  A suppression behind a verbosity flag looks
        # exactly like a rule that never matched.
        "suppressed_rules": [dict(r) for r in evaluated.get("suppressed_rules", ())],
        # B5 again: an acknowledged URL is a suppression the reader must
        # see, or it is indistinguishable from a URL that never existed.
        "acknowledged_urls": [
            dict(r) for r in evaluated.get("acknowledged_urls", ())
        ],
        "ioc_matches": [_ioc_row(m) for m in evaluated.get("ioc_matches", ())],
        # Addendum 5 §6.4: the indicator tier, promoted (same rows as
        # `ioc_matches`, additive for one release).
        "indicators": [_ioc_row(m) for m in evaluated.get("ioc_matches", ())],
        "first_seen": bool(evaluated.get("first_seen", False)),
        "comparison_base": evaluated.get("comparison_base", ""),
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
        # Spec §8: a run with a non-empty unresolved list is not complete
        # even when it recorded no coverage gap - the list names assignments
        # the analysis refused to read, which is a boundary, not a quiet
        # "nothing there".
        "fully_vetted": (
            not evaluated.get("coverage_gaps", ())
            and not evaluated.get("unresolved_assignments", ())
        ),
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
        # #20: true when the recorded analysis was served unchanged.
        "cached": bool(evaluated.get("cached", False)),
        "cached_at": evaluated.get("cached_at", "") or "",
    }
    if include_score:
        body["score"] = evaluated.get("score", 0)
        body["risk"] = evaluated.get("risk", "")
        body["risk_label"] = evaluated.get("risk_label", "") or evaluated.get("risk", "")
    if verbose:
        raw = evaluated.get("raw") or {}
        body["score_breakdown"] = list(raw.get("score_breakdown", ()))
    return body


#: Severity ladder to SARIF result level (spec §3).
_SARIF_LEVELS = {
    "FATAL": "error",
    "CRITICAL": "error",
    "HIGH": "warning",
    "MEDIUM": "warning",
}


def finding_fingerprint(finding: dict, package: str) -> str:
    """A stable fingerprint for a finding (spec §3).

    Package + rule + file + line + normalized evidence.  Stable across
    runs of the same diff, so a code-scanning system can deduplicate a
    finding that did not move without re-reading its text.
    """
    import hashlib
    import json

    evidence = finding.get("evidence") or {}
    try:
        normalized = json.dumps(
            evidence, sort_keys=True, separators=(",", ":"), default=str
        )
    except (TypeError, ValueError):
        normalized = str(sorted(evidence.items())) if isinstance(evidence, dict) else str(evidence)
    raw = "|".join((
        package,
        str(finding.get("rule_id", "")),
        str(finding.get("file", "") or ""),
        str(finding.get("line") or ""),
        normalized,
    ))
    return hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()


def _sarif_location(finding: dict, doc) -> dict | None:
    """The finding's SARIF region, or ``None`` when no line is resolvable.

    Added/context findings anchor to the post-state artifact; a finding on
    a removed line anchors to the **pre-image** with its ``old_lineno``
    (never a post-state ``new_lineno`` for a removed line).  A line that
    does not exist in the artifact it would name yields no region: SARIF
    consumers must not receive a fabricated line.
    """
    path = finding.get("file") or ""
    line = finding.get("line")
    if not path or not isinstance(line, int) or line < 1:
        return None
    if doc is None:
        return {"uri": path, "startLine": line}

    def count(side: str) -> int:
        return sum(
            1 for entry in doc.lines
            if entry.file == path and entry.side in side
        )

    post_count = count(("add", "context"))
    pre_count = count(("remove", "context"))
    has_post = any(
        entry.file == path and entry.in_hunk
        and entry.side in ("add", "context") and entry.new_lineno == line
        for entry in doc.lines
    )
    if not has_post:
        for entry in doc.lines:
            if (entry.file == path and entry.in_hunk and entry.side == "remove"
                    and entry.new_lineno == line):
                if entry.old_lineno and entry.old_lineno <= pre_count:
                    return {
                        "uri": path,
                        "startLine": entry.old_lineno,
                        "properties": {"trustsight/side": "removed"},
                    }
                return None
    if line <= post_count:
        return {"uri": path, "startLine": line}
    return None


def report_to_sarif(reports, diffs: dict | None = None) -> dict:
    """Render evaluated reports as one SARIF 2.1.0 document (spec §3).

    *reports* is an iterable of evaluated dicts (the ``report_body``
    shape) or Report-like objects with ``to_dict``.  *diffs* optionally
    maps a package name to the analysed diff text so removed-line
    findings can anchor to the pre-image; without it, locations are
    emitted only for findings whose line resolves in the post-state.

    Formatting only: every fact here is attribution the typed core
    already solved, and a finding with no resolvable line gets no region.
    """
    from .diffdoc import parse_diff

    entries = []
    for report in reports:
        if hasattr(report, "to_dict"):
            report = report.to_dict()
        entries.append(report)
    docs = {}
    for package, text in (diffs or {}).items():
        docs[package] = parse_diff(text)

    rules: dict[str, dict] = {}
    results: list[dict] = []
    for report in entries:
        package = str(report.get("package", ""))
        doc = docs.get(package)
        for finding in report.get("findings", ()):
            rule_id = str(finding.get("rule_id", ""))
            if not rule_id:
                continue
            severity = str(finding.get("severity", "")).upper()
            level = _SARIF_LEVELS.get(severity, "note")
            rules.setdefault(rule_id, {
                "id": rule_id,
                "name": finding.get("template") or rule_id,
                "shortDescription": {"text": finding.get("template") or rule_id},
                "defaultConfiguration": {"level": level},
            })
            location = _sarif_location(finding, doc)
            result = {
                "ruleId": rule_id,
                "level": level,
                "message": {"text": str(finding.get("description", ""))},
                "partialFingerprints": {
                    "trustsight/v1": finding_fingerprint(finding, package),
                },
                "properties": {
                    "package": package,
                    "severity": severity,
                    "file": finding.get("file") or "",
                    "line": finding.get("line"),
                },
            }
            if location is not None:
                result["locations"] = [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": location["uri"]},
                        "region": {"startLine": location["startLine"]},
                    },
                    **({"properties": location["properties"]}
                       if "properties" in location else {}),
                }]
            results.append(result)
    return {
        "$schema": (
            "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/"
            "Schemata/sarif-schema-2.1.0.json"
        ),
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "TrustSight",
                    "informationUri": "https://docs.trustsight.org/",
                    "rules": [rules[key] for key in sorted(rules)],
                },
            },
            "results": results,
        }],
    }


def _resolution_coverage_rows(fact) -> dict:
    """R1's resolution coverage plus the rule-level X026 pointer.

    Addendum 2 R1 (v2): when a ``match_target=resolved`` R-rule fired zero
    times while unresolved lines exist, the report points at X026 rather
    than leaving the rule's silence unqualified.
    """
    coverage = dict(getattr(fact, "resolution_coverage", {}) or {})
    not_fired = sorted(
        set(coverage.get("resolved_target_rules", ()))
        - set(coverage.get("resolved_target_rules_fired", ()))
    )
    if coverage.get("unresolved_lines", 0) and not_fired:
        coverage["x026_pointer"] = (
            f"{len(not_fired)} resolution-coupled R-rule(s) did not fire "
            f"beside {coverage['unresolved_lines']} unresolved line(s); "
            "X026 reports the refusals"
        )
    return coverage


def _boundaries_for_row(row: dict, findings: list[dict]) -> list[dict]:
    """The unified boundary list for a review row with no PackageFact."""
    from .boundaries import (
        AnalysisBoundary,
        BoundaryKind,
        boundary_kind_for_gap,
        boundary_kind_for_w_rule,
    )

    out: list[dict] = []
    for gap in row.get("coverage_gaps", ()) or ():
        kind = boundary_kind_for_gap(gap)
        if kind:
            out.append(AnalysisBoundary(kind=kind, gap=str(gap)).to_dict())
    for finding in findings:
        rule_id = str(finding.get("rule_id", ""))
        if not rule_id.startswith("W"):
            continue
        kind = boundary_kind_for_w_rule(rule_id) or BoundaryKind.UNREADABLE_FILE
        out.append(AnalysisBoundary(kind=kind, w_rule=rule_id).to_dict())
    return out


def _layer_profile_row(row: dict, findings: list[dict]) -> dict[str, dict]:
    """The layer profile for a review row that carries no PackageFact."""
    from .layers import layer_profile

    class _Boundary:
        coverage_gaps = row.get("coverage_gaps", ())
        diff_truncated = row.get("diff_truncated", False)
        scan_truncated = row.get("scan_truncated", False)

    return layer_profile(_Boundary(), findings)


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
        "comparison_base": row.get("comparison_base", ""),
        "is_trivial": row.get("is_trivial", False),
        "diff_truncated": row.get("diff_truncated", False),
        "scan_truncated": row.get("scan_truncated", False),
        "changes": list(row.get("changes", ())),
        "coverage_gaps": list(row.get("coverage_gaps", ())),
        "coverage_gaps_carried": list(row.get("coverage_gaps_carried", ())),
        "change": dict(row.get("change", {}) or {}),
        "unresolved_assignments": [
            dict(a) for a in row.get("unresolved_assignments", ()) or ()
        ],
        "partial_files": list(row.get("partial_files", ())),
        "resolution_coverage": dict(row.get("resolution_coverage", {}) or {}),
        "version_comparison": row.get("version_comparison", ""),
        "file_changes": list(row.get("file_changes", ())),
        "score_breakdown": findings,
        "suppressed_rules": list(row.get("suppressed_rules", ())),
        "cached": bool(row.get("cached", False)),
        "cached_at": row.get("cached_at", "") or "",
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
        # Addendum 5 §3: the layer profile, additive.
        "layers": _layer_profile_row(row, findings),
        "suppressed_rules": list(row.get("suppressed_rules", ())),
        "changes": list(row.get("changes", ())),
        "required_by": list(row.get("required_by", ())),
        "coverage_gaps": list(row.get("coverage_gaps", ())),
        "coverage_gaps_carried": list(row.get("coverage_gaps_carried", ())),
        # Addendum 2 W1: the unified boundary list, additive.
        "boundaries": _boundaries_for_row(row, findings),
        "change": dict(row.get("change", {}) or {}),
        "unresolved_assignments": [
            dict(a) for a in row.get("unresolved_assignments", ()) or ()
        ],
        "partial_files": list(row.get("partial_files", ())),
        "resolution_coverage": dict(row.get("resolution_coverage", {}) or {}),
        "file_changes": list(row.get("file_changes", ())),
        "first_seen": row.get("first_seen", False),
        "comparison_base": row.get("comparison_base", ""),
        "diff_truncated": row.get("diff_truncated", False),
        "scan_truncated": row.get("scan_truncated", False),
        "version_comparison": row.get("version_comparison", ""),
        "is_trivial": row.get("is_trivial", False),
        "ioc_matches": list(row.get("ioc_matches", ())),
        "indicators": list(row.get("ioc_matches", ())),
        "dependencies": list(row.get("dependencies", ())),
        "depth_truncated": bool(row.get("depth_truncated", False)),
        "cached": bool(row.get("cached", False)),
        "cached_at": row.get("cached_at", "") or "",
        "config_fingerprint": row.get("config_fingerprint", ""),
        "review_profile": policy.name,
        "review_threshold": policy.threshold,
        "flagged": policy.flagged(row.get("score") or 0),
        "raw": raw,
        "fact": None,
    }
