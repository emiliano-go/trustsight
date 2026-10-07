from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from .ioc_baseline import IocMatch


@dataclass
class DiffSummary:
    """Aggregate statistics for a PKGBUILD diff."""

    lines_added: int = 0
    lines_removed: int = 0
    files_changed: list[str] = field(default_factory=list)
    file_changes: list[dict] = field(default_factory=list)
    """Each entry: {"path": str, "status": "added"|"removed"|"modified"}"""


@dataclass
class SourceChanges:
    """Source URL and checksum changes detected in a diff."""

    added_urls: list[str] = field(default_factory=list)
    removed_urls: list[str] = field(default_factory=list)
    checksum_behavior: str = ""


@dataclass
class ExecutionChanges:
    """Resolved command strings and suspicious patterns found in a diff."""

    resolved_commands: list[str] = field(default_factory=list)
    suspicious_patterns_detected: list[str] = field(default_factory=list)
    unresolved_patterns: list[str] = field(default_factory=list)


@dataclass
class TemporalContext:
    """Explicit temporal context for H020-H022 (and H037).

    Both analysis paths declare their clock source rather than
    deriving one internally, ensuring the same package gets the
    same temporal verdict regardless of how it was analysed.
    """
    last_modified: Optional[int] = None   # Unix timestamp
    first_seen: Optional[int] = None      # Unix timestamp
    previous_modified: Optional[int] = None
    source: str = "unknown"          # "git_commit" | "aur_metadata" | "observation_history"


@dataclass
class NoveltyContext:
    """Novelty signals for URLs and maintainers relative to the observation database."""

    url_first_seen_in_this_package: bool = False
    url_first_seen_globally: bool = False
    #: The URL that made each signal true.  A NOVELTY row without it read
    #: as a finding about nothing: the reader could not tell a real source
    #: URL from a comment artefact, and could not check the claim.
    url_first_seen_in_this_package_url: str = ""
    url_first_seen_globally_url: str = ""
    maintainer_first_seen_for_this_package: bool = False
    observation_count: int = 0


@dataclass
class ScoreEntry:
    """A single rule firing that contributed to the analysis score."""

    rule_id: str = ""
    severity: str = ""
    weight: int = 0
    reason: str = ""
    params: dict = field(default_factory=dict)
    template: str = ""
    evidence: dict = field(default_factory=dict)
    file: str = ""
    line: int | None = None


@dataclass
class PackageFact:
    """The complete analysis result for a single package diff.

    This is the central data structure of the analysis pipeline.  Every
    rule, signal, and coverage gap writes to this object; scoring,
    classification, and reporting read from it.
    """

    package_name: str = ""
    old_version: str = ""
    new_version: str = ""
    old_commit: str = ""
    new_commit: str = ""
    maintainer_changed: bool = False
    previous_maintainer: str = ""
    current_maintainer: str = ""

    diff_summary: DiffSummary = field(default_factory=DiffSummary)
    source_changes: SourceChanges = field(default_factory=SourceChanges)
    source_buckets: dict[str, str] = field(default_factory=dict)
    execution_changes: ExecutionChanges = field(default_factory=ExecutionChanges)
    novelty_context: NoveltyContext = field(default_factory=NoveltyContext)

    first_seen: bool = False
    # What this run compared against: "recorded" (a stored observation of
    # this package), "parent" (the immediately preceding commit, because no
    # observation existed), "none" (no diff at all), or "" (not applicable,
    # e.g. a caller-supplied diff).  A first review must not read as a
    # whole-history verdict, so the base travels with the fact.
    comparison_base: str = ""
    suppressed_rules: list[dict] = field(default_factory=list)

    # Source URLs the operator explicitly acknowledged for this package
    # (`trustsight override add-url`).  They do not score SOURCE_BUCKET or
    # NOVELTY, and they are reported here rather than dropped: a
    # suppression the report does not show is indistinguishable from a
    # detection that never happened.
    acknowledged_urls: list[dict] = field(default_factory=list)

    # True when the diff was larger than the configured cap and only its
    # first max_diff_bytes were examined.  The score then describes a
    # prefix, not the change, so it must not be read as a clean verdict:
    # padding a diff past the cap and appending the payload otherwise
    # turns a High into a Low.
    diff_truncated: bool = False
    scan_truncated: bool = False

    recent_commit_burst: bool = False

    # True when the repository file manifest (git tree / snapshot tarball)
    # was inspected for H066-tree.  A corpus-path result analysed without
    # the snapshot must not read the same as one that saw the whole tree.
    tree_analyzed: bool = False

    # Everything this run could not look at, as coverage.GAPS values, plus
    # the source entries behind an UNRESOLVED_SOURCE gap.  A non-empty list
    # forbids a clean verdict: see coverage.fail_closed.
    coverage_gaps: list[str] = field(default_factory=list)
    unresolved_sources: list[str] = field(default_factory=list)
    # Spec §8 v1: every assignment the tokenizer refused on the analysed
    # surface, as {name, line, file}.  Additive: it names the boundary of
    # analysis to the reader and never changes a finding or a score.
    unresolved_assignments: list[dict] = field(default_factory=list)
    # The hunks behind a PARTIAL_HUNK gap, each as
    # "FILE @@ NEWSTART: header declares N new line(s), M parsed" (see
    # coverage.cut_hunk_details).  The gap's generic reason names the
    # category; these name the cut.
    partial_hunks: list[str] = field(default_factory=list)
    # Install-script files whose diff showed only part of the file, behind
    # a PARTIAL_FILE_ANALYSIS gap (spec §9).
    partial_files: list[str] = field(default_factory=list)

    # Spec §1: the typed change-as-data view, ``ChangeDelta.to_dict()``.
    # The prose summary and the JSON ``change`` object both render this, so
    # they cannot disagree.  Empty on facts stored before the field existed.
    change: dict = field(default_factory=dict)

    # Addendum 2 R1: how much of the diff the tokenizer could read, and
    # which resolution-coupled R-rules matched.  Additive.
    resolution_coverage: dict = field(default_factory=dict)

    # The subset of ``coverage_gaps`` whose root cause was already in the
    # previous recorded analysis (#19).  Still gaps - they fail closed the
    # same way - but the report says "unchanged since the previous review"
    # instead of reading as a shortfall this diff introduced.
    carried_coverage_gaps: list[str] = field(default_factory=list)

    # Newly declared dependency names, as {field: [names]} from
    # deps.extract_dependency_changes.  Populated for the change summary
    # (B7); the D-series rules compute their own view.
    dependency_changes: dict[str, list[str]] = field(default_factory=dict)

    # B7: declared facts about what the diff did, whether or not a rule
    # matched.  Context, never findings: no severity, no points, and never
    # in triggered_rules.
    changes: list[str] = field(default_factory=list)

    # The verdict band, which is *not* always risk_level(final_score): a
    # cold database or an incomplete analysis downgrades it to
    # "Inconclusive".  Readers must use this, never re-derive it.
    risk: str = ""

    # How ``old_version`` (what pacman reports as installed) relates to
    # ``new_version`` (the pkgver the AUR PKGBUILD declares).  The two are
    # not always comparable - a VCS package computes its pkgver at build
    # time - so the outcome is stated rather than implied by an arrow.
    # One of analysis.version.COMPARISON_*; "" when nothing compared them.
    version_comparison: str = ""

    # True when the diff itself moved ``pkgver``, resolving variables the
    # recipe assigns (``pkgver=${_gtkver}``).  The verdict prefix and the
    # C001/C002 split read this, so they cannot disagree.
    pkgver_changed: bool = False
    # The resolved old/new ``pkgver`` behind ``pkgver_changed``, so every
    # surface that renders the move reads the same values instead of
    # recomputing them from the diff (which lacks the post-diff text the
    # resolution may need).
    pkgver_old: str = ""
    pkgver_new: str = ""

    # True when *any* scalar of the pacman version moved - pkgver, pkgrel or
    # epoch.  This is the integrity rules' and the verdict's definition of
    # "the version moved": a pkgrel rebuild is a declared new build, so a
    # checksum change beside it is C002, not C001, and the verdict must not
    # say "Version unchanged".  `pkgver_changed` stays pkgver-only for
    # display and for H087's separate "did upstream move?" question.
    version_moved: bool = False

    # Which clock produced the temporal findings.
    temporal_source: str = "unknown"

    # Which fetch/adapter produced the analysis: "git" | "corpus" | "diff"
    adapter: str = "git"

    score_breakdown: list[ScoreEntry] = field(default_factory=list)
    final_score: int = 0

    # IOC Federation baseline matches (v0.12.0).  Context only; no score.
    ioc_matches: list["IocMatch"] = field(default_factory=list)

    #: Analysed AUR dependencies, each a full analysis in its own right with
    #: its own score and band.  Never folded into this package's score: see
    #: `depth.py` and B1 on why depth must not move a number.
    dependencies: list = field(default_factory=list)
    #: The dependency walk stopped before the closure was exhausted, which
    #: drives the ``deps_not_scanned`` coverage gap.
    depth_truncated: bool = False
    depth_note: str = ""

    #: The dependency depth this run analysed to (``resolve_depth``'s
    #: answer).  Recorded so a later run can tell whether the stored
    #: analysis was produced at the depth it is being asked for.
    depth: int = 0

    #: True when this fact was served from the recorded analysis rather
    #: than freshly computed (#20).  ``cached_at`` is the recording's
    #: timestamp.  Both are runtime markers: a stored row always has
    #: ``cached=False``, because a cache hit inserts nothing.
    cached: bool = False
    cached_at: str = ""


def fact_to_dict(fact: PackageFact) -> dict:
    """Serialize a PackageFact to a plain dict."""
    from .config import config_fingerprint
    from .ioc_baseline import IocMatch

    def _ioc_match_dict(m: IocMatch) -> dict:
        return {
            "type": m.type,
            "value": m.value,
            "source": m.source,
            "confidence": m.confidence,
            "provenance": m.provenance,
            "campaign": m.campaign,
            "added": m.added,
            "surface": m.surface,
            "line": m.line,
            "expired": m.expired,
        }

    return {
        # B1: which instrument produced this.  Two operators comparing
        # results can tell at a glance whether they are running the same
        # rules, thresholds and overrides.
        "config_fingerprint": config_fingerprint(),
        "package_name": fact.package_name,
        "old_version": fact.old_version,
        "new_version": fact.new_version,
        "old_commit": fact.old_commit,
        "new_commit": fact.new_commit,
        "maintainer_changed": fact.maintainer_changed,
        "previous_maintainer": fact.previous_maintainer,
        "current_maintainer": fact.current_maintainer,
        "pkgver_changed": fact.pkgver_changed,
        "pkgver_old": fact.pkgver_old,
        "pkgver_new": fact.pkgver_new,
        "version_moved": fact.version_moved,
        "version_comparison": fact.version_comparison,
        "temporal_source": fact.temporal_source,
        "diff_summary": {
            "lines_added": fact.diff_summary.lines_added,
            "lines_removed": fact.diff_summary.lines_removed,
            "files_changed": fact.diff_summary.files_changed,
            "file_changes": fact.diff_summary.file_changes,
        },
        "source_changes": {
            "added_urls": fact.source_changes.added_urls,
            "removed_urls": fact.source_changes.removed_urls,
            "checksum_behavior": fact.source_changes.checksum_behavior,
        },
        "source_buckets": fact.source_buckets,
        "execution_changes": {
            "resolved_commands": fact.execution_changes.resolved_commands,
            "suspicious_patterns_detected": fact.execution_changes.suspicious_patterns_detected,
            "unresolved_patterns": fact.execution_changes.unresolved_patterns,
        },
        "novelty_context": {
            "url_first_seen_in_this_package": fact.novelty_context.url_first_seen_in_this_package,
            "url_first_seen_globally": fact.novelty_context.url_first_seen_globally,
            "url_first_seen_in_this_package_url": fact.novelty_context.url_first_seen_in_this_package_url,
            "url_first_seen_globally_url": fact.novelty_context.url_first_seen_globally_url,
            "maintainer_first_seen_for_this_package": fact.novelty_context.maintainer_first_seen_for_this_package,
        },
        "first_seen": fact.first_seen,
        "comparison_base": fact.comparison_base,
        "recent_commit_burst": fact.recent_commit_burst,
        "suppressed_rules": fact.suppressed_rules,
        "acknowledged_urls": fact.acknowledged_urls,
        "diff_truncated": fact.diff_truncated,
        "scan_truncated": fact.scan_truncated,
        "tree_analyzed": fact.tree_analyzed,
        "changes": fact.changes,
        "dependency_changes": {k: sorted(v) for k, v in fact.dependency_changes.items()},
        "coverage_gaps": fact.coverage_gaps,
        "carried_coverage_gaps": fact.carried_coverage_gaps,
        "unresolved_sources": fact.unresolved_sources,
        "unresolved_assignments": fact.unresolved_assignments,
        "partial_hunks": fact.partial_hunks,
        "partial_files": fact.partial_files,
        "change": fact.change,
        "resolution_coverage": fact.resolution_coverage,
        "risk": fact.risk,
        "score_breakdown": [
            {
                "rule_id": e.rule_id,
                "severity": e.severity,
                "weight": e.weight,
                "reason": e.reason,
                "params": e.params,
                "template": e.template,
                "evidence": e.evidence,
                "file": e.file,
                "line": e.line,
            }
            for e in fact.score_breakdown
        ],
        "final_score": fact.final_score,
        "adapter": fact.adapter,
        "ioc_matches": [_ioc_match_dict(m) for m in fact.ioc_matches],
        "dependencies": [
            d.to_dict() if hasattr(d, "to_dict") else dict(d)
            for d in fact.dependencies
        ],
        "depth_truncated": fact.depth_truncated,
        "depth_note": fact.depth_note,
        "depth": fact.depth,
        "cached": fact.cached,
        "cached_at": fact.cached_at,
    }


#: Keys a stored fact must carry before it can be served back (#20).  A row
#: written by an older version lacks the later additions, and serving a
#: partial reconstruction would report fields the analysis never computed -
#: so a short row is a cache miss, not an error.
_STORED_FACT_KEYS = (
    "config_fingerprint",
    "package_name",
    "old_version",
    "new_version",
    "old_commit",
    "new_commit",
    "maintainer_changed",
    "previous_maintainer",
    "current_maintainer",
    "pkgver_changed",
    "pkgver_old",
    "pkgver_new",
    "version_moved",
    "version_comparison",
    "temporal_source",
    "diff_summary",
    "source_changes",
    "source_buckets",
    "execution_changes",
    "novelty_context",
    "first_seen",
    "recent_commit_burst",
    "suppressed_rules",
    "acknowledged_urls",
    "diff_truncated",
    "scan_truncated",
    "tree_analyzed",
    "changes",
    "dependency_changes",
    "coverage_gaps",
    "carried_coverage_gaps",
    "unresolved_sources",
    "risk",
    "score_breakdown",
    "final_score",
    "adapter",
    "ioc_matches",
    "dependencies",
    "depth_truncated",
    "depth_note",
    "depth",
)


def fact_from_dict(data: dict) -> PackageFact | None:
    """Reconstruct a PackageFact from :func:`fact_to_dict` output.

    The round-trip used by the review cache (#20): when the recorded
    analysis describes exactly what this run was about to compute, the
    stored fact is served instead of re-running the pipeline.  ``None``
    when *data* is not a stored fact or predates a key the round-trip
    needs - an old row is a cache miss, not an error.
    """
    if not isinstance(data, dict):
        return None
    if any(key not in data for key in _STORED_FACT_KEYS):
        return None

    from .depth import DependencyReport
    from .ioc_baseline import IocMatch

    try:
        diff = data["diff_summary"]
        source = data["source_changes"]
        execution = data["execution_changes"]
        novelty = data["novelty_context"]
        fact = PackageFact(
            package_name=data["package_name"],
            old_version=data["old_version"],
            new_version=data["new_version"],
            old_commit=data["old_commit"],
            new_commit=data["new_commit"],
            maintainer_changed=data["maintainer_changed"],
            previous_maintainer=data["previous_maintainer"],
            current_maintainer=data["current_maintainer"],
            pkgver_changed=data["pkgver_changed"],
            pkgver_old=data["pkgver_old"],
            pkgver_new=data["pkgver_new"],
            version_moved=data["version_moved"],
            version_comparison=data["version_comparison"],
            temporal_source=data["temporal_source"],
            diff_summary=DiffSummary(
                lines_added=diff.get("lines_added", 0),
                lines_removed=diff.get("lines_removed", 0),
                files_changed=list(diff.get("files_changed", [])),
                file_changes=list(diff.get("file_changes", [])),
            ),
            source_changes=SourceChanges(
                added_urls=list(source.get("added_urls", [])),
                removed_urls=list(source.get("removed_urls", [])),
                checksum_behavior=source.get("checksum_behavior", ""),
            ),
            source_buckets=dict(data["source_buckets"]),
            execution_changes=ExecutionChanges(
                resolved_commands=list(execution.get("resolved_commands", [])),
                suspicious_patterns_detected=list(
                    execution.get("suspicious_patterns_detected", [])),
                unresolved_patterns=list(execution.get("unresolved_patterns", [])),
            ),
            novelty_context=NoveltyContext(
                url_first_seen_in_this_package=novelty.get(
                    "url_first_seen_in_this_package", False),
                url_first_seen_globally=novelty.get("url_first_seen_globally", False),
                url_first_seen_in_this_package_url=novelty.get(
                    "url_first_seen_in_this_package_url", ""),
                url_first_seen_globally_url=novelty.get(
                    "url_first_seen_globally_url", ""),
                maintainer_first_seen_for_this_package=novelty.get(
                    "maintainer_first_seen_for_this_package", False),
            ),
            first_seen=data["first_seen"],
            # `.get`: a fact stored before this field existed is still a
            # valid cache row and simply reports no comparison base.
            comparison_base=data.get("comparison_base", ""),
            recent_commit_burst=data["recent_commit_burst"],
            suppressed_rules=list(data["suppressed_rules"]),
            # `.get`, not `[...]`: a fact stored before this field existed
            # is still a valid cache row, and a missing ack list is empty.
            acknowledged_urls=list(data.get("acknowledged_urls", [])),
            diff_truncated=data["diff_truncated"],
            scan_truncated=data["scan_truncated"],
            tree_analyzed=data["tree_analyzed"],
            changes=list(data["changes"]),
            dependency_changes={
                k: list(v) for k, v in data["dependency_changes"].items()
            },
            coverage_gaps=list(data["coverage_gaps"]),
            carried_coverage_gaps=list(data["carried_coverage_gaps"]),
            unresolved_sources=list(data["unresolved_sources"]),
            # `.get`: rows written before the field existed still serve.
            unresolved_assignments=[
                dict(a) for a in data.get("unresolved_assignments", [])
            ],
            partial_hunks=list(data.get("partial_hunks", [])),
            partial_files=list(data.get("partial_files", [])),
            change=dict(data.get("change", {})),
            resolution_coverage=dict(data.get("resolution_coverage", {})),
            risk=data["risk"],
            score_breakdown=[
                ScoreEntry(
                    rule_id=e.get("rule_id", ""),
                    severity=e.get("severity", ""),
                    weight=e.get("weight", 0),
                    reason=e.get("reason", ""),
                    params=dict(e.get("params") or {}),
                    template=e.get("template", ""),
                    evidence=dict(e.get("evidence") or {}),
                    file=e.get("file", ""),
                    line=e.get("line"),
                )
                for e in data["score_breakdown"]
            ],
            final_score=data["final_score"],
            adapter=data["adapter"],
            ioc_matches=[
                IocMatch(
                    type=m.get("type", ""),
                    value=m.get("value", ""),
                    source=m.get("source", ""),
                    confidence=m.get("confidence", ""),
                    provenance=m.get("provenance", ""),
                    campaign=m.get("campaign", ""),
                    added=m.get("added", ""),
                    surface=m.get("surface", ""),
                    line=m.get("line"),
                    expired=m.get("expired", False),
                )
                for m in data["ioc_matches"]
            ],
            dependencies=[
                DependencyReport(
                    name=d.get("name", ""),
                    depth=d.get("depth", 0),
                    score=d.get("score", 0),
                    risk=d.get("risk", ""),
                    risk_label=d.get("risk_label", ""),
                    finding_count=d.get("finding_count", 0),
                    coverage_gaps=tuple(d.get("coverage_gaps", ())),
                    via=d.get("via", ""),
                    parent=d.get("parent", ""),
                    failed=d.get("failed", False),
                    error=d.get("error", ""),
                )
                for d in data["dependencies"]
            ],
            depth_truncated=data["depth_truncated"],
            depth_note=data["depth_note"],
            depth=data["depth"],
            cached=data.get("cached", False),
            cached_at=data.get("cached_at", ""),
        )
    except (AttributeError, TypeError):
        # A sub-structure that is not the shape fact_to_dict writes (a
        # hand-edited database, a partial write) is a cache miss too.
        return None
    return fact


def with_changes(fact: PackageFact, diff_text: str = "") -> PackageFact:
    """Populate ``fact.changes`` (B7) and return it.

    Called by every producer so the summary cannot be forgotten on one
    path, which is the failure mode ``every result declares its coverage``
    exists to catch on the coverage side.
    """
    from .changes import summarise

    fact.changes = summarise(fact, diff_text)
    return fact
