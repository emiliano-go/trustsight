from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from .ioc_baseline import IocMatch


@dataclass
class DiffSummary:
    lines_added: int = 0
    lines_removed: int = 0
    files_changed: list[str] = field(default_factory=list)
    file_changes: list[dict] = field(default_factory=list)
    """Each entry: {"path": str, "status": "added"|"removed"|"modified"}"""


@dataclass
class SourceChanges:
    added_urls: list[str] = field(default_factory=list)
    removed_urls: list[str] = field(default_factory=list)
    checksum_behavior: str = ""


@dataclass
class ExecutionChanges:
    resolved_commands: list[str] = field(default_factory=list)
    suspicious_patterns_detected: list[str] = field(default_factory=list)
    unresolved_patterns: list[str] = field(default_factory=list)


@dataclass
class TemporalContext:
    """Explicit temporal context for R065–R067 (and R083).

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
    url_first_seen_in_this_package: bool = False
    url_first_seen_globally: bool = False
    maintainer_first_seen_for_this_package: bool = False
    observation_count: int = 0


@dataclass
class ScoreEntry:
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
    suppressed_rules: list[dict] = field(default_factory=list)

    # True when the diff was larger than the configured cap and only its
    # first max_diff_bytes were examined.  The score then describes a
    # prefix, not the change, so it must not be read as a clean verdict:
    # padding a diff past the cap and appending the payload otherwise
    # turns a High into a Low.
    diff_truncated: bool = False

    recent_commit_burst: bool = False

    # True when the repository file manifest (git tree / snapshot tarball)
    # was inspected for R118-tree.  A corpus-path result analysed without
    # the snapshot must not read the same as one that saw the whole tree.
    tree_analyzed: bool = False

    # Everything this run could not look at, as coverage.GAPS values, plus
    # the source entries behind an UNRESOLVED_SOURCE gap.  A non-empty list
    # forbids a clean verdict: see coverage.fail_closed.
    coverage_gaps: list[str] = field(default_factory=list)
    unresolved_sources: list[str] = field(default_factory=list)

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

    # Which clock produced the temporal findings.
    temporal_source: str = "unknown"

    # Which fetch/adapter produced the analysis: "git" | "corpus"
    adapter: str = "git"

    score_breakdown: list[ScoreEntry] = field(default_factory=list)
    final_score: int = 0

    # IOC Federation baseline matches (v0.12.0).  Context only; no score.
    ioc_matches: list["IocMatch"] = field(default_factory=list)


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
            "maintainer_first_seen_for_this_package": fact.novelty_context.maintainer_first_seen_for_this_package,
        },
        "first_seen": fact.first_seen,
        "recent_commit_burst": fact.recent_commit_burst,
        "suppressed_rules": fact.suppressed_rules,
        "diff_truncated": fact.diff_truncated,
        "tree_analyzed": fact.tree_analyzed,
        "changes": fact.changes,
        "dependency_changes": {k: sorted(v) for k, v in fact.dependency_changes.items()},
        "coverage_gaps": fact.coverage_gaps,
        "unresolved_sources": fact.unresolved_sources,
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
    }


def with_changes(fact: PackageFact, diff_text: str = "") -> PackageFact:
    """Populate ``fact.changes`` (B7) and return it.

    Called by every producer so the summary cannot be forgotten on one
    path, which is the failure mode ``every result declares its coverage``
    exists to catch on the coverage side.
    """
    from .changes import summarise

    fact.changes = summarise(fact, diff_text)
    return fact
