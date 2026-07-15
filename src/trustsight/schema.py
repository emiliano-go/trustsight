from dataclasses import dataclass, field


@dataclass
class DiffSummary:
    lines_added: int = 0
    lines_removed: int = 0
    files_changed: list[str] = field(default_factory=list)


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
class NoveltyContext:
    url_first_seen_in_this_package: bool = False
    url_first_seen_globally: bool = False
    maintainer_first_seen_for_this_package: bool = False


@dataclass
class ScoreEntry:
    rule_id: str = ""
    severity: str = ""
    weight: int = 0
    reason: str = ""


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

    score_breakdown: list[ScoreEntry] = field(default_factory=list)
    final_score: int = 0


def fact_to_dict(fact: PackageFact) -> dict:
    return {
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
        "score_breakdown": [
            {
                "rule_id": e.rule_id,
                "severity": e.severity,
                "weight": e.weight,
                "reason": e.reason,
            }
            for e in fact.score_breakdown
        ],
        "final_score": fact.final_score,
    }
