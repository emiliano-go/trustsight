"""``trustsight.api``: the supported programmatic surface.

Two things are pinned here.  The first is the shape of the surface itself,
because a public API whose names move is not one.  The second is that the
API says the same thing about a package as the CLI does: the band comes
from the analysis, coverage gaps travel with the verdict, and a package
that could not be analysed is reported rather than dropped.  Every one of
those is a property the CLI already had, and a second entry point that
quietly loses one of them is how a caller ends up gating a build on a
verdict nobody else would have given.
"""

import json
import subprocess
import sys

import pytest

import trustsight
import trustsight.db as db_module
from trustsight import api as api_module
from trustsight.api import (
    ClusterFinding,
    FLAG_THRESHOLD,
    PivotMatch,
    PivotResult,
    PackageNotFound,
    Report,
    ReviewResult,
    Status,
    TrustSight,
    TrustSightError,
    CycleReport,
)
from trustsight.db import init_db
from trustsight.schema import DiffSummary, PackageFact, ScoreEntry


@pytest.fixture
def ts(tmp_path, monkeypatch):
    """A TrustSight bound to an empty database in a tmpdir."""
    monkeypatch.setattr(db_module, "DATA_DIR", tmp_path)
    monkeypatch.setattr("trustsight.config.DATA_DIR", tmp_path)
    monkeypatch.setattr("trustsight.config.CONFIG_DIR", tmp_path / ".config")
    monkeypatch.setattr("trustsight.config.CACHE_DIR", tmp_path / ".cache")
    init_db()
    client = TrustSight(auto_import_seed=False)
    client._ready = True
    return client


def _fact(name="pkg", score=0, **kwargs):
    fields = dict(
        package_name=name,
        old_version="1.0",
        new_version="1.1",
        new_commit="abc123",
        diff_summary=DiffSummary(
            files_changed=["PKGBUILD"],
            file_changes=[{"path": "PKGBUILD", "status": "modified"}],
        ),
        final_score=score,
        risk="",
    )
    fields.update(kwargs)
    return PackageFact(**fields)


# --- the surface ------------------------------------------------------


def test_the_public_names_are_reachable_from_the_package_root():
    """`from trustsight import TrustSight` is the documented entry point."""
    for name in api_module.__all__:
        assert getattr(trustsight, name) is getattr(api_module, name)


def test_importing_the_package_does_not_import_the_cli():
    """A library caller must not pay for typer, rich or the analysis stack.

    The names are resolved on first access, so a process that imports
    trustsight for __version__ alone loads almost nothing.
    """
    code = (
        "import sys, trustsight; trustsight.__version__;"
        "assert 'typer' not in sys.modules, sorted(sys.modules)[:0];"
        "assert 'trustsight.analysis' not in sys.modules"
    )
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert out.returncode == 0, out.stderr


def test_importing_the_package_does_not_import_the_cli_renderer():
    code = (
        "import sys, trustsight; trustsight.__version__;"
        "assert 'trustsight.cli.review' not in sys.modules;"
        "assert 'trustsight.review' not in sys.modules"
    )
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert out.returncode == 0, out.stderr


def test_constructing_a_client_does_no_io(monkeypatch):
    """Construction must not touch the config directory or the database."""
    def boom(*a, **k):
        raise AssertionError("constructor performed I/O")

    monkeypatch.setattr("trustsight.config.ensure_default_configs", boom)
    monkeypatch.setattr("trustsight.db.init_db", boom)
    TrustSight()


@pytest.mark.parametrize("kwargs", [
    {"limit": -1},
    {"limit": 10_001},
    {"limit": True},
])
def test_review_rejects_invalid_limits_before_initializing(ts, kwargs):
    with pytest.raises(ValueError):
        ts.review(**kwargs)


@pytest.mark.parametrize("kwargs", [
    {"cycles": -1},
    {"cycles": True},
    {"interval": -1},
])
def test_watch_rejects_invalid_bounds_before_initializing(ts, kwargs):
    with pytest.raises(ValueError):
        ts.watch(**kwargs)


def test_review_rejects_an_oversized_explicit_package_list(ts):
    with pytest.raises(ValueError, match="at most"):
        ts.review(packages=["pkg"] * 10_001)


def test_history_and_packages_reject_invalid_limits(ts):
    with pytest.raises(ValueError):
        ts.history("pkg", limit=-1)
    with pytest.raises(ValueError):
        ts.packages(limit=10_001)


def test_api_rejects_oversized_text_and_names_before_initializing(ts, monkeypatch):
    monkeypatch.setattr(ts, "_ensure_ready", lambda: pytest.fail("initialized before validation"))
    with pytest.raises(ValueError, match="new_pkgbuild"):
        ts.analyze_text("pkg", "x" * (api_module.MAX_API_TEXT_BYTES + 1))
    with pytest.raises(ValueError, match="package"):
        ts.inspect("x" * (api_module.MAX_API_NAME_BYTES + 1), check_aur=False)
    with pytest.raises(ValueError, match="indicator"):
        ts.pivot("x" * (api_module.MAX_API_NAME_BYTES + 1))


def test_api_rejects_invalid_text_types(ts):
    with pytest.raises(ValueError, match="new_pkgbuild"):
        ts.analyze_text("pkg", None)
    with pytest.raises(ValueError, match="package name"):
        ts.review(packages=[None])
    with pytest.raises(ValueError, match="repos"):
        ts.review(repos=["repo"] * (api_module.MAX_API_REPOS + 1))
    with pytest.raises(ValueError, match="sequence"):
        ts.review(packages=(name for name in ("pkg",)))


def test_api_methods_return_dataclasses_and_not_rendered_text(ts, monkeypatch):
    from trustsight.full_aur.pipeline import CycleResult

    monkeypatch.setattr("trustsight.analysis.analyze_package", lambda name, **_kw: _fact(name))
    monkeypatch.setattr(
        "trustsight.review.discover_packages",
        lambda **kwargs: ([{"name": "alpha", "current_version": "1.0"}], 1),
    )
    monkeypatch.setattr(
        "trustsight.review.analyze_outdated_batch",
        lambda entries, cb=None, verbose=False, depth=None: [{
            "package": "alpha", "old_version": "1.0", "new_version": "1.1",
            "score": 0, "risk": "Low", "risk_label": "Low", "verdict": "ok",
            "findings": [], "file_changes": [], "changes": [], "coverage_gaps": [],
            "first_seen": False, "is_trivial": True,
        }],
    )
    monkeypatch.setattr(
        "trustsight.full_aur.pipeline.run_baseline_build",
        lambda **kw: CycleResult(added=1, changed=2, processed=3),
    )

    report = ts.inspect("alpha", check_aur=False)
    review = ts.review()
    cycle = ts.refresh_corpus()

    assert isinstance(report, Report)
    assert isinstance(review, ReviewResult)
    assert isinstance(cycle, CycleReport)
    assert isinstance(report.to_dict(), dict)
    assert isinstance(review.to_dict(), dict)
    assert isinstance(cycle.to_dict(), dict)


def test_api_methods_do_not_render_to_stdout_or_stderr(ts, monkeypatch, capsys):
    from trustsight.full_aur.pipeline import CycleResult

    monkeypatch.setattr("trustsight.analysis.analyze_package", lambda name, **_kw: _fact(name))
    monkeypatch.setattr(
        "trustsight.review.discover_packages",
        lambda **kwargs: ([{"name": "alpha", "current_version": "1.0"}], 1),
    )
    monkeypatch.setattr(
        "trustsight.review.analyze_outdated_batch",
        lambda entries, cb=None, verbose=False, depth=None: [{
            "package": "alpha", "old_version": "1.0", "new_version": "1.1",
            "score": 0, "risk": "Low", "risk_label": "Low", "verdict": "ok",
            "findings": [], "file_changes": [], "changes": [], "coverage_gaps": [],
            "first_seen": False, "is_trivial": True,
        }],
    )
    monkeypatch.setattr(
        "trustsight.full_aur.pipeline.run_baseline_build",
        lambda **kw: CycleResult(),
    )

    ts.inspect("alpha", check_aur=False)
    ts.review()
    next(ts.watch(cycles=1, sleep=lambda _: None))

    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""


# --- inspect ----------------------------------------------------------


def test_inspect_returns_a_report_built_from_the_analysis(ts, monkeypatch):
    fact = _fact("alpha", score=45, score_breakdown=[
        ScoreEntry(rule_id="R001", severity="CRITICAL", weight=40,
                   reason="curl piped to bash", file="PKGBUILD", line=12),
    ])
    monkeypatch.setattr("trustsight.analysis.analyze_package", lambda name, **_kw: fact)

    report = ts.inspect("alpha", check_aur=False)

    assert isinstance(report, Report)
    assert report.package == "alpha"
    assert report.score == 45
    assert report.new_version == "1.1"
    assert [f.rule_id for f in report.findings] == ["R001"]
    assert report.findings[0].severity == "CRITICAL"
    assert report.findings[0].line == 12
    assert report.file_changes[0].path == "PKGBUILD"


def test_inspect_raises_for_a_package_that_does_not_exist(ts, monkeypatch):
    monkeypatch.setattr("trustsight.discovery.get_aur_package_info", lambda names: {})
    monkeypatch.setattr("trustsight.db.get_package", lambda name: None)

    with pytest.raises(PackageNotFound) as exc:
        ts.inspect("no-such-package")
    assert exc.value.package == "no-such-package"


def test_inspect_accepts_a_package_known_only_locally(ts, monkeypatch):
    """A package dropped from the AUR is still analysable from history."""
    monkeypatch.setattr("trustsight.discovery.get_aur_package_info", lambda names: {})
    monkeypatch.setattr("trustsight.db.get_package", lambda name: {"id": 1})
    monkeypatch.setattr("trustsight.analysis.analyze_package", lambda name, **_kw: _fact("gone"))

    assert ts.inspect("gone").package == "gone"


def test_the_verdict_always_directs_the_reader_to_review(ts, monkeypatch):
    """B9: no result may read as permission to skip looking at the diff."""
    from trustsight.verdict import DIRECTIONS

    monkeypatch.setattr("trustsight.analysis.analyze_package", lambda name, **_kw: _fact("quiet"))
    report = ts.inspect("quiet", check_aur=False)
    assert any(report.verdict.endswith(d) for d in DIRECTIONS), report.verdict


def test_coverage_gaps_qualify_the_verdict_and_the_report(ts, monkeypatch):
    """An incomplete analysis must not present as a clean one."""
    fact = _fact("truncated", score=10,
                 diff_truncated=True,
                 coverage_gaps=["diff_truncated"],
                 risk="Inconclusive")
    monkeypatch.setattr("trustsight.analysis.analyze_package", lambda name, **_kw: fact)

    report = ts.inspect("truncated", check_aur=False)

    assert report.fully_vetted is False
    assert report.coverage_gaps == ("diff_truncated",)
    assert report.coverage_note
    assert report.verdict.startswith(report.coverage_note)


def test_the_band_is_the_analysis_band_not_one_derived_from_the_score(ts, monkeypatch):
    """`risk` must never be re-derived: risk_level(4) is "Low", but a run
    that could not read the change does not support "Low"."""
    from trustsight.scoring import risk_level

    fact = _fact("cold", score=4, coverage_gaps=["diff_truncated"], risk="Inconclusive")
    monkeypatch.setattr("trustsight.analysis.analyze_package", lambda name, **_kw: fact)

    report = ts.inspect("cold", check_aur=False)
    assert report.risk == "Inconclusive"
    assert report.risk != risk_level(report.score)


def test_analyze_text_preserves_the_engine_band_and_coverage(ts, monkeypatch):
    fact = _fact(
        "text-pkg",
        score=4,
        risk="Inconclusive",
        coverage_gaps=["unresolved_source"],
    )
    monkeypatch.setattr(
        "trustsight.full_aur.analyze.analyze_package_text",
        lambda **kwargs: fact,
    )

    report = ts.analyze_text("text-pkg", "pkgname=text-pkg\n")

    assert report.score == 4
    assert report.risk == "Inconclusive"
    assert report.coverage_gaps == ("unresolved_source",)
    assert report.fully_vetted is False
    assert report.risk_label.startswith("Inconclusive")
    assert report.verdict.startswith(report.coverage_note)


def test_review_result_and_cycle_report_serialize_to_json(ts):
    review = ReviewResult(
        reports=(Report(package="alpha", score=1, risk="Low"),),
        failures=(),
        total_installed=1,
    )
    cycle = CycleReport(
        added=1,
        changed=2,
        processed=3,
        cluster_findings=(ClusterFinding(
            rule_id="D001", name="shared-source", severity="HIGH", match="x",
            members=("a", "b"),
        ),),
        new_alerts=(("alpha", "D001"),),
    )
    pivot = PivotResult(
        indicator="evil.example",
        type="domain",
        listed=True,
        confidence="high",
        matches=(PivotMatch(package="alpha", surface="source", detail="x"),),
        sources=("corpus",),
    )
    status = Status(
        packages_tracked=1,
        total_analyses=2,
        effective_observations=3,
        seed_observations=4,
        dependency_corpus_loaded=True,
        config_dir=ts.config_dir,
        database_path=ts.database_path,
        config_fingerprint=ts.config_fingerprint,
    )

    assert json.loads(json.dumps(review.to_dict()))["total_installed"] == 1
    assert json.loads(json.dumps(cycle.to_dict()))["cluster_findings"][0]["rule_id"] == "D001"
    assert json.loads(json.dumps(pivot.to_dict()))["type"] == "domain"
    assert json.loads(json.dumps(status.to_dict()))["database_path"] == str(ts.database_path)


def test_review_api_preserves_engine_failures_and_serializes_them(ts, monkeypatch):
    _stub_review(monkeypatch, rows=[{
        "package": "broken",
        "old_version": "1.0",
        "new_version": "1.1",
        "score": None,
        "risk": "Error",
        "failed": True,
        "error": "malformed input",
        "error_type": "ValueError",
        "verdict": "Analysis failed (ValueError): this package was NOT vetted.",
    }], discovered=[{"name": "broken"}])

    result = ts.review()

    assert result.complete is False
    assert result.reports == ()
    assert result.failures[0].package == "broken"
    assert result.failures[0].error_type == "ValueError"
    payload = json.loads(json.dumps(result.to_dict()))
    assert payload["failures"][0]["package"] == "broken"


def test_suppressed_rules_are_reported_even_though_they_scored_nothing(ts, monkeypatch):
    fact = _fact("overridden", suppressed_rules=[
        {"rule_id": "R010", "severity": "LOW", "override_reason": "known good",
         "override_package": "overridden"},
    ])
    monkeypatch.setattr("trustsight.analysis.analyze_package", lambda name, **_kw: fact)

    report = ts.inspect("overridden", check_aur=False)
    assert [s.rule_id for s in report.suppressed] == ["R010"]
    assert report.suppressed[0].override_reason == "known good"


def test_flagged_matches_the_threshold_the_cli_counts(ts, monkeypatch):
    monkeypatch.setattr(
        "trustsight.analysis.analyze_package",
        lambda name, **_kw: _fact(name, score=FLAG_THRESHOLD),
    )
    assert ts.inspect("edge", check_aur=False).flagged is False

    monkeypatch.setattr(
        "trustsight.analysis.analyze_package",
        lambda name, **_kw: _fact(name, score=FLAG_THRESHOLD + 1),
    )
    assert ts.inspect("over", check_aur=False).flagged is True


def test_a_report_serialises_to_the_documented_json(ts, monkeypatch):
    monkeypatch.setattr("trustsight.analysis.analyze_package", lambda name, **_kw: _fact("json-pkg"))

    report = ts.inspect("json-pkg", check_aur=False)
    data = report.to_dict()

    # The CLI's naming, because this is the CLI's body (B11).
    assert data["package"] == "json-pkg"
    assert data["config_fingerprint"].startswith("sha256:")

    # The aggregate numbers are available on request, never volunteered.
    assert "score" not in data
    assert "risk" not in data
    assert "score_breakdown" not in data
    scored = report.to_dict(include_score=True)
    assert scored["score"] == report.score
    assert scored["risk"] == report.risk
    assert "score_breakdown" in report.to_dict(verbose=True)

    # Attribute access is the caller naming the field, so it always works.
    assert isinstance(report.score, int)

    # The serialised PackageFact is still reachable, under its own name and
    # in its own (storage) naming.
    assert report.raw["package_name"] == "json-pkg"
    assert "final_score" in report.raw

    json.loads(report.to_json())


def test_the_report_carries_the_config_fingerprint(ts, monkeypatch):
    """B1: two results are only comparable under the same instrument."""
    monkeypatch.setattr("trustsight.analysis.analyze_package", lambda name, **_kw: _fact("fp"))
    report = ts.inspect("fp", check_aur=False)
    assert report.config_fingerprint == ts.config_fingerprint


# --- review -----------------------------------------------------------


def _stub_review(monkeypatch, rows, discovered=None, total=3):
    monkeypatch.setattr(
        "trustsight.review.discover_packages",
        lambda **kwargs: (discovered if discovered is not None else [], total),
    )
    monkeypatch.setattr(
        "trustsight.review.analyze_outdated_batch",
        lambda entries, cb=None, verbose=False, depth=None: rows,
    )


def test_review_returns_one_report_per_analysed_package(ts, monkeypatch):
    _stub_review(monkeypatch, rows=[
        {"package": "alpha", "old_version": "1.0", "new_version": "1.1",
         "score": 30, "risk": "Medium", "risk_label": "Medium",
         "verdict": "Version bump.", "findings": [], "file_changes": [],
         "changes": [], "coverage_gaps": [], "first_seen": False,
         "is_trivial": False},
    ], discovered=[{"name": "alpha", "current_version": "1.0"}])

    result = ts.review()

    assert isinstance(result, ReviewResult)
    assert [r.package for r in result] == ["alpha"]
    assert len(result) == 1
    assert result.total_installed == 3
    assert result.complete is True


def test_a_package_that_could_not_be_analysed_is_a_failure_not_an_omission(ts, monkeypatch):
    """Dropping it would make an unvetted package look like a clean one."""
    _stub_review(monkeypatch, rows=[
        {"package": "fine", "old_version": "1.0", "new_version": "1.1",
         "score": 0, "risk": "Low", "verdict": "ok", "findings": [],
         "file_changes": [], "changes": [], "coverage_gaps": [],
         "first_seen": False, "is_trivial": True},
        {"package": "broken", "old_version": "1.0", "new_version": "1.1",
         "score": None, "risk": "Error", "failed": True,
         "error": "boom", "error_type": "RuntimeError",
         "verdict": "Analysis failed (RuntimeError): this package was NOT vetted."},
    ], discovered=[{"name": "fine"}, {"name": "broken"}])

    result = ts.review()

    assert [r.package for r in result.reports] == ["fine"]
    assert [f.package for f in result.failures] == ["broken"]
    assert result.failures[0].error_type == "RuntimeError"
    assert result.complete is False, "a review missing a package is not complete"


def test_review_reports_the_first_metadata_download_instead_of_nothing_to_do(ts, monkeypatch):
    """No prior snapshot means no delta, which is not the same as no changes."""
    monkeypatch.setattr("trustsight.review.discover_packages", lambda **kwargs: (None, 0))

    result = ts.review()

    assert result.metadata_bootstrapped is True
    assert result.reports == ()


def test_review_of_an_explicit_list_skips_discovery(ts, monkeypatch):
    def no_discovery(**kwargs):
        raise AssertionError("discovery ran for an explicit package list")

    monkeypatch.setattr("trustsight.review.discover_packages", no_discovery)
    seen = {}

    def batch(entries, cb=None, verbose=False, depth=None):
        seen["entries"] = entries
        return []

    monkeypatch.setattr("trustsight.review.analyze_outdated_batch", batch)

    ts.review(packages=["alpha", "beta"])
    assert [e["name"] for e in seen["entries"]] == ["alpha", "beta"]


def test_review_honours_the_limit(ts, monkeypatch):
    seen = {}

    def batch(entries, cb=None, verbose=False, depth=None):
        seen["count"] = len(entries)
        return []

    monkeypatch.setattr(
        "trustsight.review.discover_packages",
        lambda **kwargs: ([{"name": f"p{i}"} for i in range(10)], 10),
    )
    monkeypatch.setattr("trustsight.review.analyze_outdated_batch", batch)

    ts.review(limit=3)
    assert seen["count"] == 3


def test_review_reports_progress_through_the_hook(ts, monkeypatch):
    def batch(entries, cb=None, verbose=False, depth=None):
        cb(1, 2, "Fetching alpha")
        cb(-1, 0, "Reviewing packages...")
        return []

    monkeypatch.setattr("trustsight.review.discover_packages", lambda **kwargs: ([{"name": "a"}], 1))
    monkeypatch.setattr("trustsight.review.analyze_outdated_batch", batch)

    ticks = []
    ts.review(on_progress=ticks.append)

    assert [t.phase for t in ticks] == ["Fetching alpha", "Reviewing packages..."]
    assert ticks[0].indeterminate is False
    assert ticks[1].indeterminate is True


def test_review_flagged_selects_by_the_same_threshold(ts, monkeypatch):
    _stub_review(monkeypatch, rows=[
        {"package": "quiet", "score": FLAG_THRESHOLD, "risk": "Low",
         "verdict": "", "findings": [], "file_changes": [], "changes": [],
         "coverage_gaps": [], "first_seen": False, "is_trivial": True},
        {"package": "loud", "score": 80, "risk": "High",
         "verdict": "", "findings": [], "file_changes": [], "changes": [],
         "coverage_gaps": [], "first_seen": False, "is_trivial": False},
    ], discovered=[{"name": "quiet"}, {"name": "loud"}])

    assert [r.package for r in ts.review().flagged] == ["loud"]


def test_review_versions_come_from_the_review_not_the_fact(ts, monkeypatch):
    """`review` compares what pacman installed against what the AUR
    advertises; the fact holds the pair the *diff* was taken over."""
    _stub_review(monkeypatch, rows=[
        {"package": "alpha", "old_version": "0.9", "new_version": "2.0",
         "score": 0, "risk": "Low", "verdict": "", "findings": [],
         "file_changes": [], "changes": [], "coverage_gaps": [],
         "first_seen": False, "is_trivial": True,
         "_verbose_fact": _fact("alpha")},
    ], discovered=[{"name": "alpha"}])

    report = ts.review().reports[0]
    assert (report.old_version, report.new_version) == ("0.9", "2.0")
    assert report.to_dict()["old_version"] == "0.9"


# --- watch ------------------------------------------------------------


def test_watch_yields_one_report_per_cycle_and_stops_when_asked(ts, monkeypatch):
    from trustsight.full_aur.pipeline import CycleResult

    calls = []
    monkeypatch.setattr(
        "trustsight.full_aur.pipeline.run_baseline_build",
        lambda **kw: calls.append(kw) or CycleResult(added=2, changed=1, processed=3),
    )
    slept = []

    reports = list(ts.watch(interval=60, cycles=3, sleep=slept.append))

    assert len(reports) == 3
    assert len(calls) == 3
    assert reports[0].added == 2 and reports[0].processed == 3
    # no sleep after the final cycle
    assert slept == [60, 60]


def test_watch_clamps_a_too_short_interval(ts, monkeypatch):
    from trustsight.full_aur.pipeline import CycleResult

    monkeypatch.setattr(
        "trustsight.full_aur.pipeline.load_config",
        lambda: {"limits": {"watch_interval": 3600, "watch_min_interval": 60}},
    )
    monkeypatch.setattr(
        "trustsight.full_aur.pipeline.run_baseline_build",
        lambda **kw: CycleResult(),
    )
    slept = []
    list(ts.watch(interval=1, cycles=2, sleep=slept.append))
    assert slept == [60]


def test_watch_is_lazy_so_the_caller_can_stop_between_cycles(ts, monkeypatch):
    from trustsight.full_aur.pipeline import CycleResult

    calls = []
    monkeypatch.setattr(
        "trustsight.full_aur.pipeline.run_baseline_build",
        lambda **kw: calls.append(1) or CycleResult(),
    )
    stream = ts.watch(interval=60, sleep=lambda s: None)
    next(stream)
    stream.close()
    assert len(calls) == 1


def test_a_cycle_report_carries_the_new_alerts_and_the_cluster_members(ts, monkeypatch):
    from trustsight.full_aur.pipeline import CycleResult

    monkeypatch.setattr(
        "trustsight.full_aur.pipeline.run_baseline_build",
        lambda **kw: CycleResult(
            cluster_findings=[{
                "rule_id": "D001", "name": "shared-source", "severity": "HIGH",
                "match": "example.com", "params": {"members": ["a", "b"]},
            }],
            new_alerts=[("a", "D001")],
            flagged=[("a", 70)],
        ),
    )

    report = next(iter(ts.watch(cycles=1, sleep=lambda s: None)))

    assert report.new_alerts == (("a", "D001"),)
    assert report.cluster_findings[0].members == ("a", "b")
    assert report.flagged == (("a", 70),)
    assert json.loads(json.dumps(report.to_dict()))["cluster_findings"][0]["rule_id"] == "D001"


# --- stored state -----------------------------------------------------


def test_history_of_an_unanalysed_package_is_empty_not_an_error(ts):
    assert ts.history("never-seen") == []


def test_history_returns_the_stored_runs(ts):
    from trustsight.db import insert_analysis, upsert_package

    pkg_id = upsert_package("tracked", "1.0")
    insert_analysis(
        pkg_id, "1.0", "1.1", "aaa", "bbb", 30, "", "{}",
        [{"rule_id": "R001", "severity": "CRITICAL"}],
    )

    entries = ts.history("tracked", with_rules=True)
    assert len(entries) == 1
    assert entries[0].new_version == "1.1"
    assert entries[0].score == 30
    assert entries[0].triggered_rules[0]["rule_id"] == "R001"
    assert entries[0].to_dict()["score"] == 30


def test_packages_lists_what_the_database_tracks(ts):
    from trustsight.db import upsert_package

    upsert_package("alpha", "1.0")
    upsert_package("beta", "2.0")

    names = [p.name for p in ts.packages()]
    assert "alpha" in names and "beta" in names
    assert len(ts.packages(limit=1)) == 1


def test_status_describes_the_database(ts):
    from trustsight.db import upsert_package

    upsert_package("alpha", "1.0")
    status = ts.status()

    assert status.packages_tracked >= 1
    assert status.database_path == ts.database_path
    assert status.config_fingerprint.startswith("sha256:")
    assert isinstance(status.to_dict()["database_path"], str)


def test_forget_removes_a_tracked_package(ts):
    from trustsight.db import get_package_id, upsert_package

    upsert_package("doomed", "1.0")
    ts.forget("doomed")
    assert get_package_id("doomed") is None


def test_prune_refuses_to_act_on_an_empty_rpc_answer(ts, monkeypatch):
    """A network blip must not be read as "the whole AUR is gone"."""
    from trustsight.db import upsert_package

    upsert_package("alpha", "1.0")
    monkeypatch.setattr("trustsight.discovery.get_aur_package_info", lambda names: {})

    with pytest.raises(TrustSightError, match="cannot determine"):
        ts.prune()


def test_prune_dry_run_reports_without_deleting(ts, monkeypatch):
    from trustsight.db import get_package_id, upsert_package

    upsert_package("alpha", "1.0")
    upsert_package("gone", "1.0")
    monkeypatch.setattr(
        "trustsight.discovery.get_aur_package_info", lambda names: {"alpha": {}}
    )

    assert list(ts.prune(dry_run=True)) == ["gone"]
    assert get_package_id("gone") is not None


# --- pivot ------------------------------------------------------------


def test_pivot_maps_the_corpus_answer(ts, monkeypatch):
    monkeypatch.setattr("trustsight.full_aur.pivot.pivot", lambda value, type=None: {
        "indicator": "evil.example", "type": "domain", "listed": True,
        "confidence": "high", "sources": ["corpus"],
        "matches": [{"package": "alpha", "surface": "source", "detail": "https://evil.example/x"}],
    })

    result = ts.pivot("evil.example")

    assert result.type == "domain"
    assert result.searched is True
    assert result.matches[0].package == "alpha"


def test_pivot_rejects_an_unknown_indicator_type(ts):
    with pytest.raises(TrustSightError, match="unknown indicator type"):
        ts.pivot("something", type="not-a-type")


def test_pivot_over_an_empty_corpus_says_nothing_was_searched(ts, monkeypatch):
    """An empty result over an empty corpus is not a clean bill of health."""
    monkeypatch.setattr("trustsight.full_aur.pivot.pivot", lambda value, type=None: {
        "indicator": "x", "type": "domain", "listed": False,
        "confidence": None, "sources": [], "matches": [],
    })
    assert ts.pivot("x").searched is False
