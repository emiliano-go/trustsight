"""Regression tests for v0.16.2 fixes.

Covers:
- issue #19: a coverage gap whose root cause the previous recorded analysis
  already carried is reported as carried ("unchanged since the previous
  review"), not as a shortfall the current diff introduced
- issue #20: `review` serves the recorded analysis when the AUR HEAD, both
  versions, the dependency depth and the ruleset are all unchanged, instead
  of re-running the pipeline on every nightly run
"""

import contextlib
import io


_RECIPE_1 = (
    "pkgname=demo\n"
    "pkgver=1.0\n"
    "pkgrel=1\n"
    "source=(\"https://example.invalid/demo-1.0.tar.gz\")\n"
    "sha256sums=('abc123')\n"
)
_RECIPE_2 = _RECIPE_1.replace("pkgver=1.0", "pkgver=1.0.1").replace(
    "demo-1.0.tar.gz", "demo-1.0.1.tar.gz")
# Adds an AUR dependency the walk cannot analyse (the metadata answer is
# empty offline), so the run gains the deps_not_scanned gap.
_RECIPE_3 = _RECIPE_2 + "depends=('demo-aur-lib')\n"


def _commit(repo, text):
    import pygit2

    sig = pygit2.Signature("T Maintainer", "t@example.invalid")
    builder = repo.TreeBuilder()
    builder.insert("PKGBUILD", repo.create_blob(text), pygit2.GIT_FILEMODE_BLOB)
    parents = [repo.head.target] if not repo.is_empty else []
    return str(repo.create_commit("refs/heads/master", sig, sig, "c",
                                  builder.write(), parents))


def _repo(tmp_path, recipes):
    import pygit2

    repo = pygit2.init_repository(str(tmp_path / "repo"), bare=True)
    head = ""
    for text in recipes:
        head = _commit(repo, text)
    return repo, head


def _render_plain(fact) -> str:
    from trustsight.cli.inspect import _inspect_plain

    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        _inspect_plain(fact)
    return buffer.getvalue()


def _render_rich(fact) -> str:
    from rich.console import Console

    import trustsight.cli.display as display
    from trustsight.cli.inspect import _inspect_rich

    buffer = io.StringIO()
    saved = display._console
    display._console = Console(file=buffer, force_terminal=False, width=240)
    try:
        _inspect_rich(fact)
    finally:
        display._console = saved
    return buffer.getvalue()


# ---------------------------------------------------------------------------
# Issue #19: coverage-gap provenance
# ---------------------------------------------------------------------------


def test_a_gap_unchanged_since_the_previous_review_is_marked_carried(isolated, monkeypatch):
    """Reviewed twice with the same shortfall, the second report must say the
    gap is unchanged rather than read as introduced by this diff."""
    import trustsight.analysis.pipeline as pipeline
    from trustsight.reporting import evaluate_fact, report_body

    repo, _head = _repo(isolated, [_RECIPE_1, _RECIPE_2])
    monkeypatch.setattr(pipeline, "clone_or_fetch", lambda name, mtime=None: repo)
    # Force the same structural gap on every run: no readable file manifest.
    monkeypatch.setattr(pipeline, "_collect_tree_files", lambda repo, commit: ([], False))

    first = pipeline.analyze_package("demo", installed_version="1.0-1", record=True)
    assert "tree_not_analyzed" in first.coverage_gaps
    assert first.carried_coverage_gaps == [], "a first recording has nothing to carry"

    second = pipeline.analyze_package("demo", installed_version="1.0-1", record=True)
    assert "tree_not_analyzed" in second.coverage_gaps, "still a gap: it fails closed"
    assert second.carried_coverage_gaps == ["tree_not_analyzed"]

    body = report_body(evaluate_fact(second))
    assert body["coverage_gaps"] == ["tree_not_analyzed"]
    assert body["coverage_gaps_carried"] == ["tree_not_analyzed"]
    assert "unchanged since the previous review" in body["verdict"]


def test_the_carried_marker_reaches_both_inspect_renderers(isolated, monkeypatch):
    import trustsight.analysis.pipeline as pipeline

    repo, _head = _repo(isolated, [_RECIPE_1, _RECIPE_2])
    monkeypatch.setattr(pipeline, "clone_or_fetch", lambda name, mtime=None: repo)
    monkeypatch.setattr(pipeline, "_collect_tree_files", lambda repo, commit: ([], False))

    pipeline.analyze_package("demo", installed_version="1.0-1", record=True)
    second = pipeline.analyze_package("demo", installed_version="1.0-1", record=True)

    marker = "(unchanged since the previous review)"
    assert marker in _render_plain(second)
    assert marker in _render_rich(second)


def test_a_new_gap_is_not_marked_carried(isolated, monkeypatch):
    """Only the gap with the same root cause as last time is carried; a gap
    this diff introduced is reported as new."""
    import trustsight.analysis.pipeline as pipeline

    repo, _head = _repo(isolated, [_RECIPE_1, _RECIPE_2])
    monkeypatch.setattr(pipeline, "clone_or_fetch", lambda name, mtime=None: repo)
    monkeypatch.setattr(pipeline, "_collect_tree_files", lambda repo, commit: ([], False))

    pipeline.analyze_package("demo", installed_version="1.0-1", record=True)

    _commit(repo, _RECIPE_3)
    second = pipeline.analyze_package(
        "demo", installed_version="1.0-1", record=True, allow_cached=True)
    assert second.cached is False, "a moved HEAD must not be served from the cache"
    assert "deps_not_scanned" in second.coverage_gaps
    assert second.carried_coverage_gaps == ["tree_not_analyzed"]


def test_explicit_old_commit_and_full_recipe_runs_get_provenance(isolated, monkeypatch):
    """The previous-analysis row is only fetched on the incremental path, so
    runs that set the base themselves used to skip provenance entirely."""
    import trustsight.analysis.pipeline as pipeline

    repo, _head = _repo(isolated, [_RECIPE_1, _RECIPE_2])
    monkeypatch.setattr(pipeline, "clone_or_fetch", lambda name, mtime=None: repo)
    monkeypatch.setattr(pipeline, "_collect_tree_files", lambda repo, commit: ([], False))

    pipeline.analyze_package("demo", installed_version="1.0-1", record=True)

    explicit = pipeline.analyze_package(
        "demo", old_commit=_first_commit(repo), installed_version="1.0-1")
    assert explicit.carried_coverage_gaps == ["tree_not_analyzed"]

    full = pipeline.analyze_package("demo", full_recipe=True, installed_version="1.0-1")
    assert "tree_not_analyzed" in full.coverage_gaps
    assert full.carried_coverage_gaps == ["tree_not_analyzed"]


def _first_commit(repo) -> str:
    import pygit2

    commits = list(repo.walk(repo.head.target, pygit2.GIT_SORT_TIME))
    return str(commits[-1].id)


def test_describe_marks_only_the_carried_gaps():
    from trustsight.coverage import DIFF_TRUNCATED, SCAN_TRUNCATED, describe

    note = describe([DIFF_TRUNCATED, SCAN_TRUNCATED], carried={DIFF_TRUNCATED})
    assert note.count("unchanged since the previous review") == 1
    assert describe([SCAN_TRUNCATED], carried={DIFF_TRUNCATED}) == describe([SCAN_TRUNCATED])
    assert describe([], carried={DIFF_TRUNCATED}) == ""


# ---------------------------------------------------------------------------
# Issue #20: review serves the recorded analysis when nothing it read changed
# ---------------------------------------------------------------------------


def _analysis_row_count() -> int:
    from trustsight.db import get_connection

    with get_connection() as conn:
        return conn.execute("SELECT COUNT(*) AS c FROM analysis_history").fetchone()["c"]


def test_a_review_rerun_reuses_the_recorded_analysis(isolated, monkeypatch):
    """Run 2 at the same HEAD must not diff, tokenize, or write history."""
    import trustsight.analysis.pipeline as pipeline

    repo, _head = _repo(isolated, [_RECIPE_1, _RECIPE_2])
    monkeypatch.setattr(pipeline, "clone_or_fetch", lambda name, mtime=None: repo)

    first = pipeline.analyze_package("demo", installed_version="1.0-1", record=True)
    assert first.cached is False
    rows_after_first = _analysis_row_count()

    real_diff = pipeline.generate_diff_bounded
    real_tokenize = pipeline.tokenize_and_resolve_indexed

    def _boom(*args, **kwargs):
        raise AssertionError("a cached run must not diff or tokenize")

    monkeypatch.setattr(pipeline, "generate_diff_bounded", _boom)
    monkeypatch.setattr(pipeline, "tokenize_and_resolve_indexed", _boom)

    second = pipeline.analyze_package(
        "demo", installed_version="1.0-1", record=True, allow_cached=True)
    assert second.cached is True
    assert second.cached_at
    assert _analysis_row_count() == rows_after_first, "a cache hit inserts no row"
    # The served fact is the recorded analysis, not a thinner copy of it.
    assert second.final_score == first.final_score
    assert second.risk == first.risk
    assert second.coverage_gaps == first.coverage_gaps
    assert second.changes == first.changes
    assert second.new_commit == first.new_commit

    # inspect and the API keep the default: no cached facts, ever.
    monkeypatch.setattr(pipeline, "generate_diff_bounded", real_diff)
    monkeypatch.setattr(pipeline, "tokenize_and_resolve_indexed", real_tokenize)
    third = pipeline.analyze_package("demo", installed_version="1.0-1", record=True)
    assert third.cached is False


def test_a_depth_change_defeats_the_cache(isolated, monkeypatch):
    """A run asked for a different dependency depth than the recording must
    re-analyse: the stored fact only covers the depth it was made at."""
    import trustsight.analysis.pipeline as pipeline

    repo, _head = _repo(isolated, [_RECIPE_1, _RECIPE_2])
    monkeypatch.setattr(pipeline, "clone_or_fetch", lambda name, mtime=None: repo)

    pipeline.analyze_package("demo", installed_version="1.0-1", record=True)

    called = []
    real_diff = pipeline.generate_diff_bounded
    monkeypatch.setattr(
        pipeline, "generate_diff_bounded",
        lambda *a, **k: (called.append(True), real_diff(*a, **k))[1])

    second = pipeline.analyze_package(
        "demo", installed_version="1.0-1", depth=0, record=True, allow_cached=True)
    assert second.cached is False
    assert called, "a depth mismatch must fall through to a fresh analysis"


def test_a_ruleset_change_defeats_the_cache(isolated, monkeypatch):
    """The fingerprint covers rules, weights and overrides: a changed
    instrument must not answer with the old instrument's analysis."""
    import trustsight.analysis.pipeline as pipeline

    repo, _head = _repo(isolated, [_RECIPE_1, _RECIPE_2])
    monkeypatch.setattr(pipeline, "clone_or_fetch", lambda name, mtime=None: repo)

    pipeline.analyze_package("demo", installed_version="1.0-1", record=True)
    monkeypatch.setattr(pipeline, "config_fingerprint", lambda: "sha256:changed")

    second = pipeline.analyze_package(
        "demo", installed_version="1.0-1", record=True, allow_cached=True)
    assert second.cached is False


def test_a_version_drift_defeats_the_cache(isolated, monkeypatch):
    """The recording is keyed by the version pair it compared."""
    import trustsight.analysis.pipeline as pipeline

    repo, _head = _repo(isolated, [_RECIPE_1, _RECIPE_2])
    monkeypatch.setattr(pipeline, "clone_or_fetch", lambda name, mtime=None: repo)

    pipeline.analyze_package("demo", installed_version="1.0-1", record=True)

    second = pipeline.analyze_package(
        "demo", installed_version="0.9-1", record=True, allow_cached=True)
    assert second.cached is False


def test_review_batch_asks_for_the_cache_and_reports_a_reuse(isolated, monkeypatch):
    """`analyze_outdated_batch` passes allow_cached=True, and a cached fact
    reads as reused rather than as 'No changes in the AUR'."""
    import trustsight.cli.review as review_cli
    import trustsight.review as review
    from trustsight.schema import PackageFact

    monkeypatch.setattr(review, "prefetch", lambda pkgs, cb=None: {})

    seen = {}
    fact = PackageFact(
        package_name="demo",
        old_version="1.0-1",
        new_version="1.0.1-1",
        old_commit="aaaa1111",
        new_commit="aaaa1111",
        cached=True,
        cached_at="2026-09-28 03:12:11",
    )

    def fake_analyze(name, **kw):
        seen.update(kw)
        return fact

    monkeypatch.setattr(review, "analyze_package", fake_analyze)

    results = review.analyze_outdated_batch(
        [{"name": "demo", "current_version": "1.0-1", "latest_version": "1.0.1-1"}])
    assert seen.get("allow_cached") is True

    row = results[0]
    assert row["cached"] is True
    assert row["cached_at"] == "2026-09-28 03:12:11"
    assert row["aur_note"] == (
        "Unchanged since last review; reusing the analysis from 2026-09-28."
    )

    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        review_cli._render_results_plain([row], 1, False, False, False, False)
    assert "reusing the analysis from 2026-09-28" in buffer.getvalue()


def test_cached_note():
    from trustsight.schema import PackageFact
    from trustsight.verdict import cached_note

    assert cached_note(PackageFact()) is None
    assert cached_note(PackageFact(
        cached=True, cached_at="2026-09-28 03:12:11")) == (
        "Unchanged since last review; reusing the analysis from 2026-09-28.")
    assert cached_note(PackageFact(cached=True)) == (
        "Unchanged since last review; reusing the recorded analysis.")
