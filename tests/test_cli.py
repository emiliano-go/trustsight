import shutil
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from trustsight import review as engine
from trustsight.cli import app
from trustsight.safe_text import clean

pytestmark = pytest.mark.skipif(
    not shutil.which("pacman"),
    reason="pacman not available (non-Arch system)",
)


def help_text(*args) -> str:
    """The help output for *args*, with the styling removed.

    Rich styles an option's leading hyphen as its own span, so the bytes
    of ``--repo`` are ``-\x1b[0m\x1b[1;36m-repo``: the literal substring
    is not in the output and a plain ``in`` check fails even though the
    flag is right there.  Which spans Rich chooses to split is a
    presentation detail that moves between versions, so asserting on the
    decorated bytes makes the test fail for reasons that have nothing to
    do with the CLI.  ``safe_text.clean`` is the project's own escape
    stripper; using it here means these tests exercise it too.
    """
    result = CliRunner().invoke(app, list(args))
    assert result.exit_code == 0, result.output
    return clean(result.output)


def test_cli_help():
    result = CliRunner().invoke(app, ["--help"])
    assert result.exit_code == 0


def test_cli_no_args_runs_help():
    result = CliRunner().invoke(app, [])
    assert result.exit_code == 2  # typer shows help and exits with code 2


def test_cli_review_help():
    result = CliRunner().invoke(app, ["review", "--help"])
    assert result.exit_code == 0


def test_cli_inspect_help():
    result = CliRunner().invoke(app, ["inspect", "--help"])
    assert result.exit_code == 0


def test_cli_history_help():
    result = CliRunner().invoke(app, ["history", "--help"])
    assert result.exit_code == 0


def test_cli_inspect_no_args():
    result = CliRunner().invoke(app, ["inspect"])
    assert result.exit_code != 0


def test_cli_history_no_args():
    result = CliRunner().invoke(app, ["history"])
    assert result.exit_code != 0


def test_cli_review_runs(tmp_path, monkeypatch):
    monkeypatch.setattr("trustsight.config.DATA_DIR", tmp_path)
    monkeypatch.setattr("trustsight.config.CONFIG_DIR", tmp_path / ".config")
    monkeypatch.setattr("trustsight.config.CACHE_DIR", tmp_path / ".cache")
    monkeypatch.setattr("trustsight.db.DATA_DIR", tmp_path)

    from trustsight.config import ensure_default_configs
    ensure_default_configs()

    with patch("trustsight.cli.review._discover_packages", return_value=([], 0)):
        result = CliRunner().invoke(app, ["review", "--limit", "5"])
        assert result.exit_code == 0


# --- Discovery flags ---

def test_cli_review_help_shows_flags():
    out = help_text("review", "--help")
    for flag in ("--repo", "--foreign", "--all-repos"):
        assert flag in out


@pytest.fixture
def review_env(tmp_path, monkeypatch):
    """Shared setup for discovery-flag tests: isolate config + mock discovery."""
    monkeypatch.setattr("trustsight.config.DATA_DIR", tmp_path)
    monkeypatch.setattr("trustsight.config.CONFIG_DIR", tmp_path / ".config")
    monkeypatch.setattr("trustsight.config.CACHE_DIR", tmp_path / ".cache")
    monkeypatch.setattr("trustsight.db.DATA_DIR", tmp_path)
    from trustsight.config import ensure_default_configs
    ensure_default_configs()
    return tmp_path


def test_cli_review_flag_repo(tmp_path, monkeypatch):
    monkeypatch.setattr("trustsight.config.DATA_DIR", tmp_path)
    monkeypatch.setattr("trustsight.config.CONFIG_DIR", tmp_path / ".config")
    monkeypatch.setattr("trustsight.config.CACHE_DIR", tmp_path / ".cache")
    monkeypatch.setattr("trustsight.db.DATA_DIR", tmp_path)
    from trustsight.config import ensure_default_configs
    ensure_default_configs()

    with patch("trustsight.cli.review._discover_packages") as mock_disc:
        mock_disc.return_value = ([], 0)
        result = CliRunner().invoke(app, ["review", "--repo", "aur"])
        assert result.exit_code == 0, result.stdout
        mock_disc.assert_called_once()
        _, kwargs = mock_disc.call_args
        assert kwargs == {
            "repos": ["aur"],
            "include_foreign": False,
            "all_repos_flag": False,
            "all_packages": False,
            "json_output": False,
            "_warn": mock_disc.call_args[1]["_warn"],
            "force_refresh": False,
        }


def test_cli_review_flag_foreign(tmp_path, monkeypatch):
    monkeypatch.setattr("trustsight.config.DATA_DIR", tmp_path)
    monkeypatch.setattr("trustsight.config.CONFIG_DIR", tmp_path / ".config")
    monkeypatch.setattr("trustsight.config.CACHE_DIR", tmp_path / ".cache")
    monkeypatch.setattr("trustsight.db.DATA_DIR", tmp_path)
    from trustsight.config import ensure_default_configs
    ensure_default_configs()

    with patch("trustsight.cli.review._discover_packages") as mock_disc:
        mock_disc.return_value = ([], 0)
        result = CliRunner().invoke(app, ["review", "--foreign"])
        assert result.exit_code == 0, result.stdout
        mock_disc.assert_called_once()
        _, kwargs = mock_disc.call_args
        assert kwargs["include_foreign"] is True
        assert kwargs["repos"] == []
        assert kwargs["all_repos_flag"] is False


def test_cli_review_flag_all_repos(tmp_path, monkeypatch):
    monkeypatch.setattr("trustsight.config.DATA_DIR", tmp_path)
    monkeypatch.setattr("trustsight.config.CONFIG_DIR", tmp_path / ".config")
    monkeypatch.setattr("trustsight.config.CACHE_DIR", tmp_path / ".cache")
    monkeypatch.setattr("trustsight.db.DATA_DIR", tmp_path)
    from trustsight.config import ensure_default_configs
    ensure_default_configs()

    with patch("trustsight.cli.review._discover_packages") as mock_disc:
        mock_disc.return_value = ([], 0)
        result = CliRunner().invoke(app, ["review", "--all-repos"])
        assert result.exit_code == 0, result.stdout
        mock_disc.assert_called_once()
        _, kwargs = mock_disc.call_args
        assert kwargs["all_repos_flag"] is True
        assert kwargs["repos"] == []
        assert kwargs["include_foreign"] is False


def test_cli_review_flag_repo_twice(tmp_path, monkeypatch):
    monkeypatch.setattr("trustsight.config.DATA_DIR", tmp_path)
    monkeypatch.setattr("trustsight.config.CONFIG_DIR", tmp_path / ".config")
    monkeypatch.setattr("trustsight.config.CACHE_DIR", tmp_path / ".cache")
    monkeypatch.setattr("trustsight.db.DATA_DIR", tmp_path)
    from trustsight.config import ensure_default_configs
    ensure_default_configs()

    with patch("trustsight.cli.review._discover_packages") as mock_disc:
        mock_disc.return_value = ([], 0)
        result = CliRunner().invoke(app, ["review", "--repo", "aur", "--repo", "testing"])
        assert result.exit_code == 0, result.stdout
        _, kwargs = mock_disc.call_args
        assert kwargs["repos"] == ["aur", "testing"]


def test_cli_review_flag_repo_plus_foreign(tmp_path, monkeypatch):
    monkeypatch.setattr("trustsight.config.DATA_DIR", tmp_path)
    monkeypatch.setattr("trustsight.config.CONFIG_DIR", tmp_path / ".config")
    monkeypatch.setattr("trustsight.config.CACHE_DIR", tmp_path / ".cache")
    monkeypatch.setattr("trustsight.db.DATA_DIR", tmp_path)
    from trustsight.config import ensure_default_configs
    ensure_default_configs()

    with patch("trustsight.cli.review._discover_packages") as mock_disc:
        mock_disc.return_value = ([], 0)
        result = CliRunner().invoke(app, ["review", "--repo", "aur", "--foreign"])
        assert result.exit_code == 0, result.stdout
        _, kwargs = mock_disc.call_args
        assert kwargs["repos"] == ["aur"]
        assert kwargs["include_foreign"] is True


def test_cli_review_flag_all_repos_plus_foreign(tmp_path, monkeypatch):
    monkeypatch.setattr("trustsight.config.DATA_DIR", tmp_path)
    monkeypatch.setattr("trustsight.config.CONFIG_DIR", tmp_path / ".config")
    monkeypatch.setattr("trustsight.config.CACHE_DIR", tmp_path / ".cache")
    monkeypatch.setattr("trustsight.db.DATA_DIR", tmp_path)
    from trustsight.config import ensure_default_configs
    ensure_default_configs()

    with patch("trustsight.cli.review._discover_packages") as mock_disc:
        mock_disc.return_value = ([], 0)
        result = CliRunner().invoke(app, ["review", "--all-repos", "--foreign"])
        assert result.exit_code == 0, result.stdout
        _, kwargs = mock_disc.call_args
        assert kwargs["all_repos_flag"] is True
        assert kwargs["include_foreign"] is True


# --- Config-driven discovery (no CLI flags) ---

def _make_config_with_discovery(tmp_path, monkeypatch, **discovery_overrides):
    monkeypatch.setattr("trustsight.config.DATA_DIR", tmp_path)
    monkeypatch.setattr("trustsight.config.CONFIG_DIR", tmp_path / ".config")
    monkeypatch.setattr("trustsight.config.CACHE_DIR", tmp_path / ".cache")
    monkeypatch.setattr("trustsight.db.DATA_DIR", tmp_path)

    cfg_dir = tmp_path / ".config"
    cfg_dir.mkdir(parents=True, exist_ok=True)
    cfg_path = cfg_dir / "config.toml"

    from trustsight.config import DEFAULT_CONFIG
    if cfg_path.exists():
        cfg_path.unlink()
    text = DEFAULT_CONFIG
    import re
    text = re.sub(r"\n\[discovery\].*?(?=\n\[|\Z)", "", text, flags=re.DOTALL)
    text = text.rstrip() + "\n"
    discovery_lines = [
        "[discovery]",
        f'default_repos = {discovery_overrides.get("default_repos", "[]")}',
        f'include_foreign = {str(discovery_overrides.get("include_foreign", False)).lower()}',
        f'all_repos = {str(discovery_overrides.get("all_repos", False)).lower()}',
    ]
    text += "\n".join(discovery_lines) + "\n"
    cfg_path.write_text(text)


def test_cli_review_config_default_repos(tmp_path, monkeypatch):
    _make_config_with_discovery(
        tmp_path, monkeypatch,
        default_repos='["aur"]',
        include_foreign=True,
    )

    with patch("trustsight.cli.review._discover_packages") as mock_disc:
        mock_disc.return_value = ([], 0)
        result = CliRunner().invoke(app, ["review"])
        assert result.exit_code == 0, result.stdout
        _, kwargs = mock_disc.call_args
        assert kwargs["repos"] == ["aur"]
        assert kwargs["include_foreign"] is True


def test_cli_review_config_cli_overrides(tmp_path, monkeypatch):
    _make_config_with_discovery(
        tmp_path, monkeypatch,
        default_repos='["aur"]',
        include_foreign=True,
    )

    with patch("trustsight.cli.review._discover_packages") as mock_disc:
        mock_disc.return_value = ([], 0)
        result = CliRunner().invoke(app, ["review", "--repo", "cli-repo"])
        assert result.exit_code == 0, result.stdout
        _, kwargs = mock_disc.call_args
        assert kwargs["repos"] == ["cli-repo"]
        assert kwargs["include_foreign"] is False


def test_cli_review_config_no_flags_fallback_foreign(tmp_path, monkeypatch):
    monkeypatch.setattr("trustsight.config.DATA_DIR", tmp_path)
    monkeypatch.setattr("trustsight.config.CONFIG_DIR", tmp_path / ".config")
    monkeypatch.setattr("trustsight.config.CACHE_DIR", tmp_path / ".cache")
    monkeypatch.setattr("trustsight.db.DATA_DIR", tmp_path)
    from trustsight.config import ensure_default_configs
    ensure_default_configs()

    with patch("trustsight.cli.review._discover_packages") as mock_disc:
        mock_disc.return_value = ([], 0)
        result = CliRunner().invoke(app, ["review"])
        assert result.exit_code == 0, result.stdout
        _, kwargs = mock_disc.call_args
        assert kwargs["include_foreign"] is True
        assert kwargs["repos"] == []
        assert kwargs["all_repos_flag"] is False


def test_cli_history_no_history(tmp_path, monkeypatch):
    monkeypatch.setattr("trustsight.config.DATA_DIR", tmp_path)
    monkeypatch.setattr("trustsight.config.CONFIG_DIR", tmp_path / ".config")
    monkeypatch.setattr("trustsight.config.CACHE_DIR", tmp_path / ".cache")
    monkeypatch.setattr("trustsight.db.DATA_DIR", tmp_path)

    from trustsight.config import ensure_default_configs
    ensure_default_configs()

    result = CliRunner().invoke(app, ["history", "nonexistentpkg"])
    assert "has not been analysed yet" in result.stdout


def test_cli_inspect_calls_analyze(tmp_path, monkeypatch):
    monkeypatch.setattr("trustsight.config.DATA_DIR", tmp_path)
    monkeypatch.setattr("trustsight.config.CONFIG_DIR", tmp_path / ".config")
    monkeypatch.setattr("trustsight.config.CACHE_DIR", tmp_path / ".cache")
    monkeypatch.setattr("trustsight.db.DATA_DIR", tmp_path)

    from trustsight.config import ensure_default_configs
    ensure_default_configs()
    from trustsight.db import init_db, get_connection
    init_db()
    # Insert a fake installed package so the --allow-uninstalled gate passes.
    with get_connection() as conn:
        conn.execute(
            "INSERT INTO packages (name, current_version) VALUES (?, ?)",
            ("testpkg", "1.0"),
        )
        conn.commit()

    with (
        patch("trustsight.cli.inspect.analyze_package") as mock_analyze,
        patch("trustsight.discovery.get_aur_package_info") as mock_aur,
    ):
        from trustsight.schema import PackageFact, DiffSummary
        mock_aur.return_value = {"testpkg": {"Version": "1.1"}}
        mock_analyze.return_value = PackageFact(
            package_name="testpkg",
            new_version="1.1",
            diff_summary=DiffSummary(files_changed=["PKGBUILD"]),
        )
        result = CliRunner().invoke(app, ["inspect", "testpkg"])
        assert result.exit_code == 0, result.stdout
        mock_analyze.assert_called_once_with("testpkg", depth=None)


# --- batch orchestration ---

def _fact(name, score=0):
    from trustsight.schema import DiffSummary, PackageFact
    return PackageFact(
        package_name=name,
        new_version="1.1",
        diff_summary=DiffSummary(files_changed=["PKGBUILD"]),
        final_score=score,
    )


def test_batch_prefetches_then_analyses_without_refetching(monkeypatch):
    """Every package is fetched once, up front, and not again per analysis.

    The fetch is the slow step, so the batch warms all the clones
    concurrently and hands each analysis the commit time it just saw;
    analyze_package then finds the clone current and skips the network.
    """
    fetched = []

    class FakeRepo:
        def __getitem__(self, _oid):
            return type("C", (), {"commit_time": 1700000000})()

    monkeypatch.setattr(
        "trustsight.fetcher.clone_or_fetch",
        lambda name, mtime=None: fetched.append((name, mtime)) or FakeRepo(),
    )
    monkeypatch.setattr("trustsight.fetcher.last_fetch_time", lambda repo: 1700000000)

    seen = {}

    def fake_analyze(name, **kwargs):
        seen[name] = kwargs
        return _fact(name)

    monkeypatch.setattr(engine, "analyze_package", fake_analyze)
    monkeypatch.setattr(engine, "verdict_for", lambda fact: "ok")

    pkgs = [
        {"name": "alpha", "current_version": "1.0", "latest_version": "1.1",
         "last_modified": 1699999999},
        {"name": "beta", "current_version": "2.0", "latest_version": "2.1"},
    ]
    results = engine.analyze_outdated_batch(pkgs)

    assert [r["package"] for r in results] == ["alpha", "beta"]
    assert sorted(name for name, _ in fetched) == ["alpha", "beta"]
    # the RPC's LastModified is passed through to the fetcher
    assert dict(fetched)["alpha"] == 1699999999
    # and each analysis receives the freshness hint plus the known version,
    # so it neither refetches nor forks pacman.  The hint is the AUR's own
    # timestamp, never a value derived from the upstream commit.
    assert seen["alpha"]["upstream_mtime"] == 1699999999
    assert seen["alpha"]["installed_version"] == "1.0"
    # beta had no LastModified, so it falls back to our own fetch time
    assert seen["beta"]["upstream_mtime"] == 1700000000


def test_prefetch_deadline_abandons_a_stalled_fetch(monkeypatch):
    """The deadline must return, not wait for the stalled fetch to finish.

    Shutting the pool down with wait=True made the deadline cosmetic: the
    warning printed, then the run blocked - with a frozen progress bar - for
    as long as the hung fetch took.  What the deadline drops is re-fetched
    during analysis.
    """
    import threading
    import time

    release = threading.Event()
    started = threading.Event()

    def fake_fetch(name, mtime=None):
        if name == "stalled":
            started.set()
            release.wait(30)
        return object()

    monkeypatch.setattr("trustsight.fetcher.clone_or_fetch", fake_fetch)
    monkeypatch.setattr("trustsight.fetcher.last_fetch_time", lambda repo: None)
    monkeypatch.setattr(
        engine, "load_config", lambda: {"limits": {"prefetch_timeout": 1}}
    )

    pkgs = [
        {"name": "stalled", "last_modified": 111},
        {"name": "quick", "last_modified": 222},
    ]
    phases = []
    began = time.monotonic()
    try:
        hints = engine.prefetch(
            pkgs, lambda cur, total, phase: phases.append((cur, phase))
        )
        elapsed = time.monotonic() - began
    finally:
        release.set()

    assert started.is_set(), "the stalled fetch never started"
    assert elapsed < 10, f"prefetch waited {elapsed:.1f}s on an abandoned fetch"
    assert hints == {"quick": 222}
    # the bar is repainted on the way out, so it never freezes mid-fetch
    assert phases[-1][0] == -1


def test_one_bad_package_does_not_end_the_run(monkeypatch):
    """A failure is contained: other packages are still analysed."""
    monkeypatch.setattr(engine, "prefetch", lambda pkgs, cb=None: {})
    monkeypatch.setattr(engine, "verdict_for", lambda fact: "ok")

    def fake_analyze(name, **kwargs):
        if name == "broken":
            raise RuntimeError("boom")
        return _fact(name)

    monkeypatch.setattr(engine, "analyze_package", fake_analyze)

    results = engine.analyze_outdated_batch([
        {"name": "broken", "current_version": "1.0"},
        {"name": "fine", "current_version": "1.0"},
    ])
    scored = [r for r in results if not r.get("failed")]
    assert [r["package"] for r in scored] == ["fine"]
    # the failure is surfaced, not swallowed
    assert [r["package"] for r in results if r.get("failed")] == ["broken"]


def test_a_failed_package_is_reported_not_dropped(monkeypatch):
    """A package that cannot be analysed must still appear in the review.

    Dropping it made an unvetted package indistinguishable from a clean
    one, so anything able to provoke a crash could keep itself out of the
    report entirely.
    """
    monkeypatch.setattr(engine, "prefetch", lambda pkgs, cb=None: {})
    monkeypatch.setattr(engine, "verdict_for", lambda fact: "ok")

    def fake_analyze(name, **kwargs):
        if name == "evil":
            raise RuntimeError("crafted crash")
        return _fact(name)

    monkeypatch.setattr(engine, "analyze_package", fake_analyze)

    results = engine.analyze_outdated_batch([
        {"name": "evil", "current_version": "1.0", "latest_version": "1.1"},
        {"name": "good", "current_version": "1.0", "latest_version": "1.1"},
    ])

    by_name = {r["package"]: r for r in results}
    assert set(by_name) == {"evil", "good"}
    evil = by_name["evil"]
    assert evil["failed"] is True
    assert evil["score"] is None, "a failed analysis must not carry a clean score"
    assert evil["risk"] == "Error"
    assert "NOT vetted" in evil["verdict"]


def test_failed_packages_render_without_crashing(monkeypatch, tmp_path):
    """The table must cope with the absent score of a failed package."""
    from trustsight import cli

    monkeypatch.setattr("trustsight.config.CONFIG_DIR", tmp_path / ".config")
    monkeypatch.setattr(
        cli.review, "_analyze_outdated_batch",
        lambda pkgs, cb=None, verbose=False, depth=None: [
            {"package": "ok", "score": 5, "risk": "Low", "verdict": "fine",
             "first_seen": False},
            {"package": "bad", "score": None, "risk": "Error", "failed": True,
             "verdict": "Analysis failed (RuntimeError): this package was NOT vetted.",
             "first_seen": False},
        ],
    )
    # exercises the rich renderer, which formats the score cell
    cli.review._run_analysis_loop([{"name": "ok"}, {"name": "bad"}], 10, False, False, False)


# --- Regression tests for metadata-dispatch bugs ---


@patch("trustsight.full_aur.metadata.load_snapshot")
@patch("trustsight.full_aur.metadata.fetch_metadata")
@patch("trustsight.full_aur.metadata.save_metadata")
def test_discover_packages_first_run_returns_none(
    mock_save, mock_fetch, mock_load
):
    """First metadata fetch returns (None, 0). ``_discover_packages``
    must not emit "No outdated" when there is no baseline yet."""
    from trustsight.cli.review import _discover_packages

    mock_load.return_value = None
    mock_fetch.return_value = {"some-pkg": {"Version": "2.0"}}

    result, total = _discover_packages(
        repos=[], include_foreign=True, all_repos_flag=False,
        all_packages=False, _warn=lambda msg: None,
    )
    assert result is None
    assert total == 0
    mock_fetch.assert_called_once()
    mock_save.assert_called_once()


@patch("trustsight.review.get_installed_packages")
@patch("trustsight.review.load_config")
@patch("trustsight.full_aur.metadata.load_snapshot")
@patch("trustsight.full_aur.metadata.fetch_metadata")
@patch("trustsight.full_aur.metadata.save_metadata")
def test_discover_packages_all_includes_snapshot_misses(
    mock_save, mock_fetch, mock_load, mock_config, mock_installed
):
    """--all includes packages not in the AUR snapshot by default."""
    import time

    from trustsight.cli.review import _discover_packages

    mock_load.return_value = ({"known-pkg": {"Version": "2.0"}}, int(time.time()))
    mock_config.return_value = {"discovery": {"show_unmatched": True}}
    mock_installed.return_value = [
        {"name": "known-pkg", "current_version": "1.0"},
        {"name": "unknown-pkg", "current_version": "1.0"},
    ]

    result, total = _discover_packages(
        repos=[], include_foreign=True, all_repos_flag=False,
        all_packages=True, _warn=lambda msg: None,
    )

    names = [p["name"] for p in result]
    assert "known-pkg" in names
    assert "unknown-pkg" in names
    assert total == 2


@patch("trustsight.review.get_installed_packages")
@patch("trustsight.review.load_config")
@patch("trustsight.full_aur.metadata.load_snapshot")
@patch("trustsight.full_aur.metadata.fetch_metadata")
@patch("trustsight.full_aur.metadata.save_metadata")
def test_discover_packages_all_skips_snapshot_misses_when_configured(
    mock_save, mock_fetch, mock_load, mock_config, mock_installed
):
    """With show_unmatched=false, --all skips packages not in the AUR snapshot."""
    import time

    from trustsight.cli.review import _discover_packages

    mock_load.return_value = ({"known-pkg": {"Version": "2.0"}}, int(time.time()))
    mock_config.return_value = {"discovery": {"show_unmatched": False}}
    mock_installed.return_value = [
        {"name": "known-pkg", "current_version": "1.0"},
        {"name": "unknown-pkg", "current_version": "1.0"},
    ]

    result, total = _discover_packages(
        repos=[], include_foreign=True, all_repos_flag=False,
        all_packages=True, _warn=lambda msg: None,
    )

    names = [p["name"] for p in result]
    assert "known-pkg" in names
    assert "unknown-pkg" not in names
    assert total == 2


# --- The limit, and what it leaves unread ---


def test_the_summary_names_the_packages_the_limit_skipped():
    """A review that stops early has a coverage gap, and says so.

    `--limit 5` against 40 outdated packages printed "5 package(s) needing
    update and reviewed": the count of packages *needing* an update was
    silently replaced by the count the limit allowed through, so the number
    was wrong in the direction that reads as reassuring, and the 35 skipped
    were never mentioned at all.
    """
    from trustsight.cli.review import _summary_caption

    caption = _summary_caption(
        reviewed=5, failed=0, flagged=0, total_installed=120,
        all_packages=False, outdated_total=40, show_score=False,
    )
    assert "35 more needed review and were NOT read" in caption
    assert "--limit 0" in caption

    whole = _summary_caption(
        reviewed=40, failed=0, flagged=0, total_installed=120,
        all_packages=False, outdated_total=40, show_score=False,
    )
    assert "NOT read" not in whole, "nothing was skipped, so say nothing"


def test_the_configured_review_limit_is_read(tmp_path, monkeypatch):
    """`[limits] default_review_limit` shipped set to 20 and did nothing.

    The flag's own default of 0 won on every invocation, so a user who set
    the documented key saw no change. It is honoured now, and the shipped
    value is 0 - a review that reads everything - because the alternative
    silently narrows what an existing install covers.
    """
    import tomllib

    from trustsight.config import DEFAULT_CONFIG

    assert tomllib.loads(DEFAULT_CONFIG)["limits"]["default_review_limit"] == 0

    seen = {}

    def _fake_loop(pkgs, limit, *a, **k):
        seen["limit"] = limit

    monkeypatch.setattr("trustsight.config.DATA_DIR", tmp_path)
    monkeypatch.setattr("trustsight.config.CONFIG_DIR", tmp_path / ".config")
    monkeypatch.setattr("trustsight.config.CACHE_DIR", tmp_path / ".cache")
    monkeypatch.setattr("trustsight.db.DATA_DIR", tmp_path)
    from trustsight.config import ensure_default_configs
    ensure_default_configs()

    with patch("trustsight.cli.review._discover_packages",
               return_value=([{"name": "p", "current_version": "1"}], 1)), \
         patch("trustsight.cli.review._run_analysis_loop", _fake_loop), \
         patch("trustsight.cli.review.load_config",
               return_value={"limits": {"default_review_limit": 7}}):
        result = CliRunner().invoke(app, ["review"])
    assert result.exit_code == 0, result.output
    assert seen["limit"] == 7, "the configured default was ignored"

    # An explicit `--limit 0` means all of them and must beat the config.
    with patch("trustsight.cli.review._discover_packages",
               return_value=([{"name": "p", "current_version": "1"}], 1)), \
         patch("trustsight.cli.review._run_analysis_loop", _fake_loop), \
         patch("trustsight.cli.review.load_config",
               return_value={"limits": {"default_review_limit": 7}}):
        CliRunner().invoke(app, ["review", "--limit", "0"])
    assert seen["limit"] == 0


# --- Snapshot staleness ---
#
# The snapshot was downloaded on first run and then reused forever, so a
# machine whose AUR packages had moved on was told "No outdated packages
# found" - the tool's one job, answered wrongly and quietly.  Reported from a
# user's machine running 0.13.1 with four pending AUR updates.

_HOUR = 3600


def _stale_discovery(mock_installed, mock_config, snapshot_time, ttl=60):
    """Wire the mocks these tests share: one installed package, one snapshot."""
    mock_config.return_value = {"discovery": {"metadata_ttl_minutes": ttl}}
    mock_installed.return_value = [{"name": "zen-browser-bin", "current_version": "1.21.10b-1"}]
    return ({"zen-browser-bin": {"Version": "1.21.10b-1"}}, snapshot_time)


@patch("trustsight.review.get_installed_packages")
@patch("trustsight.review.load_config")
@patch("trustsight.full_aur.metadata.load_snapshot")
@patch("trustsight.full_aur.metadata.fetch_metadata")
@patch("trustsight.full_aur.metadata.save_metadata")
def test_stale_snapshot_is_refreshed_before_comparison(
    mock_save, mock_fetch, mock_load, mock_config, mock_installed
):
    """A snapshot past the TTL is refetched, so the pending update is seen."""
    import time

    from trustsight.cli.review import _discover_packages

    mock_load.return_value = _stale_discovery(
        mock_installed, mock_config, int(time.time()) - 72 * _HOUR
    )
    mock_fetch.return_value = {"zen-browser-bin": {"Version": "1.21.14b-1"}}

    result, total = _discover_packages(
        repos=[], include_foreign=True, all_repos_flag=False,
        all_packages=False, _warn=lambda msg: None,
    )

    mock_fetch.assert_called_once()
    mock_save.assert_called_once()
    assert [p["name"] for p in result] == ["zen-browser-bin"]
    assert result[0]["latest_version"] == "1.21.14b-1"
    assert total == 1


@patch("trustsight.review.get_installed_packages")
@patch("trustsight.review.load_config")
@patch("trustsight.full_aur.metadata.load_snapshot")
@patch("trustsight.full_aur.metadata.fetch_metadata")
@patch("trustsight.full_aur.metadata.save_metadata")
def test_fresh_snapshot_is_not_refetched(
    mock_save, mock_fetch, mock_load, mock_config, mock_installed
):
    """Inside the TTL the snapshot is used as-is: no 60 MB download per review."""
    import time

    from trustsight.cli.review import _discover_packages

    mock_load.return_value = _stale_discovery(
        mock_installed, mock_config, int(time.time()) - 60
    )

    _discover_packages(
        repos=[], include_foreign=True, all_repos_flag=False,
        all_packages=False, _warn=lambda msg: None,
    )

    mock_fetch.assert_not_called()
    mock_save.assert_not_called()


@patch("trustsight.review.get_installed_packages")
@patch("trustsight.review.load_config")
@patch("trustsight.full_aur.metadata.load_snapshot")
@patch("trustsight.full_aur.metadata.fetch_metadata")
@patch("trustsight.full_aur.metadata.save_metadata")
def test_snapshot_without_a_timestamp_is_refreshed(
    mock_save, mock_fetch, mock_load, mock_config, mock_installed
):
    """Unknown age is stale: a snapshot written before the stamp existed."""
    from trustsight.cli.review import _discover_packages

    mock_load.return_value = _stale_discovery(mock_installed, mock_config, None)
    mock_fetch.return_value = {"zen-browser-bin": {"Version": "1.21.14b-1"}}

    _discover_packages(
        repos=[], include_foreign=True, all_repos_flag=False,
        all_packages=False, _warn=lambda msg: None,
    )

    mock_fetch.assert_called_once()


@patch("trustsight.review.get_installed_packages")
@patch("trustsight.review.load_config")
@patch("trustsight.full_aur.metadata.load_snapshot")
@patch("trustsight.full_aur.metadata.fetch_metadata")
@patch("trustsight.full_aur.metadata.save_metadata")
def test_refresh_failure_warns_instead_of_reporting_nothing(
    mock_save, mock_fetch, mock_load, mock_config, mock_installed
):
    """A failed refresh keeps the old snapshot and says the answer may be stale."""
    import time

    from trustsight.cli.review import _discover_packages

    mock_load.return_value = _stale_discovery(
        mock_installed, mock_config, int(time.time()) - 72 * _HOUR
    )
    mock_fetch.side_effect = RuntimeError("cannot reach the AUR metadata dump")
    warnings = []

    result, _ = _discover_packages(
        repos=[], include_foreign=True, all_repos_flag=False,
        all_packages=False, _warn=warnings.append,
    )

    assert result == []
    mock_save.assert_not_called()
    assert len(warnings) == 1
    assert "3 days old" in warnings[0]
    assert "will not be reported as outdated" in warnings[0]


@patch("trustsight.review.get_installed_packages")
@patch("trustsight.review.load_config")
@patch("trustsight.full_aur.metadata.load_snapshot")
@patch("trustsight.full_aur.metadata.fetch_metadata")
@patch("trustsight.full_aur.metadata.save_metadata")
def test_empty_refresh_keeps_the_previous_snapshot(
    mock_save, mock_fetch, mock_load, mock_config, mock_installed
):
    """An empty dump must not overwrite a usable snapshot with nothing."""
    import time

    from trustsight.cli.review import _discover_packages

    mock_load.return_value = _stale_discovery(
        mock_installed, mock_config, int(time.time()) - 72 * _HOUR
    )
    mock_fetch.return_value = {}
    warnings = []

    _discover_packages(
        repos=[], include_foreign=True, all_repos_flag=False,
        all_packages=False, _warn=warnings.append,
    )

    mock_save.assert_not_called()
    assert any("keeping the snapshot" in w for w in warnings)


@patch("trustsight.review.get_installed_packages")
@patch("trustsight.review.load_config")
@patch("trustsight.full_aur.metadata.load_snapshot")
@patch("trustsight.full_aur.metadata.fetch_metadata")
@patch("trustsight.full_aur.metadata.save_metadata")
def test_ttl_of_zero_disables_the_refresh(
    mock_save, mock_fetch, mock_load, mock_config, mock_installed
):
    """The opt-out: an offline machine can pin the snapshot it has."""
    from trustsight.cli.review import _discover_packages

    mock_load.return_value = _stale_discovery(mock_installed, mock_config, None, ttl=0)

    _discover_packages(
        repos=[], include_foreign=True, all_repos_flag=False,
        all_packages=False, _warn=lambda msg: None,
    )

    mock_fetch.assert_not_called()


@patch("trustsight.cli.review._discover_packages")
@patch("trustsight.cli.display.console")
def test_review_first_run_skips_no_outdated_message(
    mock_console, mock_disc, tmp_path, monkeypatch
):
    """review() must not print 'No outdated packages found' on first metadata fetch."""
    monkeypatch.setattr("trustsight.config.DATA_DIR", tmp_path)
    monkeypatch.setattr("trustsight.config.CONFIG_DIR", tmp_path / ".config")
    monkeypatch.setattr("trustsight.config.CACHE_DIR", tmp_path / ".cache")
    monkeypatch.setattr("trustsight.db.DATA_DIR", tmp_path)
    from trustsight.config import ensure_default_configs
    ensure_default_configs()

    mock_disc.return_value = (None, 0)

    result = CliRunner().invoke(app, ["review", "--limit", "5"])
    assert result.exit_code == 0
    assert "No outdated" not in result.stdout


# --- _get_installed_packages ---


@patch("trustsight.discovery.get_installed_from_repo")
@patch("trustsight.discovery._repo_exists")
def test_get_installed_packages_warns_repo_not_exist(mock_exists, mock_repo):
    """Warning emitted when a named repo does not exist at all."""
    from trustsight.cli.review import _get_installed_packages

    mock_repo.return_value = []
    mock_exists.return_value = False

    warnings = []
    result = _get_installed_packages(
        repos=["nonexistent"], include_foreign=False,
        all_repos=False, all_packages=False,
        on_warn=lambda msg: warnings.append(msg),
    )
    assert len(warnings) == 1
    assert "does not exist" in warnings[0]
    assert result == []


@patch("trustsight.discovery.get_installed_from_repo")
@patch("trustsight.discovery._repo_exists")
def test_get_installed_packages_warns_repo_empty(mock_exists, mock_repo):
    """Warning emitted when a repo exists but nothing is installed from it."""
    from trustsight.cli.review import _get_installed_packages

    mock_repo.return_value = []
    mock_exists.return_value = True

    warnings = []
    result = _get_installed_packages(
        repos=["empty-repo"], include_foreign=False,
        all_repos=False, all_packages=False,
        on_warn=lambda msg: warnings.append(msg),
    )
    assert len(warnings) == 1
    assert "exists but no packages" in warnings[0]
    assert result == []


@patch("trustsight.discovery.get_installed_from_repo")
@patch("trustsight.discovery.get_installed_foreign")
@patch("trustsight.discovery._repo_exists")
def test_get_installed_packages_foreign_only(mock_exists, mock_foreign, mock_repo):
    """When no repos are specified, foreign packages are included by default."""
    from trustsight.cli.review import _get_installed_packages

    mock_repo.return_value = []
    mock_foreign.return_value = [("foreign-a", "1.0"), ("foreign-b", "2.0")]

    result = _get_installed_packages(
        repos=[], include_foreign=True,
        all_repos=False, all_packages=False,
    )
    assert len(result) == 2
    names = {p["name"] for p in result}
    assert names == {"foreign-a", "foreign-b"}


@patch("trustsight.discovery.get_installed_from_repo")
@patch("trustsight.discovery.get_installed_foreign")
@patch("trustsight.discovery._repo_exists")
def test_get_installed_packages_repo_plus_foreign(mock_exists, mock_foreign, mock_repo):
    """Repo packages and foreign packages both included when both flags are set."""
    from trustsight.cli.review import _get_installed_packages

    mock_repo.return_value = [("repo-pkg", "1.0")]
    mock_foreign.return_value = [("foreign-pkg", "2.0")]
    mock_exists.return_value = True

    result = _get_installed_packages(
        repos=["myrepo"], include_foreign=True,
        all_repos=False, all_packages=False,
        on_warn=lambda msg: None,
    )
    assert len(result) == 2
    names = {p["name"] for p in result}
    assert names == {"repo-pkg", "foreign-pkg"}


@patch("trustsight.discovery.get_installed_from_repo")
@patch("trustsight.discovery.get_installed_foreign")
@patch("trustsight.discovery.get_local_repos_from_pacman_conf")
@patch("trustsight.discovery._repo_exists")
def test_get_installed_packages_all_repos(
    mock_exists, mock_conf, mock_foreign, mock_installed_repo
):
    """all_repos=True scans every custom repo found in pacman.conf."""
    from trustsight.cli.review import _get_installed_packages

    mock_conf.return_value = ["custom-a", "custom-b"]
    mock_installed_repo.side_effect = [
        [("pkg-a", "1.0")],
        [("pkg-b", "2.0")],
    ]

    result = _get_installed_packages(
        repos=[], include_foreign=False,
        all_repos=True, all_packages=False,
    )
    assert len(result) == 2
    names = {p["name"] for p in result}
    assert names == {"pkg-a", "pkg-b"}
    assert mock_installed_repo.call_count == 2
    mock_installed_repo.assert_any_call("custom-a")
    mock_installed_repo.assert_any_call("custom-b")
    mock_foreign.assert_not_called()


@patch("trustsight.discovery.get_installed_from_repo")
@patch("trustsight.discovery.get_installed_foreign")
def test_get_installed_packages_deduplicates(mock_foreign, mock_repo):
    """Same package in repo and foreign lists appears only once."""
    from trustsight.cli.review import _get_installed_packages

    mock_repo.return_value = [("shared-pkg", "1.0")]
    mock_foreign.return_value = [("shared-pkg", "1.0")]

    result = _get_installed_packages(
        repos=["repo-x"], include_foreign=True,
        all_repos=False, all_packages=False,
        on_warn=lambda msg: None,
    )
    assert len(result) == 1
    assert result[0]["name"] == "shared-pkg"


# --- display_version contract ---

def test_display_version_plausible():
    from trustsight.cli.display import display_version
    assert display_version("1.2.3") == "1.2.3"
    assert display_version("2:1.0-1") == "2:1.0-1"
    assert display_version("20240101") == "20240101"


def test_display_version_raw_bash_is_unresolved():
    """Raw bash like ${_ver//...} must never be shown as a version."""
    from trustsight.cli.display import display_version
    assert display_version("${_ver//.${_ver//[0-9.]/}}") == "unresolved"


def test_display_version_none_is_em_dash():
    """None or empty string renders as an em-dash, never 'None' or '?'."""
    from trustsight.cli.display import display_version
    assert display_version(None) == "-"
    assert display_version("") == "-"


def test_display_version_spaces_are_unresolved():
    """A version string containing spaces is almost certainly unresolved."""
    from trustsight.cli.display import display_version
    assert display_version("1.0 beta") == "unresolved"


# --- full-aur --watch wiring ---


def test_full_aur_help_documents_watch():
    out = help_text("full-aur", "--help")
    for flag in ("--watch", "--interval", "--cycles"):
        assert flag in out


def test_full_aur_watch_invokes_the_loop(monkeypatch):
    # `full-aur` refuses to start when TRUSTSIGHT_OFFLINE is set, which the
    # suite sets for every test. What is asserted here is the argument
    # wiring, so the command has to be allowed to start; the loop it would
    # enter is stubbed out below and nothing reaches the network.
    monkeypatch.delenv("TRUSTSIGHT_OFFLINE", raising=False)
    seen = {}
    monkeypatch.setattr(
        "trustsight.full_aur.pipeline.run_watch",
        lambda **kwargs: seen.update(kwargs) or [],
    )
    result = CliRunner().invoke(
        app, ["full-aur", "--watch", "--interval", "120", "--cycles", "2"]
    )
    assert result.exit_code == 0, result.output
    assert seen == {"interval": 120, "cycles": 2, "json_output": False}


def test_full_aur_watch_rejects_export(monkeypatch):
    """--export/--sign describe one artifact; pairing them with a loop
    would silently overwrite it every cycle."""
    monkeypatch.setattr(
        "trustsight.full_aur.pipeline.run_watch", lambda **kwargs: []
    )
    result = CliRunner().invoke(
        app, ["full-aur", "--watch", "--export", "/tmp/baseline.tar.zst"]
    )
    assert result.exit_code == 2


# --- review --deps ---------------------------------------------------------


class _FakeMetadata:
    """A small AUR graph: two roots sharing one dependency, one level down."""

    GRAPH = {
        "app-a": ["libhelper", "libcommon"],
        "app-b": ["libhelper"],
        "libhelper": ["libdeep"],
        "libcommon": [],
        "libdeep": [],
    }

    def deps_of(self, name):
        return list(self.GRAPH.get(name, []))

    def is_aur(self, name):
        return name in self.GRAPH


def test_the_closure_records_every_dependent_not_just_the_first():
    """`walk_dependencies` attributes a shared dependency to one parent.

    Its `already_seen` is shared across roots so a dependency twenty
    packages need is analysed once, which is right for a per-package report
    and wrong for the reverse question `--deps` asks: *who* needs this. The
    closure walk keeps every edge.
    """
    from trustsight.depth import dependency_closure

    closure = dependency_closure(
        ["app-a", "app-b"], depth=2, metadata=_FakeMetadata())

    assert closure.names == ["libcommon", "libhelper", "libdeep"]
    assert closure.dependents["libhelper"] == ["app-a", "app-b"]
    assert closure.dependents["libdeep"] == ["libhelper"]
    assert closure.levels["libdeep"] == 2


def test_the_closure_honours_the_depth_it_was_given():
    from trustsight.depth import dependency_closure

    meta = _FakeMetadata()
    assert dependency_closure([], depth=1, metadata=meta).names == []
    assert dependency_closure(["app-a"], depth=0, metadata=meta).names == []
    assert dependency_closure(["app-a"], depth=1, metadata=meta).names == [
        "libcommon", "libhelper"]
    assert "libdeep" in dependency_closure(
        ["app-a"], depth=-1, metadata=meta).names


def test_a_root_is_not_reported_as_its_own_dependency():
    """`--deps` means the dependencies; the roots are the no-flag view."""
    from trustsight.depth import dependency_closure

    class SelfReferential(_FakeMetadata):
        GRAPH = {"app-a": ["app-b"], "app-b": ["app-a"]}

    closure = dependency_closure(
        ["app-a", "app-b"], depth=-1, metadata=SelfReferential())
    assert closure.names == []


def _deps_review(argv, batch):
    """Run `review` with discovery and analysis stubbed, return the output."""
    with patch("trustsight.cli.review._discover_packages",
               return_value=([
                   {"name": "app-a", "current_version": "1.0"},
                   {"name": "app-b", "current_version": "2.0"},
               ], 2)), \
         patch("trustsight.cli.review._analyze_outdated_batch", batch), \
         patch("trustsight.depth.default_metadata", return_value=_FakeMetadata()):
        return CliRunner().invoke(app, argv)


def _row_batch(pkgs, progress, verbose, depth=None):
    return [{
        "package": p["name"], "old_version": "1.0", "new_version": "1.1",
        "score": 0, "risk": "Low", "risk_label": "Low", "verdict": "ok",
        "findings": [], "changes": [], "first_seen": False,
        "is_trivial": True, "failed": False, "coverage_gaps": [],
        "dependencies": [], "file_changes": [],
    } for p in pkgs]


def test_deps_reviews_the_dependencies_and_names_what_requires_them():
    result = _deps_review(["review", "--deps", "--depth", "2", "--quiet"],
                          _row_batch)
    assert result.exit_code == 0, result.output
    out = result.output

    # The dependencies are the subject...
    for name in ("libhelper", "libcommon", "libdeep"):
        assert name in out, f"{name} was not reviewed"
    # ...the roots are not, because that is the no-flag view.
    assert "app-a" in out, "the dependent must be named"
    assert "Required by" in out
    assert "AUR dependencies reviewed" in out


def test_deps_carries_the_dependents_into_the_json_body():
    """A field on the terminal and not in the JSON is the difference in
    information B11 forbids."""
    import json as _json

    result = _deps_review(["review", "--deps", "--json", "--quiet"], _row_batch)
    assert result.exit_code == 0, result.output
    bodies = {b["package"]: b for b in _json.loads(result.output)}
    assert bodies["libhelper"]["required_by"] == ["app-a", "app-b"]
    assert bodies["libcommon"]["required_by"] == ["app-a"]


def test_an_ordinary_review_carries_an_empty_dependents_list():
    """The key is always present, so a consumer need not special-case it."""
    import json as _json

    result = _deps_review(["review", "--json", "--quiet"], _row_batch)
    bodies = _json.loads(result.output)
    assert all(b["required_by"] == [] for b in bodies)


def test_deps_with_no_dependencies_says_so():
    class Empty(_FakeMetadata):
        GRAPH = {"app-a": [], "app-b": []}

    with patch("trustsight.cli.review._discover_packages",
               return_value=([{"name": "app-a", "current_version": "1.0"}], 1)), \
         patch("trustsight.cli.review._analyze_outdated_batch", _row_batch), \
         patch("trustsight.depth.default_metadata", return_value=Empty()):
        result = CliRunner().invoke(app, ["review", "--deps", "--quiet"])
    assert result.exit_code == 0, result.output
    assert "No AUR dependencies found" in result.output


def test_the_deps_hint_appears_only_where_it_helps():
    """Advice about an empty set is noise, and so is advice you followed."""
    from trustsight.cli.review import _DEPS_HINT, _deps_hint

    with_deps = [{"package": "p", "dependencies": [{"name": "libhelper"}]}]
    assert _deps_hint(with_deps, deps_only=False) == _DEPS_HINT
    # Already there.
    assert _deps_hint(with_deps, deps_only=True) == ""
    # Nothing to point at.
    assert _deps_hint([{"package": "p", "dependencies": []}], deps_only=False) == ""
