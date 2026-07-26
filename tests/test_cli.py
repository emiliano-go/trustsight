import shutil
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from trustsight.cli import app

pytestmark = pytest.mark.skipif(
    not shutil.which("pacman"),
    reason="pacman not available (non-Arch system)",
)


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

    with patch("trustsight.discovery.discover_packages", return_value=[]):
        result = CliRunner().invoke(app, ["review", "--limit", "5"])
        assert result.exit_code == 0


# --- Discovery flags ---

def test_cli_review_help_shows_flags():
    result = CliRunner().invoke(app, ["review", "--help"])
    assert "--repo" in result.stdout
    assert "--foreign" in result.stdout
    assert "--all-repos" in result.stdout


def test_cli_review_flag_repo(tmp_path, monkeypatch):
    monkeypatch.setattr("trustsight.config.DATA_DIR", tmp_path)
    monkeypatch.setattr("trustsight.config.CONFIG_DIR", tmp_path / ".config")
    monkeypatch.setattr("trustsight.config.CACHE_DIR", tmp_path / ".cache")
    monkeypatch.setattr("trustsight.db.DATA_DIR", tmp_path)
    from trustsight.config import ensure_default_configs
    ensure_default_configs()

    with patch("trustsight.cli.discover_packages") as mock_disc:
        mock_disc.return_value = []
        result = CliRunner().invoke(app, ["review", "--repo", "aur"])
        assert result.exit_code == 0, result.stdout
        mock_disc.assert_called_once()
        kwargs = mock_disc.call_args[1]
        assert kwargs == {
            "repos": ["aur"],
            "include_foreign": False,
            "all_repos": False,
            "_warn_func": mock_disc.call_args[1]["_warn_func"],
        }


def test_cli_review_flag_foreign(tmp_path, monkeypatch):
    monkeypatch.setattr("trustsight.config.DATA_DIR", tmp_path)
    monkeypatch.setattr("trustsight.config.CONFIG_DIR", tmp_path / ".config")
    monkeypatch.setattr("trustsight.config.CACHE_DIR", tmp_path / ".cache")
    monkeypatch.setattr("trustsight.db.DATA_DIR", tmp_path)
    from trustsight.config import ensure_default_configs
    ensure_default_configs()

    with patch("trustsight.cli.discover_packages") as mock_disc:
        mock_disc.return_value = []
        result = CliRunner().invoke(app, ["review", "--foreign"])
        assert result.exit_code == 0, result.stdout
        mock_disc.assert_called_once()
        kwargs = mock_disc.call_args[1]
        assert kwargs["include_foreign"] is True
        assert kwargs["repos"] == []
        assert kwargs["all_repos"] is False


def test_cli_review_flag_all_repos(tmp_path, monkeypatch):
    monkeypatch.setattr("trustsight.config.DATA_DIR", tmp_path)
    monkeypatch.setattr("trustsight.config.CONFIG_DIR", tmp_path / ".config")
    monkeypatch.setattr("trustsight.config.CACHE_DIR", tmp_path / ".cache")
    monkeypatch.setattr("trustsight.db.DATA_DIR", tmp_path)
    from trustsight.config import ensure_default_configs
    ensure_default_configs()

    with patch("trustsight.cli.discover_packages") as mock_disc:
        mock_disc.return_value = []
        result = CliRunner().invoke(app, ["review", "--all-repos"])
        assert result.exit_code == 0, result.stdout
        mock_disc.assert_called_once()
        kwargs = mock_disc.call_args[1]
        assert kwargs["all_repos"] is True
        assert kwargs["repos"] == []
        assert kwargs["include_foreign"] is False


def test_cli_review_flag_repo_twice(tmp_path, monkeypatch):
    monkeypatch.setattr("trustsight.config.DATA_DIR", tmp_path)
    monkeypatch.setattr("trustsight.config.CONFIG_DIR", tmp_path / ".config")
    monkeypatch.setattr("trustsight.config.CACHE_DIR", tmp_path / ".cache")
    monkeypatch.setattr("trustsight.db.DATA_DIR", tmp_path)
    from trustsight.config import ensure_default_configs
    ensure_default_configs()

    with patch("trustsight.cli.discover_packages") as mock_disc:
        mock_disc.return_value = []
        result = CliRunner().invoke(app, ["review", "--repo", "aur", "--repo", "testing"])
        assert result.exit_code == 0, result.stdout
        kwargs = mock_disc.call_args[1]
        assert kwargs["repos"] == ["aur", "testing"]


def test_cli_review_flag_repo_plus_foreign(tmp_path, monkeypatch):
    monkeypatch.setattr("trustsight.config.DATA_DIR", tmp_path)
    monkeypatch.setattr("trustsight.config.CONFIG_DIR", tmp_path / ".config")
    monkeypatch.setattr("trustsight.config.CACHE_DIR", tmp_path / ".cache")
    monkeypatch.setattr("trustsight.db.DATA_DIR", tmp_path)
    from trustsight.config import ensure_default_configs
    ensure_default_configs()

    with patch("trustsight.cli.discover_packages") as mock_disc:
        mock_disc.return_value = []
        result = CliRunner().invoke(app, ["review", "--repo", "aur", "--foreign"])
        assert result.exit_code == 0, result.stdout
        kwargs = mock_disc.call_args[1]
        assert kwargs["repos"] == ["aur"]
        assert kwargs["include_foreign"] is True


def test_cli_review_flag_all_repos_plus_foreign(tmp_path, monkeypatch):
    monkeypatch.setattr("trustsight.config.DATA_DIR", tmp_path)
    monkeypatch.setattr("trustsight.config.CONFIG_DIR", tmp_path / ".config")
    monkeypatch.setattr("trustsight.config.CACHE_DIR", tmp_path / ".cache")
    monkeypatch.setattr("trustsight.db.DATA_DIR", tmp_path)
    from trustsight.config import ensure_default_configs
    ensure_default_configs()

    with patch("trustsight.cli.discover_packages") as mock_disc:
        mock_disc.return_value = []
        result = CliRunner().invoke(app, ["review", "--all-repos", "--foreign"])
        assert result.exit_code == 0, result.stdout
        kwargs = mock_disc.call_args[1]
        assert kwargs["all_repos"] is True
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

    with patch("trustsight.cli.discover_packages") as mock_disc:
        mock_disc.return_value = []
        result = CliRunner().invoke(app, ["review"])
        assert result.exit_code == 0, result.stdout
        kwargs = mock_disc.call_args[1]
        assert kwargs["repos"] == ["aur"]
        assert kwargs["include_foreign"] is True


def test_cli_review_config_cli_overrides(tmp_path, monkeypatch):
    _make_config_with_discovery(
        tmp_path, monkeypatch,
        default_repos='["aur"]',
        include_foreign=True,
    )

    with patch("trustsight.cli.discover_packages") as mock_disc:
        mock_disc.return_value = []
        result = CliRunner().invoke(app, ["review", "--repo", "cli-repo"])
        assert result.exit_code == 0, result.stdout
        kwargs = mock_disc.call_args[1]
        assert kwargs["repos"] == ["cli-repo"]
        assert kwargs["include_foreign"] is False


def test_cli_review_config_no_flags_fallback_foreign(tmp_path, monkeypatch):
    monkeypatch.setattr("trustsight.config.DATA_DIR", tmp_path)
    monkeypatch.setattr("trustsight.config.CONFIG_DIR", tmp_path / ".config")
    monkeypatch.setattr("trustsight.config.CACHE_DIR", tmp_path / ".cache")
    monkeypatch.setattr("trustsight.db.DATA_DIR", tmp_path)
    from trustsight.config import ensure_default_configs
    ensure_default_configs()

    with patch("trustsight.cli.discover_packages") as mock_disc:
        mock_disc.return_value = []
        result = CliRunner().invoke(app, ["review"])
        assert result.exit_code == 0, result.stdout
        kwargs = mock_disc.call_args[1]
        assert kwargs["include_foreign"] is True
        assert kwargs["repos"] == []
        assert kwargs["all_repos"] is False


def test_cli_history_no_history(tmp_path, monkeypatch):
    monkeypatch.setattr("trustsight.config.DATA_DIR", tmp_path)
    monkeypatch.setattr("trustsight.config.CONFIG_DIR", tmp_path / ".config")
    monkeypatch.setattr("trustsight.config.CACHE_DIR", tmp_path / ".cache")
    monkeypatch.setattr("trustsight.db.DATA_DIR", tmp_path)

    from trustsight.config import ensure_default_configs
    ensure_default_configs()

    result = CliRunner().invoke(app, ["history", "nonexistentpkg"])
    assert "not found" in result.stdout


def test_cli_inspect_calls_analyze(tmp_path, monkeypatch):
    monkeypatch.setattr("trustsight.config.DATA_DIR", tmp_path)
    monkeypatch.setattr("trustsight.config.CONFIG_DIR", tmp_path / ".config")
    monkeypatch.setattr("trustsight.config.CACHE_DIR", tmp_path / ".cache")
    monkeypatch.setattr("trustsight.db.DATA_DIR", tmp_path)

    from trustsight.config import ensure_default_configs
    ensure_default_configs()

    with patch("trustsight.cli.analyze_package") as mock_analyze:
        from trustsight.schema import PackageFact, DiffSummary
        mock_analyze.return_value = PackageFact(
            package_name="testpkg",
            new_version="1.1",
            diff_summary=DiffSummary(files_changed=["PKGBUILD"]),
        )
        result = CliRunner().invoke(app, ["inspect", "testpkg"])
        assert result.exit_code == 0, result.stdout
        mock_analyze.assert_called_once_with("testpkg")


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
    from trustsight import cli

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

    monkeypatch.setattr(cli, "analyze_package", fake_analyze)
    monkeypatch.setattr(cli, "_verdicts_for", lambda facts, cb=None: ["ok"] * len(facts))

    pkgs = [
        {"name": "alpha", "current_version": "1.0", "latest_version": "1.1",
         "last_modified": 1699999999},
        {"name": "beta", "current_version": "2.0", "latest_version": "2.1"},
    ]
    results = cli._analyze_outdated_batch(pkgs)

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


def test_one_bad_package_does_not_end_the_run(monkeypatch):
    """A failure is contained: other packages are still analysed."""
    from trustsight import cli

    monkeypatch.setattr(cli, "_prefetch", lambda pkgs, cb=None: {})
    monkeypatch.setattr(cli, "_verdicts_for", lambda facts, cb=None: ["ok"] * len(facts))

    def fake_analyze(name, **kwargs):
        if name == "broken":
            raise RuntimeError("boom")
        return _fact(name)

    monkeypatch.setattr(cli, "analyze_package", fake_analyze)

    results = cli._analyze_outdated_batch([
        {"name": "broken", "current_version": "1.0"},
        {"name": "fine", "current_version": "1.0"},
    ])
    scored = [r for r in results if not r.get("failed")]
    assert [r["package"] for r in scored] == ["fine"]
    # the failure is surfaced, not swallowed
    assert [r["package"] for r in results if r.get("failed")] == ["broken"]


def test_verdicts_keep_input_order(monkeypatch):
    """Verdicts are produced concurrently but must line up with their facts."""
    from trustsight import cli

    facts = [_fact(f"pkg{i}", score=10) for i in range(8)]
    monkeypatch.setattr(
        "trustsight.llm.generate_verdict", lambda fact: f"verdict-{fact.package_name}"
    )
    verdicts = cli._verdicts_for(facts)
    assert verdicts == [f"verdict-pkg{i}" for i in range(8)]


def test_verdict_failure_falls_back_instead_of_raising(monkeypatch):
    from trustsight import cli

    def explode(fact):
        raise RuntimeError("model unreachable")

    monkeypatch.setattr("trustsight.llm.generate_verdict", explode)
    monkeypatch.setattr("trustsight.llm.fallback_verdict", lambda fact: "offline")
    assert cli._verdicts_for([_fact("pkg", score=10)]) == ["offline"]


def test_unscored_packages_never_reach_the_model(monkeypatch):
    """A zero score uses the offline verdict, as before."""
    from trustsight import cli

    def explode(fact):
        raise AssertionError("model asked about a zero-score package")

    monkeypatch.setattr("trustsight.llm.generate_verdict", explode)
    monkeypatch.setattr("trustsight.llm.fallback_verdict", lambda fact: "offline")
    assert cli._verdicts_for([_fact("pkg", score=0)]) == ["offline"]


def test_a_failed_package_is_reported_not_dropped(monkeypatch):
    """A package that cannot be analysed must still appear in the review.

    Dropping it made an unvetted package indistinguishable from a clean
    one, so anything able to provoke a crash could keep itself out of the
    report entirely.
    """
    from trustsight import cli

    monkeypatch.setattr(cli, "_prefetch", lambda pkgs, cb=None: {})
    monkeypatch.setattr(cli, "_verdicts_for", lambda facts, cb=None: ["ok"] * len(facts))

    def fake_analyze(name, **kwargs):
        if name == "evil":
            raise RuntimeError("crafted crash")
        return _fact(name)

    monkeypatch.setattr(cli, "analyze_package", fake_analyze)

    results = cli._analyze_outdated_batch([
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
        cli, "_analyze_outdated_batch",
        lambda pkgs, cb=None, verbose=False: [
            {"package": "ok", "score": 5, "risk": "Low", "verdict": "fine",
             "first_seen": False},
            {"package": "bad", "score": None, "risk": "Error", "failed": True,
             "verdict": "Analysis failed (RuntimeError): this package was NOT vetted.",
             "first_seen": False},
        ],
    )
    # exercises the rich renderer, which formats the score cell
    cli._run_analysis_loop([{"name": "ok"}, {"name": "bad"}], 10, False, False)
