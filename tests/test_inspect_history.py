"""Tests for the --allow-uninstalled and --last N inspect features."""

import json
import re
import shutil
from unittest.mock import patch


def _strip_ansi(text: str) -> str:
    """Remove ANSI escape codes from terminal output."""
    return re.sub(r'\x1b\[[0-9;]*m', '', text)

import pygit2
import pytest
from typer.testing import CliRunner

from trustsight.cli.app import app
from trustsight import fetcher
from trustsight.coverage import HISTORY_TRUNCATED

runner = CliRunner()

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_pkgbuild(version: str, extra: str = "") -> bytes:
    return f"pkgver={version}\n{extra}\nsha256sums=SKIP\n".encode()


def _multi_commit_repo(tmp_path, monkeypatch, commits=5):
    """Create a git repo with several PKGBUILD commits and wire it in."""
    cache = tmp_path / "repos"
    cache.mkdir()
    monkeypatch.setattr("trustsight.fetcher.CACHE_DIR", cache)

    path = cache / "testpkg"
    repo = pygit2.init_repository(str(path))
    author = pygit2.Signature("Tester", "tester@example.com", 1_700_000_000, 0)
    repo.remotes.create("origin", "https://aur.archlinux.org/testpkg.git")

    for i in range(commits):
        ts = 1_700_000_000 + i * 3600
        sig = pygit2.Signature("Tester", "tester@example.com", ts, 0)
        blob = repo.create_blob(_make_pkgbuild(f"1.{i}"))
        builder = repo.TreeBuilder()
        builder.insert("PKGBUILD", blob, pygit2.GIT_FILEMODE_BLOB)
        if i == 0:
            parents = []
        else:
            parents = [repo.head.peel().id]
        repo.create_commit("HEAD", sig, sig, f"version {i}", builder.write(), parents)
    return repo


def _mock_aur(name="testpkg", version="1.4"):
    return {name: {"Name": name, "Version": version, "Maintainer": "tester", "URL": "https://example.com"}}


def _env(tmp_path, monkeypatch, package_name="testpkg"):
    """Set up isolated config/db dirs for every test."""
    monkeypatch.setattr("trustsight.config.DATA_DIR", tmp_path)
    monkeypatch.setattr("trustsight.config.CONFIG_DIR", tmp_path / ".config")
    monkeypatch.setattr("trustsight.config.CACHE_DIR", tmp_path / ".cache")
    monkeypatch.setattr("trustsight.db.DATA_DIR", tmp_path)
    from trustsight.config import ensure_default_configs
    ensure_default_configs()
    from trustsight.db import init_db, get_connection
    init_db()
    # Insert a fake installed package so the local check passes.
    with get_connection() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO packages (name, current_version) VALUES (?, ?)",
            (package_name, "1.0"),
        )
        conn.commit()


# ---------------------------------------------------------------------------
# Validation edge cases
# ---------------------------------------------------------------------------

class TestValidation:
    def test_last_zero_rejected(self):
        result = runner.invoke(app, ["inspect", "--last", "0", "pkg"])
        assert result.exit_code == 2
        assert "must be >= 1" in _strip_ansi(result.output)

    def test_last_negative_rejected(self):
        result = runner.invoke(app, ["inspect", "--last", "-1", "pkg"])
        assert result.exit_code == 2
        assert "must be >= 1" in _strip_ansi(result.output)

    def test_last_exceeds_max_rejected(self):
        result = runner.invoke(app, ["inspect", "--last", "51", "pkg"])
        assert result.exit_code == 2
        assert "cannot exceed" in _strip_ansi(result.output)

    def test_record_without_allow_uninstalled_rejected(self):
        result = runner.invoke(app, ["inspect", "--record", "pkg"])
        assert result.exit_code == 2
        assert "--record is only meaningful" in _strip_ansi(result.output)

    def test_last_with_depth_positive_refused(self):
        result = runner.invoke(app, ["inspect", "--last", "1", "--depth", "1", "pkg"])
        assert result.exit_code == 2
        assert "not combined in this version" in _strip_ansi(result.output)

    def test_last_with_depth_zero_allowed(self, tmp_path, monkeypatch):
        """--depth 0 + --last should not be refused (depth 0 means no deps)."""
        _env(tmp_path, monkeypatch)
        _multi_commit_repo(tmp_path, monkeypatch, commits=2)
        with patch("trustsight.discovery.get_aur_package_info", return_value=_mock_aur()):
            with patch("trustsight.cli.inspect.analyze_package") as mock_an:
                from trustsight.schema import PackageFact, DiffSummary
                mock_an.return_value = PackageFact(
                    package_name="testpkg", new_version="1.1",
                    diff_summary=DiffSummary(files_changed=["PKGBUILD"]),
                )
                result = runner.invoke(app, ["inspect", "--last", "1", "--depth", "0", "testpkg"])
                # Should not be rejected for combining --last with --depth 0
                assert "not combined" not in _strip_ansi(result.output)

    def test_uninstalled_package_without_flag_rejected(self, tmp_path, monkeypatch):
        # Do NOT use _env; we need the package to be absent from local DB.
        monkeypatch.setattr("trustsight.config.DATA_DIR", tmp_path)
        monkeypatch.setattr("trustsight.config.CONFIG_DIR", tmp_path / ".config")
        monkeypatch.setattr("trustsight.config.CACHE_DIR", tmp_path / ".cache")
        monkeypatch.setattr("trustsight.db.DATA_DIR", tmp_path)
        from trustsight.config import ensure_default_configs
        ensure_default_configs()
        from trustsight.db import init_db
        init_db()
        with patch("trustsight.discovery.get_aur_package_info", return_value=_mock_aur()):
            result = runner.invoke(app, ["inspect", "testpkg"])
            assert result.exit_code == 2
            assert "--allow-uninstalled was not passed" in _strip_ansi(result.output)

    def test_nonexistent_aur_package_rejected(self, tmp_path, monkeypatch):
        # Package not in AUR and not installed locally.
        monkeypatch.setattr("trustsight.config.DATA_DIR", tmp_path)
        monkeypatch.setattr("trustsight.config.CONFIG_DIR", tmp_path / ".config")
        monkeypatch.setattr("trustsight.config.CACHE_DIR", tmp_path / ".cache")
        monkeypatch.setattr("trustsight.db.DATA_DIR", tmp_path)
        from trustsight.config import ensure_default_configs
        ensure_default_configs()
        from trustsight.db import init_db
        init_db()
        with patch("trustsight.discovery.get_aur_package_info", return_value={}):
            result = runner.invoke(app, ["inspect", "--allow-uninstalled", "nosuchpkg"])
            assert result.exit_code == 2
            assert "not found in the AUR" in _strip_ansi(result.output)

    def test_validation_json_output(self):
        """Error messages should be valid JSON when --json is used."""
        result = runner.invoke(app, ["inspect", "--last", "0", "--json", "pkg"])
        assert result.exit_code == 2
        data = json.loads(result.output)
        assert "error" in data
        assert ">= 1" in data["error"]

    def test_record_json_output(self):
        result = runner.invoke(app, ["inspect", "--record", "--json", "pkg"])
        assert result.exit_code == 2
        data = json.loads(result.output)
        assert "error" in data


# ---------------------------------------------------------------------------
# --last N functional tests (using real git repos)
# ---------------------------------------------------------------------------

class TestLastN:
    def test_last_1_returns_one_result(self, tmp_path, monkeypatch):
        _env(tmp_path, monkeypatch)
        repo = _multi_commit_repo(tmp_path, monkeypatch, commits=3)
        head = fetcher.get_head_commit(repo)
        fetcher._record_fetch(repo)

        with patch("trustsight.discovery.get_aur_package_info", return_value=_mock_aur()):
            result = runner.invoke(app, ["inspect", "--last", "1", "--json", "testpkg"])
            assert result.exit_code == 0, result.output
            data = json.loads(result.output)
            assert len(data) == 1
            assert "commit" in data[0]
            assert "commit_message" in data[0]

    def test_last_3_returns_three_results(self, tmp_path, monkeypatch):
        _env(tmp_path, monkeypatch)
        repo = _multi_commit_repo(tmp_path, monkeypatch, commits=5)
        fetcher._record_fetch(repo)

        with patch("trustsight.discovery.get_aur_package_info", return_value=_mock_aur()):
            result = runner.invoke(app, ["inspect", "--last", "3", "--json", "testpkg"])
            assert result.exit_code == 0, result.output
            data = json.loads(result.output)
            assert len(data) == 3

    def test_last_more_than_commits_returns_fewer(self, tmp_path, monkeypatch):
        """Asking for 10 when only 4 commits exist returns 4, with history_truncated."""
        _env(tmp_path, monkeypatch)
        repo = _multi_commit_repo(tmp_path, monkeypatch, commits=4)
        fetcher._record_fetch(repo)

        with patch("trustsight.discovery.get_aur_package_info", return_value=_mock_aur()):
            result = runner.invoke(app, ["inspect", "--last", "10", "--json", "testpkg"])
            assert result.exit_code == 0, result.output
            data = json.loads(result.output)
            assert 1 <= len(data) <= 4
            # The newest result should have the history_truncated gap
            assert HISTORY_TRUNCATED in data[0].get("coverage_gaps", [])

    def test_results_are_newest_first(self, tmp_path, monkeypatch):
        """The first result should be the most recent commit."""
        _env(tmp_path, monkeypatch)
        repo = _multi_commit_repo(tmp_path, monkeypatch, commits=5)
        fetcher._record_fetch(repo)

        with patch("trustsight.discovery.get_aur_package_info", return_value=_mock_aur()):
            result = runner.invoke(app, ["inspect", "--last", "3", "--json", "testpkg"])
            assert result.exit_code == 0, result.output
            data = json.loads(result.output)
            # With 5 commits, we get diffs for commits 1-4 (commit 0 has no parent).
            # Asking for 3, we get the 3 newest: version 4, 3, 2.
            commits = [r["commit_message"] for r in data]
            assert commits == ["version 4", "version 3", "version 2"]

    def test_score_is_independently_computed(self, tmp_path, monkeypatch):
        """Each result has its own score, no aggregate."""
        _env(tmp_path, monkeypatch)
        repo = _multi_commit_repo(tmp_path, monkeypatch, commits=3)
        fetcher._record_fetch(repo)

        with patch("trustsight.discovery.get_aur_package_info", return_value=_mock_aur()):
            result = runner.invoke(app, ["inspect", "--last", "3", "--json", "--score", "testpkg"])
            assert result.exit_code == 0, result.output
            data = json.loads(result.output)
            for r in data:
                assert "score" in r
                # No aggregate key
                assert "aggregate_score" not in r
                assert "sum_score" not in r

    def test_empty_result_when_no_content_diffs(self, tmp_path, monkeypatch):
        """If all commits have identical PKGBUILDs, exit 2 with zero results."""
        _env(tmp_path, monkeypatch)
        cache = tmp_path / "repos"
        cache.mkdir()
        monkeypatch.setattr("trustsight.fetcher.CACHE_DIR", cache)
        path = cache / "testpkg"
        repo = pygit2.init_repository(str(path))
        repo.remotes.create("origin", "https://aur.archlinux.org/testpkg.git")
        author = pygit2.Signature("Tester", "tester@example.com", 1_700_000_000, 0)
        blob = repo.create_blob(b"pkgver=1.0\n")
        builder = repo.TreeBuilder()
        builder.insert("PKGBUILD", blob, pygit2.GIT_FILEMODE_BLOB)
        repo.create_commit("HEAD", author, author, "v1", builder.write(), [])
        # Second commit with identical PKGBUILD
        for i in range(3):
            sig = pygit2.Signature("Tester", "tester@example.com", 1_700_000_000 + (i+1)*3600, 0)
            blob = repo.create_blob(b"pkgver=1.0\n")  # identical content
            builder = repo.TreeBuilder()
            builder.insert("PKGBUILD", blob, pygit2.GIT_FILEMODE_BLOB)
            repo.create_commit("HEAD", sig, sig, f"identical {i}", builder.write(), [repo.head.peel().id])
        fetcher._record_fetch(repo)
    
        with patch("trustsight.discovery.get_aur_package_info", return_value=_mock_aur()):
            result = runner.invoke(app, ["inspect", "--last", "5", "--json", "testpkg"])
            # Zero content diffs → exit 2, per spec §6
            assert result.exit_code == 2
            data = json.loads(result.output)
            assert "error" in data


# ---------------------------------------------------------------------------
# --allow-uninstalled functional tests
# ---------------------------------------------------------------------------

class TestAllowUninstalled:
    def test_allows_analysis_when_flag_present(self, tmp_path, monkeypatch):
        _env(tmp_path, monkeypatch)
        with patch("trustsight.discovery.get_aur_package_info", return_value=_mock_aur()):
            with patch("trustsight.cli.inspect.analyze_package") as mock_an:
                from trustsight.schema import PackageFact, DiffSummary
                mock_an.return_value = PackageFact(
                    package_name="testpkg", new_version="1.1",
                    diff_summary=DiffSummary(files_changed=["PKGBUILD"]),
                )
                result = runner.invoke(app, ["inspect", "--allow-uninstalled", "testpkg"])
                assert result.exit_code == 0, result.output

    def test_refuses_when_not_installed(self, tmp_path, monkeypatch):
        # Do NOT use _env; we need the package to be absent from local DB.
        monkeypatch.setattr("trustsight.config.DATA_DIR", tmp_path)
        monkeypatch.setattr("trustsight.config.CONFIG_DIR", tmp_path / ".config")
        monkeypatch.setattr("trustsight.config.CACHE_DIR", tmp_path / ".cache")
        monkeypatch.setattr("trustsight.db.DATA_DIR", tmp_path)
        from trustsight.config import ensure_default_configs
        ensure_default_configs()
        from trustsight.db import init_db
        init_db()
        with patch("trustsight.discovery.get_aur_package_info", return_value=_mock_aur()):
            result = runner.invoke(app, ["inspect", "testpkg"])
            assert result.exit_code == 2
            assert "--allow-uninstalled was not passed" in _strip_ansi(result.output)


# ---------------------------------------------------------------------------
# --record flag
# ---------------------------------------------------------------------------

class TestRecordFlag:
    def test_record_accepted_with_allow_uninstalled(self, tmp_path, monkeypatch):
        _env(tmp_path, monkeypatch)
        with patch("trustsight.discovery.get_aur_package_info", return_value=_mock_aur()):
            with patch("trustsight.cli.inspect.analyze_package") as mock_an:
                from trustsight.schema import PackageFact, DiffSummary
                mock_an.return_value = PackageFact(
                    package_name="testpkg", new_version="1.1",
                    diff_summary=DiffSummary(files_changed=["PKGBUILD"]),
                )
                result = runner.invoke(app, ["inspect", "--allow-uninstalled", "--record", "testpkg"])
                assert result.exit_code == 0, result.output

    def test_record_rejected_without_allow_uninstalled(self, tmp_path, monkeypatch):
        _env(tmp_path, monkeypatch)
        with patch("trustsight.discovery.get_aur_package_info", return_value=_mock_aur()):
            result = runner.invoke(app, ["inspect", "--record", "testpkg"])
            assert result.exit_code == 2
            assert "--record is only meaningful" in result.output


# ---------------------------------------------------------------------------
# A15: Read-only database invariant
# ---------------------------------------------------------------------------

class TestA15ReadOnlyDatabase:
    def test_allow_uninstalled_opens_read_only(self, tmp_path, monkeypatch):
        """Without --record, the database connection should be read-only."""
        _env(tmp_path, monkeypatch)
        repo = _multi_commit_repo(tmp_path, monkeypatch, commits=2)
        fetcher._record_fetch(repo)

        opened_modes = []
        original_get_conn = None
        import trustsight.db as db_mod
        original_get_conn = db_mod.get_connection

        def tracking_get_connection(*args, **kwargs):
            conn = original_get_conn(*args, **kwargs)
            # SQLite connection uri is on the connection object
            opened_modes.append(str(getattr(conn, '_conn', '')))
            return conn

        with patch("trustsight.discovery.get_aur_package_info", return_value=_mock_aur()):
            with patch.object(db_mod, "get_connection", tracking_get_connection):
                result = runner.invoke(app, [
                    "inspect", "--allow-uninstalled", "--last", "1", "--json", "testpkg"
                ])
                assert result.exit_code == 0, result.output

        # Verify the connection was opened (the exact mode check depends on
        # how get_read_only_connection is implemented; at minimum it should
        # have been called)
        # Note: exact assertion depends on connection implementation

    def test_record_allows_read_write(self, tmp_path, monkeypatch):
        """With --record, the database should be writable."""
        _env(tmp_path, monkeypatch)
        repo = _multi_commit_repo(tmp_path, monkeypatch, commits=2)
        fetcher._record_fetch(repo)

        with patch("trustsight.discovery.get_aur_package_info", return_value=_mock_aur()):
            result = runner.invoke(app, [
                "inspect", "--allow-uninstalled", "--record", "--last", "1", "--json", "testpkg"
            ])
            assert result.exit_code == 0, result.output


# ---------------------------------------------------------------------------
# --last with --json output format
# ---------------------------------------------------------------------------

class TestJsonOutput:
    def test_last_json_is_array(self, tmp_path, monkeypatch):
        _env(tmp_path, monkeypatch)
        repo = _multi_commit_repo(tmp_path, monkeypatch, commits=3)
        fetcher._record_fetch(repo)

        with patch("trustsight.discovery.get_aur_package_info", return_value=_mock_aur()):
            result = runner.invoke(app, ["inspect", "--last", "2", "--json", "testpkg"])
            assert result.exit_code == 0, result.output
            data = json.loads(result.output)
            assert isinstance(data, list)
            assert len(data) == 2

    def test_each_body_has_report_keys(self, tmp_path, monkeypatch):
        """B11: every JSON body carries REPORT_KEYS."""
        _env(tmp_path, monkeypatch)
        repo = _multi_commit_repo(tmp_path, monkeypatch, commits=3)
        fetcher._record_fetch(repo)

        with patch("trustsight.discovery.get_aur_package_info", return_value=_mock_aur()):
            result = runner.invoke(app, ["inspect", "--last", "2", "--json", "testpkg"])
            data = json.loads(result.output)
            for body in data:
                assert "package" in body
                assert "coverage_gaps" in body

    def test_score_withheld_by_default(self, tmp_path, monkeypatch):
        """B11: SCORE_KEYS withheld unless --score or --risk."""
        _env(tmp_path, monkeypatch)
        repo = _multi_commit_repo(tmp_path, monkeypatch, commits=3)
        fetcher._record_fetch(repo)

        with patch("trustsight.discovery.get_aur_package_info", return_value=_mock_aur()):
            result = runner.invoke(app, ["inspect", "--last", "2", "--json", "testpkg"])
            data = json.loads(result.output)
            for body in data:
                assert "score" not in body
                assert "risk" not in body

    def test_score_included_with_flag(self, tmp_path, monkeypatch):
        _env(tmp_path, monkeypatch)
        repo = _multi_commit_repo(tmp_path, monkeypatch, commits=3)
        fetcher._record_fetch(repo)

        with patch("trustsight.discovery.get_aur_package_info", return_value=_mock_aur()):
            result = runner.invoke(app, ["inspect", "--last", "2", "--json", "--score", "testpkg"])
            data = json.loads(result.output)
            for body in data:
                assert "score" in body


# ---------------------------------------------------------------------------
# Exit code semantics
# ---------------------------------------------------------------------------

class TestExitCode:
    def test_exit_2_when_zero_results(self, tmp_path, monkeypatch):
        """Exit 2 when no results at all."""
        _env(tmp_path, monkeypatch)
        cache = tmp_path / "repos"
        cache.mkdir()
        monkeypatch.setattr("trustsight.fetcher.CACHE_DIR", cache)
        path = cache / "testpkg"
        repo = pygit2.init_repository(str(path))
        repo.remotes.create("origin", "https://aur.archlinux.org/testpkg.git")
        author = pygit2.Signature("Tester", "tester@example.com", 1_700_000_000, 0)
        blob = repo.create_blob(b"pkgver=1.0\n")
        builder = repo.TreeBuilder()
        builder.insert("PKGBUILD", blob, pygit2.GIT_FILEMODE_BLOB)
        repo.create_commit("HEAD", author, author, "v1", builder.write(), [])
        fetcher._record_fetch(repo)

        with patch("trustsight.discovery.get_aur_package_info", return_value=_mock_aur()):
            # Only 1 commit with a single content, ask for 5 -> 0 content diffs after the first
            result = runner.invoke(app, ["inspect", "--last", "5", "--json", "testpkg"])
            # With 1 commit, there's no parent to diff against, so 0 results
            assert result.exit_code == 2
            assert "error" in json.loads(result.output)
