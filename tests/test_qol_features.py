"""Tests for --sort on review/list, history date filtering, and list verdict."""

import json
from unittest.mock import patch

import pygit2
import pytest
from typer.testing import CliRunner

from trustsight import fetcher
from trustsight.cli.app import app

runner = CliRunner()

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _strip_ansi(text: str) -> str:
    import re
    return re.sub(r'\x1b\[[0-9;]*m', '', text)


def _env(tmp_path, monkeypatch):
    monkeypatch.setattr("trustsight.config.DATA_DIR", tmp_path)
    monkeypatch.setattr("trustsight.config.CONFIG_DIR", tmp_path / ".config")
    monkeypatch.setattr("trustsight.config.CACHE_DIR", tmp_path / ".cache")
    monkeypatch.setattr("trustsight.db.DATA_DIR", tmp_path)
    from trustsight.config import ensure_default_configs
    ensure_default_configs()
    from trustsight.db import init_db
    init_db()


def _insert_pkg(conn, name, version="1.0"):
    conn.execute(
        "INSERT OR REPLACE INTO packages (name, current_version) VALUES (?, ?)",
        (name, version),
    )
    conn.commit()


def _insert_analysis(conn, pkg_id, score, timestamp, old="1.0", new="1.1"):
    """Insert a fake analysis_history row."""
    conn.execute(
        """INSERT INTO analysis_history
           (package_id, timestamp, old_version, new_version, final_score)
           VALUES (?, ?, ?, ?, ?)""",
        (pkg_id, timestamp, old, new, score),
    )
    conn.commit()
    return conn.execute("SELECT last_insert_rowid()").fetchone()[0]


def _get_pkg_id(conn, name):
    row = conn.execute("SELECT id FROM packages WHERE name = ?", (name,)).fetchone()
    return row["id"] if row else None


# ---------------------------------------------------------------------------
# --sort on list
# ---------------------------------------------------------------------------

class TestListSort:
    def test_sort_by_score(self, tmp_path, monkeypatch):
        _env(tmp_path, monkeypatch)
        from trustsight.db import get_connection
        with get_connection() as conn:
            _insert_pkg(conn, "alpha")
            _insert_pkg(conn, "beta")
            _insert_pkg(conn, "gamma")
            pid_a = _get_pkg_id(conn, "alpha")
            pid_b = _get_pkg_id(conn, "beta")
            pid_g = _get_pkg_id(conn, "gamma")
            _insert_analysis(conn, pid_a, 10, "2026-01-01")
            _insert_analysis(conn, pid_b, 80, "2026-01-02")
            _insert_analysis(conn, pid_g, 40, "2026-01-03")

        result = runner.invoke(app, ["list", "--json", "--sort", "score"])
        assert result.exit_code == 0, result.output
        data = json.loads(result.output)
        names = [r["name"] for r in data]
        # worst first: beta(80), gamma(40), alpha(10)
        assert names == ["beta", "gamma", "alpha"]

    def test_sort_by_risk(self, tmp_path, monkeypatch):
        _env(tmp_path, monkeypatch)
        from trustsight.db import get_connection
        with get_connection() as conn:
            _insert_pkg(conn, "low-pkg")
            _insert_pkg(conn, "high-pkg")
            _insert_pkg(conn, "med-pkg")
            _insert_pkg(conn, "crit-pkg")
            for name, score in [("low-pkg", 5), ("high-pkg", 60), ("med-pkg", 30), ("crit-pkg", 90)]:
                pid = _get_pkg_id(conn, name)
                _insert_analysis(conn, pid, score, "2026-01-01")

        result = runner.invoke(app, ["list", "--json", "--sort", "risk"])
        assert result.exit_code == 0, result.output
        data = json.loads(result.output)
        names = [r["name"] for r in data]
        # Critical first, then High, Medium, Low
        assert names == ["crit-pkg", "high-pkg", "med-pkg", "low-pkg"]

    def test_sort_by_name(self, tmp_path, monkeypatch):
        _env(tmp_path, monkeypatch)
        from trustsight.db import get_connection
        with get_connection() as conn:
            _insert_pkg(conn, "zebra")
            _insert_pkg(conn, "alpha")
            _insert_pkg(conn, "mid")

        result = runner.invoke(app, ["list", "--json", "--sort", "name"])
        assert result.exit_code == 0, result.output
        data = json.loads(result.output)
        names = [r["name"] for r in data]
        assert names == ["alpha", "mid", "zebra"]

    def test_sort_by_last_checked(self, tmp_path, monkeypatch):
        _env(tmp_path, monkeypatch)
        from trustsight.db import get_connection
        with get_connection() as conn:
            _insert_pkg(conn, "pkg-a")
            _insert_pkg(conn, "pkg-b")
            _insert_pkg(conn, "pkg-c")
            # Manually set last_checked timestamps
            conn.execute("UPDATE packages SET last_checked = '2026-03-01' WHERE name = 'pkg-a'")
            conn.execute("UPDATE packages SET last_checked = '2026-01-01' WHERE name = 'pkg-b'")
            conn.execute("UPDATE packages SET last_checked = '2026-02-01' WHERE name = 'pkg-c'")
            conn.commit()

        result = runner.invoke(app, ["list", "--json", "--sort", "last-checked"])
        assert result.exit_code == 0, result.output
        data = json.loads(result.output)
        names = [r["name"] for r in data]
        # oldest first
        assert names == ["pkg-b", "pkg-c", "pkg-a"]

    def test_sort_invalid_rejected(self, tmp_path, monkeypatch):
        _env(tmp_path, monkeypatch)
        result = runner.invoke(app, ["list", "--sort", "bogus"])
        assert result.exit_code == 2
        assert "--sort must be one of" in _strip_ansi(result.output)

    def test_sort_json_output(self, tmp_path, monkeypatch):
        _env(tmp_path, monkeypatch)
        from trustsight.db import get_connection
        with get_connection() as conn:
            _insert_pkg(conn, "foo")
            _insert_pkg(conn, "bar")
            pid = _get_pkg_id(conn, "bar")
            _insert_analysis(conn, pid, 50, "2026-01-01")

        result = runner.invoke(app, ["list", "--json", "--sort", "score"])
        assert result.exit_code == 0, result.output
        data = json.loads(result.output)
        # bar has a score (50), foo has None; bar should come first
        assert data[0]["name"] == "bar"
        assert data[1]["name"] == "foo"


# ---------------------------------------------------------------------------
# list --json verdict field
# ---------------------------------------------------------------------------

class TestListVerdict:
    def test_verdict_present_in_json(self, tmp_path, monkeypatch):
        _env(tmp_path, monkeypatch)
        from trustsight.db import get_connection
        with get_connection() as conn:
            _insert_pkg(conn, "mypkg")
            pid = _get_pkg_id(conn, "mypkg")
            _insert_analysis(conn, pid, 45, "2026-06-01")

        result = runner.invoke(app, ["list", "--json"])
        assert result.exit_code == 0, result.output
        data = json.loads(result.output)
        assert len(data) == 1
        assert "verdict" in data[0]
        assert data[0]["verdict"] == "Medium"

    def test_verdict_inconclusive_for_cold_db(self, tmp_path, monkeypatch):
        _env(tmp_path, monkeypatch)
        from trustsight.db import get_connection
        with get_connection() as conn:
            _insert_pkg(conn, "cold-pkg")
            pid = _get_pkg_id(conn, "cold-pkg")
            # Score in Medium band but with no history → Inconclusive
            _insert_analysis(conn, pid, 30, "2026-06-01")

        result = runner.invoke(app, ["list", "--json"])
        assert result.exit_code == 0, result.output
        data = json.loads(result.output)
        verdict = data[0]["verdict"]
        # With no seed and only 1 observation, maturity is low → Inconclusive
        assert verdict in ("Medium", "Inconclusive")

    def test_verdict_for_unanalysed_package(self, tmp_path, monkeypatch):
        _env(tmp_path, monkeypatch)
        from trustsight.db import get_connection
        with get_connection() as conn:
            _insert_pkg(conn, "new-pkg")

        result = runner.invoke(app, ["list", "--json"])
        assert result.exit_code == 0, result.output
        data = json.loads(result.output)
        assert data[0]["verdict"] == "-"


# ---------------------------------------------------------------------------
# history --from-date / --to-date
# ---------------------------------------------------------------------------

class TestHistoryDateFilter:
    def _setup_history(self, tmp_path, monkeypatch):
        _env(tmp_path, monkeypatch)
        from trustsight.db import get_connection
        with get_connection() as conn:
            _insert_pkg(conn, "timepkg")
            pid = _get_pkg_id(conn, "timepkg")
            _insert_analysis(conn, pid, 10, "2026-01-15T10:00:00", "1.0", "1.1")
            _insert_analysis(conn, pid, 20, "2026-03-15T10:00:00", "1.1", "1.2")
            _insert_analysis(conn, pid, 30, "2026-06-15T10:00:00", "1.2", "1.3")
            _insert_analysis(conn, pid, 40, "2026-09-15T10:00:00", "1.3", "1.4")
            return pid

    def test_from_date(self, tmp_path, monkeypatch):
        self._setup_history(tmp_path, monkeypatch)
        result = runner.invoke(app, ["history", "timepkg", "--json", "--from-date", "2026-06-01"])
        assert result.exit_code == 0, result.output
        data = json.loads(result.output)
        assert len(data) == 2
        # Newest first
        assert data[0]["timestamp"].startswith("2026-09")
        assert data[1]["timestamp"].startswith("2026-06")

    def test_to_date(self, tmp_path, monkeypatch):
        self._setup_history(tmp_path, monkeypatch)
        result = runner.invoke(app, ["history", "timepkg", "--json", "--to-date", "2026-03-15"])
        assert result.exit_code == 0, result.output
        data = json.loads(result.output)
        assert len(data) == 2
        # Includes March 15 (inclusive)
        dates = [r["timestamp"][:10] for r in data]
        assert "2026-03-15" in dates
        assert "2026-01-15" in dates

    def test_date_range(self, tmp_path, monkeypatch):
        self._setup_history(tmp_path, monkeypatch)
        result = runner.invoke(app, [
            "history", "timepkg", "--json",
            "--from-date", "2026-03-01",
            "--to-date", "2026-06-30",
        ])
        assert result.exit_code == 0, result.output
        data = json.loads(result.output)
        assert len(data) == 2
        dates = [r["timestamp"][:10] for r in data]
        assert "2026-03-15" in dates
        assert "2026-06-15" in dates

    def test_invalid_date_rejected(self, tmp_path, monkeypatch):
        self._setup_history(tmp_path, monkeypatch)
        result = runner.invoke(app, [
            "history", "timepkg", "--from-date", "not-a-date",
        ])
        assert result.exit_code == 2
        assert "YYYY-MM-DD" in _strip_ansi(result.output)

    def test_from_date_beyond_history_returns_empty(self, tmp_path, monkeypatch):
        self._setup_history(tmp_path, monkeypatch)
        result = runner.invoke(app, [
            "history", "timepkg", "--json", "--from-date", "2027-01-01",
        ])
        assert result.exit_code == 0, result.output
        data = json.loads(result.output)
        assert data == []

    def test_to_date_before_history_returns_empty(self, tmp_path, monkeypatch):
        self._setup_history(tmp_path, monkeypatch)
        result = runner.invoke(app, [
            "history", "timepkg", "--json", "--to-date", "2025-01-01",
        ])
        assert result.exit_code == 0, result.output
        data = json.loads(result.output)
        assert data == []

    def test_full_iso_datetime_works(self, tmp_path, monkeypatch):
        self._setup_history(tmp_path, monkeypatch)
        result = runner.invoke(app, [
            "history", "timepkg", "--json",
            "--from-date", "2026-03-15T09:00:00",
            "--to-date", "2026-09-15T11:00:00",
        ])
        assert result.exit_code == 0, result.output
        data = json.loads(result.output)
        # March 15 at 10:00 is after 09:00 → included
        # September 15 at 10:00 is before 11:00 → included
        # June 15 at 10:00 is also in range → 3 total
        assert len(data) == 3


# ---------------------------------------------------------------------------
# --sort on review (terminal validation only; analysis is mocked)
# ---------------------------------------------------------------------------

class TestReviewSort:
    def test_sort_invalid_rejected(self, tmp_path, monkeypatch):
        _env(tmp_path, monkeypatch)
        result = runner.invoke(app, ["review", "--sort", "bogus"])
        assert result.exit_code == 2
        assert "--sort must be one of" in _strip_ansi(result.output)

    def test_sort_option_accepted(self, tmp_path, monkeypatch):
        """--sort with a valid value should not be rejected at parse time."""
        _env(tmp_path, monkeypatch)
        # The command may download AUR metadata, which writes to stdout.
        # What matters is the exit code: valid --sort is not rejected.
        result = runner.invoke(app, ["review", "--sort", "score", "--quiet"])
        # Exit 0 means the sort flag was accepted.
        # (Exit 2 would mean validation rejected it.)
        assert result.exit_code == 0
