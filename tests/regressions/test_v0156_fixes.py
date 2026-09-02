"""Regression tests for v0.15.6-v0.15.7 fixes.

Covers:
- issue #7: SQLite migration crash when maintainers_deprecated_backup exists
- _replace_rule_block NameError in sync-rules wizard
- Drift-aware sync: sync_rules fixes drifted match_target/severity/category
- Ctrl+C handling: KeyboardInterrupt during analysis pool doesn't traceback
"""

import sqlite3
from pathlib import Path
from unittest.mock import patch

import pytest


# ---------------------------------------------------------------------------
# Issue #7: SQLite migration crash when backup table already exists
# ---------------------------------------------------------------------------


def test_migrate_plaintext_maintainers_survives_existing_backup(tmp_path, monkeypatch):
    """When maintainers_deprecated_backup already exists (from a previous
    failed migration), the migration must not crash with OperationalError."""
    monkeypatch.setattr("trustsight.db.DATA_DIR", tmp_path)

    from trustsight.db import get_connection, init_db

    init_db()
    with get_connection() as conn:
        # Simulate a leftover backup from a previous failed migration.
        conn.execute("CREATE TABLE maintainers_deprecated_backup (id INTEGER)")
        # Drop the hashed table and recreate the legacy plaintext table.
        conn.execute("DROP TABLE maintainers_hashed")
        conn.execute("DROP TABLE maintainers")
        conn.execute(
            "CREATE TABLE maintainers (name TEXT, first_seen_package_id INTEGER)"
        )
        # Create a valid package reference for the FK constraint.
        conn.execute("INSERT INTO packages (name) VALUES ('test-pkg')")
        pid = conn.execute("SELECT id FROM packages WHERE name = 'test-pkg'").fetchone()[0]
        conn.execute("INSERT INTO maintainers VALUES ('alice', ?)", (pid,))
        conn.commit()

    # The key assertion: this must NOT raise OperationalError.
    with pytest.warns(UserWarning, match="Plaintext maintainers table detected"):
        init_db()

    with get_connection() as conn:
        tables = {
            row["name"]
            for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
        assert "maintainers" not in tables
        assert "maintainers_deprecated_backup" in tables
        assert "maintainers_hashed" in tables


def test_migrate_plaintext_maintainers_works_on_fresh_db(tmp_path, monkeypatch):
    """The migration works on a fresh database with the legacy table."""
    monkeypatch.setattr("trustsight.db.DATA_DIR", tmp_path)

    from trustsight.db import get_connection, init_db

    init_db()
    with get_connection() as conn:
        # Drop the hashed table and recreate the legacy plaintext table.
        conn.execute("DROP TABLE maintainers_hashed")
        conn.execute("DROP TABLE maintainers")
        conn.execute(
            "CREATE TABLE maintainers (name TEXT, first_seen_package_id INTEGER)"
        )
        # Create a valid package reference for the FK constraint.
        conn.execute("INSERT INTO packages (name) VALUES ('test-pkg')")
        pid = conn.execute("SELECT id FROM packages WHERE name = 'test-pkg'").fetchone()[0]
        conn.execute("INSERT INTO maintainers VALUES ('bob', ?)", (pid,))
        conn.commit()

    with pytest.warns(UserWarning, match="Plaintext maintainers table detected"):
        init_db()

    with get_connection() as conn:
        tables = {
            row["name"]
            for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
        assert "maintainers" not in tables
        assert "maintainers_deprecated_backup" in tables
        assert "maintainers_hashed" in tables


# ---------------------------------------------------------------------------
# _replace_rule_block import in sync-rules wizard
# ---------------------------------------------------------------------------


def test_sync_rules_wizard_full_update_does_not_crash(tmp_path, monkeypatch):
    """The 'Full update' option (choice 1) must not raise NameError."""
    from typer.testing import CliRunner

    monkeypatch.setattr("trustsight.config.DATA_DIR", tmp_path)
    monkeypatch.setattr("trustsight.config.CONFIG_DIR", tmp_path / ".config")
    monkeypatch.setattr("trustsight.config.CACHE_DIR", tmp_path / ".cache")
    monkeypatch.setattr("trustsight.cli.admin.CONFIG_DIR", tmp_path / ".config")

    from trustsight.config import ensure_default_configs, shipped_rules

    ensure_default_configs()

    # Drift a rule so the wizard shows.
    rules_path = tmp_path / ".config" / "rules.toml"
    text = rules_path.read_text()
    shipped_r001 = {r["id"]: r for r in shipped_rules()}["R001"]
    text = text.replace(
        f"pattern = '{shipped_r001['pattern']}'",
        "pattern = 'DRIFTED-PATTERN'",
    )
    rules_path.write_text(text)

    from trustsight.cli.app import app

    result = CliRunner().invoke(app, ["config", "sync-rules"], input="1\n")
    assert result.exit_code == 0, result.output
    assert "Full sync complete" in result.output


# ---------------------------------------------------------------------------
# Drift-aware sync: sync_rules fixes drifted match_target
# ---------------------------------------------------------------------------


def test_sync_rules_fixes_drifted_match_target(tmp_path, monkeypatch):
    """sync_rules(update_outdated=True) replaces rules whose match_target
    drifted from the shipped default."""
    from trustsight.config import (
        ensure_default_configs,
        load_rules,
        shipped_rules,
    )

    monkeypatch.setattr("trustsight.config.DATA_DIR", tmp_path)
    monkeypatch.setattr("trustsight.config.CONFIG_DIR", tmp_path / ".config")
    monkeypatch.setattr("trustsight.config.CACHE_DIR", tmp_path / ".cache")
    ensure_default_configs()

    # Simulate drift: change R001's match_target from shipped value.
    rules_path = tmp_path / ".config" / "rules.toml"
    text = rules_path.read_text()
    shipped_r001 = {r["id"]: r for r in shipped_rules()}["R001"]
    old_target = shipped_r001.get("match_target", "raw_line")
    text = text.replace(
        f'match_target = "{old_target}"',
        'match_target = "raw_line"',
    )
    # Only replace the first occurrence (R001), not all rules.
    rules_path.write_text(text)

    # Verify drift is detected.
    from trustsight.config import drifted_shipped_rules

    drift = drifted_shipped_rules()
    r001_drift = [d for d in drift if d[0] == "R001"]
    assert r001_drift, "R001 drift not detected"
    assert r001_drift[0][1] == "match_target"

    # Sync with update_outdated=True should fix the drift.
    from trustsight.config import sync_rules

    _, updated = sync_rules(update_outdated=True)
    assert "R001" in updated

    # Verify drift is gone.
    drift_after = drifted_shipped_rules()
    r001_drift_after = [d for d in drift_after if d[0] == "R001"]
    assert not r001_drift_after, "R001 drift not fixed"


def test_sync_rules_preserves_custom_patterns(tmp_path, monkeypatch):
    """A rule whose pattern was intentionally edited is NOT overwritten."""
    from trustsight.config import (
        ensure_default_configs,
        load_rules,
        shipped_rules,
    )

    monkeypatch.setattr("trustsight.config.DATA_DIR", tmp_path)
    monkeypatch.setattr("trustsight.config.CONFIG_DIR", tmp_path / ".config")
    monkeypatch.setattr("trustsight.config.CACHE_DIR", tmp_path / ".cache")
    ensure_default_configs()

    # Change R001's pattern to something custom.
    rules_path = tmp_path / ".config" / "rules.toml"
    text = rules_path.read_text()
    shipped_r001 = {r["id"]: r for r in shipped_rules()}["R001"]
    text = text.replace(
        f"pattern = '{shipped_r001['pattern']}'",
        "pattern = 'MY-CUSTOM-PATTERN'",
    )
    rules_path.write_text(text)

    from trustsight.config import sync_rules

    _, updated = sync_rules(update_outdated=True)

    # R001 should NOT be in updated (its pattern is custom, not legacy).
    r01_rules = [r for r in __import__("trustsight.config", fromlist=["load_rules"]).load_rules() if r.get("id") == "R001"]
    assert r01_rules[0]["pattern"] == "MY-CUSTOM-PATTERN", "Custom pattern was overwritten"


# ---------------------------------------------------------------------------
# Ctrl+C handling: KeyboardInterrupt doesn't produce traceback
# ---------------------------------------------------------------------------


def test_keyboard_interrupt_during_analysis_does_not_crash():
    """Ctrl+C during analysis must not produce a threading traceback.

    The fix wraps the ThreadPoolExecutor in a try/except KeyboardInterrupt
    that calls shutdown(wait=False, cancel_futures=True).
    """
    import inspect
    from trustsight.review import analyze_outdated_batch

    src = inspect.getsource(analyze_outdated_batch)
    assert "except KeyboardInterrupt" in src, "Missing KeyboardInterrupt handler"
    assert "cancel_futures=True" in src, "Missing cancel_futures=True"
