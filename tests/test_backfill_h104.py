"""The H104 snapshot backfill is idempotent and persists both views."""

from __future__ import annotations

import json
import sqlite3

from scripts.backfill_h104 import backfill

PLACEHOLDER = """\
pkgname=stub
pkgver=0.0.0
pkgrel=1
arch=(any)
package() { echo "placeholder"; }
"""

BENIGN = """\
pkgname=real
pkgver=1.2.3
pkgrel=1
arch=(any)
source=("https://example.invalid/real.tar.gz")
sha256sums=('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')
package() { install -Dm644 real "$pkgdir/usr/bin/real"; }
"""


def _db(tmp_path):
    path = tmp_path / "watcher.db"
    con = sqlite3.connect(path)
    con.executescript(
        """
        CREATE TABLE packages (id INTEGER PRIMARY KEY, name TEXT);
        CREATE TABLE analysis_history (
            id INTEGER PRIMARY KEY, package_id INTEGER, fact_json TEXT);
        CREATE TABLE triggered_rules (
            history_id INTEGER, rule_id TEXT, severity TEXT);
        CREATE TABLE pkgbuild_snapshots (
            package_name TEXT PRIMARY KEY, pkgbuild_text TEXT);
        """
    )
    con.execute("INSERT INTO packages VALUES (1, 'stub')")
    con.execute("INSERT INTO packages VALUES (2, 'real')")
    con.execute(
        "INSERT INTO analysis_history VALUES (10, 1, ?)",
        (json.dumps({"score_breakdown": []}),),
    )
    con.execute(
        "INSERT INTO analysis_history VALUES (20, 2, ?)",
        (json.dumps({"score_breakdown": []}),),
    )
    con.execute("INSERT INTO pkgbuild_snapshots VALUES ('stub', ?)", (PLACEHOLDER,))
    con.execute("INSERT INTO pkgbuild_snapshots VALUES ('real', ?)", (BENIGN,))
    con.commit()
    con.close()
    return path


def test_backfill_persists_h104_and_is_idempotent(tmp_path):
    path = _db(tmp_path)
    first = backfill(path)
    assert first["hits"] == 1
    assert first["inserted"] == 1
    assert first["facts_updated"] == 1

    con = sqlite3.connect(path)
    rows = con.execute(
        "SELECT history_id, rule_id, severity FROM triggered_rules"
    ).fetchall()
    assert rows == [(10, "H104", "INFO")]
    fact = json.loads(con.execute(
        "SELECT fact_json FROM analysis_history WHERE id=10"
    ).fetchone()[0])
    assert any(e["rule_id"] == "H104" for e in fact["score_breakdown"])
    con.close()

    second = backfill(path)
    assert second["hits"] == 1
    assert second["inserted"] == 0
    assert second["existing"] == 1


def test_dry_run_writes_nothing(tmp_path):
    path = _db(tmp_path)
    stats = backfill(path, dry_run=True)
    assert stats["inserted"] == 1
    con = sqlite3.connect(path)
    assert con.execute("SELECT count(*) FROM triggered_rules").fetchone()[0] == 0
    con.close()
