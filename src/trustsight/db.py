import sqlite3
from pathlib import Path
from typing import Optional

from .config import DATA_DIR


def get_db_path() -> Path:
    return DATA_DIR / "trustsight.db"


def get_connection() -> sqlite3.Connection:
    db_path = get_db_path()
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db():
    conn = get_connection()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS packages (
            id INTEGER PRIMARY KEY,
            name TEXT UNIQUE NOT NULL,
            current_version TEXT,
            last_checked TEXT
        );

        CREATE TABLE IF NOT EXISTS source_urls (
            id INTEGER PRIMARY KEY,
            url TEXT UNIQUE NOT NULL,
            first_seen_package_id INTEGER,
            first_seen_globally_timestamp TEXT,
            total_uses INTEGER DEFAULT 1,
            last_seen_timestamp TEXT,
            FOREIGN KEY (first_seen_package_id) REFERENCES packages(id)
        );

        CREATE TABLE IF NOT EXISTS maintainers (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            first_seen_package_id INTEGER,
            FOREIGN KEY (first_seen_package_id) REFERENCES packages(id),
            UNIQUE(name, first_seen_package_id)
        );

        CREATE TABLE IF NOT EXISTS analysis_history (
            id INTEGER PRIMARY KEY,
            package_id INTEGER NOT NULL,
            timestamp TEXT,
            old_version TEXT,
            new_version TEXT,
            old_commit TEXT,
            new_commit TEXT,
            final_score INTEGER,
            raw_diff_blob BLOB,
            fact_json TEXT,
            FOREIGN KEY (package_id) REFERENCES packages(id)
        );

        CREATE TABLE IF NOT EXISTS triggered_rules (
            history_id INTEGER,
            rule_id TEXT,
            severity TEXT,
            FOREIGN KEY (history_id) REFERENCES analysis_history(id)
        );

        CREATE INDEX IF NOT EXISTS idx_source_urls_url ON source_urls(url);
        CREATE INDEX IF NOT EXISTS idx_packages_name ON packages(name);
        CREATE INDEX IF NOT EXISTS idx_history_package ON analysis_history(package_id);
    """)
    conn.commit()
    conn.close()


def upsert_package(name: str, version: str) -> int:
    conn = get_connection()
    conn.execute(
        """INSERT INTO packages (name, current_version, last_checked)
           VALUES (?, ?, datetime('now'))
           ON CONFLICT(name) DO UPDATE SET
               current_version = excluded.current_version,
               last_checked = datetime('now')""",
        (name, version),
    )
    conn.commit()
    row = conn.execute("SELECT id FROM packages WHERE name = ?", (name,)).fetchone()
    conn.close()
    return row["id"]


def get_package_id(name: str) -> Optional[int]:
    conn = get_connection()
    row = conn.execute("SELECT id FROM packages WHERE name = ?", (name,)).fetchone()
    conn.close()
    return row["id"] if row else None


def get_package(name: str) -> Optional[dict]:
    conn = get_connection()
    row = conn.execute("SELECT * FROM packages WHERE name = ?", (name,)).fetchone()
    conn.close()
    return dict(row) if row else None


def get_last_analysis(package_id: int) -> Optional[dict]:
    conn = get_connection()
    row = conn.execute(
        """SELECT * FROM analysis_history
           WHERE package_id = ?
           ORDER BY id DESC LIMIT 1""",
        (package_id,),
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def get_triggered_rules(history_id: int) -> list[dict]:
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM triggered_rules WHERE history_id = ?", (history_id,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def insert_analysis(
    package_id: int,
    old_version: str,
    new_version: str,
    old_commit: str,
    new_commit: str,
    final_score: int,
    raw_diff: str,
    fact_json: str,
    triggered_rules: list[dict],
) -> int:
    conn = get_connection()
    cur = conn.execute(
        """INSERT INTO analysis_history
           (package_id, timestamp, old_version, new_version, old_commit, new_commit, final_score, raw_diff_blob, fact_json)
           VALUES (?, datetime('now'), ?, ?, ?, ?, ?, ?, ?)""",
        (package_id, old_version, new_version, old_commit, new_commit, final_score, raw_diff, fact_json),
    )
    history_id = cur.lastrowid
    for rule in triggered_rules:
        conn.execute(
            "INSERT INTO triggered_rules (history_id, rule_id, severity) VALUES (?, ?, ?)",
            (history_id, rule["rule_id"], rule["severity"]),
        )
    conn.commit()
    conn.close()
    return history_id


def update_package_version(name: str, version: str):
    conn = get_connection()
    conn.execute(
        "UPDATE packages SET current_version = ?, last_checked = datetime('now') WHERE name = ?",
        (version, name),
    )
    conn.commit()
    conn.close()


def get_history(package_id: int, limit: int = 20) -> list[dict]:
    conn = get_connection()
    rows = conn.execute(
        """SELECT * FROM analysis_history
           WHERE package_id = ?
           ORDER BY id DESC LIMIT ?""",
        (package_id, limit),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_all_packages() -> list[dict]:
    conn = get_connection()
    rows = conn.execute("SELECT * FROM packages ORDER BY name").fetchall()
    conn.close()
    return [dict(r) for r in rows]
