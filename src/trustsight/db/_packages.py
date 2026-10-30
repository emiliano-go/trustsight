"""Extracted from db.py: _packages."""

import re
from typing import Optional
from ._connection import get_connection
from ._metadata import _bump_observation_seq

__all__ = ['_RESERVED_NAMES', '_sanitize_maintainer', 'count_observations', 'get_analysis', 'get_aur_orphan_state', 'get_last_analysis', 'get_package', 'get_package_id', 'get_triggered_rules', 'insert_analysis', 'is_reserved_name', 'update_aur_orphan_state', 'update_package_maintainer', 'update_package_version', 'upsert_package']

_RESERVED_NAMES = frozenset({"__seed__"})

def is_reserved_name(name: str) -> bool:
    """True when *name* is an internal sentinel, not a real package.

    AUR package names may begin with an underscore, so ``__seed__`` is a
    name someone could actually register.  Writers reject it; callers that
    walk a corpus use this to skip it, because one such name must not be
    able to abort a cycle over ninety thousand packages.
    """
    return name in _RESERVED_NAMES or name.startswith("__")

def upsert_package(name: str, version: str) -> int:
    """Insert or update a package record, returning its id."""
    if name in _RESERVED_NAMES or name.startswith("__"):
        raise ValueError(f"reserved name cannot be tracked as a package: {name}")
    with get_connection() as conn:
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
        return row["id"]

def get_package_id(name: str) -> Optional[int]:
    """Return the internal id for *name*, or None.
    Internal sentinel rows (e.g. __seed__) are excluded."""
    if name in _RESERVED_NAMES or name.startswith("__"):
        return None
    with get_connection() as conn:
        row = conn.execute("SELECT id FROM packages WHERE name = ?", (name,)).fetchone()
        return row["id"] if row else None

def get_package(name: str) -> Optional[dict]:
    """Return the full package row for *name*, or None.
    Internal sentinel rows (e.g. __seed__) are excluded."""
    if name in _RESERVED_NAMES or name.startswith("__"):
        return None
    with get_connection() as conn:
        row = conn.execute("SELECT * FROM packages WHERE name = ?", (name,)).fetchone()
        return dict(row) if row else None

def get_last_analysis(package_id: int) -> Optional[dict]:
    """Return the most recent analysis for *package_id*, or None."""
    with get_connection() as conn:
        row = conn.execute(
            """SELECT * FROM analysis_history
               WHERE package_id = ?
               ORDER BY id DESC LIMIT 1""",
            (package_id,),
        ).fetchone()
        return dict(row) if row else None

def get_analysis(history_id: int) -> Optional[dict]:
    """Return one recorded analysis row by its history id, or None."""
    with get_connection() as conn:
        row = conn.execute(
            "SELECT * FROM analysis_history WHERE id = ?", (history_id,)
        ).fetchone()
        return dict(row) if row else None

def get_triggered_rules(history_id: int) -> list[dict]:
    """Return all triggered rules for *history_id*."""
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM triggered_rules WHERE history_id = ?", (history_id,)
        ).fetchall()
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
    """Record a new analysis and its triggered rules, returning the history id."""
    with get_connection() as conn:
        cur = conn.execute(
            """INSERT INTO analysis_history
               (package_id, timestamp, old_version, new_version, old_commit, new_commit, final_score, raw_diff_blob, fact_json)
               VALUES (?, datetime('now'), ?, ?, ?, ?, ?, ?, ?)""",
            (package_id, old_version, new_version, old_commit, new_commit, final_score, raw_diff, fact_json),
        )
        history_id = cur.lastrowid
        if triggered_rules:
            conn.executemany(
                "INSERT INTO triggered_rules (history_id, rule_id, severity) VALUES (?, ?, ?)",
                [(history_id, rule["rule_id"], rule["severity"])
                 for rule in triggered_rules],
            )
        # Advance the observation clock in the same transaction: campaign and
        # override TTLs are measured in recorded observations, so the counter
        # must move exactly when an observation is written, never separately.
        _bump_observation_seq(conn)
        conn.commit()
        return history_id

def update_package_version(name: str, version: str):
    """Update the current version and check time for *name*."""
    with get_connection() as conn:
        conn.execute(
            "UPDATE packages SET current_version = ?, last_checked = datetime('now') WHERE name = ?",
            (version, name),
        )
        conn.commit()

def _sanitize_maintainer(m: str) -> str:
    """Remove shell-injection patterns from maintainer strings."""
    m = re.sub(r'\$\([^)]*\)', '', m)
    m = re.sub(r'`[^`]*`', '', m)
    # The following whitespace collapse handles the space this used to eat.
    m = m.replace('<>', '')
    m = re.sub(r'\s+', ' ', m).strip()
    return m

def update_package_maintainer(name: str, maintainer: str):
    """Update the stored maintainer for *name*."""
    maintainer = _sanitize_maintainer(maintainer)
    with get_connection() as conn:
        conn.execute(
            "UPDATE packages SET current_maintainer = ? WHERE name = ?",
            (maintainer, name),
        )
        conn.commit()

def get_aur_orphan_state(name: str) -> int:
    """The last recorded AUR orphan state: 1 orphaned, 0 maintained, -1 unknown.

    -1 is load-bearing.  H086 claims "this package was adopted", and that
    claim needs a prior observation showing it orphaned; a database that has
    never asked must not let "no record" read as "was maintained" or as
    "was orphaned".
    """
    with get_connection() as conn:
        row = conn.execute(
            "SELECT aur_orphaned FROM packages WHERE name = ?", (name,)
        ).fetchone()
    if row is None or row["aur_orphaned"] is None:
        return -1
    return int(row["aur_orphaned"])

def update_aur_orphan_state(name: str, orphaned: Optional[bool]) -> None:
    """Record whether the AUR currently reports *name* as orphaned.

    ``None`` means the metadata was unavailable this run, which is recorded
    as unknown rather than as either state: guessing here would manufacture
    an adoption or hide one.
    """
    value = -1 if orphaned is None else int(bool(orphaned))
    with get_connection() as conn:
        conn.execute(
            "UPDATE packages SET aur_orphaned = ? WHERE name = ?", (value, name)
        )
        conn.commit()

def count_observations() -> int:
    """Total analyses recorded across all packages.

    This is the database-maturity figure that gates tier C novelty
    weights.  It is deliberately global rather than per-package: the
    question maturity answers is "has this database seen enough updates
    for 'first seen' to carry information", which is a property of the
    corpus as a whole, not of one package.
    """
    with get_connection() as conn:
        row = conn.execute("SELECT COUNT(*) AS n FROM analysis_history").fetchone()
        return row["n"] if row else 0
