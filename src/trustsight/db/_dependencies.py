"""Extracted from db.py: _dependencies."""

import threading
import sqlite3
import subprocess
from typing import Optional
from ..subproc import minimal_env
from ._connection import get_connection
from ._metadata import seed_observation_count
from ._packages import count_observations

__all__ = ['_ESTABLISHED_OBSERVATIONS', '_official_names', '_official_names_lock', 'dependency_observation_count', 'dependency_observation_counts', 'dependency_table_populated', 'effective_observation_count', 'is_established_package', 'official_package_names', 'record_dependency_names', 'top_dependency_names', 'top_dependency_pairs']

def dependency_observation_count(name: str) -> int:
    """How many times *name* has been seen as a dependency, package, or alias."""
    with get_connection() as conn:
        try:
            row = conn.execute(
                "SELECT observation_count FROM dependency_names WHERE name = ?",
                (name,),
            ).fetchone()
        except sqlite3.OperationalError:
            return 0
        return int(row["observation_count"] or 0) if row else 0

def dependency_observation_counts(names: list[str]) -> dict[str, int]:
    """Observation counts for many names in one round-trip.

    The per-name helper is fine for a handful of lookups but ruinous in a
    loop: the typosquat check ran it once per candidate.  Names absent
    from the table are absent from the result.
    """
    if not names:
        return {}
    unique = list({n for n in names if n})
    counts: dict[str, int] = {}
    with get_connection() as conn:
        # SQLITE_MAX_VARIABLE_NUMBER is 999 on older builds, so chunk.
        for start in range(0, len(unique), 900):
            chunk = unique[start:start + 900]
            placeholders = ",".join("?" * len(chunk))
            try:
                rows = conn.execute(
                    f"""SELECT name, observation_count FROM dependency_names
                        WHERE name IN ({placeholders})""",
                    chunk,
                ).fetchall()
            except sqlite3.OperationalError:
                return {}
            for row in rows:
                counts[row["name"]] = int(row["observation_count"] or 0)
    return counts

def top_dependency_names(limit: int = 5000) -> list[str]:
    """The most-depended-on names, as a popularity proxy for typosquatting.

    Observation count already ranks names by how many packages rely on
    them, so no separate "top packages" list needs shipping.
    """
    return [name for name, _ in top_dependency_pairs(limit)]

def top_dependency_pairs(limit: int = 5000) -> list[tuple[str, int]]:
    """``(name, observation_count)`` for the most-depended-on names.

    Callers that rank candidates by popularity need the count alongside
    the name; fetching it here saves them one query per candidate.
    """
    with get_connection() as conn:
        try:
            rows = conn.execute(
                """SELECT name, observation_count FROM dependency_names
                   ORDER BY observation_count DESC LIMIT ?""",
                (limit,),
            ).fetchall()
        except sqlite3.OperationalError:
            return []
        return [(r["name"], int(r["observation_count"] or 0)) for r in rows]

_ESTABLISHED_OBSERVATIONS = 10

_official_names: Optional[frozenset] = None

_official_names_lock = threading.Lock()

def official_package_names() -> frozenset:
    """Package names in the configured official repositories.

    Read once per process via pacman, the same way ``discovery.py`` already
    queries it.  An empty set is returned when pacman is unavailable or its
    databases have never been synced, and callers fall back to observation
    counts rather than failing.
    """
    global _official_names
    if _official_names is None:
        with _official_names_lock:
            if _official_names is None:
                try:
                    result = subprocess.run(
                        ["pacman", "-Slq"], capture_output=True, text=True,
                        check=False, timeout=30, env=minimal_env(),
                    )
                    _official_names = frozenset(
                        line.strip().lower()
                        for line in result.stdout.splitlines() if line.strip()
                    )
                except (OSError, subprocess.SubprocessError):
                    _official_names = frozenset()
    return _official_names

def is_established_package(name: str) -> bool:
    """True when *name* is a package worth impersonating.

    Prefers the official repositories, which is an exact answer.  Falls back
    to how many packages depend on the name: a poor proxy for repo
    membership (at 10 observations it covers 30% of official packages) but
    the best available signal when pacman cannot be reached.
    """
    if not name:
        return False
    # Resolve through the package namespace, not this module's global: the
    # public ``trustsight.db.official_package_names`` is the seam a test or an
    # embedder patches.  The module split moved this function into a submodule,
    # and its private global no longer saw the patch - a regression test that
    # stubbed the official set then passed only on a host that had pacman.
    from . import official_package_names
    official = official_package_names()
    if official:
        return name in official
    return dependency_observation_count(name) >= _ESTABLISHED_OBSERVATIONS

def dependency_table_populated() -> bool:
    """True when the dependency corpus is loaded.

    Without this the D-series cannot distinguish "never seen anywhere" from
    "no seed imported yet", and every dependency on a fresh install would
    look novel.
    """
    with get_connection() as conn:
        try:
            row = conn.execute(
                "SELECT 1 AS present FROM dependency_names LIMIT 1"
            ).fetchone()
        except sqlite3.OperationalError:
            return False
        return row is not None

def record_dependency_names(names: list[str]) -> None:
    """Fold observed dependency names into the local corpus."""
    if not names:
        return
    with get_connection() as conn:
        conn.executemany(
            """INSERT INTO dependency_names
               (name, first_seen_globally_timestamp, observation_count)
               VALUES (?, datetime('now'), 1)
               ON CONFLICT(name) DO UPDATE SET
                   observation_count = observation_count + 1""",
            [(n,) for n in names],
        )
        conn.commit()

def effective_observation_count() -> int:
    """Observations for maturity purposes: real history or the seed.

    Real analyses take over as soon as there are more of them than the
    seed asserts, so ordinary use eventually replaces the seed entirely
    and the tool never depends on external data permanently.
    """
    return max(count_observations(), seed_observation_count())
