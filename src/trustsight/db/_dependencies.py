"""Extracted from db.py: _dependencies."""

import os
import threading
import sqlite3
import subprocess
from pathlib import Path
from typing import Optional
from ..subproc import minimal_env
from ._connection import get_connection
from ._metadata import seed_observation_count
from ._packages import count_observations

__all__ = ['_ESTABLISHED_MIN_NAME_LENGTH', '_ESTABLISHED_OBSERVATIONS', '_OFFICIAL_PACKAGES_FILE', '_OFFICIAL_PACKAGES_ENV', '_official_names', '_official_names_lock', 'dependency_observation_count', 'dependency_observation_counts', 'dependency_table_populated', 'effective_observation_count', 'is_established_package', 'is_known_aur_package', 'official_list_path', 'official_membership', 'official_membership_known', 'official_package_names', 'record_dependency_names', 'top_dependency_names', 'top_dependency_pairs']

def is_known_aur_package(name: str) -> bool:
    """True when the watcher has a package row for *name*.

    The dependency corpus answers "has anything depended on this name",
    which is a different question from "does this package exist".  A
    companion package published the same day as the recipe that depends
    on it has no dependency observations yet, so D001 called it novel and
    D002 called it a typosquat.  The packages table is the watcher's own
    record that the name exists.
    """
    if not name:
        return False
    with get_connection() as conn:
        try:
            row = conn.execute(
                "SELECT 1 FROM packages WHERE name = ? LIMIT 1", (name,),
            ).fetchone()
        except sqlite3.OperationalError:
            return False
        return row is not None


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

#: Floor on the observation fallback: below this length a name cannot read
#: as "established" no matter its count.  The corpus records every name seen
#: in depends/provides/pkgname fields, and short strings accumulate
#: observations as abbreviation collisions rather than as packages - on the
#: seeded corpus 1,228 of the 61k names at >= 10 observations are <= 3
#: chars, and roughly 960 of those are not official-repo names (single
#: letters like 'c', 'k', 'q' at a dozen observations each are noise, and
#: 'ax' at 24 is archix' own abbreviation, not a package).  A
#: ``conflicts=('ax')`` against such a phantom blocks nothing: pacman has no
#: ``ax`` to refuse.  Short names that ARE real (go, xz, git, r) are still
#: certified by the exact official-repo branch wherever pacman data exists;
#: this floor only binds the noisy count fallback used on hosts without it.
_ESTABLISHED_MIN_NAME_LENGTH = 4

_official_names: Optional[frozenset] = None

_official_names_lock = threading.Lock()

#: Environment variable naming an official-package list to read when pacman
#: cannot answer.  The watcher image is ``python:3.12-slim`` and has no pacman,
#: so this file is how a container gets an exact answer instead of a guess.
_OFFICIAL_PACKAGES_ENV = "TRUSTSIGHT_OFFICIAL_PACKAGES"

#: Filename, inside the config directory, of the fallback official-package
#: list.  ``pacman -Slq > official-packages.txt`` is the expected producer.
_OFFICIAL_PACKAGES_FILE = "official-packages.txt"


def official_list_path() -> Optional[Path]:
    """Where the fallback official-package list would live.

    ``TRUSTSIGHT_OFFICIAL_PACKAGES`` wins so a container can mount the list
    from anywhere; otherwise the configured config directory holds it, which
    the watcher compose file mounts at ``/config-src`` and copies into the
    writable config dir at startup.
    """
    override = os.environ.get(_OFFICIAL_PACKAGES_ENV, "").strip()
    if override:
        return Path(override)
    try:
        from ..config import CONFIG_DIR

        return Path(CONFIG_DIR) / _OFFICIAL_PACKAGES_FILE
    except Exception:  # noqa: BLE001 - a missing config module is not fatal
        return None


def _read_pacman_names() -> frozenset:
    """The official names pacman knows, or an empty set when it cannot answer."""
    try:
        result = subprocess.run(
            ["pacman", "-Slq"], capture_output=True, text=True,
            check=False, timeout=30, env=minimal_env(),
        )
    except (OSError, subprocess.SubprocessError):
        return frozenset()
    return frozenset(
        line.strip().lower()
        for line in result.stdout.splitlines() if line.strip()
    )


def _read_official_file(path: Optional[Path]) -> frozenset:
    """Names from an operator-supplied official-package list.

    One name per line.  Blank lines and ``#`` comments are ignored, a
    ``repo/name`` prefix is dropped, and anything after the name (a version,
    the shape ``pacman -Sl`` prints) is discarded, so both ``pacman -Slq``
    and ``pacman -Sl`` output can feed it unchanged.
    """
    if path is None:
        return frozenset()
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return frozenset()
    names: set[str] = set()
    for line in text.splitlines():
        entry = line.strip()
        if not entry or entry.startswith("#"):
            continue
        name = entry.split()[0].rsplit("/", 1)[-1].strip().lower()
        if name:
            names.add(name)
    return frozenset(names)


def official_package_names() -> frozenset:
    """Package names in the configured official repositories.

    Read once per process via pacman, the same way ``discovery.py`` already
    queries it, and fall back to the list ``official_list_path`` names when
    pacman is unavailable or its databases have never been synced - a
    container image has neither.  An empty set means *unknown*: callers that
    cannot proceed on "unknown" must ask :func:`official_membership` rather
    than read a missing name as "not in a repository".
    """
    global _official_names
    if _official_names is None:
        with _official_names_lock:
            if _official_names is None:
                names = _read_pacman_names()
                if not names:
                    names = _read_official_file(official_list_path())
                _official_names = names
    return _official_names


def official_membership_known() -> bool:
    """Whether an official-repository answer exists at all.

    False means the machine has neither pacman nor an official-package list.
    Callers deciding *identity* (not just "is this name familiar") must not
    read a False :func:`is_established_package` as "this name is not in a
    repository" while this is False: the count fallback cannot certify
    ordinary names such as ``libnotify`` or ``zip``, and treating them as
    unknown-to-the-repos is what turns them into AUR ``-git`` providers.
    """
    # Resolve through the package namespace so a test embedding this module
    # patches one seam, the same one ``is_established_package`` uses.
    from . import official_package_names as names

    return bool(names())


def official_membership(name: str) -> Optional[bool]:
    """Whether *name* is in an official repository, or None when unknown.

    The tri-state is the point.  ``False`` is an exact "not in a repository",
    which lets a caller resolve a virtual ``Provides`` alias; ``None`` is
    "this machine cannot tell", and guessing there invents AUR packages for
    dependencies makepkg would install from ``core`` or ``extra``.
    """
    if not name:
        return None
    from . import official_package_names as names

    official = names()
    if not official:
        return None
    return name in official


def is_established_package(name: str) -> bool:
    """True when *name* is a package worth impersonating.

    Prefers the official repositories, which is an exact answer.  Falls back
    to how many packages depend on the name: a poor proxy for repo
    membership (at 10 observations it covers 30% of official packages) but
    the best available signal when pacman cannot be reached.  That fallback
    additionally demands a minimum name length - see
    ``_ESTABLISHED_MIN_NAME_LENGTH`` for the measurement behind it.
    """
    from ..deps import is_virtual_provide

    if is_virtual_provide(name):
        return False
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
    return (
        len(name) >= _ESTABLISHED_MIN_NAME_LENGTH
        and dependency_observation_count(name) >= _ESTABLISHED_OBSERVATIONS
    )

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
