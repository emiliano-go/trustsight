"""Extracted from db.py: _profiles."""

from datetime import datetime, timezone
import sqlite3
from typing import Optional
from ._common import log
from ._connection import get_connection
from ._packages import _RESERVED_NAMES

__all__ = ['alert_history', 'brand_new_packages_since', 'checkpoint_wal', 'forget_package', 'forget_prune', 'get_package_profile', 'introduction_rate_history', 'latest_cycle_time', 'maintainer_activity_history', 'record_alerts', 'record_cycle_events', 'save_package_profile']

def get_package_profile(package_name: str) -> Optional[dict]:
    """Return the package profile for *package_name*, or None."""
    with get_connection() as conn:
        row = conn.execute(
            "SELECT * FROM package_profiles WHERE package_name = ?",
            (package_name,),
        ).fetchone()
        return dict(row) if row else None

def save_package_profile(
    package_name: str,
    last_score: int,
    last_risk: str = "",
) -> None:
    """Insert or update the package profile."""
    # Same guard as upsert_package.  These two tables are keyed by
    # package_name directly rather than through packages(id), so they were
    # the way round the reserved-name check: a baseline artifact, or an
    # AUR package actually named __seed__, could write a row under a name
    # the rest of the code treats as internal.
    if package_name in _RESERVED_NAMES or package_name.startswith("__"):
        raise ValueError(f"reserved package name: {package_name!r}")
    with get_connection() as conn:
        conn.execute(
            """INSERT INTO package_profiles
               (package_name, observation_count, last_score, last_risk, last_seen)
               VALUES (?, 1, ?, ?, datetime('now'))
               ON CONFLICT(package_name) DO UPDATE SET
                   observation_count = observation_count + 1,
                   last_score = excluded.last_score,
                   last_risk = excluded.last_risk,
                   last_seen = excluded.last_seen""",
            (package_name, last_score, last_risk),
        )
        conn.commit()

def record_cycle_events(events: list[dict]) -> None:
    """Persist one corpus cycle's adoption-feed events (Class D).

    *events* is a list of dicts with ``package_name``, ``cycle_time``,
    ``status`` (added/modified/removed), ``maintainer`` and ``last_modified``.
    Rows are upserted so a cycle can be replayed without duplicating history.
    """
    if not events:
        return
    with get_connection() as conn:
        conn.executemany(
            """INSERT INTO cycle_events
               (package_name, cycle_time, status, maintainer, last_modified)
               VALUES (:package_name, :cycle_time, :status, :maintainer,
                       :last_modified)
               ON CONFLICT(package_name, cycle_time) DO UPDATE SET
                   status = excluded.status,
                   maintainer = excluded.maintainer,
                   last_modified = excluded.last_modified""",
            events,
        )
        conn.commit()

def brand_new_packages_since(cycle_time: int) -> list[dict]:
    """Packages added at or after *cycle_time*, with H021/H104 state.

    G011 pools brand-new packages by maintainer across a window, not just
    across one cycle: the observed placeholder burst spans several cycles,
    and the current cycle's ``processed`` set cannot see the earlier members.
    ``cycle_events`` supplies the window and the maintainer; the latest
    analysis supplies the H021 (brand-new) and H104 (placeholder) facts.

    A package with no recorded H021 is not brand-new to the AUR, even when
    this watcher has only just seen it.  A placeholder flag comes from the
    latest analysis, so a recipe that was later filled in does not stay
    counted as a placeholder.

    ``maintainer_established`` is true when the account has any cycle event
    before the window or is already known to the seed.  That is the gate
    that keeps a long-standing maintainer's legitimate multi-package launch
    out of the finding.
    """
    with get_connection() as conn:
        rows = conn.execute(
            """WITH latest AS (
                   SELECT package_id, MAX(id) AS history_id
                   FROM analysis_history
                   GROUP BY package_id
               ),
               firsts AS (
                   SELECT maintainer, MIN(cycle_time) AS first_cycle
                   FROM cycle_events
                   WHERE maintainer != ''
                   GROUP BY maintainer
               )
               SELECT ce.package_name AS package,
                      ce.maintainer AS maintainer,
                      MIN(ce.cycle_time) AS cycle_time,
                      f.first_cycle,
                      MAX(CASE WHEN tr.rule_id = 'H021' THEN 1 ELSE 0 END)
                          AS brand_new,
                      MAX(CASE WHEN tr.rule_id = 'H104' THEN 1 ELSE 0 END)
                          AS placeholder
               FROM cycle_events ce
               JOIN firsts f ON f.maintainer = ce.maintainer
               JOIN packages p ON p.name = ce.package_name
               JOIN latest l ON l.package_id = p.id
               JOIN triggered_rules tr ON tr.history_id = l.history_id
               WHERE ce.status = 'added'
                 AND ce.cycle_time >= ?
                 AND ce.maintainer != ''
               GROUP BY ce.package_name, ce.maintainer, f.first_cycle""",
            (int(cycle_time),),
        ).fetchall()
    if not rows:
        return []

    from ._maintainers import is_maintainer_globally_novel

    seen: dict[str, bool] = {}
    out: list[dict] = []
    for row in rows:
        record = dict(row)
        maintainer = record["maintainer"]
        if maintainer not in seen:
            seen[maintainer] = not is_maintainer_globally_novel(maintainer)
        first_cycle = record.pop("first_cycle", None)
        record["brand_new"] = bool(record.get("brand_new"))
        record["placeholder"] = bool(record.get("placeholder"))
        record["maintainer_established"] = bool(
            seen[maintainer]
            or (first_cycle is not None and int(first_cycle) < int(cycle_time))
        )
        out.append(record)
    return out


def introduction_rate_history(cycles: int | None = None) -> list[dict]:
    """Per-cycle introduction counts, oldest first (Class D H073).

    Returns ``[{cycle_time, introduced}]`` for every recorded cycle with at
    least one event; *cycles* limits the number returned (most recent) when
    given.
    """
    with get_connection() as conn:
        rows = conn.execute(
            """SELECT cycle_time,
                      SUM(CASE WHEN status = 'added' THEN 1 ELSE 0 END) AS introduced
               FROM cycle_events
               GROUP BY cycle_time
               ORDER BY cycle_time ASC"""
        ).fetchall()
    out = [{"cycle_time": r["cycle_time"], "introduced": int(r["introduced"] or 0)}
           for r in rows]
    if cycles is not None:
        return out[-cycles:]
    return out

def latest_cycle_time() -> int:
    """The most recent cycle_time recorded in cycle_events, or 0."""
    with get_connection() as conn:
        row = conn.execute(
            "SELECT MAX(cycle_time) AS t FROM cycle_events"
        ).fetchone()
    return int(row["t"] or 0)

def maintainer_activity_history() -> list[dict]:
    """Per-maintainer per-cycle event counts, oldest first (Class D H058).

    Returns ``[{maintainer, cycle_time, activity}]`` covering every
    recorded cycle, so a maintainer's own past activity can serve as the
    baseline for a deviation check.
    """
    with get_connection() as conn:
        rows = conn.execute(
            """SELECT maintainer, cycle_time, COUNT(*) AS activity
               FROM cycle_events
               WHERE maintainer != ''
               GROUP BY maintainer, cycle_time
               ORDER BY cycle_time ASC, maintainer ASC"""
        ).fetchall()
    return [dict(r) for r in rows]

def checkpoint_wal() -> None:
    """Fold the write-ahead log back into the database after a heavy cycle.

    Best effort, and deliberately ``PASSIVE``: a ``TRUNCATE`` checkpoint
    needs an exclusive lock and waits out every concurrent reader, turning a
    completed cycle into a stall; ``PASSIVE`` copies what it can without
    blocking.  The file stays bounded by ``journal_size_limit`` and the
    deferred ``wal_autocheckpoint`` the writer connection sets.  A reader
    holding the database open must not turn a completed cycle into a failure.
    """
    try:
        with get_connection() as conn:
            conn.execute("PRAGMA wal_checkpoint(PASSIVE)")
    except sqlite3.Error:
        log.debug("wal checkpoint failed", exc_info=True)

def forget_package(name: str) -> dict[str, int]:
    """Delete all rows for *name* across every table that references it.

    Returns counts of deleted rows keyed by table name.  Raises ValueError
    for reserved names.
    """
    if name in _RESERVED_NAMES or name.startswith("__"):
        raise ValueError(f"reserved name cannot be removed: {name}")
    counts: dict[str, int] = {}
    with get_connection() as conn:
        pkg = conn.execute("SELECT id FROM packages WHERE name = ?", (name,)).fetchone()
        if pkg is None:
            return {}
        pkg_id = pkg["id"]

        # alert_state, pkgbuild_snapshots, package_profiles, package_properties,
        # property_transitions and contact_ledger are keyed by package_name
        # directly.  observed_hosts is corpus-wide, not owned by a package.
        for table in ("alert_state", "pkgbuild_snapshots", "package_profiles",
                      "package_properties", "property_transitions",
                      "contact_ledger"):
            cur = conn.execute(f"DELETE FROM {table} WHERE package_name = ?", (name,))
            counts[table] = cur.rowcount

        # triggered_rules joins through analysis_history.
        cur = conn.execute(
            "DELETE FROM triggered_rules WHERE history_id IN "
            "(SELECT id FROM analysis_history WHERE package_id = ?)",
            (pkg_id,),
        )
        counts["triggered_rules"] = cur.rowcount

        cur = conn.execute("DELETE FROM analysis_history WHERE package_id = ?", (pkg_id,))
        counts["analysis_history"] = cur.rowcount

        # source_urls has FK to packages(id).  Reassign to the sentinel row
        # (id 0) rather than deleting; the seed may have contributed data the
        # user wants to keep.
        conn.execute(
            "UPDATE source_urls SET first_seen_package_id = 0 WHERE first_seen_package_id = ?",
            (pkg_id,),
        )
        # Per-package hashed maintainer records are owned by the package, so
        # they are removed with it.
        cur = conn.execute(
            "DELETE FROM package_maintainers_hashed WHERE package_id = ?", (pkg_id,)
        )
        counts["package_maintainers_hashed"] = cur.rowcount
        # Legacy plaintext table, if it still exists.
        try:
            conn.execute(
                "UPDATE maintainers SET first_seen_package_id = 0 WHERE first_seen_package_id = ?",
                (pkg_id,),
            )
        except sqlite3.OperationalError:
            pass

        cur = conn.execute("DELETE FROM packages WHERE id = ?", (pkg_id,))
        counts["packages"] = cur.rowcount
        conn.commit()
    return counts

def forget_prune(
    aur_names: set[str],
    dry_run: bool = False,
) -> dict[str, dict[str, int]]:
    """Remove all tracked packages not present in *aur_names*.

    Returns ``{name: {table: count, ...}}`` for every package that would
    be or was removed.
    """
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT id, name FROM packages WHERE name NOT IN ('__seed__')"
        ).fetchall()
    removed: dict[str, dict[str, int]] = {}
    for r in rows:
        if r["name"] in aur_names:
            continue
        if dry_run:
            removed[r["name"]] = {}
        else:
            removed[r["name"]] = forget_package(r["name"])
    return removed

def record_alerts(pairs: list[tuple[str, str]], now: str | None = None) -> list[tuple[str, str]]:
    """Record ``(package, rule)`` alerts and return the ones not seen before.

    ``full-aur --watch`` runs the same corpus cycle repeatedly, and a
    finding that has already been reported is not news: a maintainer who
    adopted forty packages last night would otherwise be re-announced on
    every cycle until the metadata changes again.  The first time a pair
    arrives it is returned (and stored); afterwards only its counter and
    ``last_sent`` move, so the operator sees each finding once and the
    history still records how persistent it was.
    """
    if not pairs:
        return []
    stamp = now or datetime.now(timezone.utc).isoformat()
    fresh: list[tuple[str, str]] = []
    with get_connection() as conn:
        for package_name, rule_id in pairs:
            row = conn.execute(
                "SELECT count FROM alert_state WHERE package_name = ? AND rule_id = ?",
                (package_name, rule_id),
            ).fetchone()
            if row is None:
                conn.execute(
                    "INSERT INTO alert_state (package_name, rule_id, first_seen, "
                    "last_sent, count) VALUES (?, ?, ?, ?, 1)",
                    (package_name, rule_id, stamp, stamp),
                )
                fresh.append((package_name, rule_id))
            else:
                conn.execute(
                    "UPDATE alert_state SET last_sent = ?, count = count + 1 "
                    "WHERE package_name = ? AND rule_id = ?",
                    (stamp, package_name, rule_id),
                )
        conn.commit()
    return fresh

def alert_history(package_name: str | None = None) -> list[dict]:
    """Stored alert rows, most recently sent first."""
    query = (
        "SELECT package_name, rule_id, first_seen, last_sent, count "
        "FROM alert_state"
    )
    params: tuple = ()
    if package_name:
        query += " WHERE package_name = ?"
        params = (package_name,)
    query += " ORDER BY last_sent DESC, package_name"
    with get_connection() as conn:
        return [dict(row) for row in conn.execute(query, params).fetchall()]
