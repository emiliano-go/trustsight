"""Schema creation and migrations for the local database."""

import sqlite3
import warnings
from typing import Optional

from ..rule_id_history import RENAMED_RULE_IDS
from ..maintainer_email import normalize_domain
from ._common import log

def init_db():
    """Create all tables and indexes if they do not exist."""
    from ._connection import get_connection

    with get_connection() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS packages (
                id INTEGER PRIMARY KEY,
                name TEXT UNIQUE NOT NULL,
                current_version TEXT,
                current_maintainer TEXT DEFAULT '',
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

            /* Hashed maintainer identities for novelty detection.
               Names and emails are stored only as salted SHA-256 hashes;
               no plaintext identity is retained after migration. */
            CREATE TABLE IF NOT EXISTS maintainers_hashed (
                name_hash TEXT NOT NULL,
                email_hash TEXT,
                first_seen TEXT,
                package_count INTEGER DEFAULT 0,
                packages TEXT,
                source TEXT,
                PRIMARY KEY (name_hash, email_hash)
            );
            CREATE INDEX IF NOT EXISTS idx_maintainers_hashed_name
                ON maintainers_hashed(name_hash);
            CREATE INDEX IF NOT EXISTS idx_maintainers_hashed_email
                ON maintainers_hashed(email_hash);

            /* Per-package hashed maintainer records.  This replaces the old
               plaintext ``maintainers`` table while keeping the same
               first-seen-for-this-package semantics. */
            CREATE TABLE IF NOT EXISTS package_maintainers_hashed (
                name_hash TEXT NOT NULL,
                email_hash TEXT,
                package_id INTEGER NOT NULL,
                first_seen TEXT,
                PRIMARY KEY (name_hash, email_hash, package_id),
                FOREIGN KEY (package_id) REFERENCES packages(id)
            );
            CREATE INDEX IF NOT EXISTS idx_package_maintainers_hashed_name
                ON package_maintainers_hashed(name_hash);

            /* Seed-specific metadata that must travel with the hashed
               maintainer corpus, especially the salt. */
            CREATE TABLE IF NOT EXISTS seed_meta (
                key TEXT PRIMARY KEY,
                value TEXT
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

            CREATE TABLE IF NOT EXISTS metadata (
                key TEXT PRIMARY KEY,
                value TEXT
            );

            CREATE TABLE IF NOT EXISTS maintainer_counts (
                name TEXT PRIMARY KEY,
                count INTEGER
            );

            /* Every dependency name ever observed in the AUR, so that a
               name nobody has ever depended on can be recognised as novel.
               Package names and provides() aliases are recorded here too:
               a dependency satisfied by an alias is not novel either. */
            CREATE TABLE IF NOT EXISTS dependency_names (
                id INTEGER PRIMARY KEY,
                name TEXT UNIQUE,
                first_seen_globally_timestamp TEXT,
                observation_count INTEGER,
                /* How much of observation_count came from the last imported
                   seed or baseline snapshot.  Kept apart from the locally
                   observed remainder so re-importing a snapshot replaces
                   its own contribution instead of adding to it a second
                   time (a baseline is a snapshot of the whole corpus). */
                seed_observation_count INTEGER NOT NULL DEFAULT 0
            );

            CREATE INDEX IF NOT EXISTS idx_dependency_names_name
                ON dependency_names(name);
            CREATE INDEX IF NOT EXISTS idx_source_urls_url ON source_urls(url);
            CREATE INDEX IF NOT EXISTS idx_packages_name ON packages(name);
            CREATE INDEX IF NOT EXISTS idx_history_package ON analysis_history(package_id);

            /* top_dependency_names() asks for the most-observed names on
               every analysis; without this it is a full scan plus a sort. */
            CREATE INDEX IF NOT EXISTS idx_dependency_names_count
                ON dependency_names(observation_count DESC);

            CREATE TABLE IF NOT EXISTS aur_cache (
                name TEXT PRIMARY KEY,
                version TEXT NOT NULL,
                last_modified INTEGER,
                cached_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS package_profiles (
                package_name TEXT PRIMARY KEY,
                observation_count INTEGER DEFAULT 0,
                last_score INTEGER,
                last_risk TEXT DEFAULT '',
                last_seen TEXT
            );

            CREATE TABLE IF NOT EXISTS package_properties (
                package_name TEXT NOT NULL,
                property_key TEXT NOT NULL,
                value_hash TEXT NOT NULL,
                value TEXT,
                stable_for_n INTEGER DEFAULT 0,
                first_seen TEXT NOT NULL,
                last_changed TEXT NOT NULL,
                PRIMARY KEY (package_name, property_key)
            );

            CREATE TABLE IF NOT EXISTS property_transitions (
                id INTEGER PRIMARY KEY,
                package_name TEXT NOT NULL,
                property_key TEXT NOT NULL,
                old_value TEXT,
                new_value TEXT NOT NULL,
                observed_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_property_transitions_package
                ON property_transitions(package_name);
            CREATE INDEX IF NOT EXISTS idx_property_transitions_key
                ON property_transitions(package_name, property_key);

            CREATE TABLE IF NOT EXISTS pkgbuild_snapshots (
                package_name TEXT PRIMARY KEY,
                pkgbuild_text TEXT NOT NULL,
                srcinfo_text TEXT,
                install_text TEXT,
                version TEXT NOT NULL,
                last_modified INTEGER DEFAULT 0,
                captured_at TEXT NOT NULL,
                /* Exactly one prior revision, written when the current
                   text changes.  Bounded on purpose: the analysis needs the
                   immediately preceding recipe, and an unbounded per-
                   package history would multiply the corpus by its depth.
                   A baseline import never seeds these (A13). */
                previous_pkgbuild_text TEXT,
                previous_srcinfo_text TEXT,
                previous_install_text TEXT,
                previous_version TEXT,
                previous_last_modified INTEGER DEFAULT 0,
                previous_captured_at TEXT
            );

            /* the corpus as documents. Per observed package
               version, the RecipeDoc's scalars and arrays (never the full
               text) are stored so "has this exact source-array tuple
               appeared before" is set membership rather than a statistical
               guess.  Bounded per package like every other corpus table. */
            CREATE TABLE IF NOT EXISTS recipe_observations (
                package_name TEXT NOT NULL,
                observed_at TEXT NOT NULL,
                scalars_json TEXT NOT NULL,
                PRIMARY KEY (package_name, observed_at)
            );

            CREATE TABLE IF NOT EXISTS recipe_array_observations (
                package_name TEXT NOT NULL,
                array_name TEXT NOT NULL,
                entries_hash TEXT NOT NULL,
                observed_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_recipe_array_observations
                ON recipe_array_observations(
                    package_name, array_name, entries_hash);

            CREATE TABLE IF NOT EXISTS alert_state (
                package_name TEXT NOT NULL,
                rule_id TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_sent TEXT,
                count INTEGER DEFAULT 1,
                PRIMARY KEY (package_name, rule_id)
            );

            /* Durable delivery queue.  A cycle records the alert document
               before it tries any sink, and a failed POST stays here for the
               next cycle instead of disappearing with the log line. */
            CREATE TABLE IF NOT EXISTS alert_outbox (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                webhook_id TEXT NOT NULL,
                webhook_timestamp INTEGER NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                next_attempt_at TEXT,
                ntfy_delivered INTEGER NOT NULL DEFAULT 0,
                feed_delivered INTEGER NOT NULL DEFAULT 0,
                parked_at TEXT,
                last_error TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_alert_outbox_pending
                ON alert_outbox(parked_at, next_attempt_at);

            /* Campaign alert mode: corroborated campaigns that keep a
               package's scope "primed" for a bounded number of observations.
               TTL is in observation units (see OBSERVATION_SEQ_KEY), not
               wall-clock: the tool must not consult a clock it does not
               control.  An expired campaign is filtered out by query, so
               expiry is structural rather than a sweep. */
            CREATE TABLE IF NOT EXISTS campaign_alerts (
                campaign_id TEXT PRIMARY KEY,
                scope_json TEXT NOT NULL DEFAULT '[]',
                source TEXT NOT NULL DEFAULT '',
                activated_at_obs INTEGER NOT NULL,
                ttl_obs INTEGER NOT NULL,
                expiry_announced INTEGER NOT NULL DEFAULT 0,
                /* Re-activation pressure (M006): a class that re-arms faster
                   than [alerts] campaign_min_reactivation_observations is
                   still refreshed, but the count and span let the pipeline
                   report the over-frequent re-arming as a tool-health note. */
                activation_count INTEGER NOT NULL DEFAULT 1,
                first_activated_at_obs INTEGER NOT NULL DEFAULT 0,
                last_activated_at_obs INTEGER NOT NULL DEFAULT 0
            );

            /* Class D adoption feed: one row per package per corpus cycle.
               The metadata-dump diff between cycles is the first-class
               stream the corpus sweep consumes; H045/H055/H052/H073 read
               introduction events and per-cycle timestamps from it. */
            CREATE TABLE IF NOT EXISTS cycle_events (
                package_name TEXT NOT NULL,
                cycle_time INTEGER NOT NULL,
                status TEXT NOT NULL,
                maintainer TEXT NOT NULL DEFAULT '',
                last_modified INTEGER,
                PRIMARY KEY (package_name, cycle_time)
            );
            CREATE INDEX IF NOT EXISTS idx_cycle_events_cycle
                ON cycle_events(cycle_time);

            /* IOC Federation baseline entries (v0.12.0).  One row per
               (type, value, source).  Importing a baseline for a source
               replaces all rows for that source; expired rows are kept so
               historical reports remain attributable. */
            CREATE TABLE IF NOT EXISTS ioc_entries (
                id INTEGER PRIMARY KEY,
                type TEXT NOT NULL,
                value TEXT NOT NULL,
                source TEXT NOT NULL,
                confidence TEXT,
                provenance TEXT,
                campaign TEXT,
                added TEXT,
                expires_at TEXT,
                imported_at TEXT NOT NULL DEFAULT (datetime('now')),
                shape TEXT,
                UNIQUE(type, value, source)
            );
            CREATE INDEX IF NOT EXISTS idx_ioc_entries_source
                ON ioc_entries(source);
            CREATE INDEX IF NOT EXISTS idx_ioc_entries_value
                ON ioc_entries(value);
            CREATE INDEX IF NOT EXISTS idx_ioc_entries_expires
                ON ioc_entries(expires_at);

            /* The imported watchlist: the package names and salted
               maintainer hashes a signed ``watchlist-*`` release carries,
               ingested with ``trustsight watchlist update``.  Kept apart
               from the operator's hand-curated watchlist.json and unioned
               with it at load, so a release import never clobbers the
               operator's own entries.  Maintainer rows are salted SHA-256,
               the same pseudonymous form the baseline seed uses; package
               names are public and stored as written. */
            CREATE TABLE IF NOT EXISTS watchlist_entries (
                id INTEGER PRIMARY KEY,
                kind TEXT NOT NULL,
                value TEXT NOT NULL,
                label TEXT,
                source TEXT NOT NULL,
                imported_at TEXT NOT NULL DEFAULT (datetime('now')),
                UNIQUE(kind, value, source)
            );
            CREATE INDEX IF NOT EXISTS idx_watchlist_entries_kind
                ON watchlist_entries(kind);

            /* (T-series): the ecosystem index the temporal
               rules read.  One row per signing key and per maintainer
               domain the corpus has ever observed, with its first-seen
               stamp, so "is this key/domain new to the ecosystem" is set
               membership rather than a guess.  Bounded by row count. */
            CREATE TABLE IF NOT EXISTS observed_signing_keys (
                key TEXT PRIMARY KEY,
                first_seen TEXT
            );
            CREATE TABLE IF NOT EXISTS observed_maintainer_domains (
                domain TEXT PRIMARY KEY,
                first_seen TEXT
            );

            /* added literals per package, so G002 (Shared
               Added Literal) can join across packages instead of scanning
               every package's diff in memory each cycle.  The literal is
               stored bounded; the join is over its content, so two packages
               that added the same blob meet here. */
            CREATE TABLE IF NOT EXISTS observed_added_literals (
                package_name TEXT NOT NULL,
                literal TEXT NOT NULL,
                literal_hash TEXT,
                literal_len INTEGER NOT NULL,
                observed_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_added_literals_package
                ON observed_added_literals(package_name);

            /* G001's per-cycle feed: the hosts a package *gained* this
               cycle, written where the source_hosts property transition is
               recorded.  Cleared at cycle start (clear_correlation_feeds),
               so a host gained months ago cannot re-join a later cycle. */
            CREATE TABLE IF NOT EXISTS observed_gained_hosts (
                package_name TEXT NOT NULL,
                host TEXT NOT NULL,
                observed_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_gained_hosts_package
                ON observed_gained_hosts(package_name);

            /* G003's per-cycle adoption feed: one row per maintainer
               transition observed this cycle.  A package re-processed with
               an unchanged maintainer is not an adoption, and a historical
               transition cannot re-arm a campaign. */
            CREATE TABLE IF NOT EXISTS observed_adoptions (
                package_name TEXT NOT NULL,
                maintainer TEXT NOT NULL,
                predicate TEXT NOT NULL,
                observed_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_observed_adoptions_package
                ON observed_adoptions(package_name);

            /* three indexed views the G-series correlates
               over at cycle end (O(cycle) queries, not O(packages^2)).
               Each reads a per-cycle table, so the join semantics match the
               rule contract: "in the window" is "this cycle". */
            DROP VIEW IF EXISTS gained_hosts_window;
            CREATE VIEW gained_hosts_window AS
                SELECT package_name, host, observed_at
                FROM observed_gained_hosts;

            DROP VIEW IF EXISTS added_literal_hashes;
            CREATE VIEW added_literal_hashes AS
                SELECT package_name,
                       COALESCE(literal_hash, literal) AS literal_hash,
                       literal_len,
                       observed_at
                FROM observed_added_literals;

            /* G004's feed: the remote upstream dependencies each processed
               package added this cycle, as (dependency, host) pairs.  The
               table is cleared at cycle start and repopulated by the
               corpus writer, so a row is always this cycle's addition and
               a prior cycle's row cannot re-fire the join. */
            CREATE TABLE IF NOT EXISTS observed_upstream_deps (
                package_name TEXT NOT NULL,
                dependency_name TEXT NOT NULL,
                host TEXT NOT NULL,
                observed_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_upstream_deps_package
                ON observed_upstream_deps(package_name);
            CREATE VIEW IF NOT EXISTS upstream_dep_additions AS
                SELECT package_name, dependency_name, host, observed_at
                FROM observed_upstream_deps;

            DROP VIEW IF EXISTS adoption_events;
            CREATE VIEW adoption_events AS
                SELECT package_name, maintainer, predicate, observed_at
                FROM observed_adoptions;

            /* The Contact Ledger (spec: contact-ledger): the innate layer's
               memory of first contact.  Append-only and cycle-versioned; one
               row the first time a package is seen to introduce a given
               (kind, value) to the corpus.  Weight 0 and warm-only by
               construction: it is A13 state, never a rule, and never enters
               the score or a replayable artifact.  Corrections are new rows. */
            CREATE TABLE IF NOT EXISTS contact_ledger (
                id INTEGER PRIMARY KEY,
                package_name TEXT NOT NULL,
                kind TEXT NOT NULL,
                value TEXT NOT NULL,
                maintainer TEXT NOT NULL DEFAULT '',
                cycle_time INTEGER NOT NULL,
                observed_at TEXT NOT NULL,
                UNIQUE(package_name, kind, value)
            );
            CREATE INDEX IF NOT EXISTS idx_contact_ledger_cycle
                ON contact_ledger(cycle_time);
            CREATE INDEX IF NOT EXISTS idx_contact_ledger_value
                ON contact_ledger(kind, value);

            /* The corpus-wide host-first-seen store G009 reads: one row the
               first time a canonical source host is observed at all.  G001's
               gained_hosts_window is the per-diff view; this is the ledger. */
            CREATE TABLE IF NOT EXISTS observed_hosts (
                host TEXT PRIMARY KEY,
                first_seen TEXT NOT NULL
            );
        """)
        _migrate(conn)
        conn.commit()

_ADDED_COLUMNS = {
    "packages": {
        "current_maintainer": "TEXT DEFAULT ''",
        # H086: whether the AUR reported this package as orphaned the last
        # time we asked.  -1 means "never asked", which is not the same as
        # "was not orphaned": an adoption can only be claimed against a
        # recorded prior observation, never against an absence of one.
        "aur_orphaned": "INTEGER DEFAULT -1",
    },
    # The ``.install`` scriptlet captured beside the PKGBUILD, so the corpus
    # path can scan it for an unconditional root fetch/write at install time.
    "pkgbuild_snapshots": {
        "install_text": "TEXT",
        # G004 compares this cycle's committed remote dependencies against
        # the last recorded set.  Only the live corpus writer populates it;
        # a baseline import leaves it NULL so a signed artifact cannot seed
        # prior state and suppress an addition (A13).
        "manifest_deps": "TEXT",
        # Complete normalized manifest/workflow state for U-series deltas.
        # Live writer only; baseline imports leave it NULL (A13).
        "manifest_state": "TEXT",
        "previous_pkgbuild_text": "TEXT",
        "previous_srcinfo_text": "TEXT",
        "previous_install_text": "TEXT",
        "previous_version": "TEXT",
        "previous_last_modified": "INTEGER DEFAULT 0",
        "previous_captured_at": "TEXT",
    },
    # M006 re-activation pressure: how often a campaign class has re-armed and
    # the observation span over which it did so.
    "campaign_alerts": {
        "activation_count": "INTEGER NOT NULL DEFAULT 1",
        "first_activated_at_obs": "INTEGER NOT NULL DEFAULT 0",
        "last_activated_at_obs": "INTEGER NOT NULL DEFAULT 0",
    },
    # The observed shape behind a federated `upstream_repo` indicator
    # (`exfil` or `history_sweep`); empty for every other IOC type.
    "ioc_entries": {
        "shape": "TEXT",
    },
    # G002 joins on a digest of the full literal; the stored text is the
    # bounded copy kept for diagnostics.
    "observed_added_literals": {
        "literal_hash": "TEXT",
    },
    # A seed or baseline import replaces its own contribution to the
    # dependency corpus; the local remainder is preserved.
    "dependency_names": {
        "seed_observation_count": "INTEGER NOT NULL DEFAULT 0",
    },
}

def _migrate(conn: sqlite3.Connection) -> None:
    """Add columns missing from a database created by an older version."""
    for table, columns in _ADDED_COLUMNS.items():
        try:
            existing = {
                row["name"]
                for row in conn.execute(f"PRAGMA table_info({table})").fetchall()
            }
        except sqlite3.OperationalError:
            continue
        if not existing:
            continue
        for name, decl in columns.items():
            if name not in existing:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {decl}")

    # v0.12.0: plaintext maintainer names are migrated to salted hashes.
    # The old table is renamed rather than dropped so the migration is
    # reversible and any data attached to it remains inspectable.
    _migrate_plaintext_maintainers(conn)

    _migrate_rule_ids(conn)
    _repair_first_observation_adoptions(conn)
    _migrate_dependency_seed_counts(conn)
    _migrate_observed_domains(conn)

_SCHEMA_VERSION = 1

def _migrate_observed_domains(conn: sqlite3.Connection) -> int:
    """Collapse maintainer domains the old extractor stored with the bracket.

    The domain came from everything after ``@``, so ``Name <user@Lini.de>``
    recorded ``lini.de>`` and ``user@domain (comment)`` recorded
    ``domain (comment)``.  Normalize every row, drop empty ones, and merge a
    collision on the earlier ``first_seen`` so the novelty window stays
    conservative.

    One-shot, keyed in ``metadata``: the writer now normalizes, so only rows
    from an older database need this.
    """
    key = "observed_domains_normalized_v1"
    if conn.execute(
        "SELECT 1 FROM metadata WHERE key = ?", (key,)
    ).fetchone():
        return 0
    rows = conn.execute(
        "SELECT domain, first_seen FROM observed_maintainer_domains"
    ).fetchall()
    merged: dict[str, Optional[str]] = {}
    for row in rows:
        domain = normalize_domain(row["domain"])
        if not domain:
            continue
        first = row["first_seen"]
        current = merged.get(domain)
        if domain not in merged or (first and (current is None or first < current)):
            merged[domain] = first
    conn.execute("DELETE FROM observed_maintainer_domains")
    conn.executemany(
        """INSERT OR REPLACE INTO observed_maintainer_domains(
               domain, first_seen) VALUES (?, ?)""",
        merged.items(),
    )
    conn.execute(
        "INSERT OR REPLACE INTO metadata (key, value) VALUES (?, '1')",
        (key,),
    )
    if len(merged) != len(rows):
        log.info(
            "Normalized %d observed maintainer domain(s) into %d",
            len(rows), len(merged),
        )
    return len(rows)

def _migrate_dependency_seed_counts(conn: sqlite3.Connection) -> int:
    """Split pre-0.23 dependency totals into seed and local contributions.

    Before ``seed_observation_count`` existed, the table held one total and
    every import added the whole baseline onto it, so an install that fetched
    a seed twice had doubled counts.  Those rows cannot be split after the
    fact: the old code kept no record of which part was the snapshot.  The
    only safe reading is that the whole total came from the snapshot, because
    every seed fetch contributed the entire corpus.  Marking it that way lets
    the next import subtract it and replace it, healing the inflated counts.
    Locally observed counts recorded before the upgrade are dropped at that
    point; they are re-observed by ordinary use and are far smaller than the
    corpus.

    One-shot, keyed in ``metadata``: re-running the update on a database that
    already tracks the split would relabel local observations as seed.
    """
    key = "dependency_seed_counts_v1"
    if conn.execute(
        "SELECT 1 FROM metadata WHERE key = ?", (key,)
    ).fetchone():
        return 0
    cur = conn.execute(
        "UPDATE dependency_names SET seed_observation_count = observation_count"
    )
    conn.execute(
        "INSERT OR REPLACE INTO metadata (key, value) VALUES (?, '1')",
        (key,),
    )
    if cur.rowcount:
        log.info(
            "Marked %d dependency row(s) as seed-derived for the count split",
            cur.rowcount,
        )
    return cur.rowcount

def _repair_first_observation_adoptions(conn: sqlite3.Connection) -> int:
    """Remove first-submission rows the old pipeline mislabeled as H086.

    A package absent from the previous snapshot was recorded as
    ``"" -> maintainer``.  The ``adoption_events`` view cannot tell that from
    a real orphan adoption, so identify the bug's rows by the package's
    first cycle event: it was *added* by the same maintainer the transition
    names.  A real orphan adoption by a different maintainer is kept.

    One-shot, keyed in ``metadata``: the write path no longer creates these
    rows, and deleting history on every startup would be surprising.
    """
    key = "maintainer_first_observation_repair_v1"
    if conn.execute(
        "SELECT 1 FROM metadata WHERE key = ?", (key,)
    ).fetchone():
        return 0
    cur = conn.execute("""
        DELETE FROM property_transitions
        WHERE id IN (
            SELECT pt.id
            FROM property_transitions pt
            JOIN (
                SELECT package_name, MIN(cycle_time) AS cycle_time
                FROM cycle_events
                GROUP BY package_name
            ) first_cycle ON first_cycle.package_name = pt.package_name
            JOIN cycle_events ce
              ON ce.package_name = pt.package_name
             AND ce.cycle_time = first_cycle.cycle_time
            WHERE pt.property_key = 'maintainer'
              AND COALESCE(json_extract(pt.old_value, '$'), '') = ''
              AND ce.status = 'added'
              AND lower(ce.maintainer) =
                  lower(COALESCE(json_extract(pt.new_value, '$'), ''))
        )
    """)
    conn.execute(
        "INSERT OR REPLACE INTO metadata (key, value) VALUES (?, '1')",
        (key,),
    )
    if cur.rowcount:
        log.info(
            "Removed %d first-observation row(s) misrecorded as adoptions",
            cur.rowcount,
        )
    return cur.rowcount

def _migrate_rule_ids(conn: sqlite3.Connection) -> None:
    """Rewrite stored rule ids for the heuristic rules renamed to ``H``.

    Alert de-duplication keys on ``(package_name, rule_id)``.  Without this,
    the release that renames ``R060`` to ``H015`` makes every alert an
    operator has already seen look new, and the first run after upgrading
    re-notifies for the entire watchlist.

    The rewrite cannot collide: the mapping is injective and ``H`` ids never
    existed before it, so no updated row can land on a primary key that is
    already occupied.
    """
    if conn.execute("PRAGMA user_version").fetchone()[0] >= _SCHEMA_VERSION:
        return
    pairs = [(new, old) for old, new in RENAMED_RULE_IDS.items()]
    conn.executemany(
        "UPDATE alert_state SET rule_id = ? WHERE rule_id = ?", pairs)
    conn.executemany(
        "UPDATE triggered_rules SET rule_id = ? WHERE rule_id = ?", pairs)
    # A literal, because PRAGMA does not take bound parameters. The value is
    # a module constant, never anything read from a database or a diff.
    conn.execute(f"PRAGMA user_version = {_SCHEMA_VERSION:d}")

def _migrate_plaintext_maintainers(conn: sqlite3.Connection) -> None:
    """Hash existing plaintext maintainer rows and retire the old table.

    Only runs when the legacy ``maintainers`` table has rows.  Empty new
    databases keep the plaintext table so per-package novelty works before
    the first seed import; the table is renamed when a seed is imported.
    """
    tables = {
        row["name"]
        for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
    }
    if "maintainers" not in tables:
        return

    row_count = conn.execute("SELECT COUNT(*) AS n FROM maintainers").fetchone()["n"]
    if row_count == 0:
        return

    warnings.warn(
        "Plaintext maintainers table detected; migrating to salted hashes. "
        "The old table will be renamed to maintainers_deprecated_backup.",
        stacklevel=2,
    )

    from ._connection import _ensure_salt, _hash_maintainer_rows

    salt = _ensure_salt(conn)
    _hash_maintainer_rows(conn, salt)
    # Drop any leftover backup from a previous failed migration before
    # renaming.  A previous run may have hashed the rows but crashed
    # before the RENAME, leaving both tables in place.
    if "maintainers_deprecated_backup" in tables:
        conn.execute("DROP TABLE IF EXISTS maintainers_deprecated_backup")
    conn.execute(
        "ALTER TABLE maintainers RENAME TO maintainers_deprecated_backup"
    )
    conn.commit()
