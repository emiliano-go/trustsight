"""db.py facade."""

import atexit
from datetime import datetime, timezone
import hashlib
import json
import logging
import threading
import os
import re
import sqlite3
import subprocess
import tarfile
import tempfile
import warnings
from contextlib import contextmanager
from pathlib import Path, PurePosixPath
from typing import Optional
from ..bounded_io import read_capped, read_file_capped
from ..config import DATA_DIR
from ..rule_id_history import RENAMED_RULE_IDS
from ..subproc import minimal_env
from ._common import (
    log,
)
from ._connection import (
    DEFAULT_HASH_ALGORITHM,
    MAX_SEED_BYTES,
    MAX_SEED_MEMBERS,
    MAX_SEED_MEMBER_BYTES,
    SEED_META_HASH_ALGORITHM_KEY,
    SEED_META_SALT_KEY,
    _ADDED_COLUMNS,
    _SCHEMA_VERSION,
    _SYNC_MODES,
    _SYNC_SQL,
    _ensure_salt,
    _generate_salt,
    _get_salt,
    _hash_maintainer_rows,
    _hash_maintainer_value,
    _local,
    _migrate,
    _migrate_plaintext_maintainers,
    _migrate_rule_ids,
    _new_connection,
    _synchronous_mode,
    close_connections,
    get_connection,
    get_db_path,
    get_read_only_connection,
    init_db,
    write_batch,
)
from ._dependencies import (
    _ESTABLISHED_MIN_NAME_LENGTH,
    _ESTABLISHED_OBSERVATIONS,
    _official_names,
    _official_names_lock,
    dependency_observation_count,
    dependency_observation_counts,
    dependency_table_populated,
    effective_observation_count,
    is_established_package,
    official_package_names,
    record_dependency_names,
    top_dependency_names,
    top_dependency_pairs,
)
from ._history import (
    MAX_OBSERVED_DOMAINS,
    MAX_OBSERVED_KEYS,
    MAX_OBSERVED_LITERALS,
    MAX_PROPERTY_TRANSITIONS_PER_KEY,
    MAX_RECIPE_OBSERVATIONS_PER_PACKAGE,
    _array_entries_hash,
    _parse_ts,
    array_seen_before,
    clear_correlation_feeds,
    clear_upstream_dep_additions,
    correlation_feed,
    domain_first_seen,
    domain_seen_within,
    get_all_packages,
    get_history,
    get_pkgbuild_snapshot,
    get_previous_pkgbuild_snapshot,
    get_property_transitions,
    key_observed_before,
    maintainer_first_seen,
    observed_domain_count,
    observed_key_count,
    package_added_literals,
    read_aur_cache,
    record_added_literals,
    record_adoption_event,
    record_gained_hosts,
    record_observed_domain,
    record_observed_key,
    record_property_transition,
    record_recipe_document,
    record_upstream_dep_additions,
    save_pkgbuild_snapshot,
    tuple_observation_count,
    write_aur_cache,
)
from ._maintainers import (
    get_maintainer_global_count,
    is_maintainer_globally_novel,
    lookup_maintainer,
)
from ._campaigns import (
    activate_campaign,
    active_campaigns,
    all_campaigns,
    expired_unannounced,
    mark_expiry_announced,
    reactivation_pressure,
)
from ._metadata import (
    BASELINE_MANIFEST_VERSION_KEY,
    OBSERVATION_SEQ_KEY,
    SEED_DIGEST_KEY,
    SEED_OBSERVATION_KEY,
    SEED_ORIGIN_KEY,
    SEED_OWNED_KEYS,
    SEED_VERSION_KEY,
    bump_observation_seq,
    get_metadata,
    observation_seq,
    seed_observation_count,
    set_metadata,
)
from ._packages import (
    _RESERVED_NAMES,
    _sanitize_maintainer,
    count_observations,
    get_analysis,
    get_aur_orphan_state,
    get_last_analysis,
    get_package,
    get_package_id,
    get_triggered_rules,
    insert_analysis,
    is_reserved_name,
    update_aur_orphan_state,
    update_package_maintainer,
    update_package_version,
    upsert_package,
)
from ._profiles import (
    alert_history,
    checkpoint_wal,
    forget_package,
    forget_prune,
    get_package_profile,
    introduction_rate_history,
    latest_cycle_time,
    maintainer_activity_history,
    record_alerts,
    record_cycle_events,
    save_package_profile,
)
from ._maintenance import (
    database_stats,
    prune_alert_state,
    prune_cycle_events,
    vacuum_database,
)
from ._outbox import (
    MAX_AGE as ALERT_OUTBOX_MAX_AGE,
    MAX_ATTEMPTS as ALERT_OUTBOX_MAX_ATTEMPTS,
    alert_outbox_stats,
    enqueue_alert_payload,
    mark_alert_attempt,
    mark_alert_sink,
    pending_alert_payloads,
)
from ._contacts import (
    contact_entries,
    contact_ledger_available,
    contact_ledger_size,
    contacts_for_values,
    first_seen_hosts_since,
    host_first_seen,
    record_contact,
    record_host,
)
from ._seed import (
    _decompress_sqlite_seed,
    _digest_seed_dir,
    _extract_v2_archive,
    _import_seed_from_release,
    _import_sqlite_seed,
    _import_v2_dependency_names,
    _import_v2_maintainers,
    _import_v2_seed,
    _import_v2_source_urls,
    _seed_file_digest,
    bundled_seed_path,
    import_seed,
    maybe_auto_import_seed,
)

atexit.register(close_connections)


__all__ = ['DATA_DIR', 'DEFAULT_HASH_ALGORITHM', 'MAX_OBSERVED_DOMAINS', 'MAX_OBSERVED_KEYS', 'MAX_OBSERVED_LITERALS', 'MAX_PROPERTY_TRANSITIONS_PER_KEY', 'MAX_RECIPE_OBSERVATIONS_PER_PACKAGE', 'MAX_SEED_BYTES', 'MAX_SEED_MEMBERS', 'MAX_SEED_MEMBER_BYTES', 'Optional', 'Path', 'PurePosixPath', 'RENAMED_RULE_IDS', 'BASELINE_MANIFEST_VERSION_KEY', 'SEED_DIGEST_KEY', 'SEED_META_HASH_ALGORITHM_KEY', 'SEED_META_SALT_KEY', 'SEED_OBSERVATION_KEY', 'SEED_ORIGIN_KEY', 'SEED_OWNED_KEYS', 'SEED_VERSION_KEY', 'OBSERVATION_SEQ_KEY', 'bump_observation_seq', 'observation_seq', 'activate_campaign', 'active_campaigns', 'all_campaigns', 'expired_unannounced', 'mark_expiry_announced', '_ADDED_COLUMNS', '_ESTABLISHED_MIN_NAME_LENGTH', '_ESTABLISHED_OBSERVATIONS', '_RESERVED_NAMES', '_SCHEMA_VERSION', '_SYNC_MODES', '_SYNC_SQL', '_array_entries_hash', '_decompress_sqlite_seed', '_digest_seed_dir', '_ensure_salt', '_extract_v2_archive', '_generate_salt', '_get_salt', '_hash_maintainer_rows', '_hash_maintainer_value', '_import_seed_from_release', '_import_sqlite_seed', '_import_v2_dependency_names', '_import_v2_maintainers', '_import_v2_seed', '_import_v2_source_urls', '_local', '_migrate', '_migrate_plaintext_maintainers', '_migrate_rule_ids', '_new_connection', '_official_names', '_official_names_lock', '_parse_ts', '_sanitize_maintainer', '_seed_file_digest', '_synchronous_mode', 'ALERT_OUTBOX_MAX_AGE', 'ALERT_OUTBOX_MAX_ATTEMPTS', 'alert_history', 'database_stats', 'prune_alert_state', 'prune_cycle_events', 'vacuum_database', 'alert_outbox_stats', 'enqueue_alert_payload', 'mark_alert_attempt', 'mark_alert_sink', 'pending_alert_payloads', 'array_seen_before', 'atexit', 'clear_correlation_feeds', 'clear_upstream_dep_additions', 'bundled_seed_path', 'checkpoint_wal', 'close_connections', 'contact_entries', 'contact_ledger_available', 'contact_ledger_size', 'contacts_for_values', 'contextmanager', 'correlation_feed', 'count_observations', 'datetime', 'dependency_observation_count', 'dependency_observation_counts', 'dependency_table_populated', 'domain_first_seen', 'domain_seen_within', 'effective_observation_count', 'first_seen_hosts_since', 'forget_package', 'forget_prune', 'get_all_packages', 'host_first_seen', 'get_analysis', 'get_aur_orphan_state', 'get_connection', 'get_db_path', 'get_history', 'get_last_analysis', 'get_maintainer_global_count', 'get_metadata', 'get_package', 'get_package_id', 'get_package_profile', 'get_pkgbuild_snapshot', 'get_previous_pkgbuild_snapshot', 'get_property_transitions', 'get_read_only_connection', 'get_triggered_rules', 'hashlib', 'import_seed', 'init_db', 'insert_analysis', 'introduction_rate_history', 'is_established_package', 'is_maintainer_globally_novel', 'is_reserved_name', 'json', 'key_observed_before', 'latest_cycle_time', 'log', 'logging', 'lookup_maintainer', 'maintainer_activity_history', 'maintainer_first_seen', 'maybe_auto_import_seed', 'minimal_env', 'observed_domain_count', 'observed_key_count', 'official_package_names', 'os', 'package_added_literals', 're', 'read_aur_cache', 'read_capped', 'read_file_capped', 'reactivation_pressure', 'record_added_literals', 'record_adoption_event', 'record_gained_hosts', 'record_contact', 'record_host', 'record_alerts', 'record_cycle_events', 'record_dependency_names', 'record_observed_domain', 'record_observed_key', 'record_property_transition', 'record_recipe_document', 'record_upstream_dep_additions', 'save_package_profile', 'save_pkgbuild_snapshot', 'seed_observation_count', 'set_metadata', 'sqlite3', 'subprocess', 'tarfile', 'tempfile', 'threading', 'timezone', 'top_dependency_names', 'top_dependency_pairs', 'tuple_observation_count', 'update_aur_orphan_state', 'update_package_maintainer', 'update_package_version', 'upsert_package', 'warnings', 'write_aur_cache', 'write_batch']
