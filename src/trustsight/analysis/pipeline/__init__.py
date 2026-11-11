"""pipeline.py facade."""

import difflib
import json
import logging
import re
import time
from ...buckets import classify_urls
from ...config import (
    config_fingerprint,
    drifted_shipped_rules,
    load_config,
    load_rules,
)
from ...db import (
    insert_analysis,
    record_dependency_names,
    update_package_maintainer,
    get_aur_orphan_state,
    update_aur_orphan_state,
    update_package_version,
    upsert_package,
)
from ...sandbox.store_client import (
    effective_observation_count,
    get_last_analysis,
    get_package,
    get_package_id,
)
from ...diffdoc import parse_diff_lines
from ...differ import (
    diff_summary_from_text,
    binary_metadata_in_text,
    detect_gpg_verification_removed,
    detect_verification_evidence,
    extract_urls_from_diff,
    map_diff_lines,
    truncate_diff,
)
from ...fetcher import (
    clone_or_fetch,
    get_head_commit,
    get_maintainer_from_commit,
    get_pkgbuild_at_commit,
    get_pkgver_from_head,
    get_srcinfo_at_commit,
)
from ...findings import stamp
from ...sandbox.git_client import GitOpError, GitSandboxUnavailable
from ...novelty import (
    build_novelty_context,
    normalize_url,
)
from ...deps import extract_dependency_changes
from ...override import (
    acknowledged_url_rows,
    filter_triggered_rules,
    match_url_acks,
)
from ...rules import (
    apply_rules,
    clamp_diff_lines,
    clamp_text,
    get_raw_diff_lines_indexed,
)
from ..adoption import adoption_findings
from ..buildfetch import has_unpinned_build_deps
from ...changes import change_delta
from ...coverage import (
    begin_stage_tracking,
    cut_hunk_details,
    gaps_from,
    note_stage_failure,
    stage_failures,
    oversized_lines,
    parse_time_substitution_lines,
    resolution_coverage,
    unresolved_assignment_rows,
    unresolved_source_lines,
)
from ...scoring import calculate_score
from ...schema import (
    with_changes,
    DiffSummary,
    ExecutionChanges,
    NoveltyContext,
    PackageFact,
    fact_from_dict,
    fact_to_dict,
)
from ...tokenizer import split_lines, tokenize_and_resolve_indexed
from ..base import (
    _GLOBAL_URL_KEY,
    _aggregate_pinning,
    _ensure_init,
    _get_installed_version,
    _has_install_hook,
)
from ..composition import (
    _meta_annotations,
    maintainer_keyring_composition,
    naming_cluster_annotation,
    naming_typosquat_finding,
)
from ..ioc_match import ioc_baseline_matches
from ..maintainer import _check_untrusted_maintainer_takeover
from ..structural import (
    _structural_findings,
    partial_install_files,
    recipe_checksum_parity_finding,
    unchanged_upstream_host,
)
from ..structural_rules import apply_structural_rules
from ..version import (
    any_version_scalar_moved,
    compare_installed_to_aur,
    full_version_from_pkgbuild,
    is_vcs_package,
    pkgver_move_in_diff,
)
from ..temporal import _package_is_new, _recent_update, _stale_revival
from ._analyze import (
    _make_fresh_analysis,
    _walk_dependencies,
    analyze_package,
    apply_diff_caps,
    scored_source_urls,
)
from ._common import (
    log,
)
from ._scan import (
    analyze_package_text,
    scan_diff,
)
from ._tree import (
    _NOEXTRACT_RE,
    _SCRIPTLET_ATTR_RE,
    _added_dependency_names,
    _adds_a_dependency,
    _binary_metadata_finding,
    _cached_analysis,
    _deps_not_scanned,
    _has_noextract,
    _parent_commit,
    _scriptlet_files_unread,
)

__all__ = ['DiffSummary', 'ExecutionChanges', 'GitOpError', 'GitSandboxUnavailable', 'NoveltyContext', 'PackageFact', '_COMPANION_CONTENT_RE', '_COMPANION_HEAD_BYTES', '_COMPANION_TOTAL_BYTES', '_DRAIN_CHUNK_BYTES', '_GLOBAL_URL_KEY', '_NOEXTRACT_RE', '_SCRIPTLET_ATTR_RE', '_added_dependency_names', '_adds_a_dependency', '_aggregate_pinning', '_binary_metadata_finding', '_cached_analysis', '_check_untrusted_maintainer_takeover', '_collect_tree_files', '_deps_not_scanned', '_ensure_init', '_get_installed_version', '_has_install_hook', '_has_noextract', '_make_fresh_analysis', '_meta_annotations', '_package_is_new', '_parent_commit', '_recent_update', '_scriptlet_files_unread', '_stale_revival', '_structural_findings', '_walk_dependencies', 'acknowledged_url_rows', 'adoption_findings', 'analyze_package', 'analyze_package_text', 'any_version_scalar_moved', 'apply_diff_caps', 'apply_rules', 'apply_structural_rules', 'begin_stage_tracking', 'binary_metadata_in_text', 'build_novelty_context', 'calculate_score', 'change_delta', 'clamp_diff_lines', 'clamp_text', 'classify_urls', 'clone_or_fetch', 'compare_installed_to_aur', 'config_fingerprint', 'cut_hunk_details', 'detect_gpg_verification_removed', 'detect_verification_evidence', 'diff_summary_from_text', 'difflib', 'drifted_shipped_rules', 'effective_observation_count', 'extract_dependency_changes', 'extract_urls_from_diff', 'fact_from_dict', 'fact_to_dict', 'filter_triggered_rules', 'full_version_from_pkgbuild', 'gaps_from', 'get_aur_orphan_state', 'get_head_commit', 'get_last_analysis', 'get_maintainer_from_commit', 'get_package', 'get_package_id', 'get_pkgbuild_at_commit', 'get_pkgver_from_head', 'get_raw_diff_lines_indexed', 'get_srcinfo_at_commit', 'has_unpinned_build_deps', 'insert_analysis', 'ioc_baseline_matches', 'is_vcs_package', 'json', 'load_config', 'load_rules', 'log', 'logging', 'maintainer_keyring_composition', 'map_diff_lines', 'match_url_acks', 'naming_cluster_annotation', 'naming_typosquat_finding', 'normalize_url', 'note_stage_failure', 'oversized_lines', 'parse_diff_lines', 'parse_time_substitution_lines', 'partial_install_files', 'pkgver_move_in_diff', 're', 'recipe_checksum_parity_finding', 'record_dependency_names', 'resolution_coverage', 'scan_diff', 'scored_source_urls', 'split_lines', 'stage_failures', 'stamp', 'time', 'tokenize_and_resolve_indexed', 'truncate_diff', 'unchanged_upstream_host', 'unresolved_assignment_rows', 'unresolved_source_lines', 'update_aur_orphan_state', 'update_package_maintainer', 'update_package_version', 'upsert_package', 'with_changes']
