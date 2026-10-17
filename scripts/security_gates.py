"""The security-model gates, enforced.

``docs/security.md`` states what TrustSight guarantees.  This script is the
other half of that document: every invariant it lists has a check here, and
a check that fails is a claim that has stopped being true.  The split is the
same one ``calibration_gates.py`` makes for detection: the doc says what the
property is, the gate decides whether it holds.

Two families:

* **Part A** - TrustSight as a program consuming hostile input.  These are
  structural: no shell, declared network hosts, bounded reads, parameterised
  SQL, sanitised output.
* **Part B** - what a verdict claims.  These are behavioural: an incomplete
  analysis cannot read as clean, a FATAL rule cannot be switched off, a seed
  cannot rewrite the database it is merged into.

Usage:
    python scripts/security_gates.py
    python scripts/security_gates.py --json security-gates.json

Exit code is 1 if any gate fails, 0 otherwise.
"""

from __future__ import annotations

import argparse
import ast
import contextlib
import io
import json
import re
import sys
import time
from pathlib import Path
# Bootstrap the import path before reaching the ``scripts.gates`` package.
_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "src"))
sys.path.insert(0, str(_ROOT))

def run_gates() -> list[Gate]:
    gates = [
        gate_no_interpreter_calls(),
        gate_every_child_process_gets_an_explicit_environment(),
        gate_network_is_confined(),
        gate_single_network_host(),
        gate_network_reads_are_bounded(),
        gate_no_path_based_archive_extraction(),
        gate_every_stream_read_is_bounded(),
        gate_artifact_reads_are_bounded(),
        gate_sql_is_parameterised(),
        gate_source_urls_are_never_fetched(),
        gate_every_json_report_carries_the_fingerprint(),
        gate_suppression_is_never_hidden_by_a_flag(),
        gate_the_default_output_is_not_headline_shaped(),
        gate_version_args_are_shape_checked(),
        gate_terminal_output_is_inert(),
        gate_freshness_uses_local_marker(),
        gate_rendering_is_data_driven(),
        gate_regex_input_is_bounded(),
        gate_expansion_is_bounded(),
        gate_regex_patterns_pass_adversarial_audit(),
        gate_every_live_regex_is_audited(),
        gate_untrusted_text_is_sanitised_where_it_is_rendered(),
        gate_tokenizer_smoke_is_deterministic(),
        gate_tokenizer_module_is_isolated(),
        gate_tokenizer_worker_startup_is_isolated(),
        gate_git_worker_startup_is_isolated(),
        gate_git_worker_limit_failures_are_reported(),
        gate_tokenizer_pool_wait_is_bounded(),
        gate_dead_tokenizer_child_fails_the_package(),
        gate_release_artifacts_share_commit(),
        gate_coverage_fails_closed(),
        gate_truncation_is_visible(),
        gate_differ_hostile_input_is_bounded(),
        gate_differ_output_is_deterministic(),
        gate_api_inputs_are_bounded_before_initialization(),
        gate_a_gap_is_always_shown_with_the_band(),
        gate_alert_grouping_is_reported(),
        gate_alert_counts_reconcile(),
        gate_campaign_state_is_instrument_state(),
        gate_campaign_expiry_is_structural(),
        gate_campaign_points_are_attributed(),
        gate_elevation_is_attributed(),
        gate_escalation_is_one_notch(),
        gate_escalation_never_reaches_fatal(),
        gate_escalation_chains_are_rejected(),
        gate_expired_overrides_are_reported(),
        gate_corroborated_suppression_is_terminal_visible(),
        gate_overrides_never_hide_indicator_corroboration(),
        gate_every_producer_accounts_for_coverage(),
        gate_maturity_numbers_are_not_duplicated(),
        gate_fatal_rules_cannot_be_removed(),
        gate_fatal_findings_cannot_be_suppressed(),
        gate_seed_cannot_rewrite_the_database(),
        gate_hashed_maintainers_protect_privacy(),
        gate_ioc_match_carries_source(),
        gate_ioc_no_score_contribution(),
        gate_ioc_expired_is_never_silent(),
        gate_ioc_not_in_config_layer(),
        gate_pattern_ioc_rejects_redos(),
        gate_seed_hash_is_deterministic(),
        gate_reserved_names_are_refused_everywhere(),
        gate_a_baseline_supplies_state_not_rules(),
        gate_result_reports_what_changed(),
        gate_change_entries_carry_no_severity(),
        gate_positive_evidence_never_scores(),
        gate_positive_evidence_cannot_lower_a_fatal(),
        gate_declared_findings_fire_under_shipped_config(),
        gate_score_is_deterministic_under_a_fingerprint(),
        gate_every_input_bound_is_a_source_constant(),
        gate_every_render_ends_with_a_direction(),
        gate_no_git_filters_or_hooks(),
        gate_libgit2_stays_behind_the_sandbox(),
        gate_no_template_grants_permission(),
        gate_content_findings_carry_a_location(),
        gate_flag_threshold_is_derived(),
        gate_doc_cross_references_resolve(),
    ]
    gates.append(gate_generated_diff_is_bounded_before_assembly())
    gates.append(gate_companion_reads_are_bounded_before_data())
    gates.append(gate_a_critical_finding_never_reads_medium())
    gates.append(gate_a_fatal_finding_names_itself())
    gates.append(gate_unpinned_build_deps_is_a_declared_gap())
    gates.append(gate_every_render_reports_the_same_information())
    gates.append(gate_api_and_cli_emit_the_same_body())
    gates.append(gate_score_is_withheld_by_default())
    gates.append(gate_api_and_cli_share_the_analysis())
    gates.append(gate_ci_installs_from_the_lock())
    gates.append(gate_critical_paths_are_synchronised())
    gates.append(gate_an_audit_does_not_write_history())
    gates.append(gate_h_series_intake_is_frozen())
    gates.append(gate_h_series_reduction_residue())
    gates.append(gate_retired_ids_resolve_to_live_survivors())
    gates.append(gate_the_history_walk_is_bounded())
    gates.append(gate_run_diff_assembly_is_bounded())
    gates.append(gate_a_truncated_history_walk_is_a_declared_gap())
    gates.append(gate_every_history_diff_is_scored_independently())
    gates.append(gate_docs_layer_mapping_matches_registry())
    gates.append(gate_layer_detection_and_coverage_are_independent())
    gates.append(gate_every_rule_names_shared_dependencies())
    gates.append(gate_layer_overrides_stay_within_the_closed_set())
    gates.append(gate_boundaries_are_the_coverage_view())
    gates.append(gate_every_report_key_is_documented())
    gates.append(gate_transcendence_table_is_wellformed())
    gates.append(gate_every_rule_carries_exactly_one_layer())
    gates.append(gate_boundaries_forbid_clean_exactly_when_gaps())
    gates.append(gate_indicator_tier_mirrors_ioc_matches())
    gates.append(gate_layer_profile_is_gap_precise_and_additive())
    gates.append(gate_manifest_parses_are_bounded_and_refusing())
    gates.append(gate_manifest_table_is_configuration())
    gates.append(gate_u003_joins_the_host_view())
    gates.append(gate_manifest_ledger_stays_weight_zero())
    gates.append(gate_archive_listing_adds_no_extraction())
    gates.append(gate_yaml_is_only_safe_load())
    gates.append(gate_libgit2_is_not_the_vulnerable_version())
    gates.append(gate_doc_lists_every_gate(gates))
    return gates

def main() -> int:
    parser = argparse.ArgumentParser(description="Run the security-model gates")
    parser.add_argument("--json", type=Path, help="Write the gate results here")
    args = parser.parse_args()

    gates = run_gates()
    width = max(len(g.name) for g in gates)
    for gate in gates:
        status = "PASS" if gate.passed else "FAIL"
        print(f"{status}  {gate.name:<{width}}  measured={gate.measured}")
        if gate.detail:
            print(f"        {gate.detail}")

    if args.json:
        args.json.write_text(
            json.dumps([g.as_dict() for g in gates], indent=2, default=str) + "\n"
        )

    failed = [g for g in gates if not g.passed]
    print(f"\n{len(gates) - len(failed)}/{len(gates)} gates passed")
    return 1 if failed else 0

from scripts.gates._core import (
    Gate,
    HOSTILE,
    H_SERIES_REDUCTION_TARGET,
    ROOT,
    SRC,
    _ANALYSIS_FETCH_ALLOWED,
    _ARTIFACT_MODULES,
    _ARTIFACT_READ_EXEMPT,
    _ATX_PUNCT_RE,
    _BOUNDED_IO_MODULE,
    _BOUND_CONSTANTS,
    _DYNAMIC_SQL_NODES,
    _ENDPOINT_HOST,
    _FORBIDDEN_CALLS,
    _GIT_ALLOWED_IMPORTS,
    _INLINE_CODE_RE,
    _MD_LINK_RE,
    _NETWORK_CALLS,
    _NETWORK_MODULES,
    _PERMISSION_PHRASES,
    _PERMISSION_REGEXES,
    _RELEASE_HOSTS,
    _RELEASE_MODULES,
    _SHARED_ANALYSIS,
    _URL_LITERAL_RE,
    _anchor,
    _call_name,
    _demo_fact,
    _enclosing_functions,
    _h_series_live_ceiling,
    _hostile_fact,
    _hostile_result,
    _parity_fact,
    _python_files,
    _rel,
    _render_forget_list,
    _render_inspect_text,
    _render_list_rows,
    _seed_ioc_baseline,
)
from scripts.gates._input_bounds import (
    gate_artifact_reads_are_bounded,
    gate_dead_tokenizer_child_fails_the_package,
    gate_every_child_process_gets_an_explicit_environment,
    gate_every_live_regex_is_audited,
    gate_every_stream_read_is_bounded,
    gate_expansion_is_bounded,
    gate_freshness_uses_local_marker,
    gate_git_worker_limit_failures_are_reported,
    gate_git_worker_startup_is_isolated,
    gate_network_is_confined,
    gate_network_reads_are_bounded,
    gate_no_interpreter_calls,
    gate_no_path_based_archive_extraction,
    gate_regex_patterns_pass_adversarial_audit,
    gate_single_network_host,
    gate_sql_is_parameterised,
    gate_terminal_output_is_inert,
    gate_tokenizer_module_is_isolated,
    gate_tokenizer_pool_wait_is_bounded,
    gate_tokenizer_smoke_is_deterministic,
    gate_tokenizer_worker_startup_is_isolated,
    gate_untrusted_text_is_sanitised_where_it_is_rendered,
)
from scripts.gates._integrity import (
    gate_api_inputs_are_bounded_before_initialization,
    gate_coverage_fails_closed,
    gate_differ_hostile_input_is_bounded,
    gate_differ_output_is_deterministic,
    gate_every_producer_accounts_for_coverage,
    gate_fatal_findings_cannot_be_suppressed,
    gate_fatal_rules_cannot_be_removed,
    gate_hashed_maintainers_protect_privacy,
    gate_ioc_expired_is_never_silent,
    gate_ioc_match_carries_source,
    gate_ioc_no_score_contribution,
    gate_ioc_not_in_config_layer,
    gate_maturity_numbers_are_not_duplicated,
    gate_pattern_ioc_rejects_redos,
    gate_regex_input_is_bounded,
    gate_rendering_is_data_driven,
    gate_seed_cannot_rewrite_the_database,
    gate_seed_hash_is_deterministic,
    gate_truncation_is_visible,
    gate_version_args_are_shape_checked,
)
from scripts.gates._layers import (
    gate_archive_listing_adds_no_extraction,
    gate_boundaries_are_the_coverage_view,
    gate_boundaries_forbid_clean_exactly_when_gaps,
    gate_docs_layer_mapping_matches_registry,
    gate_every_history_diff_is_scored_independently,
    gate_every_report_key_is_documented,
    gate_every_rule_carries_exactly_one_layer,
    gate_every_rule_names_shared_dependencies,
    gate_indicator_tier_mirrors_ioc_matches,
    gate_layer_detection_and_coverage_are_independent,
    gate_layer_overrides_stay_within_the_closed_set,
    gate_layer_profile_is_gap_precise_and_additive,
    gate_libgit2_is_not_the_vulnerable_version,
    gate_manifest_ledger_stays_weight_zero,
    gate_manifest_parses_are_bounded_and_refusing,
    gate_manifest_table_is_configuration,
    gate_release_artifacts_share_commit,
    gate_transcendence_table_is_wellformed,
    gate_u003_joins_the_host_view,
    gate_yaml_is_only_safe_load,
)
from scripts.gates._parity import (
    gate_a_critical_finding_never_reads_medium,
    gate_a_fatal_finding_names_itself,
    gate_a_truncated_history_walk_is_a_declared_gap,
    gate_an_audit_does_not_write_history,
    gate_api_and_cli_emit_the_same_body,
    gate_api_and_cli_share_the_analysis,
    gate_ci_installs_from_the_lock,
    gate_companion_reads_are_bounded_before_data,
    gate_critical_paths_are_synchronised,
    gate_doc_lists_every_gate,
    gate_every_render_reports_the_same_information,
    gate_generated_diff_is_bounded_before_assembly,
    gate_h_series_intake_is_frozen,
    gate_h_series_reduction_residue,
    gate_libgit2_stays_behind_the_sandbox,
    gate_retired_ids_resolve_to_live_survivors,
    gate_run_diff_assembly_is_bounded,
    gate_score_is_withheld_by_default,
    gate_the_history_walk_is_bounded,
    gate_unpinned_build_deps_is_a_declared_gap,
)
from scripts.gates._immune import (
    gate_campaign_expiry_is_structural,
    gate_corroborated_suppression_is_terminal_visible,
    gate_campaign_points_are_attributed,
    gate_campaign_state_is_instrument_state,
    gate_elevation_is_attributed,
    gate_escalation_chains_are_rejected,
    gate_escalation_is_one_notch,
    gate_escalation_never_reaches_fatal,
    gate_expired_overrides_are_reported,
    gate_overrides_never_hide_indicator_corroboration,
)
from scripts.gates._reporting import (
    gate_alert_counts_reconcile,
    gate_alert_grouping_is_reported,
    gate_a_baseline_supplies_state_not_rules,
    gate_a_gap_is_always_shown_with_the_band,
    gate_change_entries_carry_no_severity,
    gate_content_findings_carry_a_location,
    gate_declared_findings_fire_under_shipped_config,
    gate_doc_cross_references_resolve,
    gate_every_input_bound_is_a_source_constant,
    gate_every_json_report_carries_the_fingerprint,
    gate_every_render_ends_with_a_direction,
    gate_flag_threshold_is_derived,
    gate_no_git_filters_or_hooks,
    gate_no_template_grants_permission,
    gate_positive_evidence_cannot_lower_a_fatal,
    gate_positive_evidence_never_scores,
    gate_reserved_names_are_refused_everywhere,
    gate_result_reports_what_changed,
    gate_score_is_deterministic_under_a_fingerprint,
    gate_source_urls_are_never_fetched,
    gate_suppression_is_never_hidden_by_a_flag,
    gate_the_default_output_is_not_headline_shaped,
)

__all__ = ['Gate', 'HOSTILE', 'H_SERIES_REDUCTION_TARGET', 'Path', 'ROOT', 'SRC', '_ANALYSIS_FETCH_ALLOWED', '_ARTIFACT_MODULES', '_ARTIFACT_READ_EXEMPT', '_ATX_PUNCT_RE', '_BOUNDED_IO_MODULE', '_BOUND_CONSTANTS', '_DYNAMIC_SQL_NODES', '_ENDPOINT_HOST', '_FORBIDDEN_CALLS', '_GIT_ALLOWED_IMPORTS', '_INLINE_CODE_RE', '_MD_LINK_RE', '_NETWORK_CALLS', '_NETWORK_MODULES', '_PERMISSION_PHRASES', '_PERMISSION_REGEXES', '_RELEASE_HOSTS', '_RELEASE_MODULES', '_SHARED_ANALYSIS', '_URL_LITERAL_RE', '_anchor', '_call_name', '_demo_fact', '_enclosing_functions', '_h_series_live_ceiling', '_hostile_fact', '_hostile_result', '_parity_fact', '_python_files', '_rel', '_render_forget_list', '_render_inspect_text', '_render_list_rows', '_seed_ioc_baseline', 'argparse', 'ast', 'contextlib', 'gate_a_baseline_supplies_state_not_rules', 'gate_a_critical_finding_never_reads_medium', 'gate_a_fatal_finding_names_itself', 'gate_a_gap_is_always_shown_with_the_band', 'gate_a_truncated_history_walk_is_a_declared_gap', 'gate_an_audit_does_not_write_history', 'gate_api_and_cli_emit_the_same_body', 'gate_api_and_cli_share_the_analysis', 'gate_api_inputs_are_bounded_before_initialization', 'gate_archive_listing_adds_no_extraction', 'gate_artifact_reads_are_bounded', 'gate_boundaries_are_the_coverage_view', 'gate_boundaries_forbid_clean_exactly_when_gaps', 'gate_change_entries_carry_no_severity', 'gate_ci_installs_from_the_lock', 'gate_companion_reads_are_bounded_before_data', 'gate_content_findings_carry_a_location', 'gate_coverage_fails_closed', 'gate_critical_paths_are_synchronised', 'gate_dead_tokenizer_child_fails_the_package', 'gate_declared_findings_fire_under_shipped_config', 'gate_differ_hostile_input_is_bounded', 'gate_differ_output_is_deterministic', 'gate_doc_cross_references_resolve', 'gate_doc_lists_every_gate', 'gate_docs_layer_mapping_matches_registry', 'gate_every_child_process_gets_an_explicit_environment', 'gate_every_history_diff_is_scored_independently', 'gate_every_input_bound_is_a_source_constant', 'gate_every_json_report_carries_the_fingerprint', 'gate_every_live_regex_is_audited', 'gate_every_producer_accounts_for_coverage', 'gate_every_render_ends_with_a_direction', 'gate_every_render_reports_the_same_information', 'gate_every_report_key_is_documented', 'gate_every_rule_carries_exactly_one_layer', 'gate_every_rule_names_shared_dependencies', 'gate_every_stream_read_is_bounded', 'gate_expansion_is_bounded', 'gate_fatal_findings_cannot_be_suppressed', 'gate_fatal_rules_cannot_be_removed', 'gate_flag_threshold_is_derived', 'gate_freshness_uses_local_marker', 'gate_generated_diff_is_bounded_before_assembly', 'gate_git_worker_limit_failures_are_reported', 'gate_git_worker_startup_is_isolated', 'gate_h_series_intake_is_frozen', 'gate_h_series_reduction_residue', 'gate_hashed_maintainers_protect_privacy', 'gate_indicator_tier_mirrors_ioc_matches', 'gate_ioc_expired_is_never_silent', 'gate_ioc_match_carries_source', 'gate_ioc_no_score_contribution', 'gate_ioc_not_in_config_layer', 'gate_layer_detection_and_coverage_are_independent', 'gate_layer_overrides_stay_within_the_closed_set', 'gate_layer_profile_is_gap_precise_and_additive', 'gate_libgit2_is_not_the_vulnerable_version', 'gate_libgit2_stays_behind_the_sandbox', 'gate_manifest_ledger_stays_weight_zero', 'gate_manifest_parses_are_bounded_and_refusing', 'gate_manifest_table_is_configuration', 'gate_maturity_numbers_are_not_duplicated', 'gate_network_is_confined', 'gate_network_reads_are_bounded', 'gate_no_git_filters_or_hooks', 'gate_no_interpreter_calls', 'gate_no_path_based_archive_extraction', 'gate_no_template_grants_permission', 'gate_pattern_ioc_rejects_redos', 'gate_positive_evidence_cannot_lower_a_fatal', 'gate_positive_evidence_never_scores', 'gate_regex_input_is_bounded', 'gate_regex_patterns_pass_adversarial_audit', 'gate_release_artifacts_share_commit', 'gate_rendering_is_data_driven', 'gate_reserved_names_are_refused_everywhere', 'gate_result_reports_what_changed', 'gate_retired_ids_resolve_to_live_survivors', 'gate_run_diff_assembly_is_bounded', 'gate_score_is_deterministic_under_a_fingerprint', 'gate_score_is_withheld_by_default', 'gate_seed_cannot_rewrite_the_database', 'gate_seed_hash_is_deterministic', 'gate_single_network_host', 'gate_source_urls_are_never_fetched', 'gate_sql_is_parameterised', 'gate_suppression_is_never_hidden_by_a_flag', 'gate_terminal_output_is_inert', 'gate_the_default_output_is_not_headline_shaped', 'gate_the_history_walk_is_bounded', 'gate_tokenizer_module_is_isolated', 'gate_tokenizer_pool_wait_is_bounded', 'gate_tokenizer_smoke_is_deterministic', 'gate_tokenizer_worker_startup_is_isolated', 'gate_transcendence_table_is_wellformed', 'gate_truncation_is_visible', 'gate_u003_joins_the_host_view', 'gate_unpinned_build_deps_is_a_declared_gap', 'gate_untrusted_text_is_sanitised_where_it_is_rendered', 'gate_version_args_are_shape_checked', 'gate_yaml_is_only_safe_load', 'io', 'json', 'main', 're', 'run_gates', 'sys', 'time']


if __name__ == "__main__":
    sys.exit(main())
