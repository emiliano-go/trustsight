"""The one scan → finalise pipeline both analysis producers call.

``analyze_package`` (git) and ``analyze_package_text`` (corpus) used to
carry two hand-written copies of this sequence.  They drifted: a coverage
signal forwarded by one was missed by the other, and a rule added to the git
path had to be remembered in the corpus path.  Acquisition still differs -
one reads a repository, the other a snapshot - but everything from the diff
to the scored ``PackageFact`` lives here, with explicit hooks for the
findings only one path can see.

Ordering is part of the contract: ``ScanInput.pre_structural`` findings run
where each producer used to append them, and the tree/exclusion passes keep
the same sequence, so a ``fact_to_dict`` comparison is byte-identical.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from ...buckets import classify_urls
from ...changes import change_delta
from ...config import drifted_shipped_rules
from ...coverage import (
    CoverageSignals,
    cut_hunk_details,
    gaps_from,
    resolution_coverage,
    stage_failures,
)
from ...db import effective_observation_count
from ...differ import detect_gpg_verification_removed, extract_urls_from_diff, map_diff_lines
from ...diffdoc import diff_shape_fp
from ...novelty import build_novelty_context
from ...override import (
    acknowledged_url_rows,
    filter_triggered_rules,
    match_url_acks,
    suppress_acknowledged_url_findings,
)
from ...recipedoc import parse_recipe
from ...rules import (
    apply_rules,
    clamp_text,
    get_raw_diff_lines_indexed,
    load_rules,
)
from ...schema import ExecutionChanges, PackageFact, SourceChanges, with_changes
from ...scoring import calculate_score, declared_claims
from ...tokenizer import tokenize_and_resolve_indexed
from ..adoption import credential_egress_finding, source_takeover_finding
from ..base import _has_install_hook
from ..buildfetch import has_unpinned_build_deps
from ..composition import (
    _meta_annotations,
    maintainer_keyring_composition,
    naming_cluster_annotation,
    naming_typosquat_finding,
)
from ..ioc_match import ioc_baseline_matches
from ..maintainer import _check_untrusted_maintainer_takeover
from ..meta import alert_volume_finding, m_series_findings, m_tool_health
from ..persistence import stand_down_committed_staging
from ..structural import partial_install_files, unchanged_upstream_host  # noqa: F401
from ..structural._engine import ScanRequest, _structural_findings_from_request
from ..structural_rules import apply_structural_rules
from ._analyze_helpers import _campaign_corroboration
from ._resolved import split_resolved_lines
from ._evidence import Evidence, collect_evidence
from ._tree import _deps_not_scanned, _has_noextract, _scriptlet_files_unread


@dataclass(frozen=True)
class AnalysisRequest:
    """One analysis request, shared by the git and corpus entry points.

    The public functions keep their original signatures; each builds this
    object once.  A new option is added here instead of in two signatures
    that were already 12 and 20 parameters long.
    """

    package: str
    old_version: str = ""
    new_version: str = ""
    old_commit: str = ""
    new_commit: str = ""
    installed_version: str | None = None
    upstream_mtime: int | None = None
    aur_orphaned: bool | None = None
    maintainer: str = ""
    old_maintainer: str = ""
    temporal: Any = None
    srcinfo: str | None = None
    install_text: str | None = None
    install_name: str | None = None
    old_install_text: str | None = None
    tree_manifest: list | None = None
    archive_trailer_finding: dict | None = None
    snapshot_refused: bool = False
    upstream_manifest_incomplete: bool = False
    popular_candidates: list | None = None
    package_popularity: int | None = None
    manifest_deltas: tuple = ()
    workflow_deltas: tuple = ()
    depth: int | None = None
    depth_seen: set | None = None
    record: bool = False
    full_recipe: bool = False
    allow_cached: bool = False


@dataclass(frozen=True)
class ScanInput:
    """Everything the shared scan needs, with path-specific hooks.

    * ``pre_structural``: findings a producer makes before the structural
      pass (corpus metadata, git opaque/binary/SRCINFO).
    * ``transform_after_tree``: a producer's filter over the rules after the
      tree scan (git's notice-only install-modification stand-down).
    * ``append_before_filter`` / ``append_after_filter``: findings that sit
      on either side of the override filter (corpus archive trailer, git
      recent/new/revived and corpus temporal/longitudinal).
    * ``late_extra``: findings appended just before H105 (git adoption,
      corpus placeholder).
    """

    package: str
    diff_text: str
    recipe_text: str
    maintainer: str
    package_id: int
    record: bool
    maintainer_changed: bool
    tree_manifest: list = field(default_factory=list)
    tree_complete: bool = True
    whole_recipe: bool = False
    previous_diff: str = ""
    previous_commit: str = ""
    current_commit: str = ""
    tree_manifest_urls: tuple[str, ...] | None = None
    tree_analysis_text: str | None = None
    delta_transform: Callable[[Any], Any] | None = None
    pre_structural: tuple[dict, ...] = ()
    transform_after_tree: Callable[[list[dict]], list[dict]] | None = None
    append_before_filter: tuple[dict, ...] = ()
    append_after_filter: tuple[dict, ...] = ()
    late_extra: tuple[dict, ...] = ()
    adopted: bool = False
    typosquat_kwargs: dict = field(default_factory=dict)


@dataclass
class ScanResult:
    triggered_rules: list[dict]
    rule_ids: list[str]
    suppressed_rules: list[dict]
    expired_overrides: list[str]
    source_changes: SourceChanges
    source_urls: list[str]
    url_acks: dict
    scored_urls: list[str]
    source_buckets: dict[str, str]
    novelty: Any
    change_delta_obj: Any
    evidence: Evidence
    resolved_strings: list[str]
    resolved_commands: list[str]
    resolved_recipe: list[str]
    unresolved_strings: list[str]
    tree_analyzed: bool
    tree_manifest: list
    tree_complete: bool
    unpinned_build_deps: bool
    noextract_present: bool
    diff_text: str
    recipe_text: str


def scan_recipe(scan: ScanInput, config: dict) -> ScanResult:
    """Run the shared scan phase and return the rules plus their evidence."""
    diff_text = scan.diff_text
    recipe_text = scan.recipe_text

    source_changes = extract_urls_from_diff(diff_text)
    declared = set(source_changes.declared_urls)
    source_urls = [url for url in source_changes.added_urls if url not in declared]
    url_acks = match_url_acks(scan.package, source_urls)
    scored_urls = [url for url in source_urls if url not in url_acks]

    source_array = (
        parse_recipe(recipe_text, file="PKGBUILD").arrays.get("source", ())
        if recipe_text else ()
    )
    source_buckets = classify_urls(
        source_urls,
        upstream_host=unchanged_upstream_host(diff_text, recipe_text),
    )

    novelty = build_novelty_context(
        scored_urls,
        scan.package_id,
        maintainer=scan.maintainer,
        record=scan.record,
        package_name=scan.package,
        source_array=source_array,
        source_buckets=source_buckets,
    )

    resolved_strings, unresolved_strings, resolved_indices = (
        tokenize_and_resolve_indexed(diff_text)
    )
    raw_lines, raw_indices = get_raw_diff_lines_indexed(diff_text)
    resolved_commands, resolved_recipe = split_resolved_lines(
        resolved_strings, resolved_indices, raw_lines, raw_indices,
    )
    line_map = map_diff_lines(diff_text)
    triggered_rules = apply_rules(
        resolved_strings, raw_lines,
        include_experimental=config.get("rules", {}).get("experimental", False),
        line_map=line_map,
        resolved_indices=resolved_indices,
        raw_indices=raw_indices,
    )
    triggered_rules.extend(scan.pre_structural)

    change_delta_obj = change_delta(
        clamp_text(diff_text), scan.package, current_text=recipe_text)
    if scan.delta_transform is not None:
        change_delta_obj = scan.delta_transform(change_delta_obj)

    triggered_rules.extend(
        _structural_findings_from_request(ScanRequest(
            diff_text=clamp_text(diff_text),
            source_changes=source_changes,
            source_buckets=source_buckets,
            maintainer_changed=scan.maintainer_changed,
            package_name=scan.package,
            config=config,
            current_text=clamp_text(recipe_text),
            tree_manifest=scan.tree_manifest,
            whole_recipe=scan.whole_recipe,
            previous_diff=scan.previous_diff,
            previous_commit=scan.previous_commit,
            current_commit=scan.current_commit,
            delta=change_delta_obj,
        ))
    )
    triggered_rules.extend(
        apply_structural_rules(
            clamp_text(diff_text),
            current_text=clamp_text(recipe_text),
            package_name=scan.package,
        )
    )
    if scan.tree_manifest:
        from ..delivery import scan_tree_manifest

        urls = (
            scan.tree_manifest_urls
            if scan.tree_manifest_urls is not None
            else tuple(source_changes.added_urls)
        )
        triggered_rules.extend(
            scan_tree_manifest(scan.tree_manifest, urls, scan.package))

    if scan.transform_after_tree is not None:
        triggered_rules = scan.transform_after_tree(triggered_rules)
    triggered_rules = suppress_acknowledged_url_findings(
        triggered_rules, scan.package, url_acks)
    triggered_rules = stand_down_committed_staging(
        triggered_rules, scan.tree_manifest)
    triggered_rules.extend(scan.append_before_filter)

    expired_overrides: list[str] = []
    triggered_rules, suppressed_rules = filter_triggered_rules(
        triggered_rules, package=scan.package, expired_out=expired_overrides)
    triggered_rules.extend(scan.append_after_filter)

    takeover = _check_untrusted_maintainer_takeover(
        scan.maintainer_changed, scan.maintainer)
    if takeover:
        triggered_rules.append(takeover)
    triggered_rules.extend(scan.late_extra)
    if not any(rule["rule_id"] == "R007" for rule in triggered_rules):
        if _has_install_hook(diff_text):
            from ...findings import stamp

            triggered_rules.append(stamp({
                "rule_id": "H023", "name": "Install Hook Present",
                "severity": "INFO", "category": "context",
                "match": "PKGBUILD declares an install hook",
            }))
    if detect_gpg_verification_removed(diff_text):
        from ...findings import stamp

        triggered_rules.append(stamp({
            "rule_id": "H024", "name": "GPG Verification Removed",
            "severity": "HIGH", "category": "integrity",
            "match": "validpgpkeys was populated and is now empty or removed",
        }))

    h105 = source_takeover_finding(
        package_name=scan.package,
        findings=triggered_rules,
        adopted=scan.adopted,
        maintainer_changed=scan.maintainer_changed,
        added_urls=source_changes.added_urls,
        removed_urls=source_changes.removed_urls,
        current_text=recipe_text,
    )
    if h105:
        triggered_rules.append(h105)
    h107 = credential_egress_finding(
        package_name=scan.package,
        findings=triggered_rules,
        diff_text=diff_text,
    )
    if h107:
        triggered_rules.append(h107)
    triggered_rules.extend(_meta_annotations(triggered_rules, config))
    if effective_observation_count() > 0:
        typosquat = naming_typosquat_finding(
            scan.package, **scan.typosquat_kwargs)
        if typosquat:
            triggered_rules.append(typosquat)
        cluster = naming_cluster_annotation(triggered_rules, config)
        if cluster:
            triggered_rules.append(cluster)
    keyring = maintainer_keyring_composition(
        triggered_rules, scan.maintainer_changed)
    if keyring:
        triggered_rules.append(keyring)

    evidence = collect_evidence(
        diff_text, recipe_text,
        added_urls=source_changes.added_urls,
        checksum_behavior=source_changes.checksum_behavior,
    )
    tree_text = scan.tree_analysis_text or diff_text
    tree_analyzed = bool(scan.tree_manifest) and scan.tree_complete and not (
        _scriptlet_files_unread(tree_text, scan.tree_manifest))
    return ScanResult(
        triggered_rules=triggered_rules,
        rule_ids=[rule["rule_id"] for rule in triggered_rules],
        suppressed_rules=suppressed_rules,
        expired_overrides=expired_overrides,
        source_changes=source_changes,
        source_urls=source_urls,
        url_acks=url_acks,
        scored_urls=scored_urls,
        source_buckets=source_buckets,
        novelty=novelty,
        change_delta_obj=change_delta_obj,
        evidence=evidence,
        resolved_strings=resolved_strings,
        resolved_commands=resolved_commands,
        resolved_recipe=resolved_recipe,
        unresolved_strings=unresolved_strings,
        tree_analyzed=tree_analyzed,
        tree_manifest=scan.tree_manifest,
        tree_complete=scan.tree_complete,
        unpinned_build_deps=has_unpinned_build_deps(diff_text, recipe_text),
        noextract_present=_has_noextract(recipe_text),
        diff_text=diff_text,
        recipe_text=recipe_text,
    )


@dataclass(frozen=True)
class FactIdentity:
    """The package/version/depth facts a PackageFact needs, both paths."""

    package: str
    old_version: str
    new_version: str
    diff_summary: Any
    old_commit: str = ""
    new_commit: str = ""
    maintainer_changed: bool = False
    previous_maintainer: str = ""
    current_maintainer: str = ""
    first_seen: bool = False
    comparison_base: str = ""
    temporal_source: str = ""
    depth: int | None = None
    depth_result: Any = None
    pkgver_changed: bool = False
    version_moved: bool = False
    pkgver_old: str = ""
    pkgver_new: str = ""
    version_comparison: Any = None
    correlation_ran: bool = False
    recent_commit_burst: bool = False
    added_names: set | None = None
    partial_hunk_details: list | None = None
    cofire_health: list | None = None
    extra_fields: dict = field(default_factory=dict)


def finalise_fact(
    scan: ScanResult,
    signals: CoverageSignals,
    identity: FactIdentity,
    config: dict,
) -> tuple[PackageFact, list[dict], dict]:
    """Turn the scanned rules into a scored fact, with path extras applied."""
    evidence = scan.evidence
    partial_hunk_details = (
        identity.partial_hunk_details
        if identity.partial_hunk_details is not None
        else cut_hunk_details(evidence.cut_hunks)
    )
    depth_result = identity.depth_result
    added_names = identity.added_names or set()
    signals = CoverageSignals(
        diff_truncated=signals.diff_truncated,
        scan_truncated=signals.scan_truncated,
        tree_analyzed=scan.tree_analyzed,
        companion_truncated=signals.companion_truncated,
        binary_metadata=signals.binary_metadata,
        unresolved_sources=evidence.unresolved_sources,
        long_lines=signals.long_lines,
        parse_time_substitutions=evidence.parse_time_substitutions,
        snapshot_refused=signals.snapshot_refused,
        unpinned_build_deps=scan.unpinned_build_deps,
        deps_not_scanned=(
            _deps_not_scanned(depth_result, added_names)
            if depth_result is not None else signals.deps_not_scanned
        ),
        parent_baseline=signals.parent_baseline,
        ruleset_drifted=bool(drifted_shipped_rules()),
        degraded_stages=stage_failures(),
        unresolved_assignments=bool(evidence.unresolved_assignments),
        noextract_present=scan.noextract_present,
        partial_hunks=len(evidence.cut_hunks),
        partial_files=evidence.partial_files,
        upstream_manifest_incomplete=signals.upstream_manifest_incomplete,
    )
    gaps = gaps_from(signals)

    triggered_rules = scan.triggered_rules
    triggered_rules.extend(m_series_findings(
        triggered_rules, config,
        claims=declared_claims(
            evidence.verification_evidence,
            evidence.aggregate_pinning,
            scan.source_buckets,
            prebuilt=evidence.prebuilt,
        ),
    ))
    volume = alert_volume_finding(triggered_rules, config)
    if volume:
        triggered_rules.append(volume)
    score, breakdown, risk = calculate_score(
        triggered_rules,
        {url: bucket for url, bucket in scan.source_buckets.items()
         if url not in scan.url_acks},
        scan.novelty, config,
        verification_evidence=evidence.verification_evidence,
        pinning_level=evidence.aggregate_pinning,
        coverage_gaps=gaps,
        prebuilt=evidence.prebuilt,
    )
    score, breakdown, campaign_context = _campaign_corroboration(
        score, breakdown, identity.package, scan.source_changes.added_urls, gaps)

    cofire_health = m_tool_health(triggered_rules, load_rules())
    fact = PackageFact(
        package_name=identity.package,
        old_version=identity.old_version,
        new_version=identity.new_version,
        version_comparison=identity.version_comparison,
        old_commit=identity.old_commit,
        new_commit=identity.new_commit,
        maintainer_changed=identity.maintainer_changed,
        previous_maintainer=identity.previous_maintainer,
        current_maintainer=identity.current_maintainer,
        pkgver_changed=identity.pkgver_changed,
        version_moved=identity.version_moved,
        pkgver_old=identity.pkgver_old,
        pkgver_new=identity.pkgver_new,
        dependencies=list(getattr(depth_result, "reports", ()) or ()),
        depth_truncated=bool(getattr(depth_result, "truncated", False)),
        depth_note=str(getattr(depth_result, "reason", "") or ""),
        depth=identity.depth,
        diff_summary=identity.diff_summary,
        diff_shape_fp=diff_shape_fp(scan.diff_text),
        source_changes=scan.source_changes,
        source_buckets=scan.source_buckets,
        execution_changes=ExecutionChanges(
            resolved_commands=scan.resolved_commands,
            resolved_recipe=scan.resolved_recipe,
            suspicious_patterns_detected=scan.rule_ids,
            unresolved_patterns=scan.unresolved_strings,
        ),
        novelty_context=scan.novelty,
        suppressed_rules=scan.suppressed_rules,
        cofire_health=cofire_health,
        overrides_expired=scan.expired_overrides,
        acknowledged_urls=acknowledged_url_rows(scan.url_acks),
        recent_commit_burst=identity.recent_commit_burst,
        diff_truncated=signals.diff_truncated,
        scan_truncated=signals.scan_truncated,
        first_seen=identity.first_seen,
        comparison_base=identity.comparison_base,
        correlation_ran=identity.correlation_ran,
        tree_analyzed=scan.tree_analyzed,
        coverage_gaps=gaps,
        unresolved_sources=evidence.unresolved_sources,
        unresolved_assignments=evidence.unresolved_assignments,
        partial_hunks=partial_hunk_details,
        partial_files=evidence.partial_files,
        change=scan.change_delta_obj.to_dict(),
        risk=risk,
        temporal_source=identity.temporal_source,
        score_breakdown=breakdown,
        final_score=score,
        ioc_matches=ioc_baseline_matches(
            scan.diff_text, identity.package, current_text=scan.recipe_text),
        campaign_hold=bool(campaign_context.get("campaign_hold")),
        campaign_id=str(campaign_context.get("campaign_id") or ""),
        campaign_state=str(campaign_context.get("campaign_state")
                            or "unavailable"),
        **identity.extra_fields,
    )
    fact.resolution_coverage = resolution_coverage(
        scan.resolved_strings, scan.unresolved_strings,
        triggered_rules, load_rules())
    with_changes(fact, scan.diff_text)
    return fact, triggered_rules, campaign_context


def record_observed_identity(change: dict, maintainer: str) -> None:
    """Record the signing keys and maintainer domain an analysis observed.

    This is the write half of the T-series ecosystem index.  It belongs on
    both producers (git and corpus), and only when the caller asked for a
    recording run: a review must not warm the ledger (A15).
    """
    from ...db import record_observed_domain, record_observed_key
    from ...maintainer_email import maintainer_domain

    pgp = (change or {}).get("pgp_keys", {}) or {}
    for key in (*pgp.get("gained", ()), *pgp.get("lost", ())):
        record_observed_key(str(key))
    domain = maintainer_domain(maintainer)
    if domain:
        record_observed_domain(domain)
