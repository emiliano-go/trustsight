"""The no-git PackageFact builder."""

import json
import logging
from typing import Optional

from ._helpers import (
    _diff_summary,
    _extract_pkgver,
    _install_diff_text,
    _install_hunk_findings,
    _make_diff_text,
    _temporal_findings,
    _walk_corpus_dependencies,
)

from ...analysis.base import _aggregate_pinning, _has_install_hook
from ...analysis.adoption import credential_egress_finding, source_takeover_finding
from ...analysis.buildfetch import has_unpinned_build_deps
from ...analysis.composition import _meta_annotations, maintainer_keyring_composition, naming_cluster_annotation, naming_typosquat_finding
from ...analysis.crossfile import metadata_recipe_divergence
from ...analysis.longitudinal import longitudinal_findings
from ...analysis.ioc_match import ioc_baseline_matches
from ...analysis.dependencies import name_shadow_findings
from ...analysis.maintainer import _check_untrusted_maintainer_takeover
from ...analysis.meta import alert_volume_finding, m_series_findings
from ...analysis.placeholder import placeholder_finding
from ...analysis.structural import (
    _structural_findings,
    partial_install_files,
    recipe_checksum_parity_finding,
    unchanged_upstream_host,
)
from ...analysis.version import any_version_scalar_moved, pkgver_move_in_diff
from ...buckets import classify_urls
from ...changes import change_delta
from ...config import (
    drifted_shipped_rules,
    load_config,
    load_rules,
    load_thresholds,
)
from ...db import (
    effective_observation_count,
    get_connection,
    get_package,
    get_package_id,
    insert_analysis,
    record_dependency_names,
    update_package_maintainer,
    update_package_version,
    upsert_package,
)
from ...deps import extract_dependency_changes
from ...differ import (
    detect_gpg_verification_removed,
    detect_verification_evidence,
    extract_urls_from_diff,
    map_diff_lines,
    resolved_source_urls,
    truncate_diff,
)
from ...findings import stamp
from ...novelty import build_novelty_context
from ...override import (
    acknowledged_url_rows,
    filter_triggered_rules,
    match_url_acks,
)
from ...analysis.structural_rules import apply_structural_rules
from ...rules import (
    apply_rules,
    bound_tokenizer_lines,
    clamp_diff_lines,
    clamp_text,
    get_raw_diff_lines_indexed,
)
from ...coverage import (
    begin_stage_tracking,
    cut_hunk_details,
    gaps_from,
    note_stage_failure,
    oversized_lines,
    parse_time_substitution_lines,
    resolution_coverage,
    stage_failures,
    unresolved_assignment_rows,
    unresolved_source_lines,
)
from ...diffdoc import diff_shape_fp, parse_diff_lines
from ...scoring import calculate_score, declared_claims, prebuilt_declared
from ...schema import (
    with_changes,
    ExecutionChanges,
    PackageFact,
    TemporalContext,
    fact_to_dict,
)
from ...analysis.pipeline._tree import (
    _added_dependency_names,
    _deps_not_scanned,
    _scriptlet_files_unread,
)
from ...tokenizer import tokenize_and_resolve_indexed
from ..properties import extract_properties, metadata_divergence, update_properties
from ...tokenizer import split_lines

log = logging.getLogger(__name__)
def analyze_package_text(
    pkg_name: str,
    old_pkgbuild: Optional[str],
    new_pkgbuild: str,
    maintainer: str,
    temporal: TemporalContext,
    srcinfo: Optional[str] = None,
    tree_manifest: Optional[list[tuple[str, bytes]]] = None,
    archive_trailer_finding: Optional[dict] = None,
    snapshot_refused: bool = False,
    depth: int | None = None,
    _depth_seen: set | None = None,
    record: bool = False,
    popular_candidates: Optional[list[tuple[str, int]]] = None,
    package_popularity: int | None = None,
    install_text: Optional[str] = None,
    install_name: Optional[str] = None,
    old_install_text: Optional[str] = None,
    upstream_manifest_incomplete: bool = False,
    manifest_deltas=(),
    workflow_deltas=(),
) -> PackageFact:
    """Analyse a package from PKGBUILD text, without a git repository.

    This is the primary analysis path used by the full-AUR corpus builder.
    It generates a unified diff from the two texts, runs all detection
    rules, and returns a fully-populated PackageFact.

    Args:
        pkg_name:  AUR package name.
        old_pkgbuild:  Previous PKGBUILD text (None for first analysis).
        new_pkgbuild:  Current PKGBUILD text.
        maintainer:  Current maintainer string.
        temporal:  TemporalContext with clock timestamps and source.
        srcinfo:  .SRCINFO text (for richer property extraction).
        tree_manifest:  ``(path, head_bytes)`` pairs from the AUR snapshot
            tarball, when it was fetched.  Runs the H066-tree scan; when
            absent the result reports ``tree_analyzed=false`` rather than
            silently reading as full coverage.
        archive_trailer_finding:  an H070 finding stamped by
            ``check_archive_trailer`` on the snapshot tarball bytes, when
            one was produced.  Surfaced exactly like the H066-tree scan
            results, so the corpus path reports what the archive carried.
        depth:  AUR dependency levels to analyse, as on the review path.
            The corpus walk is cheaper than the review one: the metadata
            snapshot already holds every dependency edge, and a dependency's
            PKGBUILD is usually the stored snapshot rather than a fetch. A
            dependency with no stored text is reported as not vetted rather
            than fetched, because a corpus cycle already decides its own
            fetch order and re-entering it here would fight that.
        snapshot_refused:  the snapshot archive was refused by a read bound
            rather than being absent, so the missing tree is a bound that
            dropped content and not a package without a tarball.  Recorded
            as the ``snapshot_refused`` coverage gap.

    Returns:
        A fully-scored PackageFact.
    """
    config = load_config()
    old_maintainer: Optional[str] = None

    new_version = _extract_pkgver(new_pkgbuild)
    old_version = _extract_pkgver(old_pkgbuild) if old_pkgbuild else ""

    if record:
        package_id = upsert_package(pkg_name, new_version)
    else:
        package_id = get_package_id(pkg_name) or 0

    # Property stability tracking: record now, consumed in the same analysis
    # by the longitudinal rules (H047-H051/H054/H037).
    observed_at: str = ""
    if temporal.last_modified is not None:
        from datetime import datetime, timezone
        observed_at = datetime.fromtimestamp(temporal.last_modified, tz=timezone.utc).isoformat()
    else:
        from datetime import datetime, timezone
        observed_at = datetime.now(timezone.utc).isoformat()
    breaks: list = []
    if record:
        try:
            props = extract_properties(new_pkgbuild, srcinfo)
            # The pre-image under the same extractor: a stored baseline from an
            # older extractor must not read as a source/version change.
            previous_props = (
                extract_properties(old_pkgbuild) if old_pkgbuild else None
            )
            floor = int(
                load_thresholds().get("longitudinal", {}).get("stability_floor", 10)
            )
            with get_connection() as conn:
                breaks = update_properties(
                    conn, pkg_name, props, observed_at, floor=floor,
                    previous=previous_props,
                )
        except Exception:
            log.warning("property tracking failed for %s", pkg_name, exc_info=True)

    # Build the diff before walking the closure: the walk needs the added
    # dependency names to tell an unreached AUR package from an official one,
    # and the per-package walk must not share the review path's seen set.
    diff_text = ""
    if old_pkgbuild is not None:
        diff_text = _make_diff_text(old_pkgbuild, new_pkgbuild)
        if install_text and install_text != old_install_text:
            # The install scriptlet the snapshot carried: scanned here so the
            # corpus path reaches the root-fetch/write shapes only the git path
            # saw before.  The hunk carries the scriptlet's REAL basename (the
            # snapshot knows it); naming it after the package invents a file
            # the recipe never ships and sends C024 after a phantom mismatch.
            # Only a scriptlet whose text CHANGED is presented: re-adding an
            # unchanged hook to every diff made R007 (and the hook-content
            # rules) fire on every update of any package that merely HAS an
            # install file - the git path only ever shows real modifications.
            diff_text += _install_diff_text(
                install_text, install_name or f"{pkg_name}.install")
    recipe_diff = diff_text or _make_diff_text("", new_pkgbuild)
    added_names = _added_dependency_names(recipe_diff)
    depth_result = _walk_corpus_dependencies(
        pkg_name, depth, config, _depth_seen, record=record,
        added_names=added_names,
    )
    # The dependency walk recursively analyses packages, and every recursive
    # analysis starts its own thread-local stage record.  Start the root's
    # record after the walk, or the parent inherits the last dependency's
    # failures.  The root's own failures are still recorded below.
    begin_stage_tracking()

    # H092 - the metadata and the recipe describe different packages.
    metadata_findings: list[dict] = []
    for host in metadata_divergence(new_pkgbuild, srcinfo):
        metadata_findings.append(stamp({
            "rule_id": "H092",
            "name": "Metadata Names A Source The Recipe Does Not",
            "severity": "HIGH", "category": "integrity",
            "match": f".SRCINFO names {host}, which the PKGBUILD never does",
            "params": {"host": host},
        }))
    divergent = metadata_recipe_divergence(new_pkgbuild, srcinfo)
    if divergent:
        metadata_findings.append(stamp({
            "rule_id": "H103",
            "name": "Metadata And Recipe Disagree",
            "severity": "HIGH", "category": "integrity",
            "match": (".SRCINFO and the PKGBUILD disagree on "
                      + ", ".join(divergent)),
            "params": {"fields": ", ".join(divergent)},
        }))
    # G8, directional (see the per-package path in pipeline.py).
    from ...analysis.crossfile import line_of, source_divergence

    pkgbuild_only, srcinfo_only = source_divergence(new_pkgbuild, srcinfo)
    if pkgbuild_only:
        metadata_findings.append(stamp({
            "rule_id": "H103",
            "name": "Metadata And Recipe Disagree",
            "severity": "HIGH", "category": "integrity",
            "match": ("PKGBUILD fetches source(s) .SRCINFO does not declare: "
                      + ", ".join(pkgbuild_only)),
            "file": "PKGBUILD",
            "line": line_of(new_pkgbuild or "", pkgbuild_only[0]),
            "params": {"fields": "source", "direction": "pkgbuild_only",
                       "sources": ", ".join(pkgbuild_only),
                       "metadata_file": ".SRCINFO"},
        }))
    elif srcinfo_only:
        metadata_findings.append(stamp({
            "rule_id": "H103",
            "name": "Metadata And Recipe Disagree",
            "severity": "INFO", "category": "integrity",
            "match": (".SRCINFO declares source(s) the PKGBUILD does not: "
                      + ", ".join(srcinfo_only)),
            "file": ".SRCINFO",
            "line": line_of(srcinfo or "", srcinfo_only[0]),
            "params": {"fields": "source", "direction": "srcinfo_only",
                       "sources": ", ".join(srcinfo_only),
                       "recipe_file": "PKGBUILD"},
        }))

    if old_pkgbuild is None:
        novelty = build_novelty_context([], package_id, record=record)
        triggered_rules: list[dict] = []
        triggered_rules.extend(metadata_findings)
        triggered_rules.extend(
            _temporal_findings(temporal, pkg_name, True)
        )
        parity = recipe_checksum_parity_finding(new_pkgbuild)
        if parity:
            triggered_rules.append(parity)
        placeholder = placeholder_finding(new_pkgbuild)
        if placeholder:
            triggered_rules.append(placeholder)
        triggered_rules.extend(name_shadow_findings(new_pkgbuild, pkg_name))
        if tree_manifest:
            from ...analysis.delivery import scan_tree_manifest
            triggered_rules.extend(scan_tree_manifest(
                tree_manifest, resolved_source_urls(new_pkgbuild), pkg_name))
        triggered_rules.extend(_install_hunk_findings(
            install_text, install_name, pkg_name, new_pkgbuild,
            tree_manifest, config,
        ))
        if archive_trailer_finding:
            triggered_rules.append(archive_trailer_finding)
        triggered_rules.extend(
            apply_structural_rules(
                "", current_text=clamp_text(new_pkgbuild), package_name=pkg_name
            )
        )
        from ...analysis.upstream_release import upstream_release_findings

        def _upstream_add(rid, name, severity, category, match,
                          weight_override=None, **params):
            finding = {
                "rule_id": rid, "name": name, "severity": severity,
                "category": category, "match": match, "params": params,
            }
            if weight_override is not None:
                finding["weight_override"] = weight_override
            triggered_rules.append(stamp(finding))

        upstream_release_findings(
            "", None, _upstream_add, config, pkg_name, current_text=new_pkgbuild,
        )
        from ...override import suppress_acknowledged_url_findings

        url_acks: dict = {}
        triggered_rules = suppress_acknowledged_url_findings(
            triggered_rules, pkg_name, url_acks)
        expired_overrides: list[str] = []
        triggered_rules, suppressed_rules = filter_triggered_rules(
            triggered_rules, package=pkg_name, expired_out=expired_overrides
        )

        if effective_observation_count() > 0:
            typosquat = naming_typosquat_finding(
                pkg_name,
                candidates=popular_candidates,
                self_popularity=package_popularity,
            )
            if typosquat:
                triggered_rules.append(typosquat)
            cluster = naming_cluster_annotation(triggered_rules, config)
            if cluster:
                triggered_rules.append(cluster)

        unresolved_assignments = unresolved_assignment_rows(
            clamp_text(new_pkgbuild) or "", file="PKGBUILD")
        from ...analysis.pipeline._tree import _has_noextract

        triggered_rules.extend(_meta_annotations(triggered_rules, config))
        prebuilt = prebuilt_declared(new_pkgbuild)
        triggered_rules.extend(m_series_findings(
            triggered_rules, config,
            claims=declared_claims(prebuilt=prebuilt),
        ))
        volume = alert_volume_finding(triggered_rules, config)
        if volume:
            triggered_rules.append(volume)
        tree_analyzed = bool(tree_manifest) and not _scriptlet_files_unread(
            recipe_diff, tree_manifest)
        gaps = gaps_from(
            tree_analyzed=tree_analyzed,
            snapshot_refused=snapshot_refused,
            upstream_manifest_incomplete=upstream_manifest_incomplete,
            deps_not_scanned=_deps_not_scanned(depth_result, added_names),
            ruleset_drifted=bool(drifted_shipped_rules()),
            degraded_stages=stage_failures(),
            unresolved_assignments=bool(unresolved_assignments),
            noextract_present=_has_noextract(new_pkgbuild),
        )
        score, breakdown, risk = calculate_score(
            triggered_rules, {}, novelty, config, coverage_gaps=gaps,
            prebuilt=prebuilt,
        )

        fact = PackageFact(
            package_name=pkg_name,
            old_version=old_version,
            new_version=new_version,
            novelty_context=novelty,
            suppressed_rules=suppressed_rules,
            overrides_expired=expired_overrides,
            acknowledged_urls=acknowledged_url_rows(url_acks),
            # Known here and recorded two lines below by
            # `update_package_maintainer`, so leaving it off the fact meant
            # a first-seen corpus entry reported no maintainer while the
            # database had one.  The incremental path below carries it.
            current_maintainer=maintainer,
            first_seen=True,
            comparison_base="none",
            temporal_source=temporal.source,
            tree_analyzed=tree_analyzed,
            coverage_gaps=gaps,
            dependencies=list(depth_result.reports),
            depth_truncated=depth_result.truncated,
            depth_note=depth_result.reason,
            unresolved_assignments=unresolved_assignments,
            risk=risk,
            score_breakdown=breakdown,
            final_score=score,
            ioc_matches=ioc_baseline_matches("", pkg_name, current_text=new_pkgbuild),
        )

        # No diff on the first-seen path: there is nothing to compare
        # against, and the summary says so from the fact alone.
        with_changes(fact)
        if record:
            insert_analysis(
                package_id=package_id,
                old_version=old_version,
                new_version=new_version,
                old_commit="",
                new_commit="",
                final_score=score,
                raw_diff="",
                fact_json=json.dumps(fact_to_dict(fact)),
                triggered_rules=triggered_rules,
            )
            update_package_version(pkg_name, new_version)
            if maintainer:
                update_package_maintainer(pkg_name, maintainer)
            from ...recipedoc import parse_recipe
            from ...db import record_recipe_document

            try:
                recipe = parse_recipe(new_pkgbuild or "", file="PKGBUILD")
                record_recipe_document(pkg_name, recipe.scalars, recipe.arrays)
            except Exception:
                note_stage_failure("recipe-index")
            dependency_changes = extract_dependency_changes(
                recipe_diff, pkg_name, current_text=new_pkgbuild,
            )
            record_dependency_names(sorted(
                name for names in dependency_changes.values() for name in names
            ))
        return fact

    max_bytes = config.get("diff", {}).get("max_diff_bytes", 5_242_880)
    diff_text, diff_truncated = truncate_diff(diff_text, max_bytes)
    if diff_truncated:
        log.warning("diff for %s exceeds %d bytes; truncating", pkg_name, max_bytes)
    # The byte cap is not a bound on matching work: 5 MiB of short lines is
    # over a million lines.  The review paths clamp by line count; the
    # corpus path must too, or a package chooses how long its cycle runs.
    diff_text, scan_truncated = clamp_diff_lines(diff_text, pkg_name)
    long_lines = oversized_lines(diff_text.split("\n"))
    diff_text = bound_tokenizer_lines(diff_text)

    source_changes = extract_urls_from_diff(diff_text)
    declared = set(source_changes.declared_urls)
    source_urls = [u for u in source_changes.added_urls if u not in declared]
    url_acks = match_url_acks(pkg_name, source_urls)
    scored_urls = [u for u in source_urls if u not in url_acks]
    source_buckets = classify_urls(
        source_urls,
        upstream_host=unchanged_upstream_host(diff_text, new_pkgbuild),
    )
    pkgver_changed, _pkgver_old, _pkgver_new = pkgver_move_in_diff(
        diff_text, new_pkgbuild
    )
    version_moved = any_version_scalar_moved(diff_text, new_pkgbuild)

    pkg_row = get_package(pkg_name)
    if pkg_row and pkg_row.get("current_maintainer"):
        old_maintainer = pkg_row["current_maintainer"]
    from ...analysis.maintainer import maintainer_identity

    maintainer_changed = bool(
        old_maintainer and maintainer
        and maintainer_identity(old_maintainer) != maintainer_identity(maintainer)
    )

    from ...recipedoc import parse_recipe as _parse_recipe

    novelty = build_novelty_context(
        scored_urls,
        package_id,
        maintainer=maintainer,
        record=record,
        package_name=pkg_name,
        source_array=_parse_recipe(new_pkgbuild, file="PKGBUILD").arrays.get("source", ()),
        source_buckets=source_buckets,
    )

    resolved_strings, unresolved_strings, resolved_indices = (
        tokenize_and_resolve_indexed(diff_text)
    )
    raw_lines, raw_indices = get_raw_diff_lines_indexed(diff_text)
    line_map = map_diff_lines(diff_text)

    triggered_rules = apply_rules(
        resolved_strings, raw_lines,
        include_experimental=config.get("rules", {}).get("experimental", False),
        line_map=line_map,
        resolved_indices=resolved_indices,
        raw_indices=raw_indices,
    )
    triggered_rules.extend(metadata_findings)
    change_delta_obj = change_delta(clamp_text(diff_text), pkg_name,
                                current_text=new_pkgbuild)
    if manifest_deltas or workflow_deltas:
        from dataclasses import replace

        change_delta_obj = replace(
            change_delta_obj,
            files=change_delta_obj.files + tuple(workflow_deltas),
            manifests=change_delta_obj.manifests + tuple(manifest_deltas),
            hosts_gained=change_delta_obj.hosts_gained | frozenset({
                host for manifest in manifest_deltas
                for host in manifest.remote_added
            }),
        )
    triggered_rules.extend(
        _structural_findings(
            clamp_text(diff_text), source_changes, source_buckets,
            maintainer_changed=maintainer_changed,
            package_name=pkg_name, config=config,
            current_text=clamp_text(new_pkgbuild),
            tree_manifest=tree_manifest,
            delta=change_delta_obj,
        )
    )
    triggered_rules.extend(
        apply_structural_rules(
            clamp_text(diff_text),
            current_text=clamp_text(new_pkgbuild),
            package_name=pkg_name,
        )
    )
    if tree_manifest:
        from ...analysis.delivery import scan_tree_manifest
        triggered_rules.extend(
            scan_tree_manifest(
                tree_manifest, resolved_source_urls(new_pkgbuild), pkg_name)
        )
    from ...override import suppress_acknowledged_url_findings

    triggered_rules = suppress_acknowledged_url_findings(
        triggered_rules, pkg_name, url_acks)
    from ...analysis.persistence import stand_down_committed_staging
    triggered_rules = stand_down_committed_staging(triggered_rules, tree_manifest)
    if archive_trailer_finding:
        triggered_rules.append(archive_trailer_finding)
    expired_overrides: list[str] = []
    triggered_rules, suppressed_rules = filter_triggered_rules(
        triggered_rules, package=pkg_name, expired_out=expired_overrides
    )

    triggered_rules.extend(
        _temporal_findings(temporal, pkg_name, False)
    )

    triggered_rules.extend(
        longitudinal_findings(
            diff_text, pkg_name, breaks, config,
            current_text=new_pkgbuild,
        )
    )

    if not any(r["rule_id"] == "R007" for r in triggered_rules):
        if _has_install_hook(diff_text):
            triggered_rules.append(stamp({
                "rule_id": "H023", "name": "Install Hook Present",
                "severity": "INFO", "category": "context",
                "match": "PKGBUILD declares an install hook",
            }))

    if detect_gpg_verification_removed(diff_text):
        triggered_rules.append(stamp({
            "rule_id": "H024", "name": "GPG Verification Removed",
            "severity": "HIGH", "category": "integrity",
            "match": "validpgpkeys was populated and is now empty or removed",
        }))

    takeover = _check_untrusted_maintainer_takeover(
        maintainer_changed, maintainer
    )
    if takeover:
        triggered_rules.append(takeover)

    h105 = source_takeover_finding(
        package_name=pkg_name,
        findings=triggered_rules,
        adopted=False,
        maintainer_changed=maintainer_changed,
        added_urls=source_changes.added_urls,
        removed_urls=source_changes.removed_urls,
        current_text=new_pkgbuild,
    )
    if h105:
        triggered_rules.append(h105)

    h107 = credential_egress_finding(
        package_name=pkg_name,
        findings=triggered_rules,
        diff_text=diff_text,
    )
    if h107:
        triggered_rules.append(h107)

    triggered_rules.extend(_meta_annotations(triggered_rules, config))

    if effective_observation_count() > 0:
        typosquat = naming_typosquat_finding(
            pkg_name,
            candidates=popular_candidates,
            self_popularity=package_popularity,
        )
        if typosquat:
            triggered_rules.append(typosquat)
        cluster = naming_cluster_annotation(triggered_rules, config)
        if cluster:
            triggered_rules.append(cluster)

    keyring = maintainer_keyring_composition(triggered_rules, maintainer_changed)
    if keyring:
        triggered_rules.append(keyring)

    rule_ids = [r["rule_id"] for r in triggered_rules]

    aggregate_pinning = _aggregate_pinning(
        diff_text, source_changes.added_urls, source_changes.checksum_behavior,
        declared_urls=resolved_source_urls(new_pkgbuild),
    )
    verification_evidence = detect_verification_evidence(
        diff_text, source_changes.checksum_behavior
    )

    unresolved_sources = unresolved_source_lines(diff_text)
    parse_time_subs = parse_time_substitution_lines(diff_text, new_pkgbuild)
    unresolved_assignments = unresolved_assignment_rows(
        clamp_text(new_pkgbuild) or "", file="PKGBUILD",
        extra_lines=[*unresolved_sources, *parse_time_subs])
    cut_hunks = parse_diff_lines(split_lines(diff_text)).cut_hunks()
    partial_files = partial_install_files(diff_text)
    from ...analysis.pipeline._tree import _has_noextract

    prebuilt = prebuilt_declared(new_pkgbuild)
    triggered_rules.extend(m_series_findings(
        triggered_rules, config,
        claims=declared_claims(
            verification_evidence, aggregate_pinning, source_buckets,
            prebuilt=prebuilt),
    ))
    volume = alert_volume_finding(triggered_rules, config)
    if volume:
        triggered_rules.append(volume)
    tree_analyzed = bool(tree_manifest) and not _scriptlet_files_unread(
        recipe_diff, tree_manifest)
    gaps = gaps_from(
        diff_truncated=diff_truncated,
        scan_truncated=scan_truncated,
        partial_hunks=len(cut_hunks),
        partial_files=partial_files,
        tree_analyzed=tree_analyzed,
        unresolved_sources=unresolved_sources,
        long_lines=long_lines,
        parse_time_substitutions=parse_time_subs,
        snapshot_refused=snapshot_refused,
        upstream_manifest_incomplete=upstream_manifest_incomplete,
        unpinned_build_deps=has_unpinned_build_deps(diff_text, new_pkgbuild),
        deps_not_scanned=_deps_not_scanned(depth_result, added_names),
        ruleset_drifted=bool(drifted_shipped_rules()),
        degraded_stages=stage_failures(),
        unresolved_assignments=bool(unresolved_assignments),
        noextract_present=_has_noextract(new_pkgbuild),
    )

    score, breakdown, risk = calculate_score(
        triggered_rules,
        {u: b for u, b in source_buckets.items() if u not in url_acks},
        novelty, config,
        verification_evidence=verification_evidence,
        pinning_level=aggregate_pinning,
        coverage_gaps=gaps,
        prebuilt=prebuilt,
    )

    fact = PackageFact(
        package_name=pkg_name,
        old_version=old_version,
        new_version=new_version,
        maintainer_changed=maintainer_changed,
        previous_maintainer=old_maintainer,
        current_maintainer=maintainer,
        pkgver_changed=pkgver_changed,
        version_moved=version_moved,
        pkgver_old=_pkgver_old or "",
        pkgver_new=_pkgver_new or "",
        diff_summary=_diff_summary(diff_text),
        diff_shape_fp=diff_shape_fp(diff_text),
        source_changes=source_changes,
        source_buckets=source_buckets,
        execution_changes=ExecutionChanges(
            resolved_commands=resolved_strings,
            suspicious_patterns_detected=rule_ids,
            unresolved_patterns=unresolved_strings,
        ),
        novelty_context=novelty,
        suppressed_rules=suppressed_rules,
        overrides_expired=expired_overrides,
        acknowledged_urls=acknowledged_url_rows(url_acks),
        diff_truncated=diff_truncated,
        scan_truncated=scan_truncated,
        # /: the corpus cycle runs the
        # collective G-series correlation, so L8 was exercised for this
        # package's corpus result.
        correlation_ran=True,
        comparison_base="recorded",
        tree_analyzed=tree_analyzed,
        coverage_gaps=gaps,
        dependencies=list(depth_result.reports),
        depth_truncated=depth_result.truncated,
        depth_note=depth_result.reason,
        unresolved_sources=unresolved_sources,
        unresolved_assignments=unresolved_assignments,
        partial_hunks=cut_hunk_details(cut_hunks),
        partial_files=partial_files,
        change=change_delta_obj.to_dict(),
        risk=risk,
        temporal_source=temporal.source,
        score_breakdown=breakdown,
        final_score=score,
        ioc_matches=ioc_baseline_matches(diff_text, pkg_name, current_text=new_pkgbuild),
    )

    fact.resolution_coverage = resolution_coverage(
        resolved_strings, unresolved_strings, triggered_rules, load_rules())
    with_changes(fact, diff_text)
    if record:
        insert_analysis(
            package_id=package_id,
            old_version=old_version,
            new_version=new_version,
            old_commit="",
            new_commit="",
            final_score=score,
            raw_diff=diff_text,
            fact_json=json.dumps(fact_to_dict(fact)),
            triggered_rules=triggered_rules,
        )

        # Keep the added encoded literals so G002 can join across packages
        # at cycle end, the same feed the review path records.
        from ...analysis.entropy import added_literals, added_text
        from ...db import record_added_literals

        record_added_literals(pkg_name, added_literals(added_text(diff_text)))

        # index this version's RecipeDoc arrays and scalars for
        # exact tuple history.  The index is analysis-side; the signed
        # seed/baseline pipeline is untouched.
        from ...recipedoc import parse_recipe
        from ...db import record_recipe_document

        try:
            recipe = parse_recipe(new_pkgbuild or "", file="PKGBUILD")
            record_recipe_document(pkg_name, recipe.scalars, recipe.arrays)
        except Exception:
            note_stage_failure("recipe-index")

        update_package_version(pkg_name, new_version)
        if maintainer:
            update_package_maintainer(pkg_name, maintainer)

    dependency_changes = extract_dependency_changes(
        diff_text, pkg_name, current_text=new_pkgbuild
    )
    fact.dependency_changes = {k: sorted(v) for k, v in dependency_changes.items() if v}
    with_changes(fact, diff_text)
    if record:
        record_dependency_names(sorted(
            name for names in dependency_changes.values() for name in names
        ))

    return fact
