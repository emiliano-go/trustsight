"""Extracted from pipeline.py: _scan."""

import difflib
from ...buckets import classify_urls
from ...config import (
    drifted_shipped_rules,
    load_config,
    load_rules,
)
from ...diffdoc import diff_shape_fp, parse_diff_lines
from ...differ import (
    diff_summary_from_text,
    binary_metadata_in_text,
    detect_gpg_verification_removed,
    detect_verification_evidence,
    extract_urls_from_diff,
    map_diff_lines,
    resolved_source_urls,
)
from ...findings import stamp
from ...novelty import (
    normalize_url,
)
from ...deps import extract_dependency_changes
from ...override import (
    acknowledged_url_rows,
    match_url_acks,
    suppress_acknowledged_url_findings,
)
from ...rules import (
    apply_rules,
    bound_tokenizer_lines,
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
    ExecutionChanges,
    NoveltyContext,
    PackageFact,
)
from ...tokenizer import split_lines, tokenize_and_resolve_indexed
from ..base import (
    _GLOBAL_URL_KEY,
    _aggregate_pinning,
    _has_install_hook,
    _without_notice_only_install_modifications,
)
from ..composition import (
    _meta_annotations,
)
from ..ioc_match import ioc_baseline_matches
from ..structural import (
    _structural_findings,
    partial_install_files,
    unchanged_upstream_host,
)
from ..structural_rules import apply_structural_rules
from ..version import (
    any_version_scalar_moved,
    pkgver_move_in_diff,
)
from ._analyze import apply_diff_caps
from ._tree import _adds_a_dependency, _binary_metadata_finding, _has_noextract, _scriptlet_files_unread

__all__ = ['analyze_package_text', 'scan_diff']

def scan_diff(
    diff_text: str,
    rules: list[dict] | None = None,
    config: dict | None = None,
    package_name: str = "",
    seen_urls: dict[str, set[str]] | None = None,
    observation_count: int = 0,
    tree_manifest: list[tuple[str, bytes]] | None = None,
    current_text: str | None = None,
    tree_complete: bool = True,
    structural_rules: list[dict] | None = None,
) -> PackageFact:
    begin_stage_tracking()
    if config is None:
        config = load_config()

    diff_text, diff_truncated, scan_truncated = apply_diff_caps(
        diff_text, config, package_name
    )
    long_lines = oversized_lines(diff_text.split("\n"))
    diff_text = bound_tokenizer_lines(diff_text)

    source_changes = extract_urls_from_diff(diff_text, current_text=current_text)
    declared = set(source_changes.declared_urls)
    source_urls = [u for u in source_changes.added_urls if u not in declared]
    url_acks = match_url_acks(package_name, source_urls) if package_name else {}
    scored_urls = [u for u in source_urls if u not in url_acks]
    pkgver_changed, _pkgver_old, _pkgver_new = pkgver_move_in_diff(
        diff_text, current_text
    )
    version_moved = any_version_scalar_moved(diff_text, current_text)

    source_buckets = classify_urls(
        source_urls,
        upstream_host=unchanged_upstream_host(diff_text, current_text),
    )

    resolved_strings, unresolved_strings, resolved_indices = (
        tokenize_and_resolve_indexed(diff_text)
    )
    raw_lines, raw_indices = get_raw_diff_lines_indexed(diff_text)
    line_map = map_diff_lines(diff_text)

    triggered_rules = apply_rules(
        resolved_strings, raw_lines, rules,
        include_experimental=config.get("rules", {}).get("experimental", False),
        line_map=line_map,
        resolved_indices=resolved_indices,
        raw_indices=raw_indices,
    )
    change_delta_obj = change_delta(clamp_text(diff_text), package_name,
                                current_text=current_text)
    triggered_rules.extend(
        _structural_findings(
            clamp_text(diff_text), source_changes, source_buckets,
            package_name=package_name, config=config,
            current_text=clamp_text(current_text),
            tree_manifest=tree_manifest,
            delta=change_delta_obj,
        )
    )
    triggered_rules.extend(
        apply_structural_rules(
            clamp_text(diff_text),
            current_text=clamp_text(current_text),
            rules=structural_rules,
            package_name=package_name,
        )
    )
    # Same blind spot as the git path, read from the marker git wrote: a
    # binary metadata delta has no body, so no rule sees a line of it.
    binary_meta = binary_metadata_in_text(diff_text)
    if binary_meta:
        triggered_rules.append(_binary_metadata_finding(binary_meta))
    if tree_manifest:
        from ..delivery import scan_tree_manifest
        triggered_rules.extend(
            scan_tree_manifest(tree_manifest, source_changes.added_urls, package_name)
        )
    triggered_rules = _without_notice_only_install_modifications(
        triggered_rules, diff_text)
    triggered_rules = suppress_acknowledged_url_findings(
        triggered_rules, package_name, url_acks)
    from ..persistence import stand_down_committed_staging
    triggered_rules = stand_down_committed_staging(triggered_rules, tree_manifest)

    # H087 only.  was_orphaned=-1 means "no recorded observation", so H086
    # and H088 are structurally silent here: the stateless path has no AUR
    # history to claim an adoption against, and a rule that fires without
    # its state is the cold-start failure the calibration gates catch.
    adoption_findings(
        diff_text,
        package_name=package_name or "",
        was_orphaned=-1,
        currently_maintained=False,
        pkgver_moved=pkgver_changed,
        current_text=current_text,
        add=lambda rid, name, severity, category, match, **params: (
            triggered_rules.append(stamp({
                "rule_id": rid, "name": name, "severity": severity,
                "category": category, "match": match, "params": params,
            }))
        ),
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

    triggered_rules.extend(_meta_annotations(triggered_rules, config))

    rule_ids = [r["rule_id"] for r in triggered_rules]

    aggregate_pinning = _aggregate_pinning(
        diff_text, source_changes.added_urls, source_changes.checksum_behavior,
        declared_urls=resolved_source_urls(current_text),
    )
    verification_evidence = detect_verification_evidence(
        diff_text, source_changes.checksum_behavior
    )

    novelty = NoveltyContext(observation_count=observation_count)
    pkgs_seen = seen_urls if seen_urls is not None else {}
    pkg_set = pkgs_seen.setdefault(package_name, set())
    global_set = pkgs_seen.setdefault(_GLOBAL_URL_KEY, set())
    for url in scored_urls:
        nurl = normalize_url(url)
        if nurl not in pkg_set:
            novelty.url_first_seen_in_this_package = True
            if not novelty.url_first_seen_in_this_package_url:
                novelty.url_first_seen_in_this_package_url = url
            pkg_set.add(nurl)
        if nurl not in global_set:
            novelty.url_first_seen_globally = True
            if not novelty.url_first_seen_globally_url:
                novelty.url_first_seen_globally_url = url
            global_set.add(nurl)

    unresolved_sources = unresolved_source_lines(diff_text)
    change = change_delta_obj.to_dict()
    surface_doc = parse_diff_lines(split_lines(diff_text))
    cut_hunks = surface_doc.cut_hunks()
    partial_hunk_details = cut_hunk_details(cut_hunks)
    # the analysed surface is the caller's post-state text
    # when given, else the diff's own post projection (with per-file
    # origins, so each refusal names the file it came from).
    parse_time_subs = parse_time_substitution_lines(diff_text, current_text)
    unresolved_assignments = unresolved_assignment_rows(
        clamp_text(current_text or "\n".join(surface_doc.post_lines())),
        file="PKGBUILD" if current_text else "",
        origins=None if current_text else surface_doc.post_origins(),
        extra_lines=[*unresolved_sources, *parse_time_subs],
    )
    partial_files = partial_install_files(diff_text)
    gaps = gaps_from(
        diff_truncated=diff_truncated,
        scan_truncated=scan_truncated,
        tree_analyzed=(bool(tree_manifest) and tree_complete
                       and not _scriptlet_files_unread(
                           diff_text, tree_manifest)),
        binary_metadata=bool(binary_meta),
        unresolved_sources=unresolved_sources,
        long_lines=long_lines,
        parse_time_substitutions=parse_time_subs,
        unpinned_build_deps=has_unpinned_build_deps(diff_text, current_text),
        # This path analyses no dependencies at all, so any dependency the
        # diff adds is code the package now pulls in and this run did not
        # read. See the note on the incremental path above.
        deps_not_scanned=_adds_a_dependency(diff_text),
        ruleset_drifted=bool(drifted_shipped_rules()),
        degraded_stages=stage_failures(),
        unresolved_assignments=bool(unresolved_assignments),
        noextract_present=_has_noextract(current_text or diff_text),
        partial_hunks=len(cut_hunks),
        partial_files=partial_files,
    )

    # M-series predicates over the completed finding set
    # (after the ownership resolver), before scoring.
    from ..meta import alert_volume_finding, m_series_findings, m_tool_health
    from ...scoring import declared_claims, prebuilt_declared

    prebuilt = prebuilt_declared(current_text)
    triggered_rules.extend(m_series_findings(
        triggered_rules, config,
        claims=declared_claims(
            verification_evidence, aggregate_pinning, source_buckets,
            prebuilt=prebuilt)))
    _volume = alert_volume_finding(triggered_rules, config)
    if _volume:
        triggered_rules.append(_volume)
    score, breakdown, risk = calculate_score(
        triggered_rules,
        {u: b for u, b in source_buckets.items() if u not in url_acks},
        novelty, config,
        verification_evidence=verification_evidence,
        pinning_level=aggregate_pinning,
        coverage_gaps=gaps,
        prebuilt=prebuilt,
    )

    ioc_matches = ioc_baseline_matches(
        diff_text, package_name, current_text=current_text
    )

    exec_changes = ExecutionChanges(
        resolved_commands=resolved_strings,
        suspicious_patterns_detected=rule_ids,
        unresolved_patterns=unresolved_strings,
    )

    fact = PackageFact(
        package_name=package_name,
        diff_summary=diff_summary_from_text(diff_text),
        diff_shape_fp=diff_shape_fp(diff_text),
        source_changes=source_changes,
        source_buckets=source_buckets,
        execution_changes=exec_changes,
        novelty_context=novelty,
        cofire_health=m_tool_health(triggered_rules, load_rules()),
        acknowledged_urls=acknowledged_url_rows(url_acks),
        pkgver_changed=pkgver_changed,
        version_moved=version_moved,
        pkgver_old=_pkgver_old or "",
        pkgver_new=_pkgver_new or "",
        diff_truncated=diff_truncated,
        scan_truncated=scan_truncated,
        tree_analyzed=(bool(tree_manifest) and tree_complete
                       and not _scriptlet_files_unread(
                           diff_text, tree_manifest)),
        coverage_gaps=gaps,
        unresolved_sources=unresolved_sources,
        unresolved_assignments=unresolved_assignments,
        partial_hunks=partial_hunk_details,
        partial_files=partial_files,
        change=change,
        risk=risk,
        score_breakdown=breakdown,
        final_score=score,
        ioc_matches=ioc_matches,
    )
    deps_added = extract_dependency_changes(
        diff_text, package_name, current_text=current_text
    )
    fact.dependency_changes = {k: sorted(v) for k, v in deps_added.items() if v}
    fact.resolution_coverage = resolution_coverage(
        resolved_strings, unresolved_strings, triggered_rules, load_rules())
    return with_changes(fact, diff_text)

def analyze_package_text(
    pkg_name: str,
    old_text: str,
    new_text: str,
    config: dict | None = None,
    rules: list[dict] | None = None,
    adapter: str = "corpus",
    tree_manifest: list[tuple[str, bytes]] | None = None,
) -> PackageFact:
    begin_stage_tracking()
    if config is None:
        config = load_config()

    diff_text = "\n".join(difflib.unified_diff(
        # The recipe decides where its lines end only in the ways a shell
        # agrees with: a U+2028 in a PKGBUILD is a character in a word, and
        # letting difflib break there produces diff lines that do not
        # correspond to the file every downstream rule then reads.
        split_lines(old_text) if old_text else [],
        split_lines(new_text) if new_text else [],
        fromfile="PKGBUILD", tofile="PKGBUILD",
        n=config.get("diff", {}).get("max_context_lines", 3),
    ))

    fact = scan_diff(
        diff_text,
        rules=rules,
        config=config,
        package_name=pkg_name,
        tree_manifest=tree_manifest,
        current_text=new_text,
    )
    fact.adapter = adapter
    fact.temporal_source = "aur_metadata"
    return fact
