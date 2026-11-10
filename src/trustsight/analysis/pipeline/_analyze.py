"""Extracted from pipeline.py: _analyze."""

import json
import time
from ...config import (
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
from ...sandbox.store_client import get_last_analysis, get_package, get_package_id
from ...differ import (
    extract_urls_from_diff,
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
from ...novelty import build_novelty_context  # noqa: F401 - patched via the facade
from ...sandbox.git_client import GitOpError, GitSandboxUnavailable
from ...deps import extract_dependency_changes
from ...override import (
    filter_triggered_rules,
    match_url_acks,
    suppress_acknowledged_url_findings,
)
from ...rules import (
    clamp_diff_lines,
)
from ..adoption import adoption_findings
from ...coverage import (
    CoverageSignals,
    begin_stage_tracking,
    note_stage_failure,
    resolution_coverage,
)
from ...scoring import ScoreEntry
from ...schema import (
    with_changes,
    PackageFact,
    fact_to_dict,
)
from ..base import (
    _ensure_init,
    _get_installed_version,
    _without_notice_only_install_modifications,
)
from ..placeholder import placeholder_finding
from ..version import (
    any_version_scalar_moved,
    compare_installed_to_aur,
    full_version_from_pkgbuild,
    is_vcs_package,
    pkgver_move_in_diff,
)
from ..temporal import _package_is_new, _recent_update, _stale_revival
from ._common import log
from ._core import (
    FactIdentity,
    ScanInput,
    finalise_fact,
    record_observed_identity,
    scan_recipe,
)
from ._tree import _added_dependency_names, _binary_metadata_finding, _cached_analysis

__all__ = ['_make_fresh_analysis', '_walk_dependencies', 'analyze_package', 'apply_diff_caps', 'scored_source_urls']



from ._analyze_helpers import (  # noqa: E402,F401
    _present_before_findings,
    _campaign_corroboration,
    _assemble_diff,
    _resolve_comparison_base,
    _make_fresh_analysis,
)

def _walk_dependencies(pkg_name, depth, config, seen, record: bool = False,
                       added_names: set[str] | None = None):
    """Analyse the AUR dependency closure of *pkg_name*.

    A dependency is analysed by ``analyze_package`` with ``depth=0``: the
    walk owns the level counting, so a child must not start a walk of its
    own or the closure would be traversed once per node.

    *added_names* are the non-official dependencies this diff added.  They
    are checked against the same provider the walk used, so the caller can
    tell "this name is not AUR" (no gap) from "this AUR name was never
    reached" (a gap).
    """
    from ...depth import DepthResult, default_metadata, resolve_depth, walk_dependencies

    resolved = resolve_depth(depth, config)
    provider = default_metadata()
    if resolved == 0:
        result = DepthResult()
    else:
        result = walk_dependencies(
            pkg_name,
            depth=resolved,
            metadata=provider,
            analyse=lambda name: analyze_package(name, depth=0, record=record),
            already_seen=seen,
        )
    if added_names:
        reported = {report.name for report in result.reports}
        try:
            result.added_aur_unreported = any(
                name not in reported and provider.is_aur(name)
                for name in added_names
            )
        except Exception:
            log.debug("added-dependency metadata check failed", exc_info=True)
            result.metadata_unavailable = True
    result.metadata_unavailable = (
        result.metadata_unavailable
        or not getattr(provider, "available", True)
    )
    return result








def analyze_package(
    pkg_name: str,
    old_commit: str = "",
    new_version: str = "",
    installed_version: str | None = None,
    upstream_mtime: int | None = None,
    aur_orphaned: bool | None = None,
    depth: int | None = None,
    _depth_seen: set | None = None,
    record: bool = False,
    full_recipe: bool = False,
    allow_cached: bool = False,
) -> PackageFact:
    from ...depth import resolve_depth

    _ensure_init()
    begin_stage_tracking()
    config = load_config()
    resolved_depth = resolve_depth(depth, config)

    if installed_version is None:
        installed_version = _get_installed_version(pkg_name)

    project = clone_or_fetch(pkg_name, upstream_mtime)
    head_commit = get_head_commit(project)
    # Read once, here, rather than after the two fresh-analysis returns
    # below: the declared version and the VCS question are both answered
    # from this text, and both are needed on every path out of this
    # function.  It used to be read further down, which is how the first
    # analysis of a package ended up with no version comparison at all.
    head_pkgbuild = get_pkgbuild_at_commit(project, head_commit) if head_commit else ""

    # The full `[epoch:]pkgver-pkgrel` the recipe declares, not the bare
    # `pkgver=` line.  `get_pkgver_from_head` remains the fallback for a
    # repository whose HEAD tree cannot be read at all.
    head_version = (
        full_version_from_pkgbuild(head_pkgbuild)
        or get_pkgver_from_head(project)
        or new_version
    )

    if not head_version:
        head_version = new_version

    # Read-only runs must not create or touch the package row either: the
    # id is only needed to key novelty lookups and the history write that
    # is skipped, so an unknown package reads against the seed's row (0).
    if record:
        package_id = upsert_package(pkg_name, head_version)
    else:
        package_id = get_package_id(pkg_name) or 0

    if not head_commit:
        return _make_fresh_analysis(pkg_name, head_version, head_commit, package_id, project, config, installed_version=installed_version, head_pkgbuild=head_pkgbuild, record=record, resolved_depth=resolved_depth)

    # A review run whose HEAD, versions, depth and ruleset all match the
    # recorded analysis is served that analysis (#20) instead of re-running
    # the diff, tokenizer, rules, tree and dependency stages.  Review-only:
    # inspect and the API keep the default ``allow_cached=False``.
    if allow_cached and not old_commit and not full_recipe and package_id:
        cached = _cached_analysis(
            package_id, head_commit, head_version, installed_version,
            depth, config,
        )
        if cached is not None:
            if record:
                # No history row: nothing new was analysed.  The sighting
                # still moves the recorded version, as a fresh run would.
                update_package_version(pkg_name, head_version)
            return cached

    last, comparison_base, parent_baseline, old_commit, needs_fresh = (
        _resolve_comparison_base(
            project, package_id, head_commit, old_commit, full_recipe))
    if needs_fresh:
        return _make_fresh_analysis(
            pkg_name, head_version, head_commit, package_id, project, config,
            installed_version=installed_version, head_pkgbuild=head_pkgbuild,
            record=record, resolved_depth=resolved_depth)

    diff_text, diff_summary, generated_truncated = project.diff_bounded(
        old_commit, head_commit,
        config.get("diff", {}).get("max_context_lines", 3),
        max_bytes=config.get("diff", {}).get("max_diff_bytes", 5_242_880),
    )
    (diff_text, diff_summary, diff_truncated, scan_truncated,
     companion_truncated, present_before, long_lines, cut_hunks,
     partial_hunk_details) = _assemble_diff(
        project, old_commit, head_commit, config, pkg_name, parent_baseline,
        diff_text, diff_summary, generated_truncated)

    pkgver_changed, _pkgver_old, _pkgver_new = pkgver_move_in_diff(
        diff_text, head_pkgbuild
    )
    version_moved = any_version_scalar_moved(diff_text, head_pkgbuild)

    old_maintainer = get_maintainer_from_commit(project, old_commit) or ""
    new_maintainer = get_maintainer_from_commit(project, head_commit) or ""
    if not old_maintainer:
        pkg_row = get_package(pkg_name)
        if pkg_row and pkg_row.get("current_maintainer"):
            old_maintainer = pkg_row["current_maintainer"]
    from ..maintainer import maintainer_identity

    maintainer_changed = bool(
        old_maintainer and new_maintainer
        and maintainer_identity(old_maintainer) != maintainer_identity(new_maintainer)
    )

    tree_manifest, tree_complete = (
        project.tree_files(head_commit) if head_commit else ([], False))

    # Git-only findings that must sit before the structural pass, exactly
    # where they were appended before the merge.
    pre_structural: list[dict] = []
    swapped = project.opaque_changed(old_commit, head_commit)
    if swapped:
        pre_structural.append(stamp({
            "rule_id": "C009" if version_moved else "C008",
            "name": ("Unread Content Moved With The Version" if version_moved
                     else "Unread Content Moved Under A Stable Version"),
            "severity": "INFO" if version_moved else "HIGH",
            "category": "integrity",
            "match": (
                f"committed file(s) replaced with no diff body: "
                f"{', '.join(swapped[:3])}"
                + ("" if version_moved else "; pkgver/pkgrel/epoch did not change")
            ),
            "file": swapped[0], "line": None,
            "params": {"carrier": "committed-binary",
                       "members": ", ".join(swapped[:5])},
        }))
    binary_meta = project.binary_meta(old_commit, head_commit)
    if binary_meta:
        pre_structural.append(_binary_metadata_finding(binary_meta))

    from ...full_aur.properties import metadata_divergence
    srcinfo_text = get_srcinfo_at_commit(project, head_commit)
    for host in metadata_divergence(head_pkgbuild, srcinfo_text):
        pre_structural.append(stamp({
            "rule_id": "H092",
            "name": "Metadata Names A Source The Recipe Does Not",
            "severity": "HIGH", "category": "integrity",
            "match": f".SRCINFO names {host}, which the PKGBUILD never does",
            "params": {"host": host},
        }))
    from ..crossfile import metadata_recipe_divergence

    divergent = metadata_recipe_divergence(head_pkgbuild, srcinfo_text)
    if divergent:
        pre_structural.append(stamp({
            "rule_id": "H103",
            "name": "Metadata And Recipe Disagree",
            "severity": "HIGH", "category": "integrity",
            "match": (".SRCINFO and the PKGBUILD disagree on "
                      + ", ".join(divergent)),
            "params": {"fields": ", ".join(divergent)},
        }))
    from ..crossfile import line_of, source_divergence

    pkgbuild_only, srcinfo_only = source_divergence(head_pkgbuild, srcinfo_text)
    if pkgbuild_only:
        pre_structural.append(stamp({
            "rule_id": "H103",
            "name": "Metadata And Recipe Disagree",
            "severity": "HIGH", "category": "integrity",
            "match": ("PKGBUILD fetches source(s) .SRCINFO does not declare: "
                      + ", ".join(pkgbuild_only)),
            "file": "PKGBUILD",
            "line": line_of(head_pkgbuild or "", pkgbuild_only[0]),
            "params": {"fields": "source", "direction": "pkgbuild_only",
                       "sources": ", ".join(pkgbuild_only),
                       "metadata_file": ".SRCINFO"},
        }))
    elif srcinfo_only:
        pre_structural.append(stamp({
            "rule_id": "H103",
            "name": "Metadata And Recipe Disagree",
            "severity": "INFO", "category": "integrity",
            "match": (".SRCINFO declares source(s) the PKGBUILD does not: "
                      + ", ".join(srcinfo_only)),
            "file": ".SRCINFO",
            "line": line_of(srcinfo_text or "", srcinfo_only[0]),
            "params": {"fields": "source", "direction": "srcinfo_only",
                       "sources": ", ".join(srcinfo_only),
                       "recipe_file": "PKGBUILD"},
        }))

    previous_diff = ""
    if last is not None:
        try:
            if last.get("new_commit") == old_commit:
                previous_diff = str(last.get("raw_diff") or "")
        except AttributeError:
            previous_diff = ""

    # H086 compares the previous recorded AUR state before the persistence
    # write below updates it.
    was_orphaned = get_aur_orphan_state(pkg_name)
    adopted = was_orphaned == 1 and (bool(new_maintainer) or aur_orphaned is False)
    late_extra: list[dict] = []
    adoption_findings(
        diff_text,
        package_name=pkg_name,
        was_orphaned=was_orphaned,
        currently_maintained=bool(new_maintainer) or aur_orphaned is False,
        pkgver_moved=pkgver_changed,
        current_text=head_pkgbuild,
        add=lambda rid, name, severity, category, match, **params: (
            late_extra.append(stamp({
                "rule_id": rid, "name": name, "severity": severity,
                "category": category, "match": match, "params": params,
            }))
        ),
    )
    placeholder = placeholder_finding(head_pkgbuild)
    if placeholder:
        late_extra.append(placeholder)

    post_filter_findings: list[dict] = []
    recent = _recent_update(project, head_commit)
    if recent:
        post_filter_findings.append(recent)
    new_pkg = _package_is_new(project, head_commit, pkg_name)
    if new_pkg:
        post_filter_findings.append(new_pkg)
    revived = _stale_revival(project, old_commit, head_commit)
    if revived:
        post_filter_findings.append(revived)

    # T006/T007 need the retained git history, which only this producer has.
    # The shared-pipeline refactor dropped these calls with the old body.
    from ..temporal import t_metadata_git_divergence, t_packager_not_in_history

    post_filter_findings.extend(t_metadata_git_divergence(
        project, head_commit, upstream_mtime or 0, config))
    post_filter_findings.extend(t_packager_not_in_history(
        project, head_commit, new_maintainer, config))

    recent_commit_burst = False
    if head_commit:
        try:
            count_24h = 0
            for commit in project.walk(head_commit):
                if (time.time() - commit.commit_time) / 3600 <= 24:
                    count_24h += 1
                if count_24h >= 3:
                    recent_commit_burst = True
                    break
        except (GitSandboxUnavailable, GitOpError):
            note_stage_failure("commit-burst")

    scan_result = scan_recipe(
        ScanInput(
            package=pkg_name,
            diff_text=diff_text,
            recipe_text=head_pkgbuild,
            maintainer=new_maintainer,
            package_id=package_id,
            record=record,
            maintainer_changed=maintainer_changed,
            tree_manifest=tree_manifest,
            tree_complete=tree_complete,
            whole_recipe=full_recipe,
            previous_diff=previous_diff,
            previous_commit=old_commit,
            current_commit=head_commit,
            pre_structural=tuple(pre_structural),
            transform_after_tree=lambda rules: (
                _without_notice_only_install_modifications(rules, diff_text)),
            append_after_filter=tuple(post_filter_findings),
            late_extra=tuple(late_extra),
            adopted=adopted,
        ),
        config,
    )
    resolved_strings = scan_result.resolved_strings
    unresolved_strings = scan_result.unresolved_strings
    triggered_rules = scan_result.triggered_rules

    added_names = _added_dependency_names(diff_text)
    depth_result = _walk_dependencies(
        pkg_name, depth, config, _depth_seen, record=record,
        added_names=added_names,
    )

    version_comparison = compare_installed_to_aur(
        installed_version, head_version,
        is_vcs=is_vcs_package(pkg_name, head_pkgbuild),
    )
    fact, triggered_rules, campaign_context = finalise_fact(
        scan_result,
        CoverageSignals(
            diff_truncated=diff_truncated,
            scan_truncated=scan_truncated,
            companion_truncated=companion_truncated,
            binary_metadata=bool(binary_meta),
            parent_baseline=parent_baseline,
        ),
        FactIdentity(
            package=pkg_name,
            old_version=installed_version,
            new_version=head_version,
            diff_summary=diff_summary,
            old_commit=old_commit,
            new_commit=head_commit,
            maintainer_changed=maintainer_changed,
            previous_maintainer=old_maintainer,
            current_maintainer=new_maintainer,
            comparison_base=comparison_base,
            temporal_source="git_commit",
            depth=resolved_depth,
            depth_result=depth_result,
            added_names=added_names,
            pkgver_changed=pkgver_changed,
            version_moved=version_moved,
            pkgver_old=_pkgver_old or "",
            pkgver_new=_pkgver_new or "",
            version_comparison=version_comparison,
            recent_commit_burst=recent_commit_burst,
            partial_hunk_details=partial_hunk_details,
        ),
        config,
    )
    score = fact.final_score
    suppressed_rules = scan_result.suppressed_rules
    expired_overrides = scan_result.expired_overrides
    url_acks = scan_result.url_acks

    # Companion content the recorded baseline already held: reported, never
    # scored.  Appended after the campaign pass so it cannot corroborate a
    # chain or move a number.
    present_rules = suppress_acknowledged_url_findings(
        _present_before_findings(present_before, config), pkg_name, url_acks)
    if present_rules:
        present_rules, present_suppressed = filter_triggered_rules(
            present_rules, package=pkg_name, expired_out=expired_overrides)
        suppressed_rules.extend(present_suppressed)
        for finding in present_rules:
            fact.score_breakdown.append(ScoreEntry(
                rule_id=finding["rule_id"],
                severity=finding["severity"],
                weight=0,
                reason=f"{finding['name']}: {finding.get('match', '')}",
                params=dict(finding.get("params") or {}),
                template=finding.get("template", ""),
                evidence=dict(finding.get("evidence") or {}),
                file=finding.get("file", ""),
                line=finding.get("line"),
                techniques=tuple(finding.get("techniques") or ()),
            ))
    fact.suppressed_rules = suppressed_rules

    # Dependency changes are part of the fact and of the change summary, so
    # they are settled before the history write: the stored fact_json is
    # what the review cache (#20) serves back, and it must read exactly
    # like the fact this run returns.
    dependency_changes = extract_dependency_changes(
        diff_text, pkg_name, current_text=head_pkgbuild
    )
    fact.dependency_changes = {k: sorted(v) for k, v in dependency_changes.items() if v}
    fact.resolution_coverage = resolution_coverage(
        resolved_strings, unresolved_strings, triggered_rules, load_rules())
    with_changes(fact, diff_text)
    # #19: a gap whose root cause the previous recorded analysis already
    # carried is marked as carried, so the report says "unchanged since the
    # previous review" instead of reading as a shortfall this diff
    # introduced.  `last` is only populated on the incremental path, so an
    # explicit old_commit or a full-recipe run fetches the row here; the
    # fresh path has no previous analysis and keeps the empty list.  This
    # has to happen before the history write below, or the stored fact
    # would lack the provenance the next run reads back.
    if last is None and package_id:
        last = get_last_analysis(package_id)
    if last is not None:
        try:
            prev = json.loads(last.get("fact_json") or "{}")
            prev_gaps = prev.get("coverage_gaps", []) if isinstance(prev, dict) else []
        except (ValueError, TypeError):
            prev_gaps = []
        fact.carried_coverage_gaps = [g for g in fact.coverage_gaps if g in prev_gaps]
    if record:
        insert_analysis(
            package_id=package_id,
            old_version=installed_version,
            new_version=head_version,
            old_commit=old_commit,
            new_commit=head_commit,
            final_score=score,
            raw_diff=diff_text,
            fact_json=json.dumps(fact_to_dict(fact)),
            triggered_rules=triggered_rules,
        )

        update_package_version(pkg_name, head_version)
        if new_maintainer:
            update_package_maintainer(pkg_name, new_maintainer)
        update_aur_orphan_state(pkg_name, aur_orphaned)
        record_dependency_names(sorted(
            name for names in dependency_changes.values() for name in names
        ))
        record_observed_identity(fact.change, new_maintainer)

        # Keep the added encoded literals so G002 can join across packages
        # at cycle end, the same feed the corpus path records.
        from ..entropy import added_literals, added_text
        from ...db import record_added_literals

        record_added_literals(pkg_name, added_literals(added_text(diff_text)))
    return fact

def apply_diff_caps(
    diff_text: str, config: dict, package_name: str = ""
) -> tuple[str, bool, bool]:
    """Apply the byte and line caps every diff reader shares.

    Returns ``(text, diff_truncated, scan_truncated)``.  The corpus
    harness's parallel prefix pass calls this too, so the source URLs it
    records are read from exactly the text the analysis reads.
    """
    # The same cap the git path applies.  It used to live only there, so a
    # caller reaching scan_diff directly (the corpus adapter, the fixtures,
    # the gates) had no ceiling at all and no truncation flag either.
    max_bytes = config.get("diff", {}).get("max_diff_bytes", 5_242_880)
    diff_bytes = diff_text.encode("utf-8", errors="replace")
    diff_truncated = len(diff_bytes) > max_bytes
    if diff_truncated:
        log.warning("diff for %s exceeds %d bytes; truncating", package_name, max_bytes)
        diff_text = diff_bytes[:max_bytes].decode("utf-8", errors="replace")
    # The byte cap is not a bound on work: matching costs per *line*, so a
    # diff of many short lines stays under 5 MiB while taking minutes.
    diff_text, scan_truncated = clamp_diff_lines(diff_text, package_name)
    return diff_text, diff_truncated, scan_truncated

def scored_source_urls(
    diff_text: str, config: dict, package_name: str = ""
) -> list[str]:
    """The added source URLs novelty tracks, after caps and acknowledgements."""
    capped, _diff_truncated, _scan_truncated = apply_diff_caps(
        diff_text, config, package_name
    )
    changes = extract_urls_from_diff(capped)
    acks = match_url_acks(package_name, changes.added_urls) if package_name else {}
    return [u for u in changes.added_urls if u not in acks]
