"""Extracted from pipeline.py: _analyze."""

import json
import time
from ...buckets import classify_urls
from ...config import (
    drifted_shipped_rules,
    load_config,
    load_rules,
)
from ...db import (
    effective_observation_count,
    get_last_analysis,
    get_package,
    get_package_id,
    insert_analysis,
    record_dependency_names,
    update_package_maintainer,
    get_aur_orphan_state,
    update_aur_orphan_state,
    update_package_version,
    upsert_package,
)
from ...diffdoc import parse_diff_lines
from ...differ import (
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
    PackageFact,
    fact_to_dict,
)
from ...tokenizer import split_lines, tokenize_and_resolve_indexed
from ..base import (
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
from ._common import log
from ._tree import _added_dependency_names, _binary_metadata_finding, _cached_analysis, _deps_not_scanned, _has_noextract, _parent_commit, _scriptlet_files_unread

__all__ = ['_make_fresh_analysis', '_walk_dependencies', 'analyze_package', 'apply_diff_caps', 'scored_source_urls']

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


def _campaign_corroboration(
    score: int, breakdown, pkg_name: str, added_urls
) -> tuple[int, list]:
    """Attach a weight-0, attributed G007 entry when a run stands in a
    campaign's scope.

    Trained immunity, **unscored**: while a campaign is primed, a run whose
    package is a campaign member, or that newly gained a host in the
    campaign's scope, is *reported* as corroborated - one ``G007`` ``INFO``
    finding carrying ``campaign_id``, weight 0.

    It stays weight 0 because the points this used to add measured scope
    *breadth* (``len(scope)``), not corroboration, and the calibration corpus
    carries no active campaign state, so the added points were never measured
    against the benign false-positive rate.  The attributed report keeps the
    context visible without turning association into a score.

    Impersonated targets are deliberately **not** matched: a campaign targets
    ``yay``, and reviewing ``yay`` is not corroboration of anything.
    """
    from ...db import active_campaigns

    campaigns = active_campaigns()
    if not campaigns:
        return score, breakdown

    from urllib.parse import urlsplit

    hosts = set()
    for url in added_urls or ():
        try:
            host = urlsplit(str(url)).hostname
        except (ValueError, TypeError):
            host = None
        if host:
            hosts.add(host)

    for campaign in campaigns:
        scope = campaign.get("scope", {}) or {}
        if not isinstance(scope, dict):
            continue
        names = {str(n) for n in scope.get("package_names", ()) or ()}
        scoped_hosts = {str(h) for h in scope.get("hosts", ()) or ()}
        if pkg_name not in names and not (hosts & scoped_hosts):
            continue
        from ...schema import ScoreEntry

        enriched = list(breakdown)
        enriched.append(ScoreEntry(
            rule_id="G007", severity="INFO", weight=0,
            reason=("stands in active campaign "
                    f"{campaign['campaign_id']} (corroboration, weight 0)"),
            evidence={"campaign_id": campaign["campaign_id"]},
        ))
        return score, enriched
    return score, breakdown


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

    last = None
    # What this run compares against, carried on the fact so a first review
    # cannot read as a whole-history verdict.
    comparison_base = ""
    parent_baseline = False
    if full_recipe:
        old_commit = ""
        comparison_base = "none"
    elif not old_commit:
        last = get_last_analysis(package_id)
        if last is not None:
            comparison_base = "recorded"
            stored_commit = last.get("new_commit")
            if stored_commit:
                old_commit = stored_commit
            elif head_commit:
                try:
                    for c in project.walk(head_commit):
                        if not c.parents:
                            old_commit = str(c.id)
                            break
                except (GitSandboxUnavailable, GitOpError):
                    # The fallback below compares HEAD against HEAD, whose
                    # diff is empty - every rule then matches nothing and
                    # the package reports clean because the walk failed.
                    note_stage_failure("history-walk")
                if not old_commit:
                    old_commit = head_commit
        else:
            # No recorded baseline.  A read-only run never writes one, so
            # without this the first review of a package would have no diff
            # to look at at all.  The previous commit in the AUR repository
            # is the honest base: it is what "changes since last review"
            # means when there is no review yet - but it is one commit, not
            # the package's history, so the run says so with a gap.
            comparison_base = "parent"
            parent_baseline = True
            old_commit = _parent_commit(project, head_commit)
            if not old_commit:
                return _make_fresh_analysis(pkg_name, head_version, head_commit, package_id, project, config, installed_version=installed_version, head_pkgbuild=head_pkgbuild, record=record, resolved_depth=resolved_depth)

    # The generator's own truncation has to travel: a patch it declined to
    # retain leaves the assembled text at or under the cap, so measuring the
    # text below would report "complete" while content had been skipped.
    diff_text, diff_summary, generated_truncated = project.diff_bounded(
        old_commit, head_commit,
        config.get("diff", {}).get("max_context_lines", 3),
        max_bytes=config.get("diff", {}).get("max_diff_bytes", 5_242_880),
    )

    # A local source=() companion file is build input the recipe copies into
    # $srcdir and can execute; its committed content is scanned with the same
    # rules as the PKGBUILD, or a curl|bash simply moves one file over and the
    # filename filter above drops it.  Appended before the byte cap, so an
    # oversized companion truncates the combined diff and fails closed.
    companion, companion_truncated = project.companion_hunks(head_commit)
    if companion:
        diff_text = f"{diff_text.rstrip(chr(10))}\n{companion}" if diff_text.strip() else companion

    max_bytes = config.get("diff", {}).get("max_diff_bytes", 5_242_880)
    diff_text, combined_truncated = truncate_diff(diff_text, max_bytes)
    # Either half truncating means part of the change was not read.
    diff_truncated = combined_truncated or generated_truncated
    if diff_truncated:
        log.warning("diff for %s exceeds %d bytes; truncating", pkg_name, max_bytes)
    diff_text, scan_truncated = clamp_diff_lines(diff_text, pkg_name)
    # A hunk cut mid-stream with no truncation flag set is a silent
    # partial read; gaps_from declares it as `partial_hunk`, and the
    # details name the file, the hunk and the missing line count.
    cut_hunks = parse_diff_lines(split_lines(diff_text)).cut_hunks()
    partial_hunk_details = cut_hunk_details(cut_hunks)

    source_changes = extract_urls_from_diff(diff_text)
    pkgver_changed, _pkgver_old, _pkgver_new = pkgver_move_in_diff(
        diff_text, head_pkgbuild
    )
    version_moved = any_version_scalar_moved(diff_text)

    old_maintainer = get_maintainer_from_commit(project, old_commit) or ""
    new_maintainer = get_maintainer_from_commit(project, head_commit) or ""

    if not old_maintainer:
        pkg_row = get_package(pkg_name)
        if pkg_row and pkg_row.get("current_maintainer"):
            old_maintainer = pkg_row["current_maintainer"]

    maintainer_changed = bool(old_maintainer and new_maintainer and old_maintainer != new_maintainer)

    # An acknowledged URL is known to the operator for this package, so it
    # contributes no novelty and no bucket prior.  The structural rules
    # keep the full URL list and bucket map: an ack is about the generic
    # provenance score, not about switching off a concrete finding.
    url_acks = match_url_acks(pkg_name, source_changes.added_urls)
    scored_urls = [u for u in source_changes.added_urls if u not in url_acks]

    from ...recipedoc import parse_recipe as _parse_recipe

    _post_source = (
        _parse_recipe(head_pkgbuild, file="PKGBUILD").arrays.get("source", ())
        if head_pkgbuild else ()
    )
    novelty = build_novelty_context(
        scored_urls,
        package_id,
        maintainer=new_maintainer,
        record=record,
        package_name=pkg_name,
        source_array=_post_source,
    )

    source_buckets = classify_urls(
        source_changes.added_urls,
        upstream_host=unchanged_upstream_host(diff_text, head_pkgbuild),
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
    tree_manifest, tree_complete = project.tree_files(head_commit) if head_commit else ([], False)
    # A committed binary changing produces an *empty* diff - git emits no
    # body for it - so nothing downstream can see the change. The blob id
    # is a content hash and both trees are already open.
    swapped = project.opaque_changed(old_commit, head_commit)
    if swapped:
        triggered_rules.append(stamp({
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
    # A binary metadata file is a separate blind spot from a committed
    # binary: git emits no body for it either, but unlike an opaque member
    # the analysis claims to read it, and a binary PKGBUILD is never
    # legitimate.  The HIGH finding plus the gap is what stops it reading
    # clean.
    binary_meta = project.binary_meta(old_commit, head_commit)
    if binary_meta:
        triggered_rules.append(_binary_metadata_finding(binary_meta))
    # H092 on the review path: the generated metadata and the recipe must
    # describe the same package.  Host-level, the comparison measured
    # FP-free on the corpus path, where it has always run.
    from ...full_aur.properties import metadata_divergence

    srcinfo_text = get_srcinfo_at_commit(project, head_commit)
    for host in metadata_divergence(head_pkgbuild, srcinfo_text):
        triggered_rules.append(stamp({
            "rule_id": "H092",
            "name": "Metadata Names A Source The Recipe Does Not",
            "severity": "HIGH", "category": "integrity",
            "match": f".SRCINFO names {host}, which the PKGBUILD never does",
            "params": {"host": host},
        }))
    from ..crossfile import metadata_recipe_divergence

    divergent = metadata_recipe_divergence(head_pkgbuild, srcinfo_text)
    if divergent:
        triggered_rules.append(stamp({
            "rule_id": "H103",
            "name": "Metadata And Recipe Disagree",
            "severity": "HIGH", "category": "integrity",
            "match": (".SRCINFO and the PKGBUILD disagree on "
                      + ", ".join(divergent)),
            "params": {"fields": ", ".join(divergent)},
        }))
    # G8, directional: a source the PKGBUILD fetches that the
    # committed .SRCINFO never names is the executable/metadata split
    # (HIGH); the reverse is stale metadata (INFO).  Both cite the two
    # documents so the reader can compare them directly.
    from ..crossfile import line_of, source_divergence

    pkgbuild_only, srcinfo_only = source_divergence(head_pkgbuild, srcinfo_text)
    if pkgbuild_only:
        triggered_rules.append(stamp({
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
        triggered_rules.append(stamp({
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
    # only the immediately preceding recorded review of this
    # package composes; a gap in history degrades to no-firing.
    previous_diff = ""
    if last is not None:
        try:
            if last.get("new_commit") == old_commit:
                previous_diff = str(last.get("raw_diff") or "")
        except AttributeError:
            previous_diff = ""
    # /: one change-as-data construction, shared
    # by the structural rules and the stored `change` object.
    change_delta_obj = change_delta(clamp_text(diff_text), pkg_name)
    triggered_rules.extend(
        _structural_findings(
            clamp_text(diff_text), source_changes, source_buckets,
            maintainer_changed=maintainer_changed,
            package_name=pkg_name, config=config,
            current_text=clamp_text(head_pkgbuild),
            tree_manifest=tree_manifest,
            whole_recipe=full_recipe,
            previous_diff=previous_diff,
            previous_commit=old_commit,
            current_commit=head_commit,
            delta=change_delta_obj,
        )
    )
    triggered_rules.extend(
        apply_structural_rules(
            clamp_text(diff_text),
            current_text=clamp_text(head_pkgbuild),
            package_name=pkg_name,
        )
    )
    if tree_manifest:
        from ..delivery import scan_tree_manifest
        triggered_rules.extend(
            scan_tree_manifest(tree_manifest, source_changes.added_urls, pkg_name)
        )
    from ..persistence import stand_down_committed_staging
    triggered_rules = stand_down_committed_staging(triggered_rules, tree_manifest)
    expired_overrides: list[str] = []
    triggered_rules, suppressed_rules = filter_triggered_rules(
        triggered_rules, package=pkg_name, expired_out=expired_overrides
    )
    recent = _recent_update(project, head_commit)
    if recent:
        triggered_rules.append(recent)
    new_pkg = _package_is_new(project, head_commit, pkg_name)
    if new_pkg:
        triggered_rules.append(new_pkg)
    revived = _stale_revival(project, old_commit, head_commit)
    if revived:
        triggered_rules.append(revived)

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

    # H086 compares the *previous* recorded AUR state against the current
    # one, so the read has to happen before update_aur_orphan_state below.
    was_orphaned = get_aur_orphan_state(pkg_name)

    takeover = _check_untrusted_maintainer_takeover(
        maintainer_changed, new_maintainer
    )
    if takeover:
        triggered_rules.append(takeover)

    # H086/H087/H088.  Emitted before the meta annotations so H088 is in the
    # breakdown any composition or coverage logic downstream reads.
    adoption_findings(
        diff_text,
        package_name=pkg_name,
        was_orphaned=was_orphaned,
        currently_maintained=bool(new_maintainer) or aur_orphaned is False,
        pkgver_moved=pkgver_changed,
        current_text=head_pkgbuild,
        add=lambda rid, name, severity, category, match, **params: (
            triggered_rules.append(stamp({
                "rule_id": rid, "name": name, "severity": severity,
                "category": category, "match": match, "params": params,
            }))
        ),
    )

    triggered_rules.extend(_meta_annotations(triggered_rules, config))

    if effective_observation_count() > 0:
        typosquat = naming_typosquat_finding(pkg_name)
        if typosquat:
            triggered_rules.append(typosquat)
        # After H029, so the cluster can see it; H027/H043 above are not
        # recomputed, so their counts are unchanged.
        cluster = naming_cluster_annotation(triggered_rules, config)
        if cluster:
            triggered_rules.append(cluster)
    # H102 composes on H078 (emitted inside _structural_findings above),
    # so it runs here regardless of the observation-count gate.
    keyring = maintainer_keyring_composition(triggered_rules, maintainer_changed)
    if keyring:
        triggered_rules.append(keyring)

    rule_ids = [r["rule_id"] for r in triggered_rules]

    recent_commit_burst = False
    if head_commit:
        try:
            count_24h = 0
            # Bounded because history is attacker-authored, and free to
            # bound because the walk is newest-first: a burst inside 24h
            # lives in the newest commits or it is not a burst.
            for c in project.walk(head_commit):
                if (time.time() - c.commit_time) / 3600 <= 24:
                    count_24h += 1
                if count_24h >= 3:
                    recent_commit_burst = True
                    break
        except (GitSandboxUnavailable, GitOpError):
            note_stage_failure("commit-burst")

    aggregate_pinning = _aggregate_pinning(
        diff_text, source_changes.added_urls, source_changes.checksum_behavior
    )
    verification_evidence = detect_verification_evidence(
        diff_text, source_changes.checksum_behavior
    )

    unresolved_sources = unresolved_source_lines(diff_text)
    # the one change-as-data construction site, shared by the
    # prose summary and the JSON `change` object.  Clamped like every other
    # reader: a pathological line costs the tokenizer per parse, and the
    # run already declares the clamp as a coverage gap.
    change = change_delta_obj.to_dict()
    # name every assignment the tokenizer refused on the
    # analysed surface (the full post-state PKGBUILD here), plus the
    # refusals the coverage layer knows independently.
    parse_time_subs = parse_time_substitution_lines(diff_text)
    unresolved_assignments = unresolved_assignment_rows(
        clamp_text(head_pkgbuild) or "", file="PKGBUILD",
        extra_lines=[*unresolved_sources, *parse_time_subs])
    partial_files = partial_install_files(diff_text)
    # Before scoring, because a truncated walk has to reach `gaps_from`:
    # the band downgrade is decided once inside calculate_score and carried
    # on the fact, so a gap appended afterwards would never fail closed.
    added_names = _added_dependency_names(diff_text)
    depth_result = _walk_dependencies(
        pkg_name, depth, config, _depth_seen, record=record,
        added_names=added_names,
    )

    gaps = gaps_from(
        diff_truncated=diff_truncated,
        scan_truncated=scan_truncated,
        tree_analyzed=(bool(tree_manifest) and tree_complete
                       and not _scriptlet_files_unread(
                           diff_text, tree_manifest)),
        companion_truncated=companion_truncated,
        binary_metadata=bool(binary_meta),
        unresolved_sources=unresolved_sources,
        long_lines=oversized_lines(raw_lines),
        parse_time_substitutions=parse_time_subs,
        unpinned_build_deps=has_unpinned_build_deps(diff_text, head_pkgbuild),
        # A dependency this diff *adds* and this run did not analyse is
        # unread code the package now pulls in. Dependency findings never
        # move the parent's score (B1: the score is this package's own
        # evidence), which is right - but it left a clean parent with an
        # attacker-controlled new `depends=` reporting a complete analysis
        # of a change it had only half read. The score stays where it was;
        # what changes is that the report stops claiming completeness.
        # A non-AUR name is not unread code: the walk asked the same
        # provider the rest of the run uses, and --depth 0 is the
        # operator's own complete answer.
        deps_not_scanned=_deps_not_scanned(depth_result, added_names),
        parent_baseline=parent_baseline,
        ruleset_drifted=bool(drifted_shipped_rules()),
        degraded_stages=stage_failures(),
        noextract_present=_has_noextract(diff_text),
        partial_hunks=len(cut_hunks),
        partial_files=partial_files,
    )

    # T-series temporal novelty. Cold index declines
    # (the rule is silent until the ecosystem ledger has observations).
    from ..temporal import t_domain_findings, t_key_findings, t_key_rotation

    triggered_rules.extend(t_key_findings(change, config))
    triggered_rules.extend(t_key_rotation(change))
    triggered_rules.extend(t_domain_findings(new_maintainer, config))
    if record:
        from ...db import (
            record_added_literals,
            record_observed_domain,
            record_observed_key,
        )

        pgp = (change or {}).get("pgp_keys", {}) or {}
        for key in (*pgp.get("gained", ()), *pgp.get("lost", ())):
            record_observed_key(key)
        if new_maintainer and "@" in new_maintainer:
            record_observed_domain(new_maintainer.rsplit("@", 1)[1])
        # keep the added encoded literals so G002 can join
        # across packages from the corpus index.
        from ..entropy import added_literals, added_text

        record_added_literals(pkg_name, added_literals(added_text(diff_text)))

    # M-series predicates over the completed finding set
    # (after the ownership resolver), before scoring.
    from ..meta import alert_volume_finding, m_series_findings, m_tool_health
    from ...scoring import declared_claims

    triggered_rules.extend(m_series_findings(
        triggered_rules, config,
        claims=declared_claims(
            verification_evidence, aggregate_pinning, source_buckets)))
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
    )

    ioc_matches = ioc_baseline_matches(
        diff_text, pkg_name, current_text=head_pkgbuild
    )

    score, breakdown = _campaign_corroboration(
        score, breakdown, pkg_name, source_changes.added_urls)

    # The installed version is a full [epoch:]pkgver-pkgrel built locally;
    # head_version is the bare pkgver the AUR PKGBUILD declares.  For a VCS
    # package the latter is a placeholder the build replaces, so the two are
    # not comparable and the result says so rather than drawing an arrow.
    version_comparison = compare_installed_to_aur(
        installed_version, head_version,
        is_vcs=is_vcs_package(pkg_name, head_pkgbuild),
    )

    fact = PackageFact(
        package_name=pkg_name,
        old_version=installed_version,
        new_version=head_version,
        version_comparison=version_comparison,
        old_commit=old_commit,
        new_commit=head_commit,
        maintainer_changed=maintainer_changed,
        previous_maintainer=old_maintainer,
        current_maintainer=new_maintainer,
        pkgver_changed=pkgver_changed,
        version_moved=version_moved,
        pkgver_old=_pkgver_old or "",
        pkgver_new=_pkgver_new or "",
        dependencies=list(depth_result.reports),
        depth_truncated=depth_result.truncated,
        depth_note=depth_result.reason,
        depth=resolved_depth,
        diff_summary=diff_summary,
        source_changes=source_changes,
        source_buckets=source_buckets,
        execution_changes=ExecutionChanges(
            resolved_commands=resolved_strings,
            suspicious_patterns_detected=rule_ids,
            unresolved_patterns=unresolved_strings,
        ),
        novelty_context=novelty,
        suppressed_rules=suppressed_rules,
        cofire_health=m_tool_health(triggered_rules, load_rules()),
        overrides_expired=expired_overrides,
        acknowledged_urls=acknowledged_url_rows(url_acks),
        recent_commit_burst=recent_commit_burst,
        diff_truncated=diff_truncated,
        scan_truncated=scan_truncated,
        comparison_base=comparison_base,
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
        temporal_source="git_commit",
        score_breakdown=breakdown,
        final_score=score,
        ioc_matches=ioc_matches,
    )
    # An override marked `requires_clear_indicators` is visible-only when an
    # indicator matched this run: the finding renders (with the override and
    # the corroboration noted) rather than being hidden.  Applied here
    # because the indicator match is only known after the filter ran.
    from ...override import apply_indicator_cross_check

    fact.suppressed_rules = apply_indicator_cross_check(
        fact.suppressed_rules, bool(fact.ioc_matches))

    # Dependency changes are part of the fact and of the change summary, so
    # they are settled before the history write: the stored fact_json is
    # what the review cache (#20) serves back, and it must read exactly
    # like the fact this run returns.
    dependency_changes = extract_dependency_changes(diff_text, pkg_name)
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

def _make_fresh_analysis(
    pkg_name: str, version: str, commit: str, package_id: int, project, config: dict,
    installed_version: str = "", head_pkgbuild: str = "", record: bool = False,
    resolved_depth: int = 0,
) -> PackageFact:
    """A first analysis: no prior commit to diff against.

    "No diff" is not "nothing to report", and this path kept confusing the
    two. Twice now a field has been computed here and then left off the
    fact, so the same package read differently depending on whether it had
    been analysed before:

    * ``version_comparison`` was unset, so a first ``inspect`` of a VCS
      package rendered the very arrow the incremental path had been fixed
      to suppress - ``1:1.93.1.r7967.caea422f-2 -> 1.93.1.r7966.7ccbff5e``,
      an update pointing at an older commit.
    * ``triggered_rules`` were found, written to the database, and then
      dropped: the fact carried an empty ``score_breakdown`` and a
      hardcoded score of 0. A first-seen package shipping a committed ELF
      binary - H066, the Atomic Arch delivery pattern - reported **Low,
      score 0, no findings**, with the finding sitting in the database the
      whole time. First-seen is the case with the least prior evidence, so
      it is the last one that should be reported clean without looking.

    Everything knowable without a diff is therefore decided here: the
    findings and the score that follows from them, the maintainer, and the
    IOC matches against the recipe as it stands.
    """
    novelty = build_novelty_context([], package_id, record=record)
    triggered_rules: list[dict] = []
    recent = _recent_update(project, commit)
    if recent:
        triggered_rules.append(recent)
    new_pkg = _package_is_new(project, commit, pkg_name)
    if new_pkg:
        triggered_rules.append(new_pkg)
    parity = recipe_checksum_parity_finding(head_pkgbuild)
    if parity:
        triggered_rules.append(parity)
    triggered_rules.extend(
        apply_structural_rules("", current_text=head_pkgbuild, package_name=pkg_name)
    )
    tree_manifest: list = []
    tree_complete = True
    if commit:
        from ..delivery import scan_tree_manifest
        tree_manifest, tree_complete = project.tree_files(commit)
        if tree_manifest:
            triggered_rules.extend(scan_tree_manifest(tree_manifest, [], pkg_name))
    # This path used to declare tree_analyzed=True unconditionally, which
    # was false whenever there was no commit to read a tree from: a first
    # analysis of an empty repository examined nothing and reported a bare
    # "Low".  It is the same coverage accounting as every other producer.
    gaps = gaps_from(
        # There is no diff on this path, so the recipe itself is what
        # names the scriptlet.
        tree_analyzed=(bool(tree_manifest) and tree_complete
                       and not _scriptlet_files_unread(
                           head_pkgbuild, tree_manifest)),
        ruleset_drifted=bool(drifted_shipped_rules()),
        degraded_stages=stage_failures(),
        noextract_present=_has_noextract(head_pkgbuild or ""),
    )
    # The same scorer the incremental path uses, on the findings this path
    # actually made.  Novelty is empty and stays empty - "first seen" means
    # the novelty tier has nothing to say, not that the rules did not fire -
    # and the band downgrade for a coverage gap is decided inside
    # `calculate_score`, so it is not applied a second time here.
    # M-series predicates over the completed finding set
    # (after the ownership resolver), before scoring.
    from ..meta import alert_volume_finding, m_series_findings

    triggered_rules.extend(m_series_findings(triggered_rules, config))
    _volume = alert_volume_finding(triggered_rules, config)
    if _volume:
        triggered_rules.append(_volume)
    score, breakdown, risk = calculate_score(
        triggered_rules, {}, novelty, config, coverage_gaps=gaps,
    )
    fact = PackageFact(
        package_name=pkg_name,
        old_version=installed_version,
        new_version=version,
        version_comparison=compare_installed_to_aur(
            installed_version, version,
            is_vcs=is_vcs_package(pkg_name, head_pkgbuild),
        ),
        new_commit=commit,
        current_maintainer=get_maintainer_from_commit(project, commit) or "" if commit else "",
        diff_summary=DiffSummary(),
        novelty_context=novelty,
        first_seen=True,
        comparison_base="none",
        temporal_source="git_commit",
        tree_analyzed=(bool(tree_manifest) and tree_complete
                       and not _scriptlet_files_unread(
                           head_pkgbuild, tree_manifest)),
        coverage_gaps=gaps,
        ioc_matches=ioc_baseline_matches("", pkg_name, current_text=head_pkgbuild),
        score_breakdown=breakdown,
        risk=risk,
        final_score=score,
        depth=resolved_depth,
    )
    with_changes(fact)
    if record:
        insert_analysis(
            package_id=package_id,
            old_version=installed_version,
            new_version=version,
            old_commit="",
            new_commit=commit,
            # The stored score is the reported one. It was hardcoded to 0 while
            # the rules that fired went into the same row, so the history said
            # "clean" about an analysis that had found something.
            final_score=score,
            raw_diff="",
            fact_json=json.dumps(fact_to_dict(fact)),
            triggered_rules=triggered_rules,
        )
        update_package_version(pkg_name, version)
    return fact
