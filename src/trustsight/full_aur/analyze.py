"""No-git analysis path: analyze_package_text().

The primary analysis function.  Takes old/new PKGBUILD text and metadata,
generates a diff, runs the full rule set, and returns a PackageFact.
"""

import difflib
import json
import logging
import re
import time
from typing import Optional

from ..analysis.base import _aggregate_pinning, _has_install_hook
from ..analysis.buildfetch import has_unpinned_build_deps
from ..analysis.longitudinal import longitudinal_findings
from ..analysis.maintainer import _check_untrusted_maintainer_takeover
from ..analysis.structural import _structural_findings
from ..buckets import classify_urls
from ..config import load_config, load_thresholds
from ..db import (
    effective_observation_count,
    get_connection,
    get_package,
    insert_analysis,
    record_dependency_names,
    update_package_maintainer,
    update_package_version,
    upsert_package,
)
from ..deps import extract_dependency_changes
from ..differ import (
    detect_gpg_verification_removed,
    detect_verification_evidence,
    extract_urls_from_diff,
    map_diff_lines,
    truncate_diff,
)
from ..findings import stamp
from ..novelty import build_novelty_context, package_typosquat_target
from ..override import filter_triggered_rules
from ..rules import apply_rules, clamp_text, get_raw_diff_lines
from ..coverage import (
    gaps_from,
    oversized_lines,
    parse_time_substitution_lines,
    unresolved_source_lines,
)
from ..scoring import calculate_score
from ..schema import (
    with_changes,
    DiffSummary,
    ExecutionChanges,
    PackageFact,
    TemporalContext,
    fact_to_dict,
)
from ..tokenizer import tokenize_and_resolve_indexed
from .properties import extract_properties, update_properties

log = logging.getLogger(__name__)

_PKGVER_RE = re.compile(r'^pkgver\s*=\s*["\']?([^\s"\']+)', re.MULTILINE)


def _extract_pkgver(pkgbuild: str) -> str:
    m = _PKGVER_RE.search(pkgbuild)
    return m.group(1) if m else ""


def _make_diff_text(old_text: str, new_text: str, context_lines: int = 3) -> str:
    old_lines = old_text.splitlines(keepends=True)
    new_lines = new_text.splitlines(keepends=True)
    diff_lines = list(
        difflib.unified_diff(
            old_lines,
            new_lines,
            fromfile="PKGBUILD",
            tofile="PKGBUILD",
            n=context_lines,
        )
    )
    return "".join(diff_lines)


def _diff_summary(diff_text: str) -> DiffSummary:
    if not diff_text:
        return DiffSummary()
    lines = diff_text.splitlines()
    return DiffSummary(
        lines_added=sum(1 for line in lines if line.startswith("+")),
        lines_removed=sum(1 for line in lines if line.startswith("-")),
    )


def _temporal_findings(
    temporal: TemporalContext,
    pkg_name: str,
    is_new_package: bool,
) -> list[dict]:
    """Generate temporal findings (R065, R066, R067) from TemporalContext."""
    findings: list[dict] = []
    now = time.time()

    if temporal.last_modified is not None and temporal.last_modified > 0:
        hours_ago = (now - temporal.last_modified) / 3600
        if 0 <= hours_ago < 72:
            findings.append(stamp({
                "rule_id": "R065",
                "name": "Very Recent Update",
                "severity": "INFO",
                "category": "temporal",
                "match": f"updated {int(hours_ago)}h ago (< 72h)",
                "params": {"detail": f"updated {int(hours_ago)}h ago (< 72h)"},
            }))

    if temporal.first_seen is not None and is_new_package:
        days_ago = (now - temporal.first_seen) / 86400
        if 0 <= days_ago < 30:
            findings.append(stamp({
                "rule_id": "R066",
                "name": "Brand New Package",
                "severity": "INFO",
                "category": "temporal",
                "match": f"first AUR submission {int(days_ago)} days ago (< 30)",
                "params": {"detail": f"first AUR submission {int(days_ago)} days ago (< 30)"},
            }))

    if (temporal.last_modified is not None
            and temporal.previous_modified is not None
            and temporal.last_modified > 0
            and temporal.previous_modified > 0):
        gap_days = (temporal.last_modified - temporal.previous_modified) / 86400
        if gap_days > 365:
            findings.append(stamp({
                "rule_id": "R067",
                "name": "Stale Package Revived",
                "severity": "MEDIUM",
                "category": "temporal",
                "match": f"dormant {int(gap_days)} days, now has a new update (> 1 year)",
                "params": {"detail": f"dormant {int(gap_days)} days, now has a new update (> 1 year)"},
            }))

    return findings


def _corpus_dependency_fact(name: str):
    """A dependency's result, preferring what the corpus already computed.

    On the corpus path every package is analysed in its own right during the
    same cycle, so re-running the pipeline for a dependency would compute a
    number the database already holds. The stored profile is therefore the
    first source, the stored PKGBUILD snapshot the fallback, and a package
    with neither is reported as not vetted rather than fetched: the bootstrap
    owns its own fetch order, and re-entering it from inside one package's
    analysis would both fight that ordering and turn a corpus pass into an
    unbounded crawl.
    """
    from ..db import get_package_profile, get_pkgbuild_snapshot

    profile = get_package_profile(name)
    if profile and profile.get("last_score") is not None:
        return _StoredFact(
            final_score=int(profile["last_score"] or 0),
            risk=str(profile.get("last_risk") or ""),
        )

    row = get_pkgbuild_snapshot(name)
    if not row or not row["pkgbuild_text"]:
        raise LookupError(f"no stored result or PKGBUILD for {name}")
    return analyze_package_text(
        pkg_name=name,
        old_pkgbuild=None,
        new_pkgbuild=row["pkgbuild_text"],
        maintainer="",
        temporal=TemporalContext(source="corpus_depth"),
        depth=0,
    )


class _StoredFact:
    """The shape ``walk_dependencies`` reads, from a stored profile.

    A profile records the score and band, not the breakdown, so
    ``score_breakdown`` is empty and ``finding_count`` reads 0. The score and
    band are what a dependency card shows; the reader following the card runs
    ``inspect`` on the dependency for its findings.
    """

    __slots__ = ("final_score", "risk", "score_breakdown", "coverage_gaps")

    def __init__(self, final_score: int, risk: str):
        self.final_score = final_score
        self.risk = risk
        self.score_breakdown = ()
        self.coverage_gaps = ()


def _walk_corpus_dependencies(pkg_name, depth, config, seen):
    """The dependency closure, from results the corpus already has.

    ``seen`` is deliberately **not** shared across the packages of a corpus
    cycle. On the review path sharing it is a clear win: a handful of roots,
    each dependency cloned and analysed once. On the corpus path every
    package is a root, so a shared set would hand each dependency to
    whichever parent happened to be processed first and leave every other
    parent reporting an empty closure - an arbitrary attribution that reads
    as "this package has no AUR dependencies". Lookups are cheap enough that
    per-package walks are the right trade here.
    """
    from ..depth import DepthResult, default_metadata, resolve_depth, walk_dependencies

    resolved = resolve_depth(depth, config)
    if resolved == 0:
        return DepthResult()

    return walk_dependencies(
        pkg_name,
        depth=resolved,
        metadata=default_metadata(),
        analyse=_corpus_dependency_fact,
        already_seen=set(seen) if seen else None,
    )


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
            tarball, when it was fetched.  Runs the R118-tree scan; when
            absent the result reports ``tree_analyzed=false`` rather than
            silently reading as full coverage.
        archive_trailer_finding:  an R122 finding stamped by
            ``check_archive_trailer`` on the snapshot tarball bytes, when
            one was produced.  Surfaced exactly like the R118-tree scan
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
    # Before either producer builds a fact: a truncated walk has to reach
    # `gaps_from`, because the band downgrade is decided inside
    # calculate_score and carried on the fact rather than re-derived.
    depth_result = _walk_corpus_dependencies(pkg_name, depth, config, _depth_seen)
    old_maintainer: Optional[str] = None

    new_version = _extract_pkgver(new_pkgbuild)
    old_version = _extract_pkgver(old_pkgbuild) if old_pkgbuild else ""

    package_id = upsert_package(pkg_name, new_version)

    # Property stability tracking: record now, consumed in the same analysis
    # by the longitudinal rules (R094-R098/R102/R083).
    observed_at: str = ""
    if temporal.last_modified is not None:
        from datetime import datetime, timezone
        observed_at = datetime.fromtimestamp(temporal.last_modified, tz=timezone.utc).isoformat()
    else:
        from datetime import datetime, timezone
        observed_at = datetime.now(timezone.utc).isoformat()
    breaks: list = []
    try:
        props = extract_properties(new_pkgbuild, srcinfo)
        floor = int(
            load_thresholds().get("longitudinal", {}).get("stability_floor", 10)
        )
        with get_connection() as conn:
            breaks = update_properties(conn, pkg_name, props, observed_at, floor=floor)
    except Exception:
        log.warning("property tracking failed for %s", pkg_name, exc_info=True)

    if old_pkgbuild is None:
        novelty = build_novelty_context([], package_id)
        triggered_rules: list[dict] = []
        triggered_rules.extend(
            _temporal_findings(temporal, pkg_name, True)
        )
        if tree_manifest:
            from ..analysis.delivery import scan_tree_manifest
            triggered_rules.extend(scan_tree_manifest(tree_manifest, [], pkg_name))
        if archive_trailer_finding:
            triggered_rules.append(archive_trailer_finding)
        triggered_rules, suppressed_rules = filter_triggered_rules(
            triggered_rules, package=pkg_name
        )

        if effective_observation_count() > 0:
            squatted = package_typosquat_target(pkg_name)
            if squatted:
                triggered_rules.append(stamp({
                    "rule_id": "R074", "name": "Package-Name Typosquat",
                    "severity": "HIGH", "category": "naming",
                    "match": f"'{pkg_name}' resembles the far more popular '{squatted}'",
                    "params": {"pkg_name": pkg_name, "squatted": squatted},
                }))

        gaps = gaps_from(
            tree_analyzed=bool(tree_manifest),
            snapshot_refused=snapshot_refused,
            deps_not_scanned=depth_result.truncated,
        )
        score, breakdown, risk = calculate_score(
            triggered_rules, {}, novelty, config, coverage_gaps=gaps
        )

        fact = PackageFact(
            package_name=pkg_name,
            old_version=old_version,
            new_version=new_version,
            novelty_context=novelty,
            suppressed_rules=suppressed_rules,
            first_seen=True,
            temporal_source=temporal.source,
            tree_analyzed=bool(tree_manifest),
            coverage_gaps=gaps,
            dependencies=list(depth_result.reports),
            depth_truncated=depth_result.truncated,
            depth_note=depth_result.reason,
            risk=risk,
            score_breakdown=breakdown,
            final_score=score,
        )

        # No diff on the first-seen path: there is nothing to compare
        # against, and the summary says so from the fact alone.
        with_changes(fact)
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
        return fact

    diff_text = _make_diff_text(old_pkgbuild, new_pkgbuild)

    max_bytes = config.get("diff", {}).get("max_diff_bytes", 5_242_880)
    diff_text, diff_truncated = truncate_diff(diff_text, max_bytes)
    if diff_truncated:
        log.warning("diff for %s exceeds %d bytes; truncating", pkg_name, max_bytes)

    source_changes = extract_urls_from_diff(diff_text)
    source_buckets = classify_urls(source_changes.added_urls)

    pkg_row = get_package(pkg_name)
    if pkg_row and pkg_row.get("current_maintainer"):
        old_maintainer = pkg_row["current_maintainer"]
    maintainer_changed = bool(
        old_maintainer and maintainer and old_maintainer != maintainer
    )

    novelty = build_novelty_context(
        source_changes.added_urls,
        package_id,
        maintainer=maintainer,
    )

    resolved_strings, unresolved_strings, resolved_indices = (
        tokenize_and_resolve_indexed(diff_text)
    )
    raw_lines = get_raw_diff_lines(diff_text)
    line_map = map_diff_lines(diff_text)

    triggered_rules = apply_rules(
        resolved_strings, raw_lines,
        include_experimental=config.get("rules", {}).get("experimental", False),
        line_map=line_map,
        resolved_indices=resolved_indices,
    )
    triggered_rules.extend(
        _structural_findings(
            clamp_text(diff_text), source_changes, source_buckets,
            maintainer_changed=maintainer_changed,
            package_name=pkg_name, config=config,
            current_text=clamp_text(new_pkgbuild),
            tree_manifest=tree_manifest,
        )
    )
    if tree_manifest:
        from ..analysis.delivery import scan_tree_manifest
        triggered_rules.extend(
            scan_tree_manifest(tree_manifest, source_changes.added_urls, pkg_name)
        )
    if archive_trailer_finding:
        triggered_rules.append(archive_trailer_finding)
    triggered_rules, suppressed_rules = filter_triggered_rules(
        triggered_rules, package=pkg_name
    )

    triggered_rules.extend(
        _temporal_findings(temporal, pkg_name, False)
    )

    triggered_rules.extend(
        longitudinal_findings(diff_text, pkg_name, breaks, config)
    )

    if not any(r["rule_id"] == "R007" for r in triggered_rules):
        if _has_install_hook(diff_text):
            triggered_rules.append(stamp({
                "rule_id": "R068", "name": "Install Hook Present",
                "severity": "INFO", "category": "context",
                "match": "PKGBUILD declares an install hook",
            }))

    if detect_gpg_verification_removed(diff_text):
        triggered_rules.append(stamp({
            "rule_id": "R069", "name": "GPG Verification Removed",
            "severity": "HIGH", "category": "integrity",
            "match": "validpgpkeys was populated and is now empty or removed",
        }))

    takeover = _check_untrusted_maintainer_takeover(
        maintainer_changed, maintainer
    )
    if takeover:
        triggered_rules.append(takeover)

    categories = {r.get("category", "") for r in triggered_rules
                  if r.get("category") and r["rule_id"] != "R072"}
    if len(categories) >= 3:
        triggered_rules.append(stamp({
            "rule_id": "R072", "name": "Capability Density Anomaly",
            "severity": "INFO", "category": "meta",
            "match": f"rule hits span {len(categories)} distinct capability categories",
            "params": {"n_categories": len(categories)},
        }))

    if effective_observation_count() > 0:
        squatted = package_typosquat_target(pkg_name)
        if squatted:
            triggered_rules.append(stamp({
                "rule_id": "R074", "name": "Package-Name Typosquat",
                "severity": "HIGH", "category": "naming",
                "match": f"'{pkg_name}' resembles the far more popular '{squatted}'",
                "params": {"pkg_name": pkg_name, "squatted": squatted},
            }))

    rule_ids = [r["rule_id"] for r in triggered_rules]

    aggregate_pinning = _aggregate_pinning(
        diff_text, source_changes.added_urls, source_changes.checksum_behavior
    )
    verification_evidence = detect_verification_evidence(
        diff_text, source_changes.checksum_behavior
    )

    unresolved_sources = unresolved_source_lines(diff_text)
    gaps = gaps_from(
        diff_truncated=diff_truncated,
        tree_analyzed=bool(tree_manifest),
        unresolved_sources=unresolved_sources,
        long_lines=oversized_lines(raw_lines),
        parse_time_substitutions=parse_time_substitution_lines(diff_text),
        snapshot_refused=snapshot_refused,
        unpinned_build_deps=has_unpinned_build_deps(diff_text),
        deps_not_scanned=depth_result.truncated,
    )

    score, breakdown, risk = calculate_score(
        triggered_rules, source_buckets, novelty, config,
        verification_evidence=verification_evidence,
        pinning_level=aggregate_pinning,
        coverage_gaps=gaps,
    )

    fact = PackageFact(
        package_name=pkg_name,
        old_version=old_version,
        new_version=new_version,
        maintainer_changed=maintainer_changed,
        previous_maintainer=old_maintainer,
        current_maintainer=maintainer,
        diff_summary=_diff_summary(diff_text),
        source_changes=source_changes,
        source_buckets=source_buckets,
        execution_changes=ExecutionChanges(
            resolved_commands=resolved_strings,
            suspicious_patterns_detected=rule_ids,
            unresolved_patterns=unresolved_strings,
        ),
        novelty_context=novelty,
        suppressed_rules=suppressed_rules,
        diff_truncated=diff_truncated,
        tree_analyzed=bool(tree_manifest),
        coverage_gaps=gaps,
        dependencies=list(depth_result.reports),
        depth_truncated=depth_result.truncated,
        depth_note=depth_result.reason,
        unresolved_sources=unresolved_sources,
        risk=risk,
        temporal_source=temporal.source,
        score_breakdown=breakdown,
        final_score=score,
    )

    with_changes(fact, diff_text)
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

    update_package_version(pkg_name, new_version)
    if maintainer:
        update_package_maintainer(pkg_name, maintainer)

    dependency_changes = extract_dependency_changes(diff_text, pkg_name)
    fact.dependency_changes = {k: sorted(v) for k, v in dependency_changes.items() if v}
    with_changes(fact, diff_text)
    record_dependency_names(sorted(
        name for names in dependency_changes.values() for name in names
    ))

    return fact
