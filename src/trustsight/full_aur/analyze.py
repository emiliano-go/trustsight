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

from ..analysis import (
    _aggregate_pinning,
    _check_untrusted_maintainer_takeover,
    _has_install_hook,
    _structural_findings,
    detect_gpg_verification_removed,
    effective_observation_count,
    package_typosquat_target,
)
from ..analysis.longitudinal import longitudinal_findings
from ..buckets import classify_urls
from ..config import load_config, load_thresholds
from ..db import (
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
    detect_verification_evidence,
    extract_urls_from_diff,
)
from ..findings import stamp
from ..novelty import build_novelty_context
from ..override import filter_triggered_rules
from ..rules import apply_rules, get_raw_diff_lines
from ..scoring import calculate_score
from ..schema import (
    DiffSummary,
    ExecutionChanges,
    PackageFact,
    TemporalContext,
    fact_to_dict,
)
from ..tokenizer import tokenize_and_resolve
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


def analyze_package_text(
    pkg_name: str,
    old_pkgbuild: Optional[str],
    new_pkgbuild: str,
    maintainer: str,
    temporal: TemporalContext,
    srcinfo: Optional[str] = None,
    tree_manifest: Optional[list[tuple[str, bytes]]] = None,
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

    Returns:
        A fully-scored PackageFact.
    """
    config = load_config()
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

        score, breakdown, risk = calculate_score(
            triggered_rules, {}, novelty, config
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
            score_breakdown=breakdown,
            final_score=score,
        )

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
    diff_bytes = diff_text.encode("utf-8", errors="replace")
    diff_truncated = len(diff_bytes) > max_bytes
    if diff_truncated:
        log.warning("diff for %s exceeds %d bytes; truncating", pkg_name, max_bytes)
        diff_bytes = diff_bytes[:max_bytes]
        diff_text = diff_bytes.decode("utf-8", errors="replace")

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

    resolved_strings, unresolved_strings = tokenize_and_resolve(diff_text)
    raw_lines = get_raw_diff_lines(diff_text)

    triggered_rules = apply_rules(
        resolved_strings, raw_lines,
        include_experimental=config.get("rules", {}).get("experimental", False),
    )
    triggered_rules.extend(
        _structural_findings(
            diff_text, source_changes, source_buckets,
            maintainer_changed=maintainer_changed,
            package_name=pkg_name, config=config,
        )
    )
    if tree_manifest:
        from ..analysis.delivery import scan_tree_manifest
        triggered_rules.extend(
            scan_tree_manifest(tree_manifest, source_changes.added_urls, pkg_name)
        )
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

    score, breakdown, risk = calculate_score(
        triggered_rules, source_buckets, novelty, config,
        verification_evidence=verification_evidence,
        pinning_level=aggregate_pinning,
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
        temporal_source=temporal.source,
        score_breakdown=breakdown,
        final_score=score,
    )

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

    record_dependency_names(sorted(
        name
        for names in extract_dependency_changes(diff_text, pkg_name).values()
        for name in names
    ))

    return fact
