import json
import logging

from .buckets import classify_pinning_level, classify_urls

log = logging.getLogger(__name__)
from .config import ensure_default_configs, load_config
from .db import (
    get_last_analysis,
    init_db,
    insert_analysis,
    update_package_version,
    upsert_package,
)
from .differ import _has_checksum_in_post_diff, detect_verification_evidence, extract_urls_from_diff, generate_diff, is_skip_justified
from .discovery import find_outdated_packages, get_aur_latest_versions, get_installed_aur_packages
from .fetcher import clone_or_fetch, get_head_commit, get_maintainer_from_commit, get_pkgver_from_head
from .llm import generate_verdict
from .novelty import build_novelty_context
from .rules import apply_rules, get_raw_diff_lines
from .scoring import calculate_score
from .llm import fallback_verdict
from .schema import (
    DiffSummary,
    ExecutionChanges,
    NoveltyContext,
    PackageFact,
    fact_to_dict,
)
from .tokenizer import tokenize_and_resolve


def _pkgver_changed_in_diff(diff_text: str) -> bool:
    """Check whether the diff changes the *value* of ``pkgver``."""
    old_val: str | None = None
    new_val: str | None = None
    for line in diff_text.splitlines():
        if line.startswith("-pkgver="):
            old_val = line.removeprefix("-pkgver=").strip().strip("'\"")
        elif line.startswith("+pkgver="):
            new_val = line.removeprefix("+pkgver=").strip().strip("'\"")
    return old_val is not None and new_val is not None and old_val != new_val


def analyze_package(pkg_name: str, old_commit: str = "", new_version: str = "") -> PackageFact:
    ensure_default_configs()
    init_db()
    config = load_config()

    repo = clone_or_fetch(pkg_name)
    head_commit = get_head_commit(repo)
    head_version = get_pkgver_from_head(repo) or new_version

    if not head_version:
        head_version = new_version

    package_id = upsert_package(pkg_name, head_version)

    if not head_commit:
        return _make_fresh_analysis(pkg_name, head_version, head_commit, package_id, repo, config)

    if not old_commit:
        last = get_last_analysis(package_id)
        if last and last.get("new_commit"):
            old_commit = last["new_commit"]
        else:
            return _make_fresh_analysis(pkg_name, head_version, head_commit, package_id, repo, config)

    diff_text, diff_summary = generate_diff(repo, old_commit, head_commit, config.get("diff", {}).get("max_context_lines", 3))

    max_bytes = config.get("diff", {}).get("max_diff_bytes", 5_242_880)
    if len(diff_text.encode()) > max_bytes:
        log.warning("diff for %s exceeds %d bytes — truncating", pkg_name, max_bytes)
        diff_text = diff_text[:max_bytes]

    source_changes = extract_urls_from_diff(diff_text)

    old_maintainer = get_maintainer_from_commit(repo, old_commit) or ""
    new_maintainer = get_maintainer_from_commit(repo, head_commit) or ""
    maintainer_changed = bool(old_maintainer and new_maintainer and old_maintainer != new_maintainer)

    novelty = build_novelty_context(
        source_changes.added_urls,
        package_id,
        maintainer=new_maintainer,
    )

    source_buckets = classify_urls(source_changes.added_urls)

    resolved_strings, unresolved_strings = tokenize_and_resolve(diff_text)
    raw_lines = get_raw_diff_lines(diff_text)

    triggered_rules = apply_rules(resolved_strings, raw_lines)
    rule_ids = [r["rule_id"] for r in triggered_rules]

    cs_behavior = source_changes.checksum_behavior
    if cs_behavior == "changed_from_sha256_to_skip":
        skip_reason = is_skip_justified(diff_text)
        sev = "INFO" if skip_reason else "HIGH"
        triggered_rules.append({
            "rule_id": "R004",
            "name": "Checksum Disabled",
            "severity": sev,
            "category": "integrity",
            "match": f"sha256sums=SKIP ({skip_reason})" if skip_reason else "sha256sums=SKIP",
        })
        rule_ids.append("R004")
    elif cs_behavior == "checksum_array_emptied":
        triggered_rules.append({
            "rule_id": "R005",
            "name": "Checksum Emptied",
            "severity": "HIGH",
            "category": "integrity",
            "match": cs_behavior,
        })
        rule_ids.append("R005")

    pkgver_changed = _pkgver_changed_in_diff(diff_text)
    if cs_behavior == "checksum_added_or_changed" and not source_changes.added_urls and not source_changes.removed_urls:
        if not pkgver_changed:
            triggered_rules.append({
                "rule_id": "C001",
                "name": "Checksum Changed Without Source Change With Stable Version",
                "severity": "HIGH",
                "category": "integrity",
                "match": "sha256sums changed but source URLs and pkgver unchanged",
            })
            rule_ids.append("C001")
        else:
            triggered_rules.append({
                "rule_id": "C002",
                "name": "Checksum Updated With Version Bump",
                "severity": "INFO",
                "category": "integrity",
                "match": "sha256sums updated alongside pkgver",
            })
            rule_ids.append("C002")
    if source_changes.removed_urls and source_changes.added_urls and not pkgver_changed:
        src_changed = set(source_changes.removed_urls) != set(source_changes.added_urls)
        if src_changed:
            triggered_rules.append({
                "rule_id": "C003",
                "name": "Source URL Changed Without Version Bump",
                "severity": "INFO",
                "category": "integrity",
                "match": f"URLs changed: {source_changes.removed_urls} -> {source_changes.added_urls}",
            })
            rule_ids.append("C003")

    has_checksum = _has_checksum_in_post_diff(diff_text)
    pinning_levels = [
        classify_pinning_level(url, checksum_present=has_checksum)
        for url in source_changes.added_urls
    ]
    _PINNING_ORDER = ["checksum_pinned", "tag_pinned", "branch_pinned", "unpinned"]
    aggregate_pinning = "unpinned"
    if pinning_levels:
        worst_idx = max(_PINNING_ORDER.index(p) for p in pinning_levels)
        aggregate_pinning = _PINNING_ORDER[worst_idx]

    verification_evidence = detect_verification_evidence(diff_text)

    score, breakdown, risk = calculate_score(
        triggered_rules, source_buckets, novelty, config,
        verification_evidence=verification_evidence,
        pinning_level=aggregate_pinning,
    )

    fact = PackageFact(
        package_name=pkg_name,
        old_version="",
        new_version=head_version,
        old_commit=old_commit,
        new_commit=head_commit,
        maintainer_changed=maintainer_changed,
        previous_maintainer=old_maintainer,
        current_maintainer=new_maintainer,
        diff_summary=diff_summary,
        source_changes=source_changes,
        source_buckets=source_buckets,
        execution_changes=ExecutionChanges(
            resolved_commands=resolved_strings,
            suspicious_patterns_detected=rule_ids,
            unresolved_patterns=unresolved_strings,
        ),
        novelty_context=novelty,
        score_breakdown=breakdown,
        final_score=score,
    )

    insert_analysis(
        package_id=package_id,
        old_version="",
        new_version=head_version,
        old_commit=old_commit,
        new_commit=head_commit,
        final_score=score,
        raw_diff=diff_text,
        fact_json=json.dumps(fact_to_dict(fact)),
        triggered_rules=triggered_rules,
    )

    update_package_version(pkg_name, head_version)
    return fact


def scan_diff(
    diff_text: str,
    rules: list[dict] | None = None,
    config: dict | None = None,
    package_name: str = "",
    seen_urls: dict[str, set[str]] | None = None,
) -> PackageFact:
    """Run the full analysis pipeline on raw diff text.

    Used by benchmark scripts (rebaseline, calibration) that consume
    pre-extracted ``.diff`` files rather than live git repositories.

    When ``seen_urls`` is provided (``{pkg_name: {url, ...}}``), novelty
    is tracked in-memory instead of hitting the database — necessary for
    offline corpus replay where each package has many diffs processed in
    chronological order.
    """
    if config is None:
        config = load_config()

    source_changes = extract_urls_from_diff(diff_text)
    cs_behavior = source_changes.checksum_behavior

    source_buckets = classify_urls(source_changes.added_urls)

    resolved_strings, unresolved_strings = tokenize_and_resolve(diff_text)
    raw_lines = get_raw_diff_lines(diff_text)

    triggered_rules = apply_rules(resolved_strings, raw_lines, rules)
    rule_ids = [r["rule_id"] for r in triggered_rules]

    if cs_behavior == "changed_from_sha256_to_skip":
        skip_reason = is_skip_justified(diff_text)
        sev = "INFO" if skip_reason else "HIGH"
        triggered_rules.append({
            "rule_id": "R004",
            "name": "Checksum Disabled",
            "severity": sev,
            "category": "integrity",
            "match": f"sha256sums=SKIP ({skip_reason})" if skip_reason else "sha256sums=SKIP",
        })
        rule_ids.append("R004")
    elif cs_behavior == "checksum_array_emptied":
        triggered_rules.append({
            "rule_id": "R005",
            "name": "Checksum Emptied",
            "severity": "HIGH",
            "category": "integrity",
            "match": cs_behavior,
        })
        rule_ids.append("R005")

    pkgver_changed = _pkgver_changed_in_diff(diff_text)
    if cs_behavior == "checksum_added_or_changed" and not source_changes.added_urls and not source_changes.removed_urls:
        if not pkgver_changed:
            triggered_rules.append({
                "rule_id": "C001",
                "name": "Checksum Changed Without Source Change With Stable Version",
                "severity": "HIGH",
                "category": "integrity",
                "match": "sha256sums changed but source URLs and pkgver unchanged",
            })
            rule_ids.append("C001")
        else:
            triggered_rules.append({
                "rule_id": "C002",
                "name": "Checksum Updated With Version Bump",
                "severity": "INFO",
                "category": "integrity",
                "match": "sha256sums updated alongside pkgver",
            })
            rule_ids.append("C002")
    if source_changes.removed_urls and source_changes.added_urls and not pkgver_changed:
        src_changed = set(source_changes.removed_urls) != set(source_changes.added_urls)
        if src_changed:
            triggered_rules.append({
                "rule_id": "C003",
                "name": "Source URL Changed Without Version Bump",
                "severity": "INFO",
                "category": "integrity",
                "match": f"URLs changed: {source_changes.removed_urls} -> {source_changes.added_urls}",
            })
            rule_ids.append("C003")

    has_checksum = _has_checksum_in_post_diff(diff_text)
    pinning_levels = [
        classify_pinning_level(url, checksum_present=has_checksum)
        for url in source_changes.added_urls
    ]
    _PINNING_ORDER = ["checksum_pinned", "tag_pinned", "branch_pinned", "unpinned"]
    aggregate_pinning = "unpinned"
    if pinning_levels:
        worst_idx = max(_PINNING_ORDER.index(p) for p in pinning_levels)
        aggregate_pinning = _PINNING_ORDER[worst_idx]

    verification_evidence = detect_verification_evidence(diff_text)

    novelty = NoveltyContext()
    pkgs_seen = seen_urls or {}
    pkg_set = pkgs_seen.setdefault(package_name, set())
    for url in source_changes.added_urls:
        if url not in pkg_set:
            novelty.url_first_seen_in_this_package = True
            novelty.url_first_seen_globally = True
            pkg_set.add(url)
        else:
            novelty.url_first_seen_in_this_package = False
            novelty.url_first_seen_globally = False

    score, breakdown, risk = calculate_score(
        triggered_rules, source_buckets, novelty, config,
        verification_evidence=verification_evidence,
        pinning_level=aggregate_pinning,
    )

    exec_changes = ExecutionChanges(
        resolved_commands=resolved_strings,
        suspicious_patterns_detected=rule_ids,
        unresolved_patterns=unresolved_strings,
    )

    return PackageFact(
        package_name=package_name,
        diff_summary=DiffSummary(
            lines_added=sum(1 for line in diff_text.splitlines() if line.startswith("+")),
            lines_removed=sum(1 for line in diff_text.splitlines() if line.startswith("-")),
        ),
        source_changes=source_changes,
        source_buckets=source_buckets,
        execution_changes=exec_changes,
        novelty_context=novelty,
        score_breakdown=breakdown,
        final_score=score,
    )


def _make_fresh_analysis(
    pkg_name: str, version: str, commit: str, package_id: int, repo, config: dict
) -> PackageFact:
    novelty = build_novelty_context([], package_id)
    fact = PackageFact(
        package_name=pkg_name,
        new_version=version,
        new_commit=commit,
        diff_summary=DiffSummary(),
        novelty_context=novelty,
        first_seen=True,
        final_score=0,
    )
    insert_analysis(
        package_id=package_id,
        old_version="",
        new_version=version,
        old_commit="",
        new_commit=commit,
        final_score=0,
        raw_diff="",
        fact_json=json.dumps(fact_to_dict(fact)),
        triggered_rules=[],
    )
    update_package_version(pkg_name, version)
    return fact


def discover_updates(limit: int = 20, progress_callback=None) -> list[dict]:
    ensure_default_configs()
    init_db()

    installed = get_installed_aur_packages()
    names = list(installed.keys())
    latest = get_aur_latest_versions(names)
    outdated = find_outdated_packages(installed, latest)

    if progress_callback:
        progress_callback(0, 0, "AUR info gathered")

    results = []
    pkg_items = list(outdated.items())[:limit]
    for i, (name, (old_ver, new_ver)) in enumerate(pkg_items):
        if progress_callback:
            progress_callback(i, len(pkg_items), name)
        fact = analyze_package(name)
        verdict = generate_verdict(fact) if fact.final_score > 0 else fallback_verdict(fact)
        results.append(
            {
                "package": name,
                "old_version": old_ver,
                "new_version": new_ver,
                "score": fact.final_score,
                "verdict": verdict,
                "risk": "Low" if fact.final_score <= 20 else "Medium" if fact.final_score <= 50 else "High" if fact.final_score <= 80 else "Critical",
                "first_seen": fact.first_seen,
            }
        )

    return results
