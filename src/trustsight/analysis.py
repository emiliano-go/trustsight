import json

from .buckets import classify_urls
from .config import ensure_default_configs, load_config
from .db import (
    get_last_analysis,
    init_db,
    insert_analysis,
    update_package_version,
    upsert_package,
)
from .differ import extract_urls_from_diff, generate_diff
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
    PackageFact,
    fact_to_dict,
)
from .tokenizer import tokenize_and_resolve


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

    if not old_commit:
        last = get_last_analysis(package_id)
        if last and last.get("new_commit"):
            old_commit = last["new_commit"]
        else:
            return _make_fresh_analysis(pkg_name, head_version, head_commit, package_id, repo, config)

    diff_text, diff_summary = generate_diff(repo, old_commit, head_commit, config.get("diff", {}).get("max_context_lines", 3))
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

    checksum_map = {
        "changed_from_sha256_to_skip": ("R012", "Checksum changed to SKIP", "HIGH"),
        "checksum_array_emptied": ("R013", "Checksum array emptied", "HIGH"),
    }
    cs_behavior = source_changes.checksum_behavior
    if cs_behavior in checksum_map:
        rid, rname, rsev = checksum_map[cs_behavior]
        triggered_rules.append({
            "rule_id": rid,
            "name": rname,
            "severity": rsev,
            "category": "integrity",
            "match": cs_behavior,
        })
        rule_ids.append(rid)

    score, breakdown, risk = calculate_score(triggered_rules, source_buckets, novelty, config)

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


def discover_updates(limit: int = 20) -> list[dict]:
    ensure_default_configs()
    init_db()

    installed = get_installed_aur_packages()
    names = list(installed.keys())
    latest = get_aur_latest_versions(names)
    outdated = find_outdated_packages(installed, latest)

    results = []
    for name, (old_ver, new_ver) in list(outdated.items())[:limit]:
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
            }
        )

    return results
