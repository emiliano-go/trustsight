import difflib
import json
import logging
import time

import pygit2

from ..buckets import classify_urls
from ..config import load_config
from ..db import (
    effective_observation_count,
    get_last_analysis,
    get_package,
    insert_analysis,
    record_dependency_names,
    update_package_maintainer,
    update_package_version,
    upsert_package,
)
from ..differ import (
    detect_gpg_verification_removed,
    detect_verification_evidence,
    extract_urls_from_diff,
    generate_diff,
    map_diff_lines,
)
from ..fetcher import clone_or_fetch, get_head_commit, get_maintainer_from_commit, get_pkgver_from_head
from ..findings import stamp
from ..novelty import (
    build_novelty_context,
    normalize_url,
    package_typosquat_target,
)
from ..deps import extract_dependency_changes
from ..override import filter_triggered_rules
from ..rules import apply_rules, get_raw_diff_lines
from ..scoring import calculate_score
from ..schema import (
    DiffSummary,
    ExecutionChanges,
    NoveltyContext,
    PackageFact,
    fact_to_dict,
)
from ..tokenizer import tokenize_and_resolve
from .base import (
    _aggregate_pinning,
    _ensure_init,
    _get_installed_version,
    _GLOBAL_URL_KEY,
    _has_install_hook,
)
from .maintainer import _check_untrusted_maintainer_takeover
from .structural import _structural_findings
from .temporal import _package_is_new, _recent_update, _stale_revival

log = logging.getLogger(__name__)


def _collect_tree_files(repo, commit_oid: str, max_file_bytes: int = 512 * 1024, head_bytes: int = 64) -> list[tuple[str, bytes]]:
    """Walk a commit tree, returning ``(path, first_bytes)`` for each blob.

    Blobs larger than *max_file_bytes* are skipped: a committed payload is
    small, and an untrusted repository must not be able to force the
    reviewer to read a giant file.  AUR repos are small, so this is cheap.
    """
    files: list[tuple[str, bytes]] = []

    def walk(tree, prefix: str) -> None:
        for entry in tree:
            if entry.type_str == "tree":
                walk(repo[entry.id], prefix + entry.name + "/")
            elif entry.type_str == "blob":
                try:
                    blob = repo[entry.id]
                except (KeyError, TypeError, ValueError):
                    continue
                if blob.size > max_file_bytes:
                    continue
                try:
                    data = blob.data
                except (KeyError, TypeError, ValueError):
                    continue
                files.append((prefix + entry.name, data[:head_bytes]))

    try:
        commit = repo.get(commit_oid)
        if commit is not None:
            walk(commit.tree, "")
    except (KeyError, AttributeError, TypeError, ValueError):
        pass
    return files


def analyze_package(
    pkg_name: str,
    old_commit: str = "",
    new_version: str = "",
    installed_version: str | None = None,
    upstream_mtime: int | None = None,
) -> PackageFact:
    _ensure_init()
    config = load_config()

    if installed_version is None:
        installed_version = _get_installed_version(pkg_name)

    repo = clone_or_fetch(pkg_name, upstream_mtime)
    try:
        head_commit = get_head_commit(repo)
    except pygit2.GitError:
        head_commit = ""
    head_version = get_pkgver_from_head(repo) or new_version

    if not head_version:
        head_version = new_version

    package_id = upsert_package(pkg_name, head_version)

    if not head_commit:
        return _make_fresh_analysis(pkg_name, head_version, head_commit, package_id, repo, config, installed_version=installed_version)

    if not old_commit:
        last = get_last_analysis(package_id)
        if last is not None:
            stored_commit = last.get("new_commit")
            if stored_commit:
                old_commit = stored_commit
            elif head_commit:
                try:
                    for c in repo.walk(head_commit):
                        if not c.parents:
                            old_commit = str(c.id)
                            break
                except pygit2.GitError:
                    pass
                if not old_commit:
                    old_commit = head_commit
        else:
            return _make_fresh_analysis(pkg_name, head_version, head_commit, package_id, repo, config, installed_version=installed_version)

    diff_text, diff_summary = generate_diff(repo, old_commit, head_commit, config.get("diff", {}).get("max_context_lines", 3))

    max_bytes = config.get("diff", {}).get("max_diff_bytes", 5_242_880)
    diff_bytes = diff_text.encode("utf-8", errors="replace")
    diff_truncated = len(diff_bytes) > max_bytes
    if diff_truncated:
        log.warning("diff for %s exceeds %d bytes; truncating", pkg_name, max_bytes)
        diff_bytes = diff_bytes[:max_bytes]
        diff_text = diff_bytes.decode("utf-8", errors="replace")

    source_changes = extract_urls_from_diff(diff_text)

    old_maintainer = get_maintainer_from_commit(repo, old_commit) or ""
    new_maintainer = get_maintainer_from_commit(repo, head_commit) or ""

    if not old_maintainer:
        pkg_row = get_package(pkg_name)
        if pkg_row and pkg_row.get("current_maintainer"):
            old_maintainer = pkg_row["current_maintainer"]

    maintainer_changed = bool(old_maintainer and new_maintainer and old_maintainer != new_maintainer)

    novelty = build_novelty_context(
        source_changes.added_urls,
        package_id,
        maintainer=new_maintainer,
    )

    source_buckets = classify_urls(source_changes.added_urls)

    resolved_strings, unresolved_strings = tokenize_and_resolve(diff_text)
    raw_lines = get_raw_diff_lines(diff_text)
    line_map = map_diff_lines(diff_text)

    triggered_rules = apply_rules(
        resolved_strings, raw_lines,
        include_experimental=config.get("rules", {}).get("experimental", False),
        line_map=line_map,
    )
    triggered_rules.extend(
        _structural_findings(
            diff_text, source_changes, source_buckets,
            maintainer_changed=maintainer_changed,
            package_name=pkg_name, config=config,
        )
    )
    tree_manifest = _collect_tree_files(repo, head_commit)
    if tree_manifest:
        from .delivery import scan_tree_manifest
        triggered_rules.extend(
            scan_tree_manifest(tree_manifest, source_changes.added_urls, pkg_name)
        )
    triggered_rules, suppressed_rules = filter_triggered_rules(
        triggered_rules, package=pkg_name
    )
    recent = _recent_update(repo, head_commit)
    if recent:
        triggered_rules.append(recent)
    new_pkg = _package_is_new(repo, head_commit, pkg_name)
    if new_pkg:
        triggered_rules.append(new_pkg)
    revived = _stale_revival(repo, old_commit, head_commit)
    if revived:
        triggered_rules.append(revived)

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
        maintainer_changed, new_maintainer
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

    recent_commit_burst = False
    if head_commit:
        try:
            count_24h = 0
            for c in repo.walk(head_commit):
                if (time.time() - c.commit_time) / 3600 <= 24:
                    count_24h += 1
                if count_24h >= 3:
                    recent_commit_burst = True
                    break
        except (AttributeError, pygit2.GitError):
            pass

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
        old_version=installed_version,
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
        suppressed_rules=suppressed_rules,
        recent_commit_burst=recent_commit_burst,
        diff_truncated=diff_truncated,
        tree_analyzed=True,
        temporal_source="git_commit",
        score_breakdown=breakdown,
        final_score=score,
    )

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

    record_dependency_names(sorted(
        name
        for names in extract_dependency_changes(diff_text, pkg_name).values()
        for name in names
    ))
    return fact


def scan_diff(
    diff_text: str,
    rules: list[dict] | None = None,
    config: dict | None = None,
    package_name: str = "",
    seen_urls: dict[str, set[str]] | None = None,
    observation_count: int = 0,
    tree_manifest: list[tuple[str, bytes]] | None = None,
) -> PackageFact:
    if config is None:
        config = load_config()

    source_changes = extract_urls_from_diff(diff_text)

    source_buckets = classify_urls(source_changes.added_urls)

    resolved_strings, unresolved_strings = tokenize_and_resolve(diff_text)
    raw_lines = get_raw_diff_lines(diff_text)
    line_map = map_diff_lines(diff_text)

    triggered_rules = apply_rules(
        resolved_strings, raw_lines, rules,
        include_experimental=config.get("rules", {}).get("experimental", False),
        line_map=line_map,
    )
    triggered_rules.extend(
        _structural_findings(
            diff_text, source_changes, source_buckets,
            package_name=package_name, config=config,
        )
    )
    if tree_manifest:
        from .delivery import scan_tree_manifest
        triggered_rules.extend(
            scan_tree_manifest(tree_manifest, source_changes.added_urls, package_name)
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

    categories = {r.get("category", "") for r in triggered_rules
                  if r.get("category") and r["rule_id"] != "R072"}
    if len(categories) >= 3:
        triggered_rules.append(stamp({
            "rule_id": "R072", "name": "Capability Density Anomaly",
            "severity": "INFO", "category": "meta",
            "match": f"rule hits span {len(categories)} distinct capability categories",
            "params": {"n_categories": len(categories)},
        }))

    rule_ids = [r["rule_id"] for r in triggered_rules]

    aggregate_pinning = _aggregate_pinning(
        diff_text, source_changes.added_urls, source_changes.checksum_behavior
    )
    verification_evidence = detect_verification_evidence(
        diff_text, source_changes.checksum_behavior
    )

    novelty = NoveltyContext(observation_count=observation_count)
    pkgs_seen = seen_urls if seen_urls is not None else {}
    pkg_set = pkgs_seen.setdefault(package_name, set())
    global_set = pkgs_seen.setdefault(_GLOBAL_URL_KEY, set())
    for url in source_changes.added_urls:
        nurl = normalize_url(url)
        if nurl not in pkg_set:
            novelty.url_first_seen_in_this_package = True
            pkg_set.add(nurl)
        if nurl not in global_set:
            novelty.url_first_seen_globally = True
            global_set.add(nurl)

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
        tree_analyzed=bool(tree_manifest),
        score_breakdown=breakdown,
        final_score=score,
    )


def analyze_package_text(
    pkg_name: str,
    old_text: str,
    new_text: str,
    config: dict | None = None,
    rules: list[dict] | None = None,
    adapter: str = "corpus",
    tree_manifest: list[tuple[str, bytes]] | None = None,
) -> PackageFact:
    if config is None:
        config = load_config()

    diff_text = "\n".join(difflib.unified_diff(
        old_text.splitlines() if old_text else [],
        new_text.splitlines() if new_text else [],
        fromfile="PKGBUILD", tofile="PKGBUILD",
        n=config.get("diff", {}).get("max_context_lines", 3),
    ))

    fact = scan_diff(
        diff_text,
        rules=rules,
        config=config,
        package_name=pkg_name,
        tree_manifest=tree_manifest,
    )
    fact.adapter = adapter
    fact.temporal_source = "aur_metadata"
    return fact


def _make_fresh_analysis(
    pkg_name: str, version: str, commit: str, package_id: int, repo, config: dict,
    installed_version: str = "",
) -> PackageFact:
    novelty = build_novelty_context([], package_id)
    triggered_rules: list[dict] = []
    recent = _recent_update(repo, commit)
    if recent:
        triggered_rules.append(recent)
    new_pkg = _package_is_new(repo, commit, pkg_name)
    if new_pkg:
        triggered_rules.append(new_pkg)
    if commit:
        from .delivery import scan_tree_manifest
        tree_manifest = _collect_tree_files(repo, commit)
        if tree_manifest:
            triggered_rules.extend(scan_tree_manifest(tree_manifest, [], pkg_name))
    fact = PackageFact(
        package_name=pkg_name,
        old_version=installed_version,
        new_version=version,
        new_commit=commit,
        diff_summary=DiffSummary(),
        novelty_context=novelty,
        first_seen=True,
        temporal_source="git_commit",
        tree_analyzed=True,
        final_score=0,
    )
    insert_analysis(
        package_id=package_id,
        old_version=installed_version,
        new_version=version,
        old_commit="",
        new_commit=commit,
        final_score=0,
        raw_diff="",
        fact_json=json.dumps(fact_to_dict(fact)),
        triggered_rules=triggered_rules,
    )
    update_package_version(pkg_name, version)
    return fact
