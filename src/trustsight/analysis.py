import json
import logging
import re
from urllib.parse import urlparse

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
from .differ import (
    _has_checksum_in_post_diff,
    detect_checksum_removed,
    detect_verification_evidence,
    extract_urls_from_diff,
    generate_diff,
    is_skip_justified,
    source_array_has_command_substitution,
)
from .discovery import find_outdated_packages, get_aur_latest_versions, get_installed_aur_packages
from .fetcher import clone_or_fetch, get_head_commit, get_maintainer_from_commit, get_pkgver_from_head
from .llm import generate_verdict
from .novelty import build_novelty_context, normalize_url
from .override import filter_triggered_rules
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


_PINNING_ORDER = ["checksum_pinned", "tag_pinned", "branch_pinned", "unpinned"]

# Key for the cross-package URL set inside the caller-supplied seen_urls
# map.  NUL cannot appear in a package name, so it cannot collide.
_GLOBAL_URL_KEY = "\x00__global__"

# Artifacts that ship as executable content rather than buildable source.
_BINARY_ARTIFACT_RE = re.compile(
    r"\.(?:bin|exe|elf|so|dll|dylib|appimage|deb|rpm|apk|msi|jar|run)"
    r"(?:\?|#|$)",
    re.IGNORECASE,
)

# Buckets whose provenance is strong enough that a binary artifact from
# them is ordinary (-bin packages repackaging a GitHub release).
_TRUSTED_BUCKETS = frozenset({"trusted_forge", "official"})


def _url_domain(url: str) -> str:
    parsed = urlparse(url)
    return parsed.netloc.lower()


_NO_CHECKSUM_BEHAVIORS = ("changed_from_sha256_to_skip", "checksum_array_emptied")


def _aggregate_pinning(
    diff_text: str, added_urls: list[str], checksum_behavior: str = ""
) -> str:
    """Worst pinning level across all added source URLs.

    A SKIP or emptied checksum array is not a checksum: it must not earn
    the checksum_pinned discount, or disabling verification would lower
    the score.
    """
    has_checksum = (
        _has_checksum_in_post_diff(diff_text)
        and checksum_behavior not in _NO_CHECKSUM_BEHAVIORS
    )
    levels = [
        classify_pinning_level(url, checksum_present=has_checksum)
        for url in added_urls
    ]
    if not levels:
        return "unpinned"
    return _PINNING_ORDER[max(_PINNING_ORDER.index(p) for p in levels)]


def _structural_findings(
    diff_text: str,
    source_changes,
    source_buckets: dict[str, str] | None = None,
    maintainer_changed: bool = False,
) -> list[dict]:
    """Findings that need diff-pair context a single-line regex cannot see.

    These are generated in code rather than declared in ``rules.toml``
    because each one compares the before and after states of the diff:
    a checksum that changed *while* the source stayed put, a URL swapped
    *without* a version bump.  A pattern matched against one line at a
    time cannot express that.

    Shared by :func:`analyze_package` and :func:`scan_diff` so the live
    and offline pipelines cannot drift apart.
    """
    source_buckets = source_buckets or {}
    findings: list[dict] = []

    def add(rule_id: str, name: str, severity: str, category: str, match: str) -> None:
        findings.append({
            "rule_id": rule_id, "name": name, "severity": severity,
            "category": category, "match": match,
        })

    cs_behavior = source_changes.checksum_behavior
    added = source_changes.added_urls
    removed = source_changes.removed_urls
    pkgver_changed = _pkgver_changed_in_diff(diff_text)

    if cs_behavior == "changed_from_sha256_to_skip":
        skip_reason = is_skip_justified(diff_text)
        add("R004", "Checksum Disabled", "INFO" if skip_reason else "HIGH", "integrity",
            f"sha256sums=SKIP ({skip_reason})" if skip_reason else "sha256sums=SKIP")
    elif cs_behavior == "checksum_array_emptied":
        add("R005", "Checksum Emptied", "HIGH", "integrity", cs_behavior)

    if cs_behavior == "checksum_added_or_changed" and not added and not removed:
        if not pkgver_changed:
            add("C001", "Checksum Changed Without Source Change With Stable Version",
                "HIGH", "integrity",
                "sha256sums changed but source URLs and pkgver unchanged")
        else:
            add("C002", "Checksum Updated With Version Bump", "INFO", "integrity",
                "sha256sums updated alongside pkgver")

    if removed and added and not pkgver_changed and set(removed) != set(added):
        add("C003", "Source URL Changed Without Version Bump", "INFO", "integrity",
            f"URLs changed: {removed} -> {added}")

    # C004: the declaration is gone entirely, leaving nothing to verify.
    if detect_checksum_removed(diff_text) and set(removed) == set(added):
        add("C004", "Checksum Removed For Unchanged Source", "CRITICAL", "integrity",
            "checksum array deleted while source URLs stayed the same")

    # C005: an executable artifact from a domain with no strong provenance.
    # Restricted to untrusted buckets so that -bin packages repackaging a
    # GitHub release do not fire on every update.
    for url in added:
        if _BINARY_ARTIFACT_RE.search(url) and source_buckets.get(url) not in _TRUSTED_BUCKETS:
            add("C005", "Binary Artifact From Untrusted Source", "MEDIUM", "source",
                f"binary artifact from {source_buckets.get(url, 'unknown')} bucket: {url}")
            break

    # C006: a new maintainer bringing new domains with them.  Either alone
    # is routine; together they are the shape of an account takeover.
    if maintainer_changed and added:
        old_domains = {_url_domain(u) for u in removed}
        new_domains = {_url_domain(u) for u in added} - old_domains
        if new_domains:
            add("C006", "Maintainer Change With New Source Domain", "HIGH", "source",
                f"maintainer changed and new domain(s) appeared: {sorted(new_domains)}")

    # C007: command substitution in the source array runs at parse time.
    if source_array_has_command_substitution(diff_text):
        add("C007", "Command Substitution In Source Array", "CRITICAL", "execution",
            "source=() contains $( ) or backtick substitution")

    return findings


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
        log.warning("diff for %s exceeds %d bytes; truncating", pkg_name, max_bytes)
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

    triggered_rules = apply_rules(
        resolved_strings, raw_lines,
        include_experimental=config.get("rules", {}).get("experimental", False),
    )
    triggered_rules.extend(
        _structural_findings(
            diff_text, source_changes, source_buckets,
            maintainer_changed=maintainer_changed,
        )
    )
    triggered_rules, suppressed_rules = filter_triggered_rules(
        triggered_rules, package=pkg_name
    )
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
        suppressed_rules=suppressed_rules,
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
    observation_count: int = 0,
) -> PackageFact:
    """Run the full analysis pipeline on raw diff text.

    Used by benchmark scripts (rebaseline, calibration) that consume
    pre-extracted ``.diff`` files rather than live git repositories.

    When ``seen_urls`` is provided (``{pkg_name: {url, ...}}``), novelty
    is tracked in-memory instead of hitting the database; necessary for
    offline corpus replay where each package has many diffs processed in
    chronological order.

    ``observation_count`` is the offline equivalent of
    :func:`~trustsight.db.count_observations`: the number of diffs the
    replay has already processed.  It gates tier C novelty weights the
    same way database maturity does in the live path.  The default of 0
    keeps novelty inactive, which is the correct behaviour for callers
    that replay a single diff in isolation.
    """
    if config is None:
        config = load_config()

    source_changes = extract_urls_from_diff(diff_text)

    source_buckets = classify_urls(source_changes.added_urls)

    resolved_strings, unresolved_strings = tokenize_and_resolve(diff_text)
    raw_lines = get_raw_diff_lines(diff_text)

    triggered_rules = apply_rules(
        resolved_strings, raw_lines, rules,
        include_experimental=config.get("rules", {}).get("experimental", False),
    )
    triggered_rules.extend(
        _structural_findings(diff_text, source_changes, source_buckets)
    )
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
        # normalize_url so a routine version bump is not novelty, matching
        # check_url_novelty in the live path.  Per-package and global sets
        # are tracked separately: "first seen globally" means across every
        # package, not merely first in this one.  Flags are OR-ed, so one
        # familiar URL cannot mask a novel one.
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
