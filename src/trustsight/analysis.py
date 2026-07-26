import json
import logging
import re
from urllib.parse import urlparse

from .buckets import classify_pinning_level, classify_urls

log = logging.getLogger(__name__)
from .config import ensure_default_configs, load_config
from .db import (
    get_last_analysis,
    get_package,
    init_db,
    insert_analysis,
    update_package_maintainer,
    update_package_version,
    upsert_package,
)
from .deps import _strip_comment, extract_dependency_changes, is_related_package
from .db import (
    is_established_package,
    record_dependency_names,
    top_dependency_names,
)
from .differ import (
    _has_checksum_in_post_diff,
    detect_checksum_removed,
    detect_verification_evidence,
    extract_source_array_urls,
    extract_urls_from_diff,
    generate_diff,
    is_skip_justified,
    source_array_has_command_substitution,
)
from .fetcher import clone_or_fetch, get_head_commit, get_maintainer_from_commit, get_pkgver_from_head
from .novelty import (
    build_novelty_context,
    is_dependency_novel,
    normalize_url,
    typosquat_target,
)
from .override import filter_triggered_rules
from .rules import _classify_enclosing_function, apply_rules, get_raw_diff_lines
from .scoring import calculate_score
from .schema import (
    DiffSummary,
    ExecutionChanges,
    NoveltyContext,
    PackageFact,
    fact_to_dict,
)
from .tokenizer import resolve_added_lines, tokenize_and_resolve


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


_CRITICAL_FUNCTIONS = ("build", "prepare", "check", "package")

# Tools whose appearance in makedepends means the build can now reach the
# network, and therefore fetch code that no checksum covers.
_NETWORK_TOOLS = frozenset({
    "curl", "wget", "aria2", "git", "subversion", "mercurial", "rsync",
    "python-requests", "python-httpx", "python-urllib3", "python-aiohttp",
    "ruby-net-http", "nodejs", "npm", "yarn", "cargo", "go",
})

_INSTALL_HOOKS = (
    "post_install", "post_upgrade", "pre_install",
    "pre_upgrade", "pre_remove", "post_remove",
)

# Privileged operations in a hook body.  These run as root, so enabling a
# unit or setting a setuid bit from here is materially different from doing
# it under $pkgdir during build.
_HOOK_EXEC_RE = re.compile(
    r"\b(?:eval|bash\s+-c|sh\s+-c|source\s+/|systemctl\s+enable|"
    r"chmod\s+[0-7]*[2467][0-7]{3}|chmod\s+[ugoa]*\+s|useradd|usermod|visudo)\b",
    re.IGNORECASE,
)

# Patch content from outside the build tree.  Deliberately not "absent from
# source=()": patches routinely arrive inside the extracted tarball, so that
# check fires on 2.13% of benign diffs and cannot distinguish the two.
_UNTRUSTED_PATCH_RE = re.compile(
    r"(?:patch\b|git\s+apply\b)[^|;&]*?"
    r"(<\([^)]*\)"                     # process substitution
    r"|https?://[^\s'\"]+"             # fetched over the network
    r"|[<\s-][ip]?\s*['\"]?/(?!usr/bin/patch)[^\s'\"$]+\.(?:patch|diff))",
    re.IGNORECASE,
)

_NETWORK_FETCH_RE = re.compile(
    r"(?:curl|wget|aria2c|git\s+clone|svn\s+(?:co|checkout)|"
    r"python\s+-c\s+.*urllib|python\s+-m\s+http)\b[^|;&]*?"
    r"(https?://[^\s|;&'\"\)]+)",
    re.IGNORECASE,
)


# Fallbacks for a config written before [experimental_rules] existed.
# load_toml() reads the user's file verbatim and never merges the defaults
# in, so an existing install would otherwise never see a new key and R060
# would be dead for every user who already has a config.toml.
_EXPERIMENTAL_DEFAULTS = {
    "D001": True, "D002": True, "D003": True, "D004": True,
    "R060": True,   # INFO severity, weight 0: cannot move a score
    "R061": True, "R062": True, "R063": True, "R064": True,
}


def _experimental_enabled(config: dict, rule_id: str) -> bool:
    """Check whether a code-emitted rule is enabled.

    They are emitted from code rather than ``rules.toml``, so the
    ``experimental`` flag that :func:`~trustsight.rules.apply_rules`
    honours does not reach them; they need their own gate.
    """
    section = config.get("experimental_rules") if config else None
    if section is None:
        return _EXPERIMENTAL_DEFAULTS.get(rule_id, False)
    return bool(section.get(rule_id, _EXPERIMENTAL_DEFAULTS.get(rule_id, False)))


def _structural_findings(
    diff_text: str,
    source_changes,
    source_buckets: dict[str, str] | None = None,
    maintainer_changed: bool = False,
    package_name: str = "",
    config: dict | None = None,
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

    _dependency_findings(diff_text, package_name, config or {}, add)
    _build_findings(diff_text, config or {}, add)

    return findings


def _dependency_findings(diff_text, package_name, config, add) -> None:
    """D-series: rules over the dependency graph.

    ``rules.py`` strips dependency lines before any pattern runs, so these
    read the diff through :mod:`~trustsight.deps` instead.
    """
    wanted = {r for r in ("D001", "D002", "D003", "D004")
              if _experimental_enabled(config, r)}
    if not wanted:
        return

    added_deps = extract_dependency_changes(diff_text, package_name)

    if wanted & {"D001", "D002"}:
        # D002 refines D001: only a name already established as globally
        # unknown is worth an edit-distance comparison.  The candidate list
        # is loaded lazily because the overwhelming majority of diffs add no
        # novel dependency at all, and it is thousands of rows.
        candidates: list[str] | None = None
        for field in ("depends", "makedepends", "optdepends", "checkdepends"):
            for name in sorted(added_deps.get(field, ())):
                if not is_dependency_novel(name):
                    continue
                impersonated = None
                if "D002" in wanted:
                    if candidates is None:
                        candidates = top_dependency_names()
                    impersonated = typosquat_target(name, candidates)
                if impersonated:
                    add("D002", "Typosquatted Dependency", "HIGH", "dependency",
                        f"{field} '{name}' resembles '{impersonated}'")
                elif "D001" in wanted:
                    add("D001", "Novel Dependency Added", "HIGH", "dependency",
                        f"{field} '{name}' has never been seen in the AUR")

    if "D003" in wanted:
        new_network = sorted(added_deps.get("makedepends", set()) & _NETWORK_TOOLS)
        if new_network:
            add("D003", "New Network-Using Makedepends", "MEDIUM", "dependency",
                f"build can now reach the network via {new_network}")

    if "D004" in wanted:
        for field in ("provides", "replaces"):
            for name in sorted(added_deps.get(field, ())):
                # Declaring a variant of yourself is the ordinary pattern
                # (htop-vim provides htop); claiming an unrelated package is
                # how you get installed in front of it.
                if is_related_package(name, package_name):
                    continue
                if is_established_package(name):
                    add("D004", "Dependency Hijack Via Provides", "HIGH", "dependency",
                        f"{field} '{name}', an established package unrelated to "
                        f"'{package_name}'")
                    return


def _build_findings(diff_text, config, add) -> None:
    """R060 to R064: changes to the code that actually executes."""
    wanted = {r for r in ("R060", "R061", "R062", "R063", "R064")
              if _experimental_enabled(config, r)}
    if not wanted:
        return
    wants_060 = "R060" in wanted
    wants_061 = "R061" in wanted

    # Resolved with positions intact, so each line keeps its enclosing
    # function.  The hunk header cannot be used: the corpus is built with
    # `git diff -W` and an xfuncname, so its headers name the function,
    # while the live pygit2 path emits none.
    lines = resolve_added_lines(diff_text)
    enclosing = _classify_enclosing_function(lines)

    touched = sorted({
        fn for i, line in enumerate(lines)
        if line[:1] in ("+", "-")
        and (fn := enclosing.get(i)) in _CRITICAL_FUNCTIONS
    })
    if wants_060 and touched:
        # INFO, not LOW: this fires on 21.4% of benign diffs, because
        # maintainers rewrite build functions constantly.  No narrowing
        # reaches triage quality (restricting to an unchanged pkgver still
        # leaves 11.6%), so it carries weight 0 and serves as context in
        # the report rather than as a scoring signal.
        add("R060", "Critical Build Function Modified", "INFO", "build",
            f"diff modifies {', '.join(f'{f}()' for f in touched)}")

    if wants_061:
        declared = {normalize_url(u) for u in extract_source_array_urls(diff_text)}
        for i, line in enumerate(lines):
            if not line.startswith("+") or enclosing.get(i) not in _CRITICAL_FUNCTIONS:
                continue
            for match in _NETWORK_FETCH_RE.finditer(line):
                url = match.group(1)
                if normalize_url(url) not in declared:
                    add("R061", "Hidden Network Fetch In Build", "HIGH", "network",
                        f"{enclosing[i]}() downloads {url}, which is not in source=()")
                    break
            else:
                continue
            break

    if "R062" in wanted:
        # .install hooks run as root at install time, which makes them the
        # highest-privilege code a PKGBUILD carries.  generate_diff() already
        # includes *.install patches, and _classify_enclosing_function()
        # recognises post_install() exactly as it recognises build(), so the
        # hook body needs no separate parser.
        for i, line in enumerate(lines):
            if not line.startswith("+") or enclosing.get(i) not in _INSTALL_HOOKS:
                continue
            body = _strip_comment(line)
            if _NETWORK_FETCH_RE.search(body) or _HOOK_EXEC_RE.search(body):
                add("R062", "Install Hook Fetches Or Executes", "HIGH", "installer",
                    f"{enclosing[i]}() runs as root and contains: {body.strip()[:80]}")
                break

    if "R063" in wanted:
        for i, line in enumerate(lines):
            if not line.startswith("+") or enclosing.get(i) not in _CRITICAL_FUNCTIONS:
                continue
            match = _UNTRUSTED_PATCH_RE.search(_strip_comment(line))
            if match:
                add("R063", "Patch Applied From Outside The Build Tree", "HIGH", "integrity",
                    f"{enclosing[i]}() applies a patch from {match.group(1).strip()[:70]}")
                break

    if "R064" in wanted:
        before = extract_source_array_urls(diff_text, side="before")
        after = extract_source_array_urls(diff_text, side="after")
        for url in sorted(before):
            if not url.startswith("https://"):
                continue
            if url.replace("https://", "http://", 1) in after:
                add("R064", "Source URL Downgraded To HTTP", "MEDIUM", "network",
                    f"source URL downgraded from https to http: {url[:70]}")
                break


def _get_installed_version(pkg_name: str) -> str:
    try:
        import subprocess
        result = subprocess.run(
            ["pacman", "-Q", pkg_name],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode == 0 and result.stdout:
            parts = result.stdout.strip().split()
            if len(parts) >= 2:
                return parts[1]
    except (subprocess.SubprocessError, FileNotFoundError):
        pass
    return ""


def analyze_package(pkg_name: str, old_commit: str = "", new_version: str = "") -> PackageFact:
    ensure_default_configs()
    init_db()
    config = load_config()

    installed_version = _get_installed_version(pkg_name)

    repo = clone_or_fetch(pkg_name)
    head_commit = get_head_commit(repo)
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
    if len(diff_bytes) > max_bytes:
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

    # Fold the dependencies just seen into the local corpus, as the URL
    # path already does, so the database keeps growing and the shipped seed
    # matters less over time.  Deliberately not done in scan_diff(): an
    # offline corpus scan that recorded as it went would mark every name
    # known on first sight and destroy its own novelty signal.
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
        _structural_findings(
            diff_text, source_changes, source_buckets,
            package_name=package_name, config=config,
        )
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
    pkg_name: str, version: str, commit: str, package_id: int, repo, config: dict,
    installed_version: str = "",
) -> PackageFact:
    novelty = build_novelty_context([], package_id)
    fact = PackageFact(
        package_name=pkg_name,
        old_version=installed_version,
        new_version=version,
        new_commit=commit,
        diff_summary=DiffSummary(),
        novelty_context=novelty,
        first_seen=True,
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
        triggered_rules=[],
    )
    update_package_version(pkg_name, version)
    return fact



