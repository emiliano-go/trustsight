import difflib
import json
import logging
import re
import time

import pygit2

from ..buckets import classify_urls
from ..config import drifted_shipped_rules, load_config
from ..db import (
    effective_observation_count,
    get_last_analysis,
    get_package,
    insert_analysis,
    record_dependency_names,
    update_package_maintainer,
    get_aur_orphan_state,
    update_aur_orphan_state,
    update_package_version,
    upsert_package,
)
from ..differ import (
    generate_diff_bounded,
    changed_opaque_members,
    companion_source_hunks,
    detect_gpg_verification_removed,
    detect_verification_evidence,
    extract_urls_from_diff,
    map_diff_lines,
    truncate_diff,
)
from ..fetcher import (
    clone_or_fetch,
    get_head_commit,
    get_maintainer_from_commit,
    get_pkgbuild_at_commit,
    get_pkgver_from_head,
    walk_bounded,
)
from ..findings import stamp
from ..novelty import (
    build_novelty_context,
    normalize_url,
    package_typosquat_target,
)
from ..deps import extract_dependency_changes
from ..override import filter_triggered_rules
from ..rules import (
    apply_rules,
    clamp_diff_lines,
    clamp_text,
    get_raw_diff_lines,
)
from .adoption import adoption_findings
from .buildfetch import has_unpinned_build_deps
from ..coverage import (
    begin_stage_tracking,
    fail_closed,
    gaps_from,
    note_stage_failure,
    stage_failures,
    oversized_lines,
    parse_time_substitution_lines,
    unresolved_source_lines,
)
from ..scoring import calculate_score, risk_level
from ..schema import (
    with_changes,
    DiffSummary,
    ExecutionChanges,
    NoveltyContext,
    PackageFact,
    fact_to_dict,
)
from ..tokenizer import split_lines, tokenize_and_resolve_indexed
from .base import (
    _GLOBAL_URL_KEY,
    _pkgver_changed_in_diff,
    _aggregate_pinning,
    _ensure_init,
    _get_installed_version,
    _has_install_hook,
)
from .composition import _meta_annotations
from .ioc_match import ioc_baseline_matches
from .maintainer import _check_untrusted_maintainer_takeover
from .structural import _structural_findings
from .version import (
    compare_installed_to_aur,
    full_version_from_pkgbuild,
    is_vcs_package,
)
from .temporal import _package_is_new, _recent_update, _stale_revival

log = logging.getLogger(__name__)


#: Read size when draining a streamed blob.  Only the head is kept; this is
#: the memory the drain costs, not the file.
_DRAIN_CHUNK_BYTES = 256 * 1024


#: Committed files whose *content* is worth more than their magic bytes.
#:
#: 64 bytes answers "is this an ELF", which is all R118 asked. It cannot
#: answer "what does this unit file run", and that question is the one the
#: audit kept finding unanswerable: a `.service` committed in one push and
#: `install`ed in a later one shows the reviewer nothing but the install
#: line, because the payload is in a file the diff does not touch and the
#: manifest truncated at byte 64.
#:
#: The extra reading is bounded twice - per file and in total - because the
#: tree is attacker-controlled, and it is bounded to the names a recipe can
#: actually ship or apply.
_COMPANION_CONTENT_RE = re.compile(
    r"(?:\.(?:service|socket|timer|path|mount|automount|target|desktop"
    r"|rules|conf|cfg|ini|install|hook|patch|diff|sh|bash|zsh|py|pl|rb)\Z"
    r"|(?:\A|/)(?:\.?[A-Za-z0-9_.-]+\.d/|PKGBUILD\Z|\.SRCINFO\Z))",
    re.IGNORECASE,
)

#: Per-file and whole-tree ceilings on the selective read.
_COMPANION_HEAD_BYTES = 16 * 1024
_COMPANION_TOTAL_BYTES = 512 * 1024


def _collect_tree_files(
    repo,
    commit_oid: str,
    max_file_bytes: int = 512 * 1024,
    head_bytes: int = 64,
    max_stream_bytes: int = 64 * 1024 * 1024,
) -> tuple[list[tuple[str, bytes]], bool]:
    """Walk a commit tree, returning ``([(path, first_bytes)], complete)``.

    ``complete`` is False when any member could not be read, so the caller
    can say the tree was not fully examined instead of implying it was.

    A blob larger than *max_file_bytes* used to be **skipped**, on the
    reasoning that "a committed payload is small".  That is an assumption
    about the attacker, and the attacker reads it: R118 fires on a
    committed ELF, and a payload binary is far more likely to be large than
    small, so anything over 512 KiB was invisible - while
    ``tree_analyzed`` still reported True because some other file had been
    read.  An incomplete read reporting as complete is what
    [B2](../../docs/security.md) forbids.

    The size cap existed because ``blob.data`` materialises the whole blob.
    Streaming the head instead removes the reason for it over the range that
    matters: R118 needs the magic bytes, not the file.

    Streaming has its own bound.  ``pygit2.BlobIO`` runs libgit2's filter
    chain on a worker thread feeding a ``Queue(maxsize=1)``, and ``close()``
    waits for that writer to finish - so reading 64 bytes of a 1 MiB blob
    and closing deadlocks, with the writer parked on a full queue forever.
    Reading the head therefore means draining the rest, which costs time
    linear in the blob but holds memory at one chunk.  Past
    *max_stream_bytes* that time is the attacker's to choose, so the member
    is left unread and *reported* unread - the fallback is the old
    behaviour, minus the silence.
    """
    files: list[tuple[str, bytes]] = []
    complete = True
    budget = _COMPANION_TOTAL_BYTES

    def head_of(blob, want: int) -> bytes | None:
        """The first *want* bytes of *blob*, or None if it was not read."""
        if blob.size <= max_file_bytes:
            try:
                return blob.data[:want]
            except (KeyError, TypeError, ValueError):
                note_stage_failure("tree-blob-read")
                return None
        if blob.size > max_stream_bytes:
            return None
        try:
            stream = pygit2.BlobIO(blob)
        except Exception:
            note_stage_failure("tree-blob-read")
            return None
        try:
            head = stream.read(want)
            # Drain, or close() blocks on the writer thread.
            while stream.read(_DRAIN_CHUNK_BYTES):
                pass
            return head
        except Exception:
            note_stage_failure("tree-blob-read")
            return None
        finally:
            try:
                stream.close()
            except Exception:
                pass

    def walk(tree, prefix: str) -> None:
        nonlocal complete, budget
        for entry in tree:
            if entry.type_str == "tree":
                try:
                    walk(repo[entry.id], prefix + entry.name + "/")
                except (KeyError, TypeError, ValueError):
                    complete = False
            elif entry.type_str == "blob":
                try:
                    blob = repo[entry.id]
                except (KeyError, TypeError, ValueError):
                    complete = False
                    continue
                path = prefix + entry.name
                want = head_bytes
                if budget > 0 and _COMPANION_CONTENT_RE.search(path):
                    want = max(head_bytes, min(_COMPANION_HEAD_BYTES, budget))
                data = head_of(blob, want)
                if data is None:
                    complete = False
                    continue
                if want > head_bytes:
                    budget -= len(data)
                    # A companion cut short is a companion partly read, and
                    # saying the tree was fully examined would be the same
                    # untruth the size cap used to tell.
                    if blob.size > len(data):
                        complete = False
                files.append((path, data))

    try:
        commit = repo.get(commit_oid)
        if commit is not None:
            walk(commit.tree, "")
        else:
            complete = False
    except (KeyError, AttributeError, TypeError, ValueError):
        complete = False
    return files, complete


_SCRIPTLET_ATTR_RE = re.compile(
    r"^\+?\s*(?:install|changelog)\s*=\s*[\"']?([^\"'\s#;]+)",
    re.MULTILINE,
)


def _scriptlet_files_unread(diff_text: str, tree_manifest) -> bool:
    """True when `install=` names a file the manifest does not carry.

    An `.install` scriptlet runs as root on the installing machine, and the
    recipe names it rather than containing it. When a tree was read, the
    absence of `tree_not_analyzed` says the committed files were examined -
    but a manifest that does not hold the named hook means the one file
    whose whole purpose is to run as root was never examined at all, and
    the report said the tree was complete.
    """
    if not tree_manifest:
        return False
    names = {m.group(1).rsplit("/", 1)[-1]
             for m in _SCRIPTLET_ATTR_RE.finditer(diff_text)}
    if not names:
        return False
    have = {path.rsplit("/", 1)[-1] for path, _head in tree_manifest}
    return bool(names - have)


def _adds_a_dependency(diff_text: str) -> bool:
    """True when the diff adds a runtime or build dependency."""
    from ..deps import extract_dependency_changes

    try:
        added = extract_dependency_changes(diff_text, "")
    except Exception:
        return False
    return any(added.get(field) for field in
               ("depends", "makedepends", "checkdepends", "optdepends"))


def _walk_dependencies(pkg_name, depth, config, seen):
    """Analyse the AUR dependency closure of *pkg_name*.

    A dependency is analysed by ``analyze_package`` with ``depth=0``: the
    walk owns the level counting, so a child must not start a walk of its
    own or the closure would be traversed once per node.
    """
    from ..depth import DepthResult, default_metadata, resolve_depth, walk_dependencies

    resolved = resolve_depth(depth, config)
    if resolved == 0:
        return DepthResult()
    return walk_dependencies(
        pkg_name,
        depth=resolved,
        metadata=default_metadata(),
        analyse=lambda name: analyze_package(name, depth=0),
        already_seen=seen,
    )


def analyze_package(
    pkg_name: str,
    old_commit: str = "",
    new_version: str = "",
    installed_version: str | None = None,
    upstream_mtime: int | None = None,
    aur_orphaned: bool | None = None,
    depth: int | None = None,
    _depth_seen: set | None = None,
) -> PackageFact:
    _ensure_init()
    begin_stage_tracking()
    config = load_config()

    if installed_version is None:
        installed_version = _get_installed_version(pkg_name)

    repo = clone_or_fetch(pkg_name, upstream_mtime)
    try:
        head_commit = get_head_commit(repo)
    except pygit2.GitError:
        head_commit = ""
    # Read once, here, rather than after the two fresh-analysis returns
    # below: the declared version and the VCS question are both answered
    # from this text, and both are needed on every path out of this
    # function.  It used to be read further down, which is how the first
    # analysis of a package ended up with no version comparison at all.
    head_pkgbuild = get_pkgbuild_at_commit(repo, head_commit) if head_commit else ""

    # The full `[epoch:]pkgver-pkgrel` the recipe declares, not the bare
    # `pkgver=` line.  `get_pkgver_from_head` remains the fallback for a
    # repository whose HEAD tree cannot be read at all.
    head_version = (
        full_version_from_pkgbuild(head_pkgbuild)
        or get_pkgver_from_head(repo)
        or new_version
    )

    if not head_version:
        head_version = new_version

    package_id = upsert_package(pkg_name, head_version)

    if not head_commit:
        return _make_fresh_analysis(pkg_name, head_version, head_commit, package_id, repo, config, installed_version=installed_version, head_pkgbuild=head_pkgbuild)

    if not old_commit:
        last = get_last_analysis(package_id)
        if last is not None:
            stored_commit = last.get("new_commit")
            if stored_commit:
                old_commit = stored_commit
            elif head_commit:
                try:
                    for c in walk_bounded(repo, head_commit):
                        if not c.parents:
                            old_commit = str(c.id)
                            break
                except pygit2.GitError:
                    # The fallback below compares HEAD against HEAD, whose
                    # diff is empty - every rule then matches nothing and
                    # the package reports clean because the walk failed.
                    note_stage_failure("history-walk")
                if not old_commit:
                    old_commit = head_commit
        else:
            return _make_fresh_analysis(pkg_name, head_version, head_commit, package_id, repo, config, installed_version=installed_version, head_pkgbuild=head_pkgbuild)

    # The generator's own truncation has to travel: a patch it declined to
    # retain leaves the assembled text at or under the cap, so measuring the
    # text below would report "complete" while content had been skipped.
    diff_text, diff_summary, generated_truncated = generate_diff_bounded(
        repo, old_commit, head_commit,
        config.get("diff", {}).get("max_context_lines", 3),
        max_bytes=config.get("diff", {}).get("max_diff_bytes", 5_242_880),
    )

    # A local source=() companion file is build input the recipe copies into
    # $srcdir and can execute; its committed content is scanned with the same
    # rules as the PKGBUILD, or a curl|bash simply moves one file over and the
    # filename filter above drops it.  Appended before the byte cap, so an
    # oversized companion truncates the combined diff and fails closed.
    companion, companion_truncated = companion_source_hunks(repo, head_commit)
    if companion:
        diff_text = f"{diff_text.rstrip(chr(10))}\n{companion}" if diff_text.strip() else companion

    max_bytes = config.get("diff", {}).get("max_diff_bytes", 5_242_880)
    diff_text, combined_truncated = truncate_diff(diff_text, max_bytes)
    # Either half truncating means part of the change was not read.
    diff_truncated = combined_truncated or generated_truncated
    if diff_truncated:
        log.warning("diff for %s exceeds %d bytes; truncating", pkg_name, max_bytes)
    diff_text, scan_truncated = clamp_diff_lines(diff_text, pkg_name)

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
    tree_manifest, tree_complete = _collect_tree_files(repo, head_commit)
    # A committed binary changing produces an *empty* diff - git emits no
    # body for it - so nothing downstream can see the change. The blob id
    # is a content hash and both trees are already open.
    swapped = changed_opaque_members(repo, old_commit, head_commit)
    if swapped:
        version_moved = _pkgver_changed_in_diff(diff_text)
        triggered_rules.append(stamp({
            "rule_id": "C009" if version_moved else "C008",
            "name": ("Unread Content Moved With The Version" if version_moved
                     else "Unread Content Moved Under A Stable Version"),
            "severity": "INFO" if version_moved else "HIGH",
            "category": "integrity",
            "match": (
                f"committed file(s) replaced with no diff body: "
                f"{', '.join(swapped[:3])}"
                + ("" if version_moved else "; pkgver did not change")
            ),
            "file": swapped[0], "line": None,
            "params": {"carrier": "committed-binary",
                       "members": ", ".join(swapped[:5])},
        }))
    triggered_rules.extend(
        _structural_findings(
            clamp_text(diff_text), source_changes, source_buckets,
            maintainer_changed=maintainer_changed,
            package_name=pkg_name, config=config,
            current_text=clamp_text(head_pkgbuild),
            tree_manifest=tree_manifest,
        )
    )
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

    # R141 compares the *previous* recorded AUR state against the current
    # one, so the read has to happen before update_aur_orphan_state below.
    was_orphaned = get_aur_orphan_state(pkg_name)

    takeover = _check_untrusted_maintainer_takeover(
        maintainer_changed, new_maintainer
    )
    if takeover:
        triggered_rules.append(takeover)

    # R141/R142/R143.  Emitted before the meta annotations so R143 is in the
    # breakdown any composition or coverage logic downstream reads.
    adoption_findings(
        diff_text,
        package_name=pkg_name,
        was_orphaned=was_orphaned,
        currently_maintained=bool(new_maintainer) or aur_orphaned is False,
        add=lambda rid, name, severity, category, match, **params: (
            triggered_rules.append(stamp({
                "rule_id": rid, "name": name, "severity": severity,
                "category": category, "match": match, "params": params,
            }))
        ),
    )

    triggered_rules.extend(_meta_annotations(triggered_rules, config))

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
            # Bounded because history is attacker-authored, and free to
            # bound because the walk is newest-first: a burst inside 24h
            # lives in the newest commits or it is not a burst.
            for c in walk_bounded(repo, head_commit):
                if (time.time() - c.commit_time) / 3600 <= 24:
                    count_24h += 1
                if count_24h >= 3:
                    recent_commit_burst = True
                    break
        except (AttributeError, pygit2.GitError):
            note_stage_failure("commit-burst")

    aggregate_pinning = _aggregate_pinning(
        diff_text, source_changes.added_urls, source_changes.checksum_behavior
    )
    verification_evidence = detect_verification_evidence(
        diff_text, source_changes.checksum_behavior
    )

    unresolved_sources = unresolved_source_lines(diff_text)
    # Before scoring, because a truncated walk has to reach `gaps_from`:
    # the band downgrade is decided once inside calculate_score and carried
    # on the fact, so a gap appended afterwards would never fail closed.
    depth_result = _walk_dependencies(pkg_name, depth, config, _depth_seen)

    gaps = gaps_from(
        diff_truncated=diff_truncated,
        scan_truncated=scan_truncated,
        tree_analyzed=(bool(tree_manifest) and tree_complete
                       and not _scriptlet_files_unread(
                           diff_text, tree_manifest)),
        companion_truncated=companion_truncated,
        unresolved_sources=unresolved_sources,
        long_lines=oversized_lines(raw_lines),
        parse_time_substitutions=parse_time_substitution_lines(diff_text),
        unpinned_build_deps=has_unpinned_build_deps(diff_text),
        # A dependency this diff *adds* and this run did not analyse is
        # unread code the package now pulls in. Dependency findings never
        # move the parent's score (B1: the score is this package's own
        # evidence), which is right - but it left a clean parent with an
        # attacker-controlled new `depends=` reporting a complete analysis
        # of a change it had only half read. The score stays where it was;
        # what changes is that the report stops claiming completeness.
        deps_not_scanned=(
            depth_result.truncated
            or (_adds_a_dependency(diff_text) and not depth_result.reports)
        ),
        ruleset_drifted=bool(drifted_shipped_rules()),
        degraded_stages=stage_failures(),
    )

    score, breakdown, risk = calculate_score(
        triggered_rules, source_buckets, novelty, config,
        verification_evidence=verification_evidence,
        pinning_level=aggregate_pinning,
        coverage_gaps=gaps,
    )

    ioc_matches = ioc_baseline_matches(
        diff_text, pkg_name, current_text=head_pkgbuild
    )

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
        dependencies=list(depth_result.reports),
        depth_truncated=depth_result.truncated,
        depth_note=depth_result.reason,
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
        scan_truncated=scan_truncated,
        tree_analyzed=(bool(tree_manifest) and tree_complete
                       and not _scriptlet_files_unread(
                           diff_text, tree_manifest)),
        coverage_gaps=gaps,
        unresolved_sources=unresolved_sources,
        risk=risk,
        temporal_source="git_commit",
        score_breakdown=breakdown,
        final_score=score,
        ioc_matches=ioc_matches,
    )

    with_changes(fact, diff_text)
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


    dependency_changes = extract_dependency_changes(diff_text, pkg_name)
    fact.dependency_changes = {k: sorted(v) for k, v in dependency_changes.items() if v}
    with_changes(fact, diff_text)
    record_dependency_names(sorted(
        name for names in dependency_changes.values() for name in names
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
    current_text: str | None = None,
    tree_complete: bool = True,
) -> PackageFact:
    begin_stage_tracking()
    if config is None:
        config = load_config()

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

    source_changes = extract_urls_from_diff(diff_text)

    source_buckets = classify_urls(source_changes.added_urls)

    resolved_strings, unresolved_strings, resolved_indices = (
        tokenize_and_resolve_indexed(diff_text)
    )
    raw_lines = get_raw_diff_lines(diff_text)
    line_map = map_diff_lines(diff_text)

    triggered_rules = apply_rules(
        resolved_strings, raw_lines, rules,
        include_experimental=config.get("rules", {}).get("experimental", False),
        line_map=line_map,
        resolved_indices=resolved_indices,
    )
    triggered_rules.extend(
        _structural_findings(
            clamp_text(diff_text), source_changes, source_buckets,
            package_name=package_name, config=config,
            current_text=clamp_text(current_text),
            tree_manifest=tree_manifest,
        )
    )
    if tree_manifest:
        from .delivery import scan_tree_manifest
        triggered_rules.extend(
            scan_tree_manifest(tree_manifest, source_changes.added_urls, package_name)
        )

    # R142 only.  was_orphaned=-1 means "no recorded observation", so R141
    # and R143 are structurally silent here: the stateless path has no AUR
    # history to claim an adoption against, and a rule that fires without
    # its state is the cold-start failure the calibration gates catch.
    adoption_findings(
        diff_text,
        package_name=package_name or "",
        was_orphaned=-1,
        currently_maintained=False,
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

    triggered_rules.extend(_meta_annotations(triggered_rules, config))

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

    unresolved_sources = unresolved_source_lines(diff_text)
    gaps = gaps_from(
        diff_truncated=diff_truncated,
        scan_truncated=scan_truncated,
        tree_analyzed=(bool(tree_manifest) and tree_complete
                       and not _scriptlet_files_unread(
                           diff_text, tree_manifest)),
        unresolved_sources=unresolved_sources,
        long_lines=oversized_lines(raw_lines),
        parse_time_substitutions=parse_time_substitution_lines(diff_text),
        unpinned_build_deps=has_unpinned_build_deps(diff_text),
        # This path analyses no dependencies at all, so any dependency the
        # diff adds is code the package now pulls in and this run did not
        # read. See the note on the incremental path above.
        deps_not_scanned=_adds_a_dependency(diff_text),
        ruleset_drifted=bool(drifted_shipped_rules()),
        degraded_stages=stage_failures(),
    )

    score, breakdown, risk = calculate_score(
        triggered_rules, source_buckets, novelty, config,
        verification_evidence=verification_evidence,
        pinning_level=aggregate_pinning,
        coverage_gaps=gaps,
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
        diff_summary=DiffSummary(
            lines_added=sum(1 for line in split_lines(diff_text) if line.startswith("+")),
            lines_removed=sum(1 for line in split_lines(diff_text) if line.startswith("-")),
        ),
        source_changes=source_changes,
        source_buckets=source_buckets,
        execution_changes=exec_changes,
        novelty_context=novelty,
        diff_truncated=diff_truncated,
        scan_truncated=scan_truncated,
        tree_analyzed=(bool(tree_manifest) and tree_complete
                       and not _scriptlet_files_unread(
                           diff_text, tree_manifest)),
        coverage_gaps=gaps,
        unresolved_sources=unresolved_sources,
        risk=risk,
        score_breakdown=breakdown,
        final_score=score,
        ioc_matches=ioc_matches,
    )
    deps_added = extract_dependency_changes(diff_text, package_name)
    fact.dependency_changes = {k: sorted(v) for k, v in deps_added.items() if v}
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


def _make_fresh_analysis(
    pkg_name: str, version: str, commit: str, package_id: int, repo, config: dict,
    installed_version: str = "", head_pkgbuild: str = "",
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
      binary - R118, the Atomic Arch delivery pattern - reported **Low,
      score 0, no findings**, with the finding sitting in the database the
      whole time. First-seen is the case with the least prior evidence, so
      it is the last one that should be reported clean without looking.

    Everything knowable without a diff is therefore decided here: the
    findings and the score that follows from them, the maintainer, and the
    IOC matches against the recipe as it stands.
    """
    novelty = build_novelty_context([], package_id)
    triggered_rules: list[dict] = []
    recent = _recent_update(repo, commit)
    if recent:
        triggered_rules.append(recent)
    new_pkg = _package_is_new(repo, commit, pkg_name)
    if new_pkg:
        triggered_rules.append(new_pkg)
    tree_manifest: list = []
    tree_complete = True
    if commit:
        from .delivery import scan_tree_manifest
        tree_manifest, tree_complete = _collect_tree_files(repo, commit)
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
    )
    # The same scorer the incremental path uses, on the findings this path
    # actually made.  Novelty is empty and stays empty - "first seen" means
    # the novelty tier has nothing to say, not that the rules did not fire -
    # and the band downgrade for a coverage gap is decided inside
    # `calculate_score`, so it is not applied a second time here.
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
        current_maintainer=get_maintainer_from_commit(repo, commit) or "" if commit else "",
        diff_summary=DiffSummary(),
        novelty_context=novelty,
        first_seen=True,
        temporal_source="git_commit",
        tree_analyzed=(bool(tree_manifest) and tree_complete
                       and not _scriptlet_files_unread(
                           head_pkgbuild, tree_manifest)),
        coverage_gaps=gaps,
        ioc_matches=ioc_baseline_matches("", pkg_name, current_text=head_pkgbuild),
        score_breakdown=breakdown,
        risk=risk,
        final_score=score,
    )
    with_changes(fact)
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
