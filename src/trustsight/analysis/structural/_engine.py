"""Extracted from structural.py: _engine."""

import re
from ...differ import (
    _touched_checksum_arrays,
    checksum_array_parity_in_text,
    is_skip_justified,
    map_diff_lines,
    source_array_has_command_substitution,
)
from ..base import _url_domain
from ..version import any_version_scalar_moved
from ..crossfire import _crossfire_findings
from ..sabotage import _sabotage_findings
from ..build import (
    _build_findings,
    _build_flag_findings,
    _function_shadow_findings,
    _reconstruction_findings,
)
from ..delivery import (
    _delivery_findings,
    install_hook_transition,
    pinning_lost,
    source_name_host_swaps,
)
from ..dependencies import _dependency_findings
from ..ioc import _ioc_findings
from ..network import (
    _dlagents_override_findings,
    _moved_git_ref_findings,
)
from ..persistence import (
    _persistence_findings,
)
from ..version import _epoch_findings
from ...findings import stamp
from ...recipedoc import recipe_states
from ...rules import find_line_in_diff
from ...diffdoc import parse_diff_lines
from ...tokenizer import split_lines
from ._checksums import _is_checksum_array, _package_fetch_client, addendum4_findings, array_order_changes, isolated_checksum_insertion
from ._common import _BINARY_ARTIFACT_RE, _TRUSTED_BUCKETS
from ._hooks import install_script_findings
from ._hygiene import _build_hygiene_findings, _splicing_findings, capability_in_diff, diff_structure_findings
from ._provenance import _PREBUILT_SUFFIX, _declared_upstream_url, _fork_source_divergence, _head_upstream_host, _head_upstream_text, _prebuilt_host_divergence, _registered_domain, _source_divergence_allow, _upstream_domain_typosquat
from ._signing import _signing_key_findings, _unread_carrier_findings

__all__ = ['_structural_findings']

#: An arch-scoped checksum array name, ``sha256sums_x86_64`` or ``md5sums_i686``.
#: ``_touched_checksum_arrays`` tracks only the generic names, so this is how
#: the C004 refactor check sees an arch split.  ``_ARCH_SCOPED_ADDED_SUMS``
#: finds one on an added diff line without walking the diff line by line.
_ARCH_SCOPED_SUMS = re.compile(
    r"(?:md5|sha1|sha224|sha256|sha384|sha512|b2)sums?_[A-Za-z0-9_]+",
    re.IGNORECASE,
)
_ARCH_SCOPED_ADDED_SUMS = re.compile(
    r"^\+.*(?:md5|sha1|sha224|sha256|sha384|sha512|b2)sums?_[A-Za-z0-9_]+",
    re.IGNORECASE | re.MULTILINE,
)

def _structural_findings(
    diff_text: str,
    source_changes,
    source_buckets: dict[str, str] | None = None,
    maintainer_changed: bool = False,
    package_name: str = "",
    config: dict | None = None,
    current_text: str | None = None,
    tree_manifest: list[tuple[str, bytes]] | None = None,
    whole_recipe: bool = False,
    previous_diff: str = "",
    previous_commit: str = "",
    current_commit: str = "",
    delta=None,
) -> list[dict]:
    source_buckets = source_buckets or {}
    findings: list[dict] = []
    # Every code-emitted finding names its location as a 1-based index into
    # the diff stream (`find_line_in_diff`, `_epoch_findings`, the IOC
    # `_line_of`).  That is not a line of the file: a hunk header and every
    # preceding file move the number, so `PKGBUILD line 126` pointed at a
    # comment and a full-recipe finding could cite line 148 of a 115-line
    # file.  The typed parse already knows the true location; project it
    # once here rather than trust each producer to carry it.
    line_map = map_diff_lines(diff_text)
    # the resolved pipeline facts, computed once and
    # shared by the edge-engine predicates dispatched below.
    from ..edges import build_context, run_edge_instances

    ctx = build_context(diff_text, config or {}, current_text=current_text,
                        tree_manifest=tree_manifest, whole_recipe=whole_recipe)
    # /: the change-as-data object, built once and
    # shared by the dependency, epoch and checksum rules below.
    if delta is None:
        from ...changes import change_delta

        delta = change_delta(diff_text, package_name)
    # Distinct name: the local ``delta`` is reused below for per-array
    # ``ArrayDelta`` values, and the shared change object must survive that.
    cdelta = delta

    def add(rule_id: str, name: str, severity: str, category: str, match: str, file: str = "PKGBUILD", line: int | None = None, span=None, **extra) -> None:
        if span is not None:
            # A typed-core span is already a real file line: the recipe
            # knows where the value was read.
            file = span.file or file
            line = span.line or None
        elif line is not None:
            mapped = line_map.get(line - 1)
            if mapped is not None:
                file, line = mapped
            else:
                # An index the parse does not map is a header or a line
                # that does not exist in the new file; a wrong location is
                # worse than none (B8).
                line = None
        finding = {
            "rule_id": rule_id, "name": name, "severity": severity,
            "category": category, "match": match,
            "file": file, "line": line,
        }
        if extra:
            finding["params"] = extra
        findings.append(stamp(finding))

    cs_behavior = source_changes.checksum_behavior
    added = source_changes.added_urls
    removed = source_changes.removed_urls
    # The integrity rules' one definition of "the version moved": pkgver,
    # pkgrel or epoch by resolved value.  A pkgrel rebuild with a changed
    # checksum is C002, not the HIGH C001 that claims the version stood still.
    version_moved = any_version_scalar_moved(diff_text)

    # H003 is about sources that arrive with *no* checksum backing at all.
    # Removing one hash still leaves the array in place, so it is not this
    # rule's business; a whole array removed, or emptied, or set to SKIP,
    # does leave the source unbacked.  Consolidated into the URL engine.
    from ..url_engine import URLContext, run_url_instances

    urlctx = URLContext(diff_text, config or {}, source_changes=source_changes)
    run_url_instances(urlctx, add, only=frozenset({"H003"}))

    if cs_behavior == "changed_from_sha256_to_skip":
        skip_reason = is_skip_justified(diff_text, current_text)
        suffix = f" ({skip_reason})" if skip_reason else ""
        add("H001", "Checksum Disabled", "INFO" if skip_reason else "HIGH", "integrity",
            f"sha256sums=SKIP ({skip_reason})" if skip_reason else "sha256sums=SKIP",
            line=find_line_in_diff(diff_text, r"SKIP|NONE"),
            skip_suffix=suffix)
    elif cs_behavior == "checksum_array_emptied":
        add("H002", "Checksum Emptied", "HIGH", "integrity", cs_behavior,
            line=find_line_in_diff(diff_text, r"sha256sums\s*=\s*\(\s*\)"))

    # H091 - makepkg pairs `source=()` with each `*sums=()` by position,
    # and no rule looked at the two lengths together. The shared ChangeDelta
    # Carries the diff-side parity; the whole-recipe fallback stays
    # here because the complete PKGBUILD is not part of a diff object.
    parity = cdelta.checksum_parity
    if parity is None and current_text and cdelta.source_array_grew:
        # The arrays are not wholly added, but the source list grew: the
        # lengths are read from the complete recipe instead of the hunk, so
        # no partially visible array is ever counted.
        parity = checksum_array_parity_in_text(current_text)
    if parity is not None:
        n_src, n_sum, var = parity
        add("H091", "Checksum Array Shorter Than Source Array", "HIGH",
            "integrity",
            f"{n_src} sources declared against {n_sum} {var} entries",
            line=find_line_in_diff(diff_text, r"source\s*=\s*\("),
            sources=n_src, sums=n_sum, var=var)

    # One parse serves the function-scoped rules below, the array-order
    # rule and the install-script analysis; a refusal leaves them silent
    # (the coverage layer already names the boundary).
    scope_doc = None
    try:
        scope_doc = parse_diff_lines(split_lines(diff_text))
        scope_pre, scope_post = recipe_states(scope_doc)
    except Exception:
        scope_pre = scope_post = None

    # C014 (re-filed from H099): a checksum array
    # reordered during a content change.  Set semantics discard position,
    # so a hash shuffled away from the slot a reviewer checks was invisible;
    # reorder alone is reformatting, so the default gate requires the array
    # to have changed content (or moved a SKIP) too.
    for name, delta, span in array_order_changes(
            diff_text, config, pre=scope_pre, post=scope_post):
        add("C014", "Array Order Manipulation", "MEDIUM", "integrity",
            f"{name} entries changed order"
            + (f" (gained {len(delta.gained)}, lost {len(delta.lost)})"
               if delta.gained or delta.lost else " (SKIP position moved)"),
            span=span, array=name,
            gained=", ".join(delta.gained), lost=", ".join(delta.lost))

    # , mildest shape: an isolated checksum insertion whose index does
    # not match the index at which the corresponding source entry appeared, so
    # the hash/source positional pairing shifted without a reorder.  Scored
    # below the reorder shape (LOW).
    if scope_pre is not None and scope_post is not None:
        ck_names = {n for n in scope_post.arrays if _is_checksum_array(n)}
        for name in sorted(ck_names):
            pair = isolated_checksum_insertion(scope_pre, scope_post, name)
            if pair is None:
                continue
            ck_idx, src_idx = pair
            spans = scope_post.array_spans.get(name) or ()
            add("C014", "Array Order Manipulation", "LOW", "integrity",
                f"{name} entry inserted at index {ck_idx} while source "
                f"inserted at index {src_idx}",
                span=spans[0] if spans else None, array=name,
                checksum_index=ck_idx, source_index=src_idx)

    # , low priority: backup= gains an entry (annotation-tier).
    # backup-listed files get config-file treatment on upgrade, so a new entry
    # changes what pacman preserves; the value is real but niche, so INFO.
    if scope_pre is not None and scope_post is not None:
        from ...recipedoc import array_diff

        delta = array_diff(
            scope_pre.arrays.get("backup", ()),
            scope_post.arrays.get("backup", ()),
        )
        if delta.gained:
            add("C029", "Backup Array Gains Entries", "INFO", "persistence",
                "backup=() gained "
                + ", ".join(delta.gained),
                array="backup", gained=", ".join(delta.gained))

    # C015 (re-filed from H100): a fetch in
    # package().  Sources belong in prepare/build, where the checksum
    # arrays apply; fetching at artifact-assembly time bypasses that
    # accounting.  Reads RecipeDoc.functions only - the whole body, never a
    # Line walk. (H076 already owns the write-outside-$pkgdir half of
    # for package(), so no second rule is filed for it.)
    if scope_post is not None:
        client = _package_fetch_client(
            scope_post.functions.get("package", ""))
        if client:
                add("C015", "Fetch In package()", "HIGH", "network",
                    f"package() fetches with '{client}'; sources must be "
                    "fetched in prepare/build where checksums apply",
                    span=scope_post.function_spans.get("package"),
                    client=client[:40])

    # C016/C017 (re-filed from H102/H103): a
    # complete .install script's hook bodies, read as functions.
    if scope_doc is not None:
        findings.extend(install_script_findings(scope_doc))
        # the L1 structural rules over the typed DiffFile
        # metadata (mode, rename) and empty-file shape.
        diff_structure_findings(scope_doc, add)

    # G1/G3/G4/G5/G6/G7 predicates over the same parse.
    addendum4_findings(diff_text, scope_doc, scope_pre, scope_post,
                       source_changes, config or {}, add,
                       tree_manifest=tree_manifest, post_text=current_text)

    # the E-series entropy predicates. Silent until their
    # thresholds are configured (they ship empty).
    from ..entropy import entropy_findings

    entropy_findings(diff_text, config or {}, add)

    # Cross-cutting (T8): command splicing (X) and build-hygiene (C) signals.
    _splicing_findings(diff_text, add)
    _build_hygiene_findings(diff_text, add, current_text)

    if cs_behavior == "checksum_added_or_changed" and not added and not removed:
        # F8: a version move only stands the tamper signal down when the
        # diff adds no new code capability.  A bump that also starts
        # downloading or running something is the checksum-refresh shape
        # used as cover.  Gated by `[thresholds] c001.require_capability_signal`
        # (default true) because it touches the most common operation there
        # is; one config flip reverts to the old C002-for-every-bump rule.
        gate = ((config or {}).get("thresholds", {})
                .get("c001", {}).get("require_capability_signal", True))
        capability = None
        if version_moved and gate:
            capability = capability_in_diff(diff_text, current_text)
        if not version_moved or capability:
            match = (
                "sha256sums changed but source URLs and pkgver/pkgrel/epoch "
                "unchanged"
                if not version_moved
                else "checksum updated with a version bump that also adds "
                     f"{capability}"
            )
            add("C001", "Checksum Changed Without Source Change With Stable Version",
                "HIGH", "integrity", match,
                line=find_line_in_diff(diff_text, r"""sha256sums\s*=\s*\('"""))
        else:
            add("C002", "Checksum Updated With Version Bump", "INFO", "integrity",
                "sha256sums updated alongside a version move",
                line=find_line_in_diff(diff_text, r"""sha256sums\s*=\s*\('"""))

    if removed and added and not version_moved and set(removed) != set(added):
        add("C003", "Source URL Changed Without Version Bump", "INFO", "integrity",
            f"URLs changed: {removed} -> {added}",
            line=find_line_in_diff(diff_text, r"source(?:_[a-z0-9_]+)?\s*=\s*\("),
            added=str(added), removed=str(removed))

    # H099 - the quiet swap: the local name a reviewer recognises stays,
    # the server behind it changes.  Suppressed on a version move, where a
    # new host is the ordinary shape of an upstream that relocated.
    if not version_moved:
        swaps = source_name_host_swaps(diff_text)
        if swaps:
            name, old_host, new_host, old_dom, new_dom, span = swaps[0]
            add("H099", "Source Host Swapped Under A Kept Local Name", "HIGH",
                "source",
                f"source '{name}' moved from {old_host} to {new_host} "
                f"with no version change",
                span=span,
                local_name=name, old_domain=old_dom, new_domain=new_dom,
                old_host=old_host, new_host=new_host)

    # H100 - a root-running hook appears or is retargeted.  HIGH when the
    # hook script itself ships in the same diff, MEDIUM when the
    # declaration alone moves (the script may predate it).
    old_hook, new_hook, hook_in_diff, hook_span = install_hook_transition(diff_text)
    if new_hook and old_hook != new_hook:
        add("H100", "Install Hook Added Or Retargeted",
            "HIGH" if hook_in_diff else "MEDIUM", "installer",
            (f"install hook retargeted: {old_hook} -> {new_hook}" if old_hook
             else f"install hook added: {new_hook}")
            + ("; hook script is in this diff" if hook_in_diff else ""),
            span=hook_span,
            old=old_hook, new=new_hook)

    # H101 - a verifiable source becomes a moving target.  P008 says where
    # a floating source stands; this says the package *lost* pinning,
    # which is the transition a watch replay exists to catch.
    lost = pinning_lost(diff_text)
    if lost:
        name, old_url, new_url, span, renamed = lost[0]
        # A pin that moved in place (same local name) is MEDIUM, the H099
        # signal.  Deleting a checksummed archive and replacing it with a
        # floating VCS entry under a new name drops the pin outright, which
        # is HIGH on its own.
        add("H101", "Source Pinning Lost", "HIGH" if renamed else "MEDIUM",
            "integrity",
            f"source '{name}' was pinned and now tracks a moving target: "
            f"{old_url} -> {new_url}",
            span=span,
            local_name=name, old_url=old_url, new_url=new_url)

    _unread_carrier_findings(diff_text, version_moved, add)

    # C004 covers both ways verification is weakened with the source left
    # alone: the whole array deleted, and one hash removed from an array
    # that stays.  They were two notions of "checksum removed", and the
    # entry-removal half was invisible on every detector - a multiline array
    # whose opener is a context line lost a hash silently while *adding* one
    # fired.  Both now arrive through `checksum_behavior`, so the rule, the
    # summary and the verification evidence cannot disagree about whether a
    # checksum change happened at all.
    if set(removed) == set(added) and cs_behavior in (
        "checksum_array_removed", "checksum_entry_removed",
    ):
        # A hash "removed" from one array but moved to an arch-scoped one
        # (`sha256sums` -> `sha256sums_x86_64`/`_aarch64`) is a layout
        # refactor, not weakened verification: the hash is still in the
        # recipe.  Fire only when a removed hash is genuinely gone from the
        # whole recipe (the full head text); without it, keep the old
        # behaviour rather than guess.
        removed_hashes = {
            item.strip("'\"")
            for array in _touched_checksum_arrays(diff_text)
            for item in array.removed_items
            if any(c.isalnum() for c in item)
        }
        still_present = bool(current_text and removed_hashes) and all(
            digest in current_text for digest in removed_hashes
        )
        # A generic array whose entries move to arch-scoped arrays
        # (`sha256sums` -> `sha256sums_x86_64`/`_aarch64`) is a layout
        # refactor: the hashes differ per arch, so the removed generic hash is
        # genuinely gone yet every source is still checksummed.  The
        # `still_present` test above only catches the same hash reused; this
        # catches the split where the arch hashes differ.
        arch_split = bool(_ARCH_SCOPED_SUMS.search(current_text or "")) or bool(
            _ARCH_SCOPED_ADDED_SUMS.search(diff_text)
        )
        if not still_present and not arch_split:
            add("C004", "Checksum Removed For Unchanged Source", "CRITICAL",
                "integrity",
                "checksum array deleted while source URLs stayed the same"
                if cs_behavior == "checksum_array_removed" else
                "checksum entry removed while source URLs stayed the same",
                line=find_line_in_diff(diff_text, r"sha256sums", prefix=r"\-"))

    # The declared upstream host serves C005 and C011 alike: a binary
    # artifact, or a prebuilt package's source, on the project's own host (or
    # a host the operator allow-listed as its distribution CDN) is not a
    # third-party fetch.  Computed once here so the two rules cannot disagree
    # about what "the upstream" is.
    upstream_host = _head_upstream_host(diff_text, current_text) if added else ""
    upstream_reg = _registered_domain(upstream_host) if upstream_host else ""
    divergence_allow = _source_divergence_allow(config)

    for url in added:
        if not _BINARY_ARTIFACT_RE.search(url):
            continue
        bucket = source_buckets.get(url, "unknown")
        if bucket in _TRUSTED_BUCKETS:
            continue
        source_reg = _registered_domain(_url_domain(url))
        if source_reg and (source_reg == upstream_reg
                           or source_reg in divergence_allow):
            continue
        # Sliced *before* escaping, not after. Cutting an escaped
        # string can land between a backslash and the character it
        # escapes, which is not a legal pattern - the compile then
        # fails, the fallback escapes the already-escaped text, and
        # the line number is silently lost on exactly the long URLs
        # this rule exists to report.
        escaped = re.escape(url[:80])
        add("C005", "Binary Artifact From Untrusted Source", "MEDIUM", "source",
            f"binary artifact from {bucket} bucket: {url}",
            line=find_line_in_diff(diff_text, escaped),
            url=url, bucket=bucket)
        break

    if maintainer_changed and added:
        old_domains = {_url_domain(u) for u in removed}
        new_domains = {_url_domain(u) for u in added} - old_domains
        if new_domains:
            add("C006", "Maintainer Change With New Source Domain", "HIGH", "source",
                f"maintainer changed and new domain(s) appeared: {sorted(new_domains)}",
                line=find_line_in_diff(diff_text, r"#\s*Maintainer"),
                new_domains=", ".join(sorted(new_domains)))

    # C011 - a prebuilt (-bin) package that fetches its artifact from a host
    # that is neither the declared upstream's registered domain nor a known
    # distribution channel.  The upstream `url=` is declared by the same
    # party under review, so this is a heuristic, not proof; it names the
    # divergence a reviewer has to judge.  The upstream-payload gap itself
    # (the bytes behind the URL) stays outside static analysis.
    if package_name.endswith(_PREBUILT_SUFFIX) and upstream_host:
        divergence = _prebuilt_host_divergence(
            added, source_buckets, package_name, upstream_host,
            divergence_allow,
        )
        if divergence is not None:
            url, source_reg, upstream_reg = divergence
            add("C011", "Prebuilt Binary From Non-Upstream Host", "MEDIUM",
                "source",
                f"prebuilt package sources from {source_reg}, "
                f"not declared upstream {upstream_reg}",
                line=find_line_in_diff(diff_text, re.escape(url[:80])),
                url=url, source_host=source_reg, upstream_host=upstream_reg)

    # C012 - a source domain one or two edits from the declared upstream's own
    # domain.  R013b only sees mixed-script homoglyphs and the package/dep
    # typosquat never looks at domains, so a pure-ASCII `githab.com` was
    # invisible.  Scoped to a trusted-forge/official upstream for precision.
    if added:
        upstream_host = _head_upstream_host(diff_text, current_text)
        if upstream_host:
            typo = _upstream_domain_typosquat(added, source_buckets, upstream_host)
            if typo is not None:
                url, source_reg, upstream_reg, distance = typo
                add("C012", "Source Domain Resembles Declared Upstream", "MEDIUM",
                    "deception",
                    f"source host {source_reg} is {distance} edit(s) from "
                    f"declared upstream {upstream_reg}",
                    line=find_line_in_diff(diff_text, re.escape(url[:80])),
                    url=url, source_host=source_reg, upstream_host=upstream_reg,
                    distance=distance)

    # C013 - the recipe declares one project as its upstream and fetches the
    # code from a same-named fork under a different owner on the same forge.
    # `-git` packages that build a maintainer's fork hit this, so it names the
    # divergence rather than asserting intent.
    if added:
        upstream_url = _declared_upstream_url(
            _head_upstream_text(diff_text, current_text)
        )
        if upstream_url:
            fork = _fork_source_divergence(added, upstream_url)
            if fork is not None:
                url, forge, src_owner, repo, up_owner = fork
                add("C013", "Source Fork Diverges From Declared Upstream", "MEDIUM",
                    "source",
                    f"source is {forge}/{src_owner}/{repo}, upstream declares "
                    f"{forge}/{up_owner}/{repo}",
                    line=find_line_in_diff(diff_text, re.escape(url[:80])),
                    url=url, forge=forge, source_owner=src_owner,
                    repo=repo, upstream_owner=up_owner)

    if source_array_has_command_substitution(diff_text):
        add("C007", "Command Substitution In Source Array", "CRITICAL", "execution",
            "source=() contains $( ) or backtick substitution",
            line=find_line_in_diff(diff_text, r"\$\(|`"))

    _crossfire_findings(diff_text, config or {}, add,
                        previous_diff=previous_diff,
                        previous_commit=previous_commit,
                        current_commit=current_commit)
    _sabotage_findings(diff_text, config or {}, add)
    _dependency_findings(
        diff_text, package_name, config or {}, add, current_text=current_text,
        delta=cdelta,
    )
    # U-series: committed upstream dependency manifests (spec: Upstream
    # Manifests).  Reads the diff's ManifestDelta and names a refusal.
    from ..upstream_manifests import upstream_manifest_findings

    upstream_manifest_findings(
        diff_text, tree_manifest, cdelta, add, config or {}, package_name
    )
    _build_findings(diff_text, config or {}, add, current_text=current_text,
                    ctx=ctx)
    from ..persistence_engine import run_persistence_instances

    run_persistence_instances(ctx, add, only=frozenset({"H004"}))
    _build_flag_findings(diff_text, config or {}, add)
    _function_shadow_findings(diff_text, config or {}, add)
    _reconstruction_findings(diff_text, config or {}, add)
    _signing_key_findings(diff_text, add)
    run_edge_instances(ctx, add, only=frozenset({"H075"}))
    run_edge_instances(ctx, add, only=frozenset({"H080"}))
    _delivery_findings(
        diff_text, config or {}, add, tree_manifest=tree_manifest,
        current_text=current_text, ctx=ctx,
    )
    _persistence_findings(diff_text, config or {}, add, current_text=current_text,
                          ctx=ctx)
    run_edge_instances(ctx, add, only=frozenset({"H040"}))
    run_url_instances(urlctx, add, only=frozenset({"H034"}))
    run_url_instances(urlctx, add, only=frozenset({"H031"}))
    run_edge_instances(ctx, add, only=frozenset({"H077"}))
    _dlagents_override_findings(diff_text, config or {}, add)
    run_edge_instances(ctx, add, only=frozenset({"H041"}))
    # H033 asks the current file which variable feeds a git ref; the diff
    # alone shows only the hunk around the pin.
    _moved_git_ref_findings(diff_text, config or {}, add, current_text=current_text)
    run_edge_instances(ctx, add, only=frozenset({"H071"}))
    _epoch_findings(diff_text, config or {}, add, whole_recipe=whole_recipe,
                    delta=cdelta)
    # H056 reads the current file where the caller has it: an indicator that
    # predates this diff is still a fact about the package being reviewed.
    _ioc_findings(diff_text, package_name, config or {}, add,
                  current_text=current_text)

    return findings
