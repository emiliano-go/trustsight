import re

from ..differ import (
    _post_diff_lines,
    checksum_array_parity,
    checksum_array_parity_in_text,
    is_skip_justified,
    map_diff_lines,
    source_array_grew_in_diff,
    source_array_has_command_substitution,
)
from .base import _url_domain
from .version import any_version_scalar_moved
from .crossfire import _crossfire_findings
from .sabotage import _sabotage_findings
from .build import (
    _build_findings,
    _build_flag_findings,
    _function_shadow_findings,
    _indirect_expansion_findings,
    _indirect_remote_execution_findings,
    _INTERPRETER_FETCH,
    _reconstruction_findings,
    _sudo_findings,
)
from ..config import NETWORK_CLIENT
from .composition import _recon_findings
from .delivery import (
    _delivery_findings,
    install_hook_transition,
    pinning_lost,
    source_name_host_swaps,
)
from .dependencies import _dependency_findings
from .ioc import _ioc_findings
from .network import (
    _covert_egress_findings,
    _dlagents_override_findings,
    _parse_time_fetch_findings,
    _paste_egress_findings,
    _exotic_protocol_findings,
    _moved_git_ref_findings,
    _version_in_url_findings,
)
from .persistence import (
    _HOME_PREFIX_RE,
    _persistence_findings,
    _raw_targets,
    _WW_DIR_RE,
)
from .version import _epoch_findings
from ..findings import stamp
from ..line_lex import strip_comment
from ..recipedoc import parse_recipe, recipe_states
from ..rules import find_line_in_diff
from ..diffdoc import parse_diff_lines
from ..tokenizer import split_lines

_BINARY_ARTIFACT_RE = re.compile(
    r"\.(?:bin|exe|elf|so|dll|dylib|appimage|deb|rpm|apk|msi|jar|run)"
    r"(?:\?|#|$)",
    re.IGNORECASE,
)

_TRUSTED_BUCKETS = frozenset({"trusted_forge", "official"})

_CHECKSUM_SKIP_RE = re.compile(
    r"sha256sums\s*=\s*\(?\s*[\'\"]?(?:SKIP|NONE)"
)

_CHECKSUM_EMPTIED_RE = re.compile(
    r"sha256sums\s*=\s*\(\s*\)"
)

_CHECKSUM_ADDED_RE = re.compile(
    r"sha256sums\s*=\s*\('[a-fA-F0-9]"
)

_CHECKSUM_REMOVED_LINE_RE = re.compile(
    r"sha256sums"
)


_VALIDPGPKEYS_ENTRY_RE = re.compile(r"[\'\"]([A-Fa-f0-9]{8,40})[\'\"]")
_VALIDPGPKEYS_LINE_RE = re.compile(r"^\s*validpgpkeys\s*=|^\s*validpgpkeys\s*=?\s*\(", re.IGNORECASE)


def _signing_key_findings(diff_text: str, add) -> None:
    """The set of keys trusted to sign this package's sources changed (H078).

    ``validpgpkeys`` is the list of key fingerprints whose signature makepkg
    will accept for a signed source.  Whoever holds one of those keys can
    ship code to every user of the package, so the set changing is a trust
    change, and the diff states it as a declared fact.

    H024 owns the *removal* case (verification taken away).  H078 owns the
    other two:

    - a key **replaced** (one fingerprint out, a different one in) means the
      same sources are now trusted under a different holder: HIGH.
    - a key **added** to an existing set widens who may sign: MEDIUM.

    Introducing ``validpgpkeys`` where there was none is signature checking
    being switched on, so it is reported as a neutral fact at INFO rather
    than as a finding against the package.
    """
    added_keys: set[str] = set()
    removed_keys: set[str] = set()
    had_keys_before = False
    in_added = in_removed = False
    # The dominant AUR edit shape opens the array on a CONTEXT line and
    # changes one quoted key per `+`/`-` line:
    #     validpgpkeys=(
    #    -        'OLDKEY...')
    #   +        'NEWKEY...')
    # `array_open` carries that opener, or the `+`/`-` member lines are
    # never collected (the context branch used to reset the state instead).
    # It ends on a context line holding `)` or at a file/hunk header - not
    # on a member line's `)`, because the removal side closes before the
    # addition side has been read.  Collection is gated by the quoted-hex
    # entry regex, so a trailing unclosed region gathers nothing real.
    array_open = False
    for line in parse_diff_lines(split_lines(diff_text)).lines:
        raw = line.raw
        if raw.startswith(("+++ ", "--- ", "@@")):
            array_open = in_added = in_removed = False
            continue
        if line.is_content:
            side = {"add": "+", "remove": "-", "context": " "}[line.side]
            body = line.content
        else:
            side = " "
            body = raw
        opens = bool(_VALIDPGPKEYS_LINE_RE.match(body))
        if side == "-" and (opens or in_removed or array_open):
            had_keys_before = had_keys_before or bool(_VALIDPGPKEYS_ENTRY_RE.search(body))
            removed_keys |= {m.upper() for m in _VALIDPGPKEYS_ENTRY_RE.findall(body)}
            in_removed = ")" not in body
            continue
        if side == "+" and (opens or in_added or array_open):
            added_keys |= {m.upper() for m in _VALIDPGPKEYS_ENTRY_RE.findall(body)}
            in_added = ")" not in body
            continue
        if side == " ":
            if opens:
                array_open = ")" not in body
            elif array_open:
                if _VALIDPGPKEYS_ENTRY_RE.search(body):
                    had_keys_before = True
                if ")" in body:
                    array_open = False
            in_added = in_removed = False

    genuinely_added = added_keys - removed_keys
    genuinely_removed = removed_keys - added_keys
    if not genuinely_added:
        return
    keys = ", ".join(sorted(k[-8:] for k in genuinely_added))
    line_no = find_line_in_diff(diff_text, r"validpgpkeys")
    if genuinely_removed:
        add("H078", "Signing Key Replaced", "HIGH", "integrity",
            f"validpgpkeys now trusts {keys} instead of "
            f"{', '.join(sorted(k[-8:] for k in genuinely_removed))}",
            line=line_no, added_keys=keys,
            removed_keys=", ".join(sorted(k[-8:] for k in genuinely_removed)),
            detail=f"signing key replaced: now {keys}")
    elif had_keys_before:
        add("H078", "Signing Key Added", "MEDIUM", "integrity",
            f"validpgpkeys gained {keys}; another holder may now sign this "
            f"package's sources",
            line=line_no, added_keys=keys,
            detail=f"signing key {keys} added to an existing set")
    else:
        add("H078", "Signature Verification Introduced", "INFO", "integrity",
            f"validpgpkeys introduced with {keys}",
            line=line_no, added_keys=keys,
            detail=f"validpgpkeys introduced with {keys}")


#: A git submodule's recorded commit.  A gitlink is how a repository names
#: code it does not contain, and the diff shows the move as a one-line
#: change with no content behind it.
_SUBMODULE_COMMIT_RE = re.compile(r"^([+-])Subproject commit ([0-9a-f]{7,40})", re.M)

#: A Git-LFS pointer.  The pointer file is committed text; the bytes it
#: names are not in the repository at all, so the OID *is* the content's
#: identity as far as any reader is concerned.
_LFS_OID_RE = re.compile(r"^([+-])\s*oid\s+sha256:([0-9a-f]{16,64})", re.M)


def _unread_carrier_findings(diff_text, pkgver_changed, add) -> None:
    """Contents this analysis cannot read, whose identity changed (C008).

    The upstream-payload gap is real and documented: a checksummed tarball's
    bytes are not in the diff, so the recipe can look untouched while the
    code it builds is replaced.  What *is* in the diff is the carrier's
    identity - the checksum, the commit, the OID - and a change to that with
    no version change is the same event H033 already claims for a git ref
    and C001 for a checksum.

    Two carriers had no such claim.  A submodule gitlink names code the
    repository does not contain; an LFS pointer names bytes that are not
    there either.  Moving one is a content change with no content in the
    diff, which is precisely the shape that reads as "nothing happened".

    The version distinguishes the two readings, as it does for H033: an
    upstream bump moves the pointer *and* the version, and moving it while
    the version stands still means anyone who already built this version
    gets different code than anyone who builds it now.
    """
    for label, pattern, what in (
        ("submodule", _SUBMODULE_COMMIT_RE, "a submodule commit"),
        ("lfs", _LFS_OID_RE, "a Git-LFS object id"),
    ):
        before = {m.group(2) for m in pattern.finditer(diff_text)
                  if m.group(1) == "-"}
        after = {m.group(2) for m in pattern.finditer(diff_text)
                 if m.group(1) == "+"}
        moved = sorted(after - before)
        if not (before and moved):
            continue
        old = sorted(before)[0][:12]
        new = moved[0][:12]
        if pkgver_changed:
            add("C009", "Unread Content Moved With The Version", "INFO",
                "integrity",
                f"{what} moved from {old} to {new} alongside a version bump",
                line=find_line_in_diff(diff_text, moved[0][:12]),
                carrier=label, old_id=old, new_id=new)
        else:
            add("C008", "Unread Content Moved Under A Stable Version", "HIGH",
                "integrity",
                f"{what} moved from {old} to {new} while pkgver did not change; "
                f"the bytes it names are not in this diff",
                line=find_line_in_diff(diff_text, moved[0][:12]),
                carrier=label, old_id=old, new_id=new)
        return


#: A literal ``url=`` scalar in a PKGBUILD.  A value carrying a shell
#: variable is skipped: resolving it needs the whole recipe, and a wrong
#: upstream is worse than no upstream for C011.
_URL_SCALAR_RE = re.compile(r"^\s*url\s*=\s*['\"]?([^'\"\s]+)", re.MULTILINE)

#: The AUR convention for a package that ships a prebuilt binary.  A
#: convention, not a guarantee: a prebuilt package without the suffix is
#: outside C011's scope.
_PREBUILT_SUFFIX = "-bin"

#: Buckets whose source is already trusted or a declared distribution
#: channel; a host in one of these is never a C011 divergence.
_TRUSTED_SOURCE_BUCKETS = frozenset(
    {"trusted_forge", "official", "raw_hosting", "homograph_attack"}
)


def _declared_upstream_url(pkgbuild_text: str | None) -> str:
    """The PKGBUILD's literal ``url=`` value, or "" when unusable.

    A value carrying a shell variable is skipped: resolving it needs the
    whole recipe, and a wrong upstream is worse than no upstream for C011
    and C013.
    """
    if not pkgbuild_text:
        return ""
    match = _URL_SCALAR_RE.search(pkgbuild_text)
    if not match:
        return ""
    value = match.group(1)
    if "$" in value or "{" in value:
        return ""
    return value


def _declared_upstream_host(pkgbuild_text: str | None) -> str:
    """The host of the PKGBUILD's ``url=`` scalar, or "" when unusable."""
    return _url_domain(_declared_upstream_url(pkgbuild_text))


def _forge_owner_repo(url: str) -> tuple[str, str, str] | None:
    """``(registered_forge, owner, repo)`` for a trusted-forge URL, else None."""
    from urllib.parse import urlparse

    from ..buckets import canonical_host, classify_url

    bucket, _ = classify_url(url)
    if bucket != "trusted_forge":
        return None
    parsed = urlparse(url)
    forge = _registered_domain(canonical_host(parsed.netloc))
    parts = [p for p in parsed.path.split("/") if p]
    if len(parts) < 2:
        return None
    owner = parts[0].lower()
    repo = parts[1][:-4] if parts[1].endswith(".git") else parts[1]
    repo = repo.lower()
    if not owner or not repo:
        return None
    return forge, owner, repo


def _registered_domain(host: str) -> str:
    """The registrable domain (eTLD+1) of *host*, or *host* when unknown.

    Registered domain rather than host so a subdomain or CDN under the
    upstream's own domain (``dl.google.com`` for ``google.com``) is not a
    divergence.
    """
    if not host:
        return ""
    from ..buckets import _extract

    extracted = _extract(host.split(":", 1)[0])
    if extracted.suffix:
        return f"{extracted.domain}.{extracted.suffix}"
    return host


def _source_divergence_allow(config: dict | None) -> frozenset[str]:
    """Registered domains exempted from C011 by the operator."""
    from ..config import DEFAULT_SOURCE_DIVERGENCE_ALLOW

    section = (config or {}).get("source_host_divergence") or {}
    values = section.get("allow") or DEFAULT_SOURCE_DIVERGENCE_ALLOW
    return frozenset(str(v).lower() for v in values)


def _prebuilt_host_divergence(
    added: list[str],
    source_buckets: dict[str, str],
    package_name: str,
    upstream_host: str,
    allow: frozenset[str],
) -> tuple[str, str, str] | None:
    """Return ``(url, source_registered, upstream_registered)`` for C011, or None.

    Only the highest-trust host shape is exempt: a source already in a
    trusted, official or raw-hosting bucket, or one sharing the upstream's
    registered domain.  The first divergent source is the one reported, the
    way SOURCE_BUCKET reports the least-trusted single URL rather than one
    finding per URL.
    """
    upstream_reg = _registered_domain(upstream_host)
    if not upstream_reg:
        return None
    for url in added:
        if source_buckets.get(url, "unknown") in _TRUSTED_SOURCE_BUCKETS:
            continue
        source_reg = _registered_domain(_url_domain(url))
        if not source_reg or source_reg == upstream_reg or source_reg in allow:
            continue
        return url, source_reg, upstream_reg
    return None


def _head_upstream_text(diff_text: str, current_text: str | None) -> str:
    """The head PKGBUILD when available, else the post-diff lines.

    The git and corpus paths supply the full head file; a caller that gives
    only a diff (the fixture gates) still sees the ``url=`` scalar when it
    sits in a hunk's context.
    """
    if current_text is not None:
        return current_text
    return "\n".join(_post_diff_lines(diff_text))


def _head_upstream_host(diff_text: str, current_text: str | None) -> str:
    """The declared ``url=`` host, from the head PKGBUILD when available."""
    return _declared_upstream_host(_head_upstream_text(diff_text, current_text))


def unchanged_upstream_host(diff_text: str, current_text: str | None) -> str:
    """The declared ``url=`` host, or "" when this diff adds a ``url=`` line.

    A ``url=`` set in the same change as the source proves nothing about it.
    """
    added = "\n".join(
        line.content
        for line in parse_diff_lines(split_lines(diff_text)).lines
        if line.side == "add" and not line.raw.startswith("+++")
    )
    if _URL_SCALAR_RE.search(added):
        return ""
    return _head_upstream_host(diff_text, current_text)


def _fork_source_divergence(
    added: list[str],
    upstream_url: str,
) -> tuple[str, str, str, str, str] | None:
    """Return ``(url, forge, source_owner, repo, upstream_owner)`` for C013.

    Same forge, same repository name, different owner: the recipe names one
    project as its upstream and fetches the code from a fork of it.  A
    cross-forge source is deliberately not claimed here - a mirror on another
    forge is common and is not evidence on its own.
    """
    upstream = _forge_owner_repo(upstream_url)
    if upstream is None:
        return None
    up_forge, up_owner, up_repo = upstream
    for url in added:
        source = _forge_owner_repo(url)
        if source is None:
            continue
        src_forge, src_owner, src_repo = source
        if src_forge != up_forge or src_repo != up_repo or src_owner == up_owner:
            continue
        return url, src_forge, src_owner, src_repo, up_owner
    return None


def _upstream_domain_typosquat(
    added: list[str],
    source_buckets: dict[str, str],
    upstream_host: str,
) -> tuple[str, str, str, int] | None:
    """Return ``(url, source_registered, upstream_registered, distance)`` for C012.

    Only an upstream already on a trusted forge or official project is
    eligible, which keeps the near-miss meaningful: a source host that
    resembles an unknown upstream is not evidence of impersonation.  The
    suffix must match, so ``github.com`` vs ``github.io`` is a different
    domain rather than a typo.
    """
    from ..buckets import classify_url
    from ..novelty import _damerau_levenshtein

    upstream_reg = _registered_domain(upstream_host)
    if not upstream_reg:
        return None
    upstream_bucket, _ = classify_url(f"https://{upstream_host}")
    if upstream_bucket not in _TRUSTED_BUCKETS:
        return None
    suffix = upstream_reg.rsplit(".", 1)[-1]
    limit = 1 if len(upstream_reg) < 8 else 2
    for url in added:
        if source_buckets.get(url, "unknown") in _TRUSTED_SOURCE_BUCKETS:
            continue
        source_reg = _registered_domain(_url_domain(url))
        if not source_reg or source_reg == upstream_reg:
            continue
        if source_reg.rsplit(".", 1)[-1] != suffix:
            continue
        distance = _damerau_levenshtein(source_reg, upstream_reg, limit)
        if 1 <= distance <= limit:
            return url, source_reg, upstream_reg, distance
    return None


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
    # does leave the source unbacked.
    if cs_behavior not in ("checksum_added_or_changed", "checksum_entry_removed"):
        http_sources = [url for url in added if url.startswith("http://")]
        if http_sources:
            add("H003", "Insecure Download Protocol", "LOW", "integrity",
                f"http:// sources without checksum backing: {http_sources}",
                line=find_line_in_diff(diff_text, r"http://"),
                http_sources=", ".join(http_sources))

    if cs_behavior == "changed_from_sha256_to_skip":
        skip_reason = is_skip_justified(diff_text)
        suffix = f" ({skip_reason})" if skip_reason else ""
        add("H001", "Checksum Disabled", "INFO" if skip_reason else "HIGH", "integrity",
            f"sha256sums=SKIP ({skip_reason})" if skip_reason else "sha256sums=SKIP",
            line=find_line_in_diff(diff_text, r"SKIP|NONE"),
            skip_suffix=suffix)
    elif cs_behavior == "checksum_array_emptied":
        add("H002", "Checksum Emptied", "HIGH", "integrity", cs_behavior,
            line=find_line_in_diff(diff_text, r"sha256sums\s*=\s*\(\s*\)"))

    # H091 - makepkg pairs `source=()` with each `*sums=()` by position,
    # and no rule looked at the two lengths together. A source slipped in
    # beside a checksum list nobody recounted scored nothing but priors.
    parity = checksum_array_parity(diff_text)
    if parity is None and current_text and source_array_grew_in_diff(diff_text):
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

    # C014 (spec §6, re-filed from H099 per Addendum 3): a checksum array
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

    # C015 (spec §7, re-filed from H100 per Addendum 3): a fetch in
    # package().  Sources belong in prepare/build, where the checksum
    # arrays apply; fetching at artifact-assembly time bypasses that
    # accounting.  Reads RecipeDoc.functions only - the whole body, never a
    # line walk.  (H076 already owns the write-outside-$pkgdir half of §7
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

    # C016/C017 (spec §9, re-filed from H102/H103 per Addendum 3): a
    # complete .install script's hook bodies, read as functions.
    if scope_doc is not None:
        findings.extend(install_script_findings(scope_doc))
        # Addendum 5 §7: the L1 structural rules over the typed DiffFile
        # metadata (mode, rename) and empty-file shape.
        diff_structure_findings(scope_doc, add)

    # Addendum 4: G1/G3/G4/G5/G6/G7 predicates over the same parse.
    addendum4_findings(diff_text, scope_doc, scope_pre, scope_post,
                       source_changes, config or {}, add)

    # Addendum 5 §6.3: the E-series entropy predicates.  Silent until their
    # thresholds are configured (they ship empty).
    from .entropy import entropy_findings

    entropy_findings(diff_text, config or {}, add)

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
        name, old_url, new_url, span = lost[0]
        add("H101", "Source Pinning Lost", "MEDIUM", "integrity",
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
        add("C004", "Checksum Removed For Unchanged Source", "CRITICAL", "integrity",
            "checksum array deleted while source URLs stayed the same"
            if cs_behavior == "checksum_array_removed" else
            "checksum entry removed while source URLs stayed the same",
            line=find_line_in_diff(diff_text, r"sha256sums", prefix=r"\-"))

    for url in added:
        if _BINARY_ARTIFACT_RE.search(url) and source_buckets.get(url) not in _TRUSTED_BUCKETS:
            bucket = source_buckets.get(url, "unknown")
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
    if package_name.endswith(_PREBUILT_SUFFIX) and added:
        upstream_host = _head_upstream_host(diff_text, current_text)
        if upstream_host:
            divergence = _prebuilt_host_divergence(
                added, source_buckets, package_name, upstream_host,
                _source_divergence_allow(config),
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
    )
    _build_findings(diff_text, config or {}, add, current_text=current_text)
    _sudo_findings(diff_text, config or {}, add, current_text=current_text)
    _build_flag_findings(diff_text, config or {}, add)
    _function_shadow_findings(diff_text, config or {}, add)
    _reconstruction_findings(diff_text, config or {}, add)
    _signing_key_findings(diff_text, add)
    _indirect_remote_execution_findings(diff_text, config or {}, add)
    _indirect_expansion_findings(diff_text, config or {}, add)
    _delivery_findings(
        diff_text, config or {}, add, tree_manifest=tree_manifest,
        current_text=current_text,
    )
    _persistence_findings(diff_text, config or {}, add, current_text=current_text)
    _recon_findings(diff_text, config or {}, add, current_text=current_text)
    _exotic_protocol_findings(diff_text, config or {}, add)
    _version_in_url_findings(diff_text, config or {}, add)
    _parse_time_fetch_findings(diff_text, config or {}, add)
    _dlagents_override_findings(diff_text, config or {}, add)
    _paste_egress_findings(diff_text, config or {}, add)
    # H033 asks the current file which variable feeds a git ref; the diff
    # alone shows only the hunk around the pin.
    _moved_git_ref_findings(diff_text, config or {}, add, current_text=current_text)
    _covert_egress_findings(diff_text, config or {}, add)
    _epoch_findings(diff_text, config or {}, add, whole_recipe=whole_recipe)
    # H056 reads the current file where the caller has it: an indicator that
    # predates this diff is still a fact about the package being reviewed.
    _ioc_findings(diff_text, package_name, config or {}, add,
                  current_text=current_text)

    return findings


#: C015's matcher: a fetch client at a command position, so a client name
#: inside a quoted dependency list or a comment is not a fetch.  The
#: interpreter arm additionally requires a scheme-bearing address on the
#: line, because `python -m pip install .` installs the local source.
_FETCH_IN_PACKAGE_RE = re.compile(
    r"(?:^|[;&|(])\s*(?:" + NETWORK_CLIENT + r")\b",
    re.IGNORECASE | re.MULTILINE,
)
_INTERPRETER_FETCH_RE = re.compile(_INTERPRETER_FETCH, re.IGNORECASE)
#: Scheme markers as substrings.  A regex that hunts for a scheme is
#: retried from every position on a hostile full-length line (the regex
#: audit measures exactly that); the substring check is linear and exact
#: for the question asked ("is there an address on this line").
_SCHEME_MARKERS = ("://", "magnet:", "ipfs:", "ipns:")


def _line_has_scheme(line: str) -> bool:
    lowered = line.lower()
    return any(marker in lowered for marker in _SCHEME_MARKERS)


def _package_fetch_client(body: str) -> str | None:
    """The first fetch command in a function body, or ``None``.

    Command-position only (see the regexes above); an assignment whose
    value is literal data is skipped, while a command substitution
    (``x=$(curl ...)``) is still a fetch.
    """
    for raw_line in split_lines(body):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if (re.match(r"(?:export\s+|local\s+)?[A-Za-z_]\w*\s*\+?=", stripped)
                and "$(" not in stripped and "`" not in stripped):
            continue
        match = _FETCH_IN_PACKAGE_RE.search(raw_line)
        if match:
            return match.group(0).strip()
        interpreter = _INTERPRETER_FETCH_RE.search(raw_line)
        if interpreter and _line_has_scheme(raw_line):
            return interpreter.group(0)
    return None


#: The checksum arrays makepkg reads, without their arch suffixes.
_CHECKSUM_ARRAY_NAMES = frozenset({
    "md5sums", "sha1sums", "sha224sums", "sha256sums", "sha384sums",
    "sha512sums", "b2sums",
})


def _is_checksum_array(name: str) -> bool:
    return (name in _CHECKSUM_ARRAY_NAMES
            or name.split("_", 1)[0] in _CHECKSUM_ARRAY_NAMES)


def _skip_positions(entries) -> set[int]:
    return {
        index for index, entry in enumerate(entries)
        if entry.strip().upper() in ("SKIP", "NONE")
    }


def _require_content_change(config) -> bool:
    """The ``c014.require_content_change`` gate (spec §6; ``h099`` alias)."""
    thresholds = (config or {}).get("thresholds", {})
    section = thresholds.get("c014") or thresholds.get("h099") or {}
    return bool(section.get("require_content_change", True))


def array_order_changes(diff_text: str, config: dict | None = None,
                        pre=None, post=None):
    """Checksum arrays whose entries moved, with delta and span (spec §6).

    Returns ``[(array_name, ArrayDelta, span)]``.  Ordering facts come from
    the typed recipe arrays (positions are preserved there); the rule never
    re-reads diff text.  A reorder with no content change and no SKIP
    movement is reformatting, so the default gate stands it down.
    """
    from ..recipedoc import array_diff, recipe_states

    if pre is None or post is None:
        try:
            pre, post = recipe_states(parse_diff_lines(split_lines(diff_text)))
        except Exception:
            return []
    require_content = _require_content_change(config)
    names = {name for name in pre.arrays if _is_checksum_array(name)}
    names |= {name for name in post.arrays if _is_checksum_array(name)}
    changes = []
    for name in sorted(names):
        old = pre.arrays.get(name, ())
        new = post.arrays.get(name, ())
        delta = array_diff(old, new)
        if not delta.reordered:
            continue
        content_changed = bool(delta.gained or delta.lost)
        skip_moved = _skip_positions(old) != _skip_positions(new)
        if require_content and not (content_changed or skip_moved):
            continue
        spans = post.array_spans.get(name) or pre.array_spans.get(name) or ()
        changes.append((name, delta, spans[0] if spans else None))
    return changes


#: Addendum 4: checksum strength order, strongest first.
_CHECKSUM_STRENGTH = ("b2sums", "sha512sums", "sha256sums", "sha1sums",
                      "md5sums")
_HARDENING_OPTIONS = frozenset(
    {"!strip", "!debug", "!lto", "!fortify", "!debugsplit"})


def _family_values(arrays, base: str) -> tuple[str, ...]:
    """Every ``base``/``base_<arch>`` array's entries, concatenated."""
    out: list[str] = []
    for key in sorted(arrays):
        if key == base or key.startswith(base + "_"):
            out.extend(arrays[key])
    return tuple(out)


def _removed_declarations(doc) -> set[str]:
    """Array names whose declaration line is removed and not re-added."""
    if doc is None:
        return set()
    removed: set[str] = set()
    added: set[str] = set()
    for line in doc.lines:
        match = re.match(r"\s*([A-Za-z_]\w*)\s*\+?=", line.content)
        if not match:
            continue
        if line.side == "remove":
            removed.add(match.group(1))
        elif line.side == "add":
            added.add(match.group(1))
    return removed - added


def _url_host(url: str) -> str:
    from ..buckets import canonical_host

    if "://" not in url:
        return ""
    return canonical_host(url.split("://", 1)[1].split("/", 1)[0])


def _userinfo_urls(urls) -> list[str]:
    """URLs carrying userinfo before the host (credentials in a source)."""
    return [url for url in urls if "://" in url
            and "@" in url.split("://", 1)[1].split("/", 1)[0]]


def _ip_literal_hosts(hosts) -> list[str]:
    import ipaddress

    out: list[str] = []
    for host in hosts:
        try:
            ipaddress.ip_address(host.strip("[]"))
        except ValueError:
            continue
        out.append(host)
    return out


def addendum4_findings(diff_text, scope_doc, pre, post, source_changes,
                       config, add) -> None:
    """G1/G3/G4/G5/G6/G7 predicates over the typed core (Addendum 4)."""
    from ..recipedoc import array_diff

    # G1 (C020): credentials embedded in a gained source URL.  The value
    # itself is never printed - evidence shows the host only.
    if _userinfo_urls(source_changes.added_urls):
        hosts = []
        for url in _userinfo_urls(source_changes.added_urls):
            host = _url_host(url)
            if host and host not in hosts:
                hosts.append(host)
        add("C020", "Credentials In A Source URL", "HIGH", "source",
            "gained source URL(s) carry embedded credentials for "
            + ", ".join(hosts),
            line=find_line_in_diff(diff_text, r"://[^/\s'\"]*@"),
            hosts=", ".join(hosts))

    # G6 (C024): an added/modified .install no install= declaration names.
    if scope_doc is not None:
        declared = post.scalars.get("install", "") if post is not None else ""
        if not declared:
            for file in scope_doc.files:
                if file.path.endswith(".install") and file.status != "removed":
                    add("C024", "Install Script Not Declared", "MEDIUM",
                        "composition",
                        f"{file.path} is shipped but install= does not name "
                        "it; pacman never runs the hook",
                        file=file.path, line=None)
                    break

    if pre is None or post is None:
        return

    # G3 (C021): a test/dependency array removed while a build function
    # changed - dropping the checks that would catch a payload.
    for name in ("checkdepends", "optdepends"):
        lost = array_diff(_family_values(pre.arrays, name),
                          _family_values(post.arrays, name)).lost
        if not lost:
            continue
        touched = any(
            pre.functions.get(fn) != post.functions.get(fn)
            for fn in ("build", "prepare", "check")
        )
        if touched:
            add("C021", "Dependency Removal During A Build Change", "MEDIUM",
                "composition",
                f"{name} lost {', '.join(sorted(set(lost))[:3])} while a "
                "build function changed",
                line=None, field=name, lost=", ".join(sorted(set(lost))[:5]))

    # G4 (C022): verification downgraded to a weaker algorithm.  The
    # strongest array must be *declared removed in this diff* (a partial
    # post projection that simply does not show it is not a removal), and
    # a strictly weaker array must remain.
    present = {base: _family_values(pre.arrays, base)
               for base in _CHECKSUM_STRENGTH}
    post_present = {base: _family_values(post.arrays, base)
                    for base in _CHECKSUM_STRENGTH}
    removed_names = _removed_declarations(scope_doc)
    strongest = next((base for base in _CHECKSUM_STRENGTH if present[base]), None)
    strongest_gone = strongest is not None and (
        strongest in removed_names
        or (strongest in post.arrays and not post_present[strongest])
    )
    if strongest is not None and strongest_gone:
        weaker = [base for base in _CHECKSUM_STRENGTH
                  if base != strongest and post_present[base]]
        # Stands down when every array was removed together: H002 owns it.
        if weaker and any(post_present.values()):
            add("C022", "Checksum Strength Downgraded", "HIGH", "integrity",
                f"{strongest} removed or emptied while "
                f"{', '.join(weaker)} remains",
                line=None, lost=strongest, retained=", ".join(weaker))

    # G5 (C023): a gained host that is a bare IP literal.
    literal_hosts = _ip_literal_hosts(
        sorted({_url_host(url) for url in source_changes.added_urls} - {""}))
    if literal_hosts:
        add("C023", "IP-Literal Source Host", "MEDIUM", "source",
            "gained source host(s) are IP literals: "
            + ", ".join(literal_hosts[:3]),
            line=None, hosts=", ".join(literal_hosts[:5]))

    # G7 (C025): a hardening option gained.
    gained_options = array_diff(
        pre.arrays.get("options", ()), post.arrays.get("options", ())).gained
    hardening = sorted(set(gained_options) & _HARDENING_OPTIONS)
    if hardening:
        add("C025", "Hardening Option Disabled", "LOW", "build",
            "options gained hardening-disabling entries: "
            + ", ".join(hardening),
            line=None, options=", ".join(hardening))


#: A hook that runs an interpreter or a shell explicitly.  Command-position
#: anchored, so `install -m` and a quoted word cannot match.
_HOOK_INTERPRETER_RE = re.compile(
    r"(?:^|[;&|(])\s*(?:/(?:usr/)?bin/)?"
    r"(?:ba|z|da|k|a|mk|pdk|ya|po)?sh\b(?!\s*[=<])"
    r"|(?:^|[;&|(])\s*(?:/(?:usr/)?bin/)?"
    r"(?:python[23]?|perl|ruby|node|php)\b",
    re.IGNORECASE | re.MULTILINE,
)

#: User-writable or temporary locations a root hook has no business
#: writing to (spec §9, re-filed from H103).
_XDG_PREFIX_RE = re.compile(r"^\$?\{?XDG_[A-Z_]+\}?(?:/|$)")
_RUNTIME_USER_RE = re.compile(r"^/run/user/")
#: Root's home, spelled absolutely: a hook running as root writing into
#: ``/root/.config`` is the same shape as ``$HOME``.
_ROOT_HOME_RE = re.compile(r"^/root(?:/|$)")


def _user_writable_target(target: str) -> bool:
    value = target.strip().strip("\"'")
    return bool(
        _HOME_PREFIX_RE.match(value)
        or _WW_DIR_RE.match(value)
        or _XDG_PREFIX_RE.match(value)
        or _RUNTIME_USER_RE.match(value)
        or _ROOT_HOME_RE.match(value)
    )


def _hook_names(recipe) -> list[str]:
    return [
        name for name in recipe.functions
        if name.endswith(("_install", "_upgrade", "_remove"))
    ]


def partial_install_files(diff_text: str) -> list[str]:
    """Install-script files whose diff is not the whole file (spec §9).

    Added files are complete by construction.  A modified file counts as
    complete only when its first hunk starts at line 1 and no hunk was cut
    (``DiffDoc.cut_hunks``); anything else is a fragment, and the hook
    rules must not read it as a whole script.
    """
    try:
        doc = parse_diff_lines(split_lines(diff_text))
    except Exception:
        return []
    cuts = {path for path, *_rest in doc.cut_hunks()}
    partial: list[str] = []
    for file in doc.files:
        if not file.path.endswith(".install") or file.status == "removed":
            continue
        if file.status == "added":
            continue
        if not file.hunks or file.hunks[0].new_start != 1 or file.path in cuts:
            partial.append(file.path)
    return partial


def install_script_findings(doc) -> list[dict]:
    """C016/C017 over complete ``.install`` scripts (spec §9, re-filed).

    The file's post-state text is read as a ``RecipeDoc``; every hook body
    is a function.  Findings attribute to the ``.install`` file and its own
    line numbers via the recipe's spans.  A partial file is skipped here:
    :func:`partial_install_files` declares it as a coverage gap instead.
    """
    cuts = {path for path, *_rest in doc.cut_hunks()}
    out: list[dict] = []
    for file in doc.files:
        if not file.path.endswith(".install") or file.status == "removed":
            continue
        if (file.status != "added"
                and (not file.hunks or file.hunks[0].new_start != 1
                     or file.path in cuts)):
            continue
        text = "\n".join(
            line.content for line in doc.lines
            if line.file == file.path and line.side in ("add", "context")
        )
        origins = [
            (line.file, line.new_lineno or 0, line.side)
            for line in doc.lines
            if line.file == file.path and line.side in ("add", "context")
        ]
        try:
            recipe = parse_recipe(text, origins=origins)
        except Exception:
            continue
        for name in _hook_names(recipe):
            body = recipe.functions.get(name, "")
            if not body:
                continue
            span = recipe.function_spans.get(name)
            match = _HOOK_INTERPRETER_RE.search(body)
            if match:
                out.append(stamp({
                    "rule_id": "C016",
                    "name": "Interpreter Invocation In Install Hook",
                    "severity": "HIGH", "category": "execution",
                    "match": f"{name}() invokes '{match.group(0).strip()}'; "
                             "a hook runs as root at pacman time",
                    "file": span.file if span else file.path,
                    "line": span.line if span else None,
                    "params": {"hook": name, "interpreter": match.group(0).strip()[:40]},
                }))
            for raw_line in split_lines(body):
                for target in _raw_targets(strip_comment(raw_line)):
                    if _user_writable_target(target):
                        out.append(stamp({
                            "rule_id": "C017",
                            "name": "Install Hook Writes To A User-Writable Location",
                            "severity": "HIGH", "category": "persistence",
                            "match": f"{name}() writes to {target.strip()}; "
                                     "the hook runs as root",
                            "file": span.file if span else file.path,
                            "line": span.line if span else None,
                            "params": {"hook": name, "path": target.strip()[:80]},
                        }))
                        break
    return out


#: Git's executable file mode.  A committed file carrying it can be run
#: directly from the source tree; the structural twin of the artifact-side
#: mode check (Addendum 5 §12, A-MODE).
_EXECUTABLE_MODE = "100755"


def diff_structure_findings(doc, add) -> None:
    """C-MODE / C-RENAME / C-EMPTY over typed ``DiffFile`` metadata (§7).

    Three L1 projections of the parse, with no new walker: an added file
    with the executable bit, any declared rename, and an added file with no
    hunks (a marker or placeholder drop).  A finding carries the file it
    concerns; none of these three has a single line to attribute.
    """
    for file in doc.files:
        if file.status == "added" and file.new_mode == _EXECUTABLE_MODE:
            add("C018", "Executable File Committed", "MEDIUM", "integrity",
                f"{file.path} is added with the executable bit set",
                file=file.path)
        if file.renamed:
            add("C019", "File Renamed", "INFO", "integrity",
                f"{file.rename_from or '?'} renamed to "
                f"{file.rename_to or file.path}",
                file=file.path,
                old_path=file.rename_from, new_path=file.rename_to or file.path)
        if file.status == "added" and not file.hunks:
            add("C026", "Empty File Added", "INFO", "integrity",
                f"{file.path} is added with no content",
                file=file.path)


def capability_in_diff(diff_text: str, current_text: str | None = None) -> str | None:
    """A new fetch or non-source execution added in a critical function.

    F8's predicate: a version bump that also starts downloading or running
    something is not the benign checksum refresh C002 describes.  Returns a
    short description, or ``None`` when the diff adds no such capability.
    """
    import os

    from .delivery import (
        _BUILD_FUNCTIONS,
        _H072_BENIGN_EXEC,
        _collect_executions,
        _declared_source_basenames,
        _FETCH_CLIENT_RE,
        _recipe_lines,
        resolve_added_lines,
    )
    from ..line_lex import strip_comment
    from ..rules import ScopeResolver

    lines = resolve_added_lines(diff_text)
    scopes = ScopeResolver(lines, _recipe_lines(current_text))
    source_basenames = _declared_source_basenames(diff_text, current_text)
    for i, line in enumerate(lines):
        fn = scopes.within(i, _BUILD_FUNCTIONS)
        if not line.startswith("+") or fn is None:
            continue
        body = strip_comment(line[1:])
        client = _FETCH_CLIENT_RE.search(body)
        if client:
            return f"a network fetch ({client.group(0)[:40]})"
        for path in _collect_executions(body):
            base = os.path.basename(path)
            # Only a *script-like* execution is a capability: `python -m
            # unittest` in a newly added check() is ordinary test
            # infrastructure, while `bash stage.sh` / `escript f.erl` is a
            # file being run.  A module name has no dot and no path.
            if "." not in base and "/" not in path:
                continue
            if base and base not in _H072_BENIGN_EXEC \
                    and base not in source_basenames:
                return f"an execution of {path}"
    return None


def recipe_checksum_parity_finding(recipe_text: str) -> dict | None:
    """H091 for a first-seen recipe, which has no diff to read arrays from.

    A new package is exactly where a source slipped in beside a checksum
    list nobody recounted is least likely to be noticed, and the fresh
    analysis path ran no integrity rule at all.
    """
    if not recipe_text:
        return None
    parity = checksum_array_parity_in_text(recipe_text)
    if parity is None:
        return None
    n_src, n_sum, var = parity
    return stamp({
        "rule_id": "H091", "name": "Checksum Array Shorter Than Source Array",
        "severity": "HIGH", "category": "integrity",
        "match": f"{n_src} sources declared against {n_sum} {var} entries",
        "file": "PKGBUILD", "line": None,
        "params": {"sources": n_src, "sums": n_sum, "var": var},
    })
