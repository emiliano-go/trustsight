import re

from ..differ import (
    checksum_array_parity,
    detect_checksum_removed,
    is_skip_justified,
    source_array_has_command_substitution,
)
from .base import (
    _pkgver_changed_in_diff,
    _url_domain,
)
from .crossfire import _crossfire_findings
from .sabotage import _sabotage_findings
from .build import (
    _build_findings,
    _build_flag_findings,
    _indirect_expansion_findings,
    _indirect_remote_execution_findings,
    _reconstruction_findings,
    _sudo_findings,
)
from .composition import _recon_findings
from .delivery import _delivery_findings
from .dependencies import _dependency_findings
from .ioc import _ioc_findings
from .network import (
    _covert_egress_findings,
    _parse_time_fetch_findings,
    _paste_egress_findings,
    _exotic_protocol_findings,
    _moved_git_ref_findings,
    _version_in_url_findings,
)
from .persistence import _persistence_findings
from .version import _epoch_findings
from ..findings import stamp
from ..rules import find_line_in_diff
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
    """The set of keys trusted to sign this package's sources changed (R130).

    ``validpgpkeys`` is the list of key fingerprints whose signature makepkg
    will accept for a signed source.  Whoever holds one of those keys can
    ship code to every user of the package, so the set changing is a trust
    change, and the diff states it as a declared fact.

    R069 owns the *removal* case (verification taken away).  R130 owns the
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
    for line in split_lines(diff_text):
        if line.startswith(("+++", "---", "@@")):
            continue
        side = line[0] if line[:1] in ("+", "-", " ") else " "
        body = line[1:] if line[:1] in ("+", "-", " ") else line
        opens = bool(_VALIDPGPKEYS_LINE_RE.match(body))
        if side == "-" and (opens or in_removed):
            had_keys_before = had_keys_before or bool(_VALIDPGPKEYS_ENTRY_RE.search(body))
            removed_keys |= {m.upper() for m in _VALIDPGPKEYS_ENTRY_RE.findall(body)}
            in_removed = opens and ")" not in body if opens else (")" not in body)
            continue
        if side == "+" and (opens or in_added):
            added_keys |= {m.upper() for m in _VALIDPGPKEYS_ENTRY_RE.findall(body)}
            in_added = opens and ")" not in body if opens else (")" not in body)
            continue
        if side == " ":
            if opens or _VALIDPGPKEYS_ENTRY_RE.search(body) and in_added:
                had_keys_before = had_keys_before or bool(
                    _VALIDPGPKEYS_ENTRY_RE.search(body)
                )
            in_added = in_removed = False

    genuinely_added = added_keys - removed_keys
    genuinely_removed = removed_keys - added_keys
    if not genuinely_added:
        return
    keys = ", ".join(sorted(k[-8:] for k in genuinely_added))
    line_no = find_line_in_diff(diff_text, r"validpgpkeys")
    if genuinely_removed:
        add("R130", "Signing Key Replaced", "HIGH", "integrity",
            f"validpgpkeys now trusts {keys} instead of "
            f"{', '.join(sorted(k[-8:] for k in genuinely_removed))}",
            line=line_no, added_keys=keys,
            removed_keys=", ".join(sorted(k[-8:] for k in genuinely_removed)),
            detail=f"signing key replaced: now {keys}")
    elif had_keys_before:
        add("R130", "Signing Key Added", "MEDIUM", "integrity",
            f"validpgpkeys gained {keys}; another holder may now sign this "
            f"package's sources",
            line=line_no, added_keys=keys,
            detail=f"signing key {keys} added to an existing set")
    else:
        add("R130", "Signature Verification Introduced", "INFO", "integrity",
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
    no version change is the same event R079 already claims for a git ref
    and C001 for a checksum.

    Two carriers had no such claim.  A submodule gitlink names code the
    repository does not contain; an LFS pointer names bytes that are not
    there either.  Moving one is a content change with no content in the
    diff, which is precisely the shape that reads as "nothing happened".

    The version distinguishes the two readings, as it does for R079: an
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


def _structural_findings(
    diff_text: str,
    source_changes,
    source_buckets: dict[str, str] | None = None,
    maintainer_changed: bool = False,
    package_name: str = "",
    config: dict | None = None,
    current_text: str | None = None,
    tree_manifest: list[tuple[str, bytes]] | None = None,
) -> list[dict]:
    source_buckets = source_buckets or {}
    findings: list[dict] = []

    def add(rule_id: str, name: str, severity: str, category: str, match: str, file: str = "PKGBUILD", line: int | None = None, **extra) -> None:
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
    pkgver_changed = _pkgver_changed_in_diff(diff_text)

    if cs_behavior != "checksum_added_or_changed":
        http_sources = [url for url in added if url.startswith("http://")]
        if http_sources:
            add("R006", "Insecure Download Protocol", "LOW", "integrity",
                f"http:// sources without checksum backing: {http_sources}",
                line=find_line_in_diff(diff_text, r"http://"),
                http_sources=", ".join(http_sources))

    if cs_behavior == "changed_from_sha256_to_skip":
        skip_reason = is_skip_justified(diff_text)
        suffix = f" ({skip_reason})" if skip_reason else ""
        add("R004", "Checksum Disabled", "INFO" if skip_reason else "HIGH", "integrity",
            f"sha256sums=SKIP ({skip_reason})" if skip_reason else "sha256sums=SKIP",
            line=find_line_in_diff(diff_text, r"SKIP|NONE"),
            skip_suffix=suffix)
    elif cs_behavior == "checksum_array_emptied":
        add("R005", "Checksum Emptied", "HIGH", "integrity", cs_behavior,
            line=find_line_in_diff(diff_text, r"sha256sums\s*=\s*\(\s*\)"))

    # R147 - makepkg pairs `source=()` with each `*sums=()` by position,
    # and no rule looked at the two lengths together. A source slipped in
    # beside a checksum list nobody recounted scored nothing but priors.
    parity = checksum_array_parity(diff_text)
    if parity is not None:
        n_src, n_sum, var = parity
        add("R147", "Checksum Array Shorter Than Source Array", "HIGH",
            "integrity",
            f"{n_src} sources declared against {n_sum} {var} entries",
            line=find_line_in_diff(diff_text, r"source\s*=\s*\("),
            sources=n_src, sums=n_sum, var=var)

    if cs_behavior == "checksum_added_or_changed" and not added and not removed:
        if not pkgver_changed:
            add("C001", "Checksum Changed Without Source Change With Stable Version",
                "HIGH", "integrity",
                "sha256sums changed but source URLs and pkgver unchanged",
                line=find_line_in_diff(diff_text, r"""sha256sums\s*=\s*\('"""))
        else:
            add("C002", "Checksum Updated With Version Bump", "INFO", "integrity",
                "sha256sums updated alongside pkgver",
                line=find_line_in_diff(diff_text, r"""sha256sums\s*=\s*\('"""))

    if removed and added and not pkgver_changed and set(removed) != set(added):
        add("C003", "Source URL Changed Without Version Bump", "INFO", "integrity",
            f"URLs changed: {removed} -> {added}",
            line=find_line_in_diff(diff_text, r"source(?:_[a-z0-9_]+)?\s*=\s*\("),
            added=str(added), removed=str(removed))

    _unread_carrier_findings(diff_text, pkgver_changed, add)

    if detect_checksum_removed(diff_text) and set(removed) == set(added):
        add("C004", "Checksum Removed For Unchanged Source", "CRITICAL", "integrity",
            "checksum array deleted while source URLs stayed the same",
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

    if source_array_has_command_substitution(diff_text):
        add("C007", "Command Substitution In Source Array", "CRITICAL", "execution",
            "source=() contains $( ) or backtick substitution",
            line=find_line_in_diff(diff_text, r"\$\(|`"))

    _crossfire_findings(diff_text, config or {}, add)
    _sabotage_findings(diff_text, config or {}, add)
    _dependency_findings(diff_text, package_name, config or {}, add)
    _build_findings(diff_text, config or {}, add, current_text=current_text)
    _sudo_findings(diff_text, config or {}, add, current_text=current_text)
    _build_flag_findings(diff_text, config or {}, add)
    _reconstruction_findings(diff_text, config or {}, add)
    _signing_key_findings(diff_text, add)
    _indirect_remote_execution_findings(diff_text, config or {}, add)
    _indirect_expansion_findings(diff_text, config or {}, add)
    _delivery_findings(
        diff_text, config or {}, add, tree_manifest=tree_manifest,
        current_text=current_text,
    )
    _persistence_findings(diff_text, config or {}, add)
    _recon_findings(diff_text, config or {}, add)
    _exotic_protocol_findings(diff_text, config or {}, add)
    _version_in_url_findings(diff_text, config or {}, add)
    _parse_time_fetch_findings(diff_text, config or {}, add)
    _paste_egress_findings(diff_text, config or {}, add)
    # R079 asks the current file which variable feeds a git ref; the diff
    # alone shows only the hunk around the pin.
    _moved_git_ref_findings(diff_text, config or {}, add, current_text=current_text)
    _covert_egress_findings(diff_text, config or {}, add)
    _epoch_findings(diff_text, config or {}, add)
    # R106 reads the current file where the caller has it: an indicator that
    # predates this diff is still a fact about the package being reviewed.
    _ioc_findings(diff_text, package_name, config or {}, add,
                  current_text=current_text)

    return findings
