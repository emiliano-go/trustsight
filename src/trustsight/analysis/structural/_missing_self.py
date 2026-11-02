"""The missing-self axis: what a recipe stopped proving about itself.

The corpus is mostly "a foreign antigen is present".  These predicates watch
the opposite direction: a verification surface that was there and is now
gone, a source slot that lost TLS, a recipe whose prose was gutted, and a
generated metadata file that no longer agrees with its recipe.

Every function here returns findings through the structural engine's
``add`` callback.  They are pure-diff: no fetch, no execution, no history
read.  Existing rules own the aggregate cases (H024 whole-key removal, H091
short checksums, H001 SKIP, C004 removed arrays, H019 exact URL downgrade);
the rules below stand down when one of those owns the shape, so the axis is
complementary rather than a second score for the same change.
"""

from __future__ import annotations

import re
from itertools import islice
from urllib.parse import urlsplit

from ...buckets import canonical_host, host_is_non_routable
from ...deps import _strip_comment
from ...rules import find_line_in_diff

#: Bound every list read from a parsed recipe.  The tokenizer already caps
#: input, but these helpers are also called directly by tests and callers.
MAX_ARRAY_ENTRIES = 5_000
MAX_URL_CHARS = 4_096
MAX_SRCINFO_BYTES = 4 * 1024 * 1024

__all__ = [
    "comment_deletion_findings",
    "missing_self_findings",
    "scheme_downgrade_findings",
    "srcinfo_version_findings",
    "vouch_surface_findings",
]

#: A comment in a recipe, whole-line or trailing.  Inline prose is what a
#: reviewer reads beside the code, so deleting it is the same loss C033
#: claims; only a `#` inside quotes is data.
def _is_comment(line: str) -> bool:
    if not isinstance(line, str) or not line.strip():
        return False
    return _strip_comment(line).rstrip() != line.rstrip()


def _array_values(values) -> list[str]:
    """A bounded, string-only view of one recipe array."""
    if isinstance(values, str):
        return [values]
    try:
        items = list(islice(values or (), MAX_ARRAY_ENTRIES))
    except (TypeError, ValueError):
        return []
    return [str(value) for value in items]


def _threshold(config, section: str, key: str, default):
    """Read *key* from config thresholds, then thresholds.toml, then default."""
    table = ((config or {}).get("thresholds", {}) or {}).get(section, {}) or {}
    if key in table:
        return table[key]
    try:
        from ...config import load_thresholds

        loaded = (load_thresholds().get(section, {}) or {})
        if key in loaded:
            return loaded[key]
    except Exception:  # noqa: BLE001 - a missing file is the default
        pass
    return default


def vouch_surface_findings(diff_text: str, scope_pre, scope_post, add,
                           config=None) -> None:
    """T004: a ``validpgpkeys`` entry was removed with nothing gained.

    H024 owns the whole-array removal and T003/H078 own a rotation, so this
    fires only on the gap: at least one key removed, none added, and at least
    one key still declared.  Checksum surfaces are deliberately not repeated
    here (H091/H001/C004 own them); the rule page names those stand-downs.
    """
    if scope_pre is None or scope_post is None:
        return
    try:
        pre_arrays = scope_pre.arrays or {}
        post_arrays = scope_post.arrays or {}
    except AttributeError:
        return
    before = set(_array_values(pre_arrays.get("validpgpkeys", ())))
    after = set(_array_values(post_arrays.get("validpgpkeys", ())))
    if not before:
        return  # missing from birth is not decay
    lost = before - after
    try:
        floor = int(_threshold(config, "t004", "min_removed_keys", 1))
    except (TypeError, ValueError):
        floor = 1
    if len(lost) < max(1, floor):
        return
    # A whole-array removal is H024's; a widening (more keys than before) is
    # not a loss.  A one-for-one "rotation" is deliberately *not* excused:
    # adding a decoy fingerprint alongside a real one is the cheap way to
    # hide a vouch-surface removal, and T004 cannot tell a real rotation from
    # a decoy offline.  Rotation still reports; the reviewer sees the keys.
    if not after or len(after) > len(before):
        return
    add(
        "T004", "Vouch Surface Removed", "MEDIUM", "temporal",
        f"validpgpkeys lost {len(lost)} key(s) with no replacement; "
        f"{len(after)} key(s) remain",
        line=find_line_in_diff(diff_text, r"validpgpkeys"),
        removed=len(lost), remaining=len(after),
    )


def _url_of(entry: str) -> str | None:
    """The URL inside a source entry, ``name::url`` accepted."""
    text = str(entry or "").strip()[:MAX_URL_CHARS]
    if "::" in text:
        text = text.split("::", 1)[1]
    if "://" not in text:
        return None
    return text


def _source_arrays(scope) -> dict[str, tuple[str, ...]]:
    if scope is None:
        return {}
    try:
        arrays = scope.arrays or {}
    except AttributeError:
        return {}
    return {
        str(name): _array_values(values)
        for name, values in arrays.items()
        if str(name) == "source" or str(name).startswith("source_")
    }


def scheme_downgrade_findings(scope_pre, scope_post, add) -> None:
    """T005: the same source host downgraded TLS while the path also changed.

    H019 owns the exact ``https://x`` -> ``http://x`` swap.  This covers the
    quieter shape it misses: the URL moved (new version, new filename) and
    the scheme fell with it.  Positional pairing is bounded by the shorter
    array, so a deleted or inserted entry is never guessed across.
    """
    pre = _source_arrays(scope_pre)
    post = _source_arrays(scope_post)

    def by_host(values: list[str], scheme: str) -> dict[str, list[str]]:
        """HTTPS/HTTP URLs grouped by canonical host, in array order.

        Pairing by position across the whole array let an inserted decoy
        shift every later entry and hide a downgrade.  Grouping by the host
        the downgrade keeps is stable under an insertion on another host.
        """
        out: dict[str, list[str]] = {}
        for raw in values:
            url = _url_of(raw)
            if not url or not url.lower().startswith(scheme):
                continue
            try:
                host = canonical_host(urlsplit(url).hostname or "")
            except (TypeError, ValueError):
                continue
            if not host or host_is_non_routable(host):
                continue
            out.setdefault(host, []).append(url)
        return out

    seen: set[tuple[str, str]] = set()
    for name in sorted(set(pre) & set(post)):
        before_hosts = by_host(pre[name], "https://")
        after_hosts = by_host(post[name], "http://")
        for host in sorted(set(before_hosts) & set(after_hosts)):
            for before, after in zip(before_hosts[host], after_hosts[host]):
                if after == before.replace("https://", "http://", 1):
                    continue  # H019 owns the exact downgrade
                # No path/query equality escape: a fragment-only edit is
                # still a TLS downgrade, and H019 does not claim it because
                # the URL is not identical.
                key = (name, host)
                if key in seen:
                    continue
                seen.add(key)
                add(
                    "T005", "Scheme Downgrade", "MEDIUM", "temporal",
                    f"{name} moved from https to http on {host} while the "
                    "URL changed; the old URL was never plain http",
                    host=host, array=name, before=before[:80], after=after[:80],
                )


def comment_deletion_findings(diff_doc, add, config=None) -> None:
    """C033: a diff deletes a large fraction of the recipe's comment prose.

    Honest edits rarely gut prose wholesale.  A comment-gutting campaign
    shrinks what a reviewer reads without touching the payload.  The ratio
    and the absolute floor are config-pinned and corpus-adjudicated; a
    one-line comment deletion is never a finding.

    The rule is pure-diff and deliberately does not read history, so a
    deletion split across several diffs can stay under the absolute floor.
    That is a documented threshold limit, not a claim that the recipe was
    not gutted; the ratio still reports every diff that crosses the floor.
    """
    if diff_doc is None:
        return
    try:
        min_ratio = float(_threshold(
            config, "c033", "min_deleted_comment_ratio", 0.50))
        min_lines = int(_threshold(
            config, "c033", "min_deleted_comment_lines", 8))
    except (TypeError, ValueError):
        min_ratio, min_lines = 0.50, 8
    min_ratio = min(1.0, max(0.0, min_ratio))
    min_lines = max(1, min_lines)
    try:
        pre_lines = diff_doc.pre_lines()
        diff_lines = diff_doc.lines
    except (AttributeError, TypeError):
        return
    before = [line for line in pre_lines if _is_comment(line)]
    deleted = [
        line.content for line in diff_lines
        if getattr(line, "side", "") == "remove"
        and _is_comment(getattr(line, "content", ""))
    ]
    if len(deleted) < min_lines or not before:
        return
    ratio = len(deleted) / len(before)
    if ratio < min_ratio:
        return
    add(
        "C033", "Context Bleed", "MEDIUM", "integrity",
        f"{len(deleted)} of {len(before)} pre-existing comment line(s) "
        f"removed ({ratio:.0%}); the recipe's prose shrank",
        deleted=len(deleted), before=len(before), ratio=round(ratio, 4),
    )


def _srcinfo_from_manifest(manifest) -> str:
    try:
        entries = list(islice(manifest or (), MAX_ARRAY_ENTRIES))
    except (TypeError, ValueError):
        return ""
    for entry in entries:
        try:
            path, content = entry
        except (TypeError, ValueError):
            continue
        if str(path).rsplit("/", 1)[-1] != ".SRCINFO":
            continue
        try:
            raw = content[:MAX_SRCINFO_BYTES]
            return raw.decode("utf-8", "replace")
        except (AttributeError, TypeError):
            return str(content)[:MAX_SRCINFO_BYTES]
    return ""


def _srcinfo_from_diff(diff_text: str) -> str:
    """The post-image version fields from an added/changed .SRCINFO.

    The tree manifest is unavailable on the diff-only (watcher) path.  A
    diff that touches .SRCINFO still carries the new version line, which is
    enough for the INFO drift comparison; an unchanged .SRCINFO cannot
    introduce drift, so its absence is not a blind spot for this rule.
    """
    path = ""
    fields: dict[str, str] = {}
    for raw in str(diff_text or "").splitlines():
        if raw.startswith("+++ "):
            path = raw[4:].strip()
            continue
        if not path.endswith(".SRCINFO") or not raw.startswith("+"):
            continue
        if raw.startswith("+++"):
            continue
        match = re.match(r"\s*(pkgver|pkgrel|epoch)\s*=\s*(\S+)", raw[1:])
        if match:
            fields[match.group(1)] = match.group(2).strip("\"'")
    if not fields:
        return ""
    return "pkgbase = demo\n" + "".join(
        f"\t{key} = {value}\n" for key, value in fields.items())


def srcinfo_version_findings(current_text, tree_manifest, add, diff_text="") -> None:
    """C034: committed ``.SRCINFO`` disagrees with the recipe's version fields.

    H103 compares the fields that change what a build does and deliberately
    leaves ``pkgver``/``pkgrel`` alone: a stale version line is ordinary.
    This reports that ordinary shape as INFO, feed-tier, so a consumer can
    see the metadata drift without calling it suspicious.
    """
    if not current_text or (not tree_manifest and not diff_text):
        return
    srcinfo = _srcinfo_from_manifest(tree_manifest) or _srcinfo_from_diff(diff_text)
    if not srcinfo:
        return
    from ..crossfile import version_metadata_divergence

    divergent = version_metadata_divergence(current_text, srcinfo)
    if not divergent:
        return
    add(
        "C034", "Metadata Inconsistency", "INFO", "maintainer-and-metadata",
        ".SRCINFO and PKGBUILD disagree on " + "; ".join(divergent),
        file=".SRCINFO", line=None, fields=", ".join(divergent),
    )


def missing_self_findings(diff_text: str, diff_doc, scope_pre, scope_post,
                          add, config=None) -> None:
    """Run the pure-diff missing-self predicates in one deterministic order."""
    vouch_surface_findings(diff_text, scope_pre, scope_post, add, config)
    scheme_downgrade_findings(scope_pre, scope_post, add)
    comment_deletion_findings(diff_doc, add, config)
