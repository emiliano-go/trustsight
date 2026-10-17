"""Extracted from structural.py: _provenance."""

import re
from ...differ import (
    _post_diff_lines,
)
from ..base import _url_domain
from ...diffdoc import parse_diff_lines
from ...tokenizer import split_lines
from ._common import _TRUSTED_BUCKETS

__all__ = ['_PREBUILT_SUFFIX', '_TRUSTED_SOURCE_BUCKETS', '_URL_SCALAR_RE', '_declared_upstream_host', '_declared_upstream_url', '_forge_owner_repo', '_fork_source_divergence', '_head_upstream_host', '_head_upstream_text', '_prebuilt_host_divergence', '_registered_domain', '_source_divergence_allow', '_upstream_domain_typosquat', 'unchanged_upstream_host']

_URL_SCALAR_RE = re.compile(r"^\s*url\s*=\s*['\"]?([^'\"\s]+)", re.MULTILINE)

_PREBUILT_SUFFIX = "-bin"

_TRUSTED_SOURCE_BUCKETS = frozenset(
    {"trusted_forge", "official", "raw_hosting", "homograph_attack",
     "declared_upstream"}
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

    from ...buckets import canonical_host, classify_url

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
    from ...buckets import _extract

    extracted = _extract(host.split(":", 1)[0])
    if extracted.suffix:
        return f"{extracted.domain}.{extracted.suffix}"
    return host

def _source_divergence_allow(config: dict | None) -> frozenset[str]:
    """Registered domains exempted from C011 by the operator."""
    from ...config import DEFAULT_SOURCE_DIVERGENCE_ALLOW

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
    from ...buckets import classify_url
    from ...novelty import _damerau_levenshtein

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
