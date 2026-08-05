"""Phase 3 - network-surface rules (plan §5).

R076/R080/R123 share one question: does the PKGBUILD's declared or
executed network surface carry an injection or a covert channel?  All three
are code rules because each needs more than a regex:

- R076 needs the literal ``pkgver``/``_pkgver`` value and its interpolation
  into a source URL;
- R080 needs the raw source array with its scheme tokens (``git+https://``,
  ``svn://``, ...);
- R123 needs config-driven endpoint and client lists plus command position.

R080 is additive evidence for R089's ``foreign_fetch`` stage and R123 for
its ``exfil`` stage; all three are deliberately quiet so the benign corpus
never cries wolf.
"""

import re

from ..config import (
    DEFAULT_COVERT_EGRESS_CLIENTS,
    DEFAULT_COVERT_EGRESS_ENDPOINTS,
    DEFAULT_SOURCE_SCHEMES,
    load_hosts,
)
from ..deps import _strip_comment
from ..rules import _classify_enclosing_function
from ..tokenizer import resolve_added_lines
from .base import iter_scheme_urls
from .build import _CRITICAL_FUNCTIONS, _INSTALL_HOOKS
from .delivery import _find_line

_SCOPE_FUNCTIONS = frozenset(_CRITICAL_FUNCTIONS) | frozenset(_INSTALL_HOOKS)

_SOURCE_ARRAY_RE = re.compile(r"^\s*source(?:_[a-z0-9_]+)?\s*=\s*\(")
_SOURCE_SCALAR_RE = re.compile(r"^\s*source(?:_[a-z0-9_]+)?\s*=\s*(\S+)")
# URL tokens are found by scanning for "://" (see base.iter_scheme_urls);
# the regex form was quadratic on a line with no scheme at all.
_URL_STOP_CHARS = frozenset(" \t\r\n'\")")

# ---------------------------------------------------------------------------
# Shared: source-array URL tokens
# ---------------------------------------------------------------------------


def _source_url_tokens(diff_text):
    """Yield ``(scheme, url)`` for every scheme:// token on an added source
    line (array or scalar / .SRCINFO form)."""
    in_array = False
    for line in diff_text.splitlines():
        if line.startswith(("+++", "---", "@@")):
            continue
        if line.startswith("-"):
            if in_array and ")" in line:
                in_array = False
            continue
        body = line[1:] if line[:1] == "+" else line
        is_source = bool(_SOURCE_ARRAY_RE.match(body) or _SOURCE_SCALAR_RE.match(body))
        if not in_array and not is_source:
            continue
        for scheme, url in iter_scheme_urls(body, _URL_STOP_CHARS):
            yield scheme, url
        if ")" in body:
            in_array = False


def _hosts(config) -> dict:
    if config and "hosts" in config:
        return config["hosts"]
    return load_hosts().get("hosts", {})


# ---------------------------------------------------------------------------
# R080 - exotic source protocol
# ---------------------------------------------------------------------------


def _source_schemes(config=None) -> frozenset[str]:
    schemes = _hosts(config).get("source_schemes") or DEFAULT_SOURCE_SCHEMES
    return frozenset(s.lower() for s in schemes)


def _exotic_protocol_findings(diff_text, config, add) -> None:
    """A source URL uses a scheme outside the configured allowlist (R080)."""
    allowed = _source_schemes(config)
    for scheme, url in _source_url_tokens(diff_text):
        base = scheme.rsplit("+", 1)[-1].lower()
        if base not in allowed:
            add("R080", "Exotic Source Protocol", "MEDIUM", "network",
                f"source URL uses non-allowlisted scheme {scheme}: {url[:70]}",
                url=url[:70], scheme=scheme)
            return


# ---------------------------------------------------------------------------
# R076 - version-in-URL injection
# ---------------------------------------------------------------------------

_PKGVER_ASSIGN_RE = re.compile(
    r"^\s*(?:(?:local|export|readonly)\s+)?(_?pkgver)\s*=\s*(.+)"
)
# Version characters, per plan §5: anything else in an interpolated value is
# an injection candidate.
_SAFE_VERSION_RE = re.compile(r"^[A-Za-z0-9._+\-]+$")


def _version_in_url_findings(diff_text, config, add) -> None:
    """``pkgver``/``_pkgver`` interpolated into a source URL with a value
    carrying characters outside ``[A-Za-z0-9._+-]`` (R076).

    A literal version like ``1.2.3`` or ``2026.08.01`` is safe.  A value
    containing ``;``, whitespace, ``/`` or other delimiters that is then
    substituted into a fetched URL is an injection vector.
    """
    bad_values: dict[str, str] = {}
    for line in resolve_added_lines(diff_text):
        if not line.startswith("+"):
            continue
        match = _PKGVER_ASSIGN_RE.match(line[1:])
        if not match:
            continue
        name, value = match.group(1), match.group(2).strip()
        value = value.strip("\"'")
        if not _SAFE_VERSION_RE.match(value):
            bad_values[name] = value

    if not bad_values:
        return
    for _, url in _source_url_tokens(diff_text):
        for name, value in bad_values.items():
            braced = re.search(r"\$\{" + re.escape(name) + r"\}", url)
            bare = re.search(r"\$" + re.escape(name) + r"(?![\w])", url)
            if not (braced or bare):
                continue
            add("R076", "Version-In-URL Injection", "MEDIUM", "network",
                f"{name}={value!r} carries injection chars and is "
                f"interpolated into a source URL: {url[:70]}",
                url=url[:70], variable=name, value=value[:40])
            return


# ---------------------------------------------------------------------------
# R123 - covert egress
# ---------------------------------------------------------------------------

_ONION_HOST_RE = re.compile(r"\b[a-z0-9-]+\.(?:onion|i2p)\b", re.IGNORECASE)
_DOH_QUERY_RE = re.compile(r"https?://[^\s'\"\)]*dns-query", re.IGNORECASE)
_DOH_HOST_RE = re.compile(r"https?://([a-z0-9.-]+)/", re.IGNORECASE)


def _covert_clients(config) -> list[re.Pattern]:
    frags = _hosts(config).get("covert_egress_clients") or DEFAULT_COVERT_EGRESS_CLIENTS
    return [
        re.compile(r"(?:\A\s*|[;&|]\s*)(?:" + f + r")", re.IGNORECASE)
        for f in frags
    ]


def _covert_endpoints(config) -> frozenset[str]:
    endpoints = (
        _hosts(config).get("covert_egress_endpoints")
        or DEFAULT_COVERT_EGRESS_ENDPOINTS
    )
    return frozenset(e.lower() for e in endpoints)


def _covert_egress_findings(diff_text, config, add) -> None:
    """.onion/.i2p hosts, DoH endpoints or tunneling clients anywhere they
    have no packaging purpose (R123)."""
    lines = resolve_added_lines(diff_text)
    enclosing = _classify_enclosing_function(lines)
    clients = _covert_clients(config)
    endpoints = _covert_endpoints(config)

    for i, line in enumerate(lines):
        if not line.startswith("+"):
            continue
        body = _strip_comment(line[1:])
        if _ONION_HOST_RE.search(body):
            add("R123", "Covert Egress", "HIGH", "network",
                f"source or command references an onion/i2p host: {body.strip()[:80]}",
                line=_find_line(diff_text, ".onion"), detail=".onion/.i2p host referenced")
            return
        if _DOH_QUERY_RE.search(body):
            add("R123", "Covert Egress", "HIGH", "network",
                f"DoH (DNS-over-HTTPS) query issued: {body.strip()[:80]}",
                line=_find_line(diff_text, "dns-query"), detail="DoH endpoint queried")
            return
        match = _DOH_HOST_RE.search(body)
        if match and match.group(1).lower() in endpoints:
            add("R123", "Covert Egress", "HIGH", "network",
                f"DoH endpoint {match.group(1)} queried: {body.strip()[:80]}",
                line=_find_line(diff_text, match.group(1)[:40]),
                detail=f"DoH endpoint {match.group(1)} queried")
            return

    for i, line in enumerate(lines):
        if not line.startswith("+") or enclosing.get(i) not in _SCOPE_FUNCTIONS:
            continue
        body = _strip_comment(line[1:])
        for client in clients:
            if client.search(body):
                add("R123", "Covert Egress", "HIGH", "network",
                    f"{enclosing[i]}() invokes a tunneling/covert client: "
                    f"{body.strip()[:80]}",
                    position=enclosing[i], body=body.strip()[:80])
                return