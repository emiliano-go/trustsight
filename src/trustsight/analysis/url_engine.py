"""The URL-semantics engine: scheme/host/declaration predicates as data.

 consolidates the URL-family rules onto one
``canonical_host``-based query.  This module owns the shared context and the
:data:`URL_INSTANCES` table; the predicates read a diff's source tokens and
the shared ``ChangeDelta`` facts.

Rule ids, severities and finding text are unchanged.  H049 (a
``PropertyBreak`` history rule), H052 (a corpus-sweep cluster) and H092 (a
two-document ``.SRCINFO`` comparison) are not per-diff URL predicates and are
consolidated by the temporal/corpus engines or stay on their own surface.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable

from ..differ import extract_source_array_urls
from ..rules import find_line_in_diff
from ..tokenizer import resolve_added_lines
from .base import _code_rule_enabled
from .network import (
    _declared_dlagent_schemes,
    _source_schemes,
    _source_url_tokens,
)

_PKGVER_ASSIGN_RE = re.compile(
    r"^\s*(?:(?:local|export|readonly)\s+)?(_?pkgver)\s*=\s*(.+)"
)
_SAFE_VERSION_RE = re.compile(r"^[A-Za-z0-9._+\-]+$")


@dataclass
class URLContext:
    """The facts a URL predicate reads, computed once."""

    diff_text: str
    config: dict
    #: The pipeline's source-changes object (added/removed URLs and the
    #: checksum classification); H003 reads it.  Optional so a caller that
    #: only needs the token-scanning predicates can omit it.
    source_changes: object | None = None
    #: Parsed ``(scheme, url)`` source tokens, lazily materialised once.
    _tokens: list | None = field(default=None, repr=False)

    def tokens(self) -> list:
        if self._tokens is None:
            self._tokens = list(_source_url_tokens(self.diff_text))
        return self._tokens


@dataclass(frozen=True)
class URLInstance:
    """One URL rule's predicate row."""

    rule_id: str
    name: str
    predicate: str
    severity: str
    doc: str
    fixtures: tuple[str, ...]
    emitter: Callable[[URLContext, Callable], None]


def emit_insecure_protocol(ctx: URLContext, add: Callable) -> None:
    """H003: an ``http://`` source with no checksum backing."""
    source_changes = ctx.source_changes
    if source_changes is None:
        return
    cs_behavior = source_changes.checksum_behavior
    if cs_behavior in ("checksum_added_or_changed", "checksum_entry_removed"):
        return
    added = source_changes.added_urls
    http_sources = [url for url in added if url.startswith("http://")]
    if http_sources:
        add("H003", "Insecure Download Protocol", "LOW", "integrity",
            f"http:// sources without checksum backing: {http_sources}",
            line=find_line_in_diff(ctx.diff_text, r"http://"),
            http_sources=", ".join(http_sources))


def emit_scheme_downgrade(ctx: URLContext, add: Callable) -> None:
    """H019: a source URL downgraded https -> http."""
    if not _code_rule_enabled(ctx.config, "H019"):
        return
    before = extract_source_array_urls(ctx.diff_text, side="before")
    after = extract_source_array_urls(ctx.diff_text, side="after")
    for url in sorted(before):
        if not url.startswith("https://"):
            continue
        if url.replace("https://", "http://", 1) in after:
            add("H019", "Source URL Downgraded To HTTP", "MEDIUM", "network",
                f"source URL downgraded from https to http: {url[:70]}",
                url=url[:70])
            break


def emit_exotic_protocol(ctx: URLContext, add: Callable) -> None:
    """H034: a source scheme outside the configured allowlist."""
    allowed = _source_schemes(ctx.config) | _declared_dlagent_schemes(ctx.diff_text)
    for scheme, url in ctx.tokens():
        base = scheme.rsplit("+", 1)[-1].lower()
        if base not in allowed:
            add("H034", "Exotic Source Protocol", "MEDIUM", "network",
                f"source URL uses non-allowlisted scheme {scheme}: {url[:70]}",
                url=url[:70], scheme=scheme)
            return


def emit_version_in_url(ctx: URLContext, add: Callable) -> None:
    """H031: a bad ``pkgver`` value interpolated into a source URL."""
    bad_values: dict[str, str] = {}
    for line in resolve_added_lines(ctx.diff_text):
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
    for _, url in ctx.tokens():
        for name, value in bad_values.items():
            braced = re.search(r"\$\{" + re.escape(name) + r"\}", url)
            bare = re.search(r"\$" + re.escape(name) + r"(?![\w])", url)
            if not (braced or bare):
                continue
            add("H031", "Version-In-URL Injection", "MEDIUM", "network",
                f"{name}={value!r} carries injection chars and is "
                f"interpolated into a source URL: {url[:70]}",
                url=url[:70], variable=name, value=value[:40])
            return


#: The per-diff URL predicates.  Order is the dispatch order.
URL_INSTANCES: tuple[URLInstance, ...] = (
    URLInstance("H003", "Insecure Download Protocol", "scheme", "LOW",
                "docs/reference/rules/fetch-and-execution.md",
                ("tests/test_url_acks.py",), emit_insecure_protocol),
    URLInstance("H019", "Source URL Downgraded To HTTP", "scheme_transition",
                "MEDIUM", "docs/reference/rules/fetch-and-execution.md",
                ("tests/test_deps_rules.py",), emit_scheme_downgrade),
    URLInstance("H034", "Exotic Source Protocol", "scheme_allowlist", "MEDIUM",
                "docs/reference/rules/fetch-and-execution.md",
                ("tests/test_network.py",), emit_exotic_protocol),
    URLInstance("H031", "Version-In-URL Injection", "declaration", "MEDIUM",
                "docs/reference/rules/fetch-and-execution.md",
                ("tests/test_network.py",), emit_version_in_url),
)


def run_url_instances(
    ctx: URLContext, add: Callable, *, only: frozenset[str] | None = None
) -> None:
    """Dispatch the URL predicates over *ctx*."""
    for instance in URL_INSTANCES:
        if only is not None and instance.rule_id not in only:
            continue
        instance.emitter(ctx, add)
