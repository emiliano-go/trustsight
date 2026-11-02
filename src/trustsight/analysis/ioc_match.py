"""IOC Federation baseline match stage.

This stage runs after rule matching and produces :class:`IocMatch` objects
that are attached to the :class:`PackageFact` for rendering.  Matches do not
affect the score or appear in ``score_breakdown``; they are contextual
indicators for the reviewer.
"""

from __future__ import annotations

import re

from ..config import load_ioc_sources
from ..deps import extract_dependency_changes
from ..ioc_baseline import (
    IocMatch,
    active_iocs,
    active_patterns,
    match_domains,
    match_file_paths,
    match_hashes,
    match_packages,
)
from .ioc_paths import touched_paths
from .buildfetch import registry_install_names
from .ioc import _HEX_RE, _added_bodies, _digests_in, _hosts_in, _line_of
from ..tokenizer import split_lines

_CHECKSUM_ARRAY_RE = re.compile(
    r"\b(?:sha256sums|sha512sums|md5sums|b2sums)\s*=\s*\(",
    re.IGNORECASE,
)
_DEP_FIELDS = ("depends", "makedepends", "optdepends", "checkdepends",
               "provides", "replaces", "conflicts")


def _as_added(text: str) -> str:
    """Present whole-file text as an all-added diff for scanning."""
    return "\n".join("+" + line for line in split_lines(text))


def _checksum_digests(body: str) -> set[str]:
    """Return hex digests declared inside a checksum array on *body*."""
    digests: set[str] = set()
    for match in _CHECKSUM_ARRAY_RE.finditer(body):
        start = match.end()
        end = body.find(")", start)
        if end == -1:
            end = len(body)
        inner = body[start:end]
        for token in _HEX_RE.finditer(inner):
            digests.add(token.group(1).lower())
    return digests


def _match_body(body: str, diff_text: str, want_domains: bool,
                pattern_hits, source_allowed, add) -> None:
    """Emit baseline matches for one added body."""
    if want_domains:
        hosts: dict[str, str] = {}
        for host, origin in _hosts_in(body):
            hosts.setdefault(host, origin)
        for host, found in match_domains(hosts).items():
            origin = hosts[host]
            for m in found:
                if source_allowed(m.source):
                    surface = "source_host" if origin == "url" else "referenced_host"
                    add(m, surface, _line_of(diff_text, host))

    checksum_digests = {d.lower() for d in _checksum_digests(body)}
    for digest, found in match_hashes(checksum_digests).items():
        for m in found:
            if source_allowed(m.source):
                add(m, "checksum_array", _line_of(diff_text, digest))

    other_digests = {
        digest for digest in _digests_in(body)
        if digest.lower() not in checksum_digests
    }
    for digest, found in match_hashes(other_digests).items():
        for m in found:
            if source_allowed(m.source):
                add(m, "artifact_hash", _line_of(diff_text, digest))

    if pattern_hits and body.strip():
        for entry, compiled in pattern_hits:
            if compiled.search(body):
                add(IocMatch(
                    type=entry.type, value=entry.value, source=entry.source,
                    confidence=entry.confidence, provenance=entry.provenance,
                    campaign=entry.campaign, added=entry.added,
                    surface="added_line",
                    line=_line_of(diff_text, body.strip()[:60]),
                ), "added_line", _line_of(diff_text, body.strip()[:60]))


def ioc_baseline_matches(
    diff_text: str,
    package_name: str,
    current_text: str | None = None,
) -> list[IocMatch]:
    """Return IOC baseline matches for a diff.

    The stage is gated by ``[baselines.ioc] enabled`` and filtered to the
    configured ``sources`` list (empty means all sources).  Domains are
    matched via registered domain; hashes are matched exactly inside checksum
    arrays and anywhere else in the visible text; package names match
    ``pkgname``/``pkgbase`` and declared dependency arrays.
    """
    from ..config import load_config

    config = load_config()
    section = config.get("baselines", {}).get("ioc", {})
    if not section.get("enabled", True):
        return []

    configured_sources = load_ioc_sources()
    scan_text = _as_added(current_text) if current_text else diff_text
    matches: list[IocMatch] = []
    seen: set[tuple[str, str, str]] = set()

    def add(match: IocMatch, surface: str, line: int | None) -> None:
        key = (match.type, match.value, match.source)
        if key in seen:
            return
        seen.add(key)
        matches.append(match.__class__(
            type=match.type,
            value=match.value,
            source=match.source,
            confidence=match.confidence,
            provenance=match.provenance,
            campaign=match.campaign,
            added=match.added,
            surface=surface,
            line=line,
            expired=match.expired,
        ))

    def source_allowed(source: str) -> bool:
        return not configured_sources or source in configured_sources

    active = active_iocs(source=None, expired=False)
    if configured_sources:
        active = [e for e in active if e.source in configured_sources]
    want_packages = any(e.type == "package" for e in active)
    want_domains = any(e.type == "domain" for e in active)
    want_paths = any(e.type == "file_path" for e in active)

    # Package name, pkgbase, dependency arrays and build-time installs: one
    # batched lookup for every name this analysis asks about.
    package_requests: list[tuple[str, str, int | None]] = []
    if package_name:
        package_requests.append(("package_name", package_name, None))
    if current_text:
        pkgbase_match = re.search(r"^\s*pkgbase\s*=\s*['\"]?([^'\"\s]+)", current_text, re.MULTILINE)
        if pkgbase_match:
            package_requests.append(("pkgbase", pkgbase_match.group(1), None))

    declared = extract_dependency_changes(scan_text, package_name)
    for field in _DEP_FIELDS:
        for name in declared.get(field, ()):
            package_requests.append((field, name, _line_of(diff_text, name)))

    # Names a build step installs from a registry.  A `package` indicator
    # otherwise reaches only the AUR package name, pkgbase and the
    # dependency arrays, and the June 2026 campaign named its payload in
    # none of those: `atomic-lockfile` appeared solely as an argument to
    # `npm install` inside prepare(), so a curator's list naming it would
    # have matched nothing at all.
    for _fn, command, name in registry_install_names(scan_text):
        package_requests.append((
            "build_install", name,
            _line_of(diff_text, name) or _line_of(diff_text, command[:40]),
        ))

    # The same surface over the *resolved* lines.  `registry_install_names`
    # reads the raw text, and the wave-3 campaign spelled `bun add` and the
    # package name in ANSI-C quoting, so the literal never appears; the
    # tokenizer resolves it for rule matching but the raw pass cannot see it.
    # Gated on an active package indicator: with none, this is pure cost on a
    # hostile input, which is exactly what the bounded-input gate measures.
    if want_packages:
        resolved = "\n".join("+" + body for body in _added_bodies(scan_text))
        if resolved:
            for _fn, command, name in registry_install_names(resolved):
                package_requests.append((
                    "build_install", name,
                    _line_of(diff_text, name) or _line_of(diff_text, command[:40]),
                ))

    package_hits = match_packages(
        {name for _surface, name, _line in package_requests})
    for surface, name, line in package_requests:
        for m in package_hits.get(name, ()):
            if source_allowed(m.source):
                add(m, surface, line)

    # Domains, hashes, paths and patterns from visible text.
    if want_paths:
        touched = list(touched_paths(diff_text, current_text))
        path_hits = match_file_paths({path for path, _status in touched})
        for path, _status in touched:
            for m in path_hits.get(path, ()):
                if source_allowed(m.source):
                    add(m, "file_path", _line_of(diff_text, path))

    pattern_hits = [
        (entry, compiled)
        for entry, compiled in active_patterns()
        if source_allowed(entry.source)
    ] if any(e.type == "pkgbuild_pattern" for e in active) else []

    for body in _added_bodies(scan_text):
        _match_body(body, diff_text, want_domains, pattern_hits,
                    source_allowed, add)

    return matches
