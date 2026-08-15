"""IOC Federation baseline match stage (v0.12.0 spec §2).

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
    match_domain,
    match_hash,
    match_package,
)
from .buildfetch import registry_install_names
from .ioc import _added_bodies, _digests_in, _hosts_in

_CHECKSUM_ARRAY_RE = re.compile(
    r"\b(?:sha256sums|sha512sums|md5sums|b2sums)\s*=\s*\(",
    re.IGNORECASE,
)
_HEX_RE = re.compile(r"(?<![0-9a-fA-F])([0-9a-fA-F]{32,128})(?![0-9a-fA-F])")

_DEP_FIELDS = ("depends", "makedepends", "optdepends", "checkdepends",
               "provides", "replaces")


def _as_added(text: str) -> str:
    """Present whole-file text as an all-added diff for scanning."""
    return "\n".join("+" + line for line in text.splitlines())


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


def _value_in_body(pattern: str, body: str) -> bool:
    return bool(re.search(pattern, body, re.IGNORECASE))


def _find_line(diff_text: str, needle: str) -> int | None:
    """1-based diff line carrying *needle* on an added line."""
    lowered = needle.lower()
    for i, line in enumerate(diff_text.splitlines()):
        if line.startswith("+") and not line.startswith("+++"):
            if lowered in line.lower():
                return i + 1
    return None


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

    # Package name and pkgbase.
    if package_name:
        for m in match_package(package_name):
            if source_allowed(m.source):
                add(m, "package_name", None)

    if current_text:
        pkgbase_match = re.search(r"^\s*pkgbase\s*=\s*['\"]?([^'\"\s]+)", current_text, re.MULTILINE)
        if pkgbase_match:
            for m in match_package(pkgbase_match.group(1)):
                if source_allowed(m.source):
                    add(m, "pkgbase", None)

    # Dependency arrays.
    declared = extract_dependency_changes(scan_text, package_name)
    for field in _DEP_FIELDS:
        for name in declared.get(field, ()):
            for m in match_package(name):
                if source_allowed(m.source):
                    add(m, field, _find_line(diff_text, name))

    # Names a build step installs from a registry.  A `package` indicator
    # otherwise reaches only the AUR package name, pkgbase and the
    # dependency arrays, and the June 2026 campaign named its payload in
    # none of those: `atomic-lockfile` appeared solely as an argument to
    # `npm install` inside prepare(), so a curator's list naming it would
    # have matched nothing at all.
    for _fn, command, name in registry_install_names(scan_text):
        for m in match_package(name):
            if source_allowed(m.source):
                add(m, "build_install", _find_line(diff_text, name) or
                    _find_line(diff_text, command[:40]))

    # Domains and hashes from visible text.
    want_domains = bool(active_iocs(source=None, expired=False))
    if configured_sources:
        want_domains = any(
            active_iocs(source=s, expired=False) for s in configured_sources
        )

    for body in _added_bodies(scan_text):
        if want_domains:
            for host, origin in _hosts_in(body):
                for m in match_domain(host):
                    if source_allowed(m.source):
                        surface = "source_host" if origin == "url" else "referenced_host"
                        add(m, surface, _find_line(diff_text, host))

        # Hashes inside checksum arrays first, then any other hex digest.
        for digest in _checksum_digests(body):
            for m in match_hash(digest):
                if source_allowed(m.source):
                    add(m, "checksum_array", _find_line(diff_text, digest))

        for digest in _digests_in(body):
            # Avoid double-reporting digests already found in checksum arrays.
            if digest.lower() in {d.lower() for d in _checksum_digests(body)}:
                continue
            for m in match_hash(digest):
                if source_allowed(m.source):
                    add(m, "artifact_hash", _find_line(diff_text, digest))

    return matches
