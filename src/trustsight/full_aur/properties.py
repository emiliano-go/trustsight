"""Property tracking for longitudinal stability analysis.

Records per-package, per-key property values across analyses.
``update_properties()`` persists state and returns ``PropertyBreak``
objects on value changes.  ``longitudinal_findings()`` is a stub that
returns ``[]`` until R094–R102 are implemented.
"""

import hashlib
import json
import logging
import re
from dataclasses import dataclass
from typing import Any, Optional

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Canonical serialization  (order-stable, type-stable)
# ---------------------------------------------------------------------------

def canonical(value: Any) -> str:
    """Deterministic serialization.  Sets are sorted, bools are lowercased."""
    if isinstance(value, (set, frozenset)):
        return json.dumps(sorted(value), separators=(",", ":"), ensure_ascii=False)
    if isinstance(value, bool):
        return "true" if value else "false"
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False)


def value_hash(value: Any) -> str:
    """SHA-256 hex digest of the canonical serialization."""
    return hashlib.sha256(canonical(value).encode()).hexdigest()


# ---------------------------------------------------------------------------
# Weighting  (how significant a break is)
# ---------------------------------------------------------------------------

# A property must hold this many consecutive observations before a change is
# even reported.  Below the floor the weight is 0 and no PropertyBreak is
# emitted; overridden by ``[longitudinal] stability_floor`` in thresholds.toml.
STABILITY_FLOOR_DEFAULT = 10


def stability_weight(stable_for_n: int, floor: int = STABILITY_FLOOR_DEFAULT) -> float:
    """Weight a property break by how long the value held.

    Ranges 0.0–1.0.  Nothing is reported below *floor* observations — a
    value that never stabilised carries no longitudinal signal.  From the
    floor the weight ramps steeply through the first ~30 observations and
    flattens near 1.0 by ~40, so an attacker who waits out a long stable
    period pays no more weight than the analyst who catches the break early.
    """
    if stable_for_n <= 0 or stable_for_n < floor:
        return 0.0
    return min(1.0, _logistic_ish(stable_for_n - floor + 1))


def _logistic_ish(n: int) -> float:
    return 1.0 - 1.0 / (1.0 + n ** 0.7)


# ---------------------------------------------------------------------------
# PropertyBreak
# ---------------------------------------------------------------------------

@dataclass
class PropertyBreak:
    """A property value that just changed after a period of stability."""
    key: str
    old_value: str
    new_value: str
    stable_for_n: int
    weight: float


# ---------------------------------------------------------------------------
# Bucketing  (numeric properties need coarse ranges to stabilize)
# ---------------------------------------------------------------------------

_LINE_COUNT_BUCKETS = [
    (0, 5), (6, 15), (16, 40), (41, 100), (101, 300), (301, 1000), (1001, float("inf")),
]


def _bucket_line_count(n: int) -> str:
    for lo, hi in _LINE_COUNT_BUCKETS:
        if lo <= n <= hi:
            return f"{lo}-{hi}" if hi != float("inf") else f"{lo}+"
    return "unknown"


# ---------------------------------------------------------------------------
# Property extraction
# ---------------------------------------------------------------------------

_FLAG_RE = re.compile(r"(--?[a-zA-Z][a-zA-Z0-9_-]*)")
_PKGDESC_RE = re.compile(r"^\s*pkgdesc\s*=\s*['\"]?(.*?)['\"]?\s*$", re.MULTILINE)
_PKGVER_RE = re.compile(r"^\s*pkgver\s*=\s*['\"]?([^\s'\"]+)", re.MULTILINE)
_INSTALL_RE = re.compile(r"^\s*install\s*=\s*['\"]?([^'\"]+)", re.MULTILINE)

# Build-system marker keywords, searched in build/prepare/package function bodies
_BUILD_SYSTEM_MARKERS: dict[str, re.Pattern] = {
    "cmake": re.compile(r"\bcmake\b"),
    "meson": re.compile(r"\bmeson\b"),
    "autotools": re.compile(r"\./(?:configure|autogen\.sh|bootstrap)\b"),
    "make": re.compile(r"\b(?<!cmake )make\b"),
}

_STOPWORDS = frozenset({
    "a", "an", "the", "is", "are", "was", "were", "be", "been",
    "for", "of", "to", "in", "on", "at", "and", "or", "not",
    "with", "from", "by", "as", "it", "its", "this", "that",
})


def extract_properties(new_pkgbuild: str, srcinfo: Optional[str] = None) -> dict[str, Any]:
    """Extract tracked properties from a PKGBUILD (and optionally .SRCINFO).

    Returns a dict keyed by ``property_key`` (see §1.1 of the spec).
    Values are normalised as specified in the tracking table.
    """
    props: dict[str, Any] = {}

    # version_scheme
    pkgver_match = _PKGVER_RE.search(new_pkgbuild)
    pkgver = pkgver_match.group(1) if pkgver_match else ""
    props["version_scheme"] = _classify_version(pkgver)

    # pkgdesc_tokens
    desc_match = _PKGDESC_RE.search(new_pkgbuild)
    pkgdesc = desc_match.group(1) if desc_match else ""
    tokens = _tokenize_desc(pkgdesc)
    props["pkgdesc_tokens"] = frozenset(tokens)

    # depends: prefer .SRCINFO (structured), fall back to PKGBUILD regex
    depends: set[str] = set()
    if srcinfo:
        for line in srcinfo.splitlines():
            m = re.match(r"^\s*depends\s*=\s*['\"]?([^'\"\s<>=!~]+)", line)
            if m:
                depends.add(m.group(1))
    else:
        in_depends = False
        for line in new_pkgbuild.splitlines():
            stripped = line.strip()
            m = re.match(r"^\s*depends\s*=\s*\(([^)]*)\)", stripped)
            if m:
                # single-line: depends=('a' 'b')
                for d in re.finditer(r"""['\"]([^'\"]+)['\"]""", m.group(1)):
                    depends.add(d.group(1))
                continue
            if re.match(r"^\s*depends\s*=\s*\(", stripped):
                in_depends = True
                continue
            if in_depends:
                if stripped.startswith(")"):
                    in_depends = False
                    continue
                for d in re.finditer(r"""['\"]([^'\"]+)['\"]""", stripped):
                    depends.add(d.group(1))
    props["depends"] = frozenset(depends)

    # source_hosts / source_orgs: extracted from source=() entries
    hosts: set[str] = set()
    orgs: set[str] = set()
    in_source = False
    for line in new_pkgbuild.splitlines():
        stripped = line.strip()
        m = re.match(r"^\s*source(?:_x86_64|_i686|_any)?\s*=\s*\(([^)]*)\)", stripped)
        if m:
            # single-line: source=('https://...')
            for u in _URL_RE.finditer(m.group(1)):
                _extract_host_org(u.group(0), hosts, orgs)
            continue
        if re.match(r"^\s*source(?:_x86_64|_i686|_any)?\s*=\s*\(", stripped):
            in_source = True
            continue
        if in_source:
            if stripped.startswith(")"):
                in_source = False
                continue
            for u in _URL_RE.finditer(stripped):
                _extract_host_org(u.group(0), hosts, orgs)
    props["source_hosts"] = frozenset(hosts)
    props["source_orgs"] = frozenset(orgs)

    # build_system_markers
    markers: set[str] = set()
    body = _build_function_bodies(new_pkgbuild)
    for name, pattern in _BUILD_SYSTEM_MARKERS.items():
        if pattern.search(body):
            markers.add(name)
    if not markers:
        markers.add("none")
    props["build_system_markers"] = frozenset(markers)

    # build_line_count
    line_count = len(body.splitlines()) if body.strip() else 0
    props["build_line_count"] = _bucket_line_count(line_count)

    # configure_flags
    flags: set[str] = set()
    for line in body.splitlines():
        for m in _FLAG_RE.finditer(line):
            flags.add(m.group(1))
    props["configure_flags"] = frozenset(flags)

    # install_hook_present
    install_match = _INSTALL_RE.search(new_pkgbuild)
    props["install_hook_present"] = install_match is not None

    # license: from .SRCINFO if available
    if srcinfo:
        licenses: set[str] = set()
        for line in srcinfo.splitlines():
            m = re.match(r"^\s*license\s*=\s*['\"]?([^'\"]+)", line)
            if m:
                licenses.add(m.group(1))
        props["license"] = frozenset(licenses)

    return props


def _classify_version(pkgver: str) -> str:
    if not pkgver:
        return "other"
    # Check for pure hash (git commit-ish)
    if re.match(r"^[a-f0-9]{7,40}$", pkgver) and not re.match(r"^\d", pkgver):
        return "hash"
    # Check for calver: YYYY.M(.minor)?
    if re.match(r"^\d{4}\.\d{1,2}(\.\d+)?$", pkgver):
        return "calver"
    # Check for date-like: YYYYMMDD (8-digit, no separators)
    if re.match(r"^\d{8}$", pkgver):
        return "date"
    # Check for semver: X.Y.Z
    if re.match(r"^\d+\.\d+\.\d+", pkgver):
        return "semver"
    return "other"


def _tokenize_desc(desc: str) -> list[str]:
    tokens = re.findall(r"[a-zA-Z][a-zA-Z0-9_-]*", desc.lower())
    return [t for t in tokens if t not in _STOPWORDS]


_URL_RE = re.compile(r"https?://[^\s\"')\]]+")


def _extract_host_org(url: str, hosts: set[str], orgs: set[str]) -> None:
    from urllib.parse import urlparse
    try:
        parsed = urlparse(url)
        host = parsed.hostname
        if host:
            hosts.add(host)
            path = parsed.path.strip("/")
            parts = path.split("/")
            if parts and parts[0]:
                orgs.add(f"{host}/{parts[0]}")
    except Exception:
        pass


def _build_function_bodies(pkgbuild: str) -> str:
    """Concatenate build(), prepare(), and package() function bodies."""
    in_func = False
    depth = 0
    lines: list[str] = []
    targets = ("build()", "prepare()", "package()")
    for line in pkgbuild.splitlines():
        stripped = line.strip()
        if not in_func:
            if any(stripped.startswith(t) for t in targets):
                in_func = True
                depth = stripped.count("{")
            continue
        depth += stripped.count("{")
        depth -= stripped.count("}")
        if depth <= 0:
            in_func = False
            continue
        lines.append(line)
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Property update step
# ---------------------------------------------------------------------------

def update_properties(
    conn,
    package: str,
    extracted: dict[str, Any],
    observed_at: str,
    floor: int = STABILITY_FLOOR_DEFAULT,
) -> list[PropertyBreak]:
    """Record property state; return the breaks that just occurred.

    Returns breaks so rules can consume them in the same analysis.
    The stored ``stable_for_n`` is updated AFTER the break is reported.
    """
    breaks: list[PropertyBreak] = []
    for key, value in extracted.items():
        h = value_hash(value)
        ser = canonical(value)
        row = conn.execute(
            "SELECT value_hash, value, stable_for_n FROM package_properties "
            "WHERE package_name=? AND property_key=?", (package, key)
        ).fetchone()

        if row is None:
            conn.execute(
                "INSERT INTO package_properties "
                "(package_name, property_key, value_hash, value, stable_for_n, first_seen, last_changed) "
                "VALUES (?,?,?,?,0,?,?)",
                (package, key, h, ser, observed_at, observed_at),
            )
            continue

        old_hash, old_ser, stable_n = row
        if old_hash == h:
            conn.execute(
                "UPDATE package_properties SET stable_for_n = stable_for_n + 1 "
                "WHERE package_name=? AND property_key=?", (package, key),
            )
            continue

        w = stability_weight(stable_n, floor)
        if w > 0.0:
            breaks.append(PropertyBreak(key, old_ser, ser, stable_n, w))
        conn.execute(
            "UPDATE package_properties SET value_hash=?, value=?, stable_for_n=0, last_changed=? "
            "WHERE package_name=? AND property_key=?",
            (h, ser, observed_at, package, key),
        )
    return breaks
