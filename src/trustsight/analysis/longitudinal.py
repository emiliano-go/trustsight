"""Phase 5 — Class C longitudinal rules (plan §7).

These rules consume ``PropertyBreak`` objects from
``full_aur/properties.py`` plus the diff.  The property layer runs on every
cycle and records even when no consumer exists; this module is the consumer.

Rules are keyed by tracked property (see the deferred-spec tracking table):

- R094 — ``configure_flags`` changed, dropping or adding a security-relevant
  hardening flag.
- R095 — ``depends`` changed such that a dependency was removed *and* the diff
  vendors a new source whose name matches the removed dependency (the narrowed,
  mechanical case).
- R096 — ``source_hosts`` / ``source_orgs`` changed after a long-stable run.
- R097 — ``version_scheme`` changed (semver -> hash, ...). Context only, weight 0.
- R098 — ``pkgdesc_tokens`` changed.
- R102 — ``build_system_markers`` / ``build_line_count`` changed.
- R083 — a tracked-but-otherwise-unowned property (``license``,
  ``install_hook_present``) changed after stability.

All of them require the break to clear STABILITY_FLOOR: ``PropertyBreak``
objects are only emitted by ``update_properties`` once a value has held for
``stability_floor`` observations, which is what makes fire_rate(cold_db) == 0.
"""

import json

from ..config import (
    DEFAULT_SECURITY_RELEVANT_FLAGS,
    DEFAULT_SECURITY_RELEVANT_LIBRARIES,
    load_patterns,
    load_thresholds,
)
from ..differ import extract_urls_from_diff
from ..findings import stamp

# Property keys each rule owns.  R083 claims the tracked-but-quoted residue
# (license, install_hook_present); ``depends`` is R095's (needs the diff).
_RULE_FOR_KEY = {
    "configure_flags": "R094",
    "source_hosts": "R096",
    "source_orgs": "R096",
    "version_scheme": "R097",
    "pkgdesc_tokens": "R098",
    "build_system_markers": "R102",
    "build_line_count": "R102",
}

_ARCHIVE_SUFFIXES = (
    ".tar.gz", ".tar.bz2", ".tar.xz", ".tar.zst", ".tar.lz", ".tgz",
    ".tar", ".zip", ".gz", ".bz2", ".xz", ".zst", ".7z", ".Z", ".lzma",
)


def _stability_floor(config) -> int:
    thresholds = load_thresholds().get("longitudinal", {})
    return int(thresholds.get("stability_floor", 10))


def _security_flags() -> frozenset:
    patterns = load_patterns().get("patterns", {})
    flags = patterns.get("security_relevant_flags")
    return frozenset(flags) if flags else frozenset(DEFAULT_SECURITY_RELEVANT_FLAGS)


def _security_libs() -> frozenset:
    patterns = load_patterns().get("patterns", {})
    libs = patterns.get("security_relevant_libraries")
    return frozenset(libs) if libs else frozenset(DEFAULT_SECURITY_RELEVANT_LIBRARIES)


def _deserialize(value: str):
    """Recover a property value from its canonical serialization."""
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return value


def _changed_by(break_) -> tuple[set, set]:
    """Return the (old, new) element sets of a break."""
    old = set(_deserialize(break_.old_value) or ())
    new = set(_deserialize(break_.new_value) or ())
    return old, new


def _source_name(url: str) -> str:
    """Project-name approximation from a source URL's basename.

    ``https://x/openssl-3.0.1.tar.gz`` -> ``openssl``.  Good enough for R095's
    mechanical dep-vs-source name match; exact archive layouts are not assumed.
    """
    base = url.split("/")[-1].split("?")[0].split("#")[0]
    for suffix in _ARCHIVE_SUFFIXES:
        if base.endswith(suffix):
            base = base[: -len(suffix)]
            break
    return base.split("-")[0].split("_")[0]


def _vendored_in_diff(diff_text: str, removed_deps: set[str]) -> set[str]:
    """Removed deps for which the diff adds a source whose name matches."""
    added = extract_urls_from_diff(diff_text).added_urls
    vendored: set[str] = set()
    for url in added:
        name = _source_name(url)
        for dep in removed_deps:
            if name and dep and name == dep:
                vendored.add(dep)
    return vendored


def longitudinal_findings(
    diff_text: str,
    package_name: str,
    breaks: list,
    config: dict | None = None,
) -> list[dict]:
    """Concrete findings from a cycle's property breaks (R094-R098/R102/R083).

    *breaks* come from ``update_properties`` in the same analysis.  Anything
    below the stability floor has weight 0 and is never present here anyway;
    a defensive re-check keeps the gating explicit.
    """
    config = config or {}
    floor = _stability_floor(config)
    findings: list[dict] = []
    for break_ in breaks:
        if break_.weight <= 0.0 or break_.stable_for_n < floor:
            continue
        findings.extend(_finding_for_break(diff_text, break_, config))
    return findings


def _finding_for_break(diff_text, break_, config) -> list[dict]:
    key = break_.key

    if key == "depends":
        return _r095(diff_text, break_)

    rule_id = _RULE_FOR_KEY.get(key)
    if rule_id is None:
        if key in ("license", "install_hook_present"):
            rule_id = "R083"
        else:
            return []

    if rule_id == "R094":
        old, new = _changed_by(break_)
        sec = _security_flags()
        sec_changed = sorted((old ^ new) & sec)
        if not sec_changed:
            return []
        severity = "HIGH" if (old - new) & sec else "MEDIUM"
        return [stamp({
            "rule_id": "R094", "name": "Security-Relevant Build Flag Change",
            "severity": severity, "category": "build",
            "match": f"configure_flags changed security flags after "
                     f"{break_.stable_for_n} stable obs: {sec_changed}",
            "params": {"flags": ", ".join(sec_changed),
                       "stable_for_n": break_.stable_for_n},
        })]

    if rule_id == "R096":
        return [stamp({
            "rule_id": "R096", "name": "Source Host Changed",
            "severity": "MEDIUM", "category": "source",
            "match": f"source {key} changed after {break_.stable_for_n} stable obs",
            "params": {"key": key,
                       "stable_for_n": break_.stable_for_n},
        })]

    if rule_id == "R097":
        return [stamp({
            "rule_id": "R097", "name": "Version Scheme Changed",
            "severity": "INFO", "category": "context",
            "match": f"version scheme changed {break_.old_value} -> {break_.new_value}",
            "params": {"old_scheme": break_.old_value,
                       "new_scheme": break_.new_value,
                       "stable_for_n": break_.stable_for_n},
        })]

    if rule_id == "R098":
        return [stamp({
            "rule_id": "R098", "name": "Package Description Changed",
            "severity": "MEDIUM", "category": "integrity",
            "match": f"pkgdesc changed after {break_.stable_for_n} stable obs",
            "params": {"stable_for_n": break_.stable_for_n},
        })]

    if rule_id == "R102":
        return [stamp({
            "rule_id": "R102", "name": "Build System Changed",
            "severity": "MEDIUM", "category": "build",
            "match": f"build {key} changed after {break_.stable_for_n} stable obs: "
                     f"{break_.old_value} -> {break_.new_value}",
            "params": {"key": key, "stable_for_n": break_.stable_for_n,
                       "old_value": break_.old_value, "new_value": break_.new_value},
        })]

    if rule_id == "R083":
        return [stamp({
            "rule_id": "R083", "name": "Long-Stable Property Changed",
            "severity": "MEDIUM", "category": "temporal",
            "match": f"{key} changed after {break_.stable_for_n} stable obs",
            "params": {"key": key, "stable_for_n": break_.stable_for_n},
        })]

    return []


def _r095(diff_text: str, break_) -> list[dict]:
    """A dependency was removed and the diff vendors a matching source (R095).

    Narrowed to the mechanical case: the removed name must match the added
    source's project name, so a routine dep swap with a differently-named
    source stays quiet.
    """
    old, new = _changed_by(break_)
    removed = old - new
    if not removed:
        return []
    vendored = _vendored_in_diff(diff_text, removed)
    if not vendored:
        return []
    sec = _security_libs()
    severity = "HIGH" if vendored & sec else "MEDIUM"
    return [stamp({
        "rule_id": "R095", "name": "Dependency Vendored Into Source",
        "severity": severity, "category": "dependency",
        "match": f"removed dep(s) {sorted(vendored)} now sourced in-tree after "
                 f"{break_.stable_for_n} stable obs",
        "params": {"vendored": ", ".join(sorted(vendored)),
                   "stable_for_n": break_.stable_for_n},
    })]
