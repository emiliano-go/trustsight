"""G-series: cross-package correlation (Addendum 5 §6.2).

The only family whose input is the *set* of recent analyses, not one
package.  Mechanistically distinct from D (single-package graph walk) and T
(single-package history): G's input is collective, so it runs at cycle end
in the full-AUR sweep, never on a single ``review``.

Runs over a list of per-package correlation records (the corpus builder
supplies them), so the join logic is testable without a live corpus:

* **G001 Shared Gained Host** (HIGH): the same gained canonical host appears
  in at least N packages in the window.  A "new CDN" is plausible once,
  damning five times.
* **G002 Shared Added Literal** (HIGH): an identical added literal above a
  length floor appears in at least two unrelated packages.
* **G003 Coordinated Adoption** (MEDIUM): the same maintainer key adopted
  at least M packages in the window.

Members are named in the finding; the roundup is one alert, not N.
"""

from __future__ import annotations

from collections import defaultdict

__all__ = ["correlate", "shared_gained_host", "shared_added_literal",
           "coordinated_adoption"]


def _thresholds(config) -> dict:
    return (config or {}).get("thresholds", {})


def shared_gained_host(records, min_packages: int = 5) -> list[dict]:
    """G001: a gained host shared by *min_packages* distinct packages."""
    by_host: dict[str, set[str]] = defaultdict(set)
    for record in records:
        for host in record.get("hosts_gained", ()) or ():
            if host:
                by_host[host].add(str(record.get("package", "")))
    out = []
    for host, members in sorted(by_host.items()):
        if len(members) >= min_packages:
            out.append({
                "rule_id": "G001",
                "name": "Shared Gained Host",
                "severity": "HIGH", "category": "correlation",
                "match": (f"gained host {host} appears in {len(members)} "
                          "packages in the window"),
                "params": {"members": sorted(members), "host": host},
            })
    return out


def shared_added_literal(records, min_packages: int = 2,
                         min_length: int = 256) -> list[dict]:
    """G002: an identical added literal in *min_packages* packages."""
    by_literal: dict[str, set[str]] = defaultdict(set)
    for record in records:
        for literal in record.get("added_literals", ()) or ():
            text = str(literal)
            if len(text) >= min_length:
                by_literal[text].add(str(record.get("package", "")))
    out = []
    for literal, members in by_literal.items():
        if len(members) >= min_packages:
            out.append({
                "rule_id": "G002",
                "name": "Shared Added Literal",
                # Never print the literal's content: name its class only.
                "severity": "HIGH", "category": "correlation",
                "match": (f"an added literal of {len(literal)} chars appears "
                          f"in {len(members)} packages in the window"),
                "params": {"members": sorted(members),
                           "literal_length": len(literal)},
            })
    return out


def coordinated_adoption(records, min_members: int = 3) -> list[dict]:
    """G003: one maintainer key adopting *min_members* packages."""
    by_maintainer: dict[str, set[str]] = defaultdict(set)
    for record in records:
        maintainer = str(record.get("maintainer", "") or "").strip().lower()
        if maintainer and record.get("adoption"):
            by_maintainer[maintainer].add(str(record.get("package", "")))
    out = []
    for maintainer, members in sorted(by_maintainer.items()):
        if len(members) >= min_members:
            out.append({
                "rule_id": "G003",
                "name": "Coordinated Adoption",
                "severity": "MEDIUM", "category": "correlation",
                "match": (f"maintainer adopted {len(members)} packages in the "
                          "window"),
                "params": {"members": sorted(members)},
            })
    return out


def correlate(records, config=None) -> list[dict]:
    """All G-series findings for one cycle's records."""
    thresholds = _thresholds(config)
    host_n = int(thresholds.get("g_host", {}).get("min_packages", 5))
    blob_n = int(thresholds.get("g_blob", {}).get("min_packages", 2))
    blob_len = int(thresholds.get("g_blob", {}).get("min_length", 256))
    adopt_m = int(thresholds.get("g_adopt", {}).get("min_members", 3))
    out: list[dict] = []
    out.extend(shared_gained_host(records, host_n))
    out.extend(shared_added_literal(records, blob_n, blob_len))
    out.extend(coordinated_adoption(records, adopt_m))
    return out
