"""The Contact Ledger (spec: contact-ledger).

A weight-0, warm-only **first-contact feed**: every "stranger" a package
introduces - a first-seen host, maintainer account, file kind or upstream -
is *recorded, not attacked*.  The ledger is the innate layer's memory: when a
future IOC or campaign lands, "who-met-what-when" is a query rather than an
archaeology project.  It never scores, never gates, never accuses (A13b): a
first contact is a claim about *newness*, never about intent.

Two pure layers, so the join logic is testable without a live DB (the same
correlation-record contract the G-series uses):

* :func:`contact_candidates` turns one correlation record into the
  ``(kind, value)`` pairs the diff introduced;
* :func:`shared_first_seen_host` (G010) is the plurality join that promotes
  *coordinated* strangers into signal.

and a thin DB-backed layer that records entries and reads the ledger for the
report's "First contact" panel.
"""

from __future__ import annotations

import hashlib
from collections import defaultdict
from dataclasses import dataclass
from pathlib import PurePosixPath
from urllib.parse import urlsplit

__all__ = [
    "COLD_NOTE",
    "CONTACT_KINDS",
    "ContactRecord",
    "contact_candidates",
    "contact_id",
    "contact_panel",
    "contacts_for_fact",
    "panel_lines",
    "record_cycle_contacts",
    "shared_first_seen_host",
]

#: The four contact surfaces.  ``host`` and ``maintainer_account`` are
#: corpus-wide (the whole ecosystem has not met them); ``file_kind`` and
#: ``upstream`` are per-package (this package's history has not met them).
CONTACT_KINDS = ("host", "maintainer_account", "file_kind", "upstream")

#: The standing note a cold replay renders in place of a contact panel, so a
#: silent panel never masquerades as a clean one (the interoception
#: principle: the tool states its own sensory state).
COLD_NOTE = ("contact_ledger_unavailable: cold replay; first-contact facts "
             "not recorded")


@dataclass(frozen=True)
class ContactRecord:
    """One first-contact event (spec §2).

    ``basis`` is ``ledger`` when this analysis wrote the entry and
    ``matched`` when an earlier cycle did (emitted for one cycle so the panel
    can show recent arrivals without re-deriving queries).
    """

    contact_id: str
    contact_kind: str
    contact_value: str
    first_seen_cycle: int
    first_seen_utc: str
    basis: str
    package: str = ""

    def to_dict(self) -> dict:
        return {
            "contact_id": self.contact_id,
            "package": self.package,
            "kind": self.contact_kind,
            "value": self.contact_value,
            "first_seen_cycle": self.first_seen_cycle,
            "first_seen_utc": self.first_seen_utc,
            "basis": self.basis,
        }


def contact_id(pkgbase: str, kind: str, value: str, cycle_id) -> str:
    """Deterministic content hash of ``(pkgbase, kind, value, cycle_id)``."""
    material = "\x1f".join(
        (pkgbase or "", kind or "", value or "", str(cycle_id)))
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]


def _dedupe(pairs) -> list:
    seen: set = set()
    out: list = []
    for kind, value in pairs:
        if not value or (kind, value) in seen:
            continue
        seen.add((kind, value))
        out.append((kind, value))
    return out


def contact_candidates(record) -> list:
    """The ``(kind, value)`` contacts one correlation record introduces."""
    out: list = []
    gained = record.get("hosts_gained", ()) or ()
    if isinstance(gained, str):
        gained = [gained]
    for host in gained:
        if host:
            out.append(("host", str(host)))
    maintainer = str(record.get("maintainer", "") or "").strip()
    if maintainer:
        out.append(("maintainer_account", maintainer))
    for label in record.get("added_file_kinds", ()) or ():
        if label:
            out.append(("file_kind", str(label)))
    for entry in record.get("upstream_dep_additions", ()) or ():
        if isinstance(entry, (list, tuple)):
            value = entry[0] if entry else ""
        else:
            value = entry
        if value:
            out.append(("upstream", str(value)))
    return _dedupe(out)


def record_cycle_contacts(records, cycle_time: int, observed_at: str) -> dict:
    """Record every first-contact in *records*; return the cycle's ledger view.

    Returns ``{"records": [ContactRecord], "hosts_new": set}``.  ``hosts_new``
    is the hosts this cycle introduced to the corpus, G010's novelty join.
    """
    from .db import record_contact, record_host, write_batch

    entries: list[ContactRecord] = []
    hosts_new: set = set()
    seen: set = set()
    # One transaction for the cycle's first contacts.  Each writer commits
    # itself; a sweep that meets thousands of new contacts would otherwise
    # pay one WAL append per row.
    with write_batch():
        for record in records or ():
            package = str(record.get("package", ""))
            maintainer = str(record.get("maintainer", "") or "")
            for kind, value in contact_candidates(record):
                key = (package, kind, value)
                if key in seen:
                    continue
                seen.add(key)
                new = record_contact(package, kind, value, cycle_time,
                                     observed_at, maintainer)
                if kind == "host" and record_host(value, observed_at):
                    hosts_new.add(value)
                entries.append(ContactRecord(
                    contact_id=contact_id(package, kind, value, cycle_time),
                    contact_kind=kind, contact_value=value,
                    first_seen_cycle=int(cycle_time), first_seen_utc=observed_at,
                    basis="ledger" if new else "matched", package=package))
    return {"records": entries, "hosts_new": hosts_new}


def shared_first_seen_host(records, min_packages: int = 5,
                           first_seen_hosts=None) -> list:
    """G010: a first-seen host gained by *min_packages* packages in the window.

    The G001 shape with the novelty join instead of the gained-host join: only
    hosts new to the corpus count, so one honest newcomer per window is the
    AUR being the AUR and five is a distribution infrastructure.  Weight 0
    (INFO): strangers in company are a signal, strangers alone are a census.
    """
    from .analysis.correlation import (
        _UBIQUITOUS_BUCKETS, _one_name_family, _one_project,
    )
    from .buckets import canonical_host, classify_url

    fresh = None if first_seen_hosts is None else {str(h) for h in first_seen_hosts}
    by_host: dict[str, dict[str, dict]] = defaultdict(dict)
    for record in records or ():
        gained = record.get("hosts_gained", ()) or ()
        if isinstance(gained, str):
            gained = [gained]
        for host in gained:
            normalised = canonical_host(str(host)) if host else ""
            if not normalised:
                continue
            if fresh is not None and normalised not in fresh:
                continue
            by_host[normalised][str(record.get("package", ""))] = record
    out: list = []
    for host, members in sorted(by_host.items()):
        if len(members) < int(min_packages) or _one_project(members.values()):
            continue
        maintainers = {
            str(record.get("maintainer") or "").strip().lower()
            for record in members.values()
        }
        maintainers.discard("")
        if maintainers and len(maintainers) < 2 and _one_name_family(members):
            continue
        try:
            bucket, _domain = classify_url(f"https://{host}")
        except Exception:
            bucket = "unknown"
        if bucket in _UBIQUITOUS_BUCKETS:
            continue
        out.append({
            "rule_id": "G010",
            "name": "Shared First-Seen Host",
            "severity": "INFO", "category": "correlation",
            "match": (f"first-seen host {host} gained by {len(members)} "
                      "packages in the window"),
            "params": {"members": sorted(members), "host": host},
        })
    return out


def _url_host(url: str) -> str:
    from .buckets import canonical_host

    try:
        netloc = urlsplit(str(url)).netloc
    except ValueError:
        return ""
    return canonical_host(netloc) if netloc else ""


def _file_kind(path: str) -> str:
    """The extension/class a tree path contributes (spec §2)."""
    name = PurePosixPath(str(path)).name
    suffix = PurePosixPath(name).suffix.lstrip(".")
    return (suffix or name).lower()


def _candidates_from_fact(fact) -> list:
    """The contacts a single package's fact introduces, from its diff."""
    out: list = []
    for url in getattr(fact.source_changes, "added_urls", ()) or ():
        host = _url_host(url)
        if host:
            out.append(("host", host))
    maintainer = (getattr(fact, "current_maintainer", "") or "").strip()
    if maintainer:
        out.append(("maintainer_account", maintainer))
    for change in getattr(fact.diff_summary, "file_changes", ()) or ():
        if change.get("status") == "added":
            kind = _file_kind(change.get("path", ""))
            if kind:
                out.append(("file_kind", kind))
    for names in (getattr(fact, "dependency_changes", {}) or {}).values():
        for name in names or ():
            if name:
                out.append(("upstream", str(name)))
    return _dedupe(out)


def contacts_for_fact(fact) -> list:
    """The fact's contacts as report rows, each tagged with its basis.

    Read-only: ``matched`` when the value is already in the ledger, ``ledger``
    when this analysis is the first to meet it.  Nothing here writes, so the
    reporting path is safe to call on a replay.
    """
    from .db import contacts_for_values

    candidates = _candidates_from_fact(fact)
    by_kind: dict[str, list[str]] = defaultdict(list)
    for kind, value in candidates:
        by_kind[kind].append(value)
    known = {kind: contacts_for_values(kind, values)
             for kind, values in by_kind.items()}
    rows = []
    for kind, value in candidates:
        matched = known.get(kind, {}).get(value)
        rows.append({
            "package": fact.package_name,
            "kind": kind,
            "value": value,
            "basis": "matched" if matched else "ledger",
            "first_seen_utc": matched or "",
        })
    rows.sort(key=lambda row: (row["kind"], row["value"]))
    return rows


def _enabled(config) -> bool:
    return bool(((config or {}).get("contacts", {}) or {}).get("enabled", True))


def contact_panel(fact) -> dict:
    """The report's "First contact" panel.

    On a cold replay (the ledger disabled or absent) the panel is the single
    standing note, so a silent panel never reads as a clean one.
    """
    from .config import load_config
    from .db import contact_ledger_available

    if not _enabled(load_config()) or not contact_ledger_available():
        return {"available": False, "note": COLD_NOTE, "records": []}
    return {"available": True, "note": "", "records": contacts_for_fact(fact)}


def panel_lines(panel) -> list:
    """The "First contact" panel as terminal lines, shared by every render.

    A cold panel renders its single standing note; a warm panel with no
    first contacts renders nothing (there is no claim to make), which the
    cold note exists to distinguish from a panel that simply went quiet.
    """
    from .safe_text import clean

    if not panel:
        return []
    if not panel.get("available", True):
        return [f"  [First contact: {clean(panel.get('note', COLD_NOTE))}]"]
    records = panel.get("records", ()) or ()
    if not records:
        return []
    lines = ["  First contact (weight 0):"]
    for row in records:
        kind = clean(str(row.get("kind", "")))
        value = clean(str(row.get("value", "")))
        basis = clean(str(row.get("basis", "")))
        lines.append(f"    {kind} {value} ({basis})")
    return lines
