"""Weight-0 tag events and the opsonization panel.

A tag is evidence that something happened, not a verdict about it: a first
contact, a campaign context, an entropy bump, an annotation, or a crossfire
technique.  Tags never score.  They coat the diff so later detection has
somewhere to look, and the panel is the one grouped surface where a reader
sees the coating.

The kinds are a closed, ordered table.  The convergence threshold is
config-pinned; the tag table itself is shipped, so two operators with the
same config cannot disagree about what a tag kind means.
"""

from __future__ import annotations

from dataclasses import dataclass
from itertools import islice

from .safe_text import clean

__all__ = [
    "MAX_TAG_EVENTS",
    "MAX_TAG_VALUE_CHARS",
    "TAG_KINDS",
    "TagEvent",
    "tag_convergence",
    "tag_events_from_breakdown",
    "tag_panel",
]

#: Ordered so the panel and the convergence count are deterministic.
TAG_KINDS: tuple[str, ...] = (
    "contact",
    "first_seen_host",
    "first_seen_literal",
    "entropy_bump",
    "campaign",
    "annotation",
    "technique",
)

#: Bound the panel: a package can declare many contacts/techniques, and the
#: report is not the place to materialise an unbounded list.
MAX_TAG_EVENTS = 256
MAX_TAG_VALUE_CHARS = 200

_ANNOTATION_PREFIXES = ("P", "U", "W")
_ANNOTATION_IDS = frozenset({"T007"})


@dataclass(frozen=True, slots=True)
class TagEvent:
    """One weight-0 tag on a diff."""

    kind: str
    value: str
    source_rule: str = ""

    def __post_init__(self) -> None:
        value = "" if self.value is None else str(self.value)
        object.__setattr__(
            self, "value",
            clean(value[:MAX_TAG_VALUE_CHARS * 4],
                  limit=MAX_TAG_VALUE_CHARS))
        object.__setattr__(
            self, "source_rule", clean(self.source_rule,
                                       limit=MAX_TAG_VALUE_CHARS))

    @property
    def sort_key(self) -> tuple[str, str, str]:
        return (self.kind, self.value, self.source_rule)

    def to_dict(self) -> dict:
        return {
            "kind": self.kind,
            "value": self.value,
            "source_rule": self.source_rule,
            "weight": 0,
        }


def _kind_for(rule_id: str) -> str | None:
    if not rule_id:
        return None
    if rule_id in ("G006", "G007"):
        return "campaign"
    if rule_id in ("G001", "G010"):
        return "first_seen_host"
    if rule_id == "G002":
        return "first_seen_literal"
    if rule_id.startswith("E"):
        return "entropy_bump"
    if rule_id.startswith(_ANNOTATION_PREFIXES) or rule_id in _ANNOTATION_IDS:
        return "annotation"
    return None


def tag_events_from_breakdown(breakdown, contacts=None) -> list[TagEvent]:
    """Every weight-0 tag this run carries, grouped and sorted.

    *breakdown* is the scored entry list; *contacts* is the Contact Ledger
    panel's ``records`` (dicts with ``kind`` and ``value``), already
    weight-0 and warm-only.
    """
    events: list[TagEvent] = []
    for entry in breakdown or ():
        rule_id = str(getattr(entry, "rule_id", "") or "")
        if getattr(entry, "weight", 0) != 0:
            continue
        kind = _kind_for(rule_id)
        params = getattr(entry, "params", {}) or {}
        if kind and len(events) < MAX_TAG_EVENTS:
            value = (params.get("campaign_id") or params.get("host")
                     or params.get("literal") or params.get("url") or rule_id)
            events.append(TagEvent(kind, str(value), rule_id))
        techniques = getattr(entry, "techniques", ()) or ()
        try:
            techniques = list(techniques)[:MAX_TAG_EVENTS]
        except TypeError:
            techniques = []
        for tag in techniques:
            if len(events) >= MAX_TAG_EVENTS:
                break
            events.append(TagEvent("technique", str(tag), rule_id))
    for record in islice(contacts or (), MAX_TAG_EVENTS):
        if len(events) >= MAX_TAG_EVENTS:
            break
        if not isinstance(record, dict):
            continue
        value = str(record.get("value") or "")
        if value:
            events.append(TagEvent("contact", value,
                                   str(record.get("kind", "contact"))))
    return sorted(events, key=lambda event: event.sort_key)[:MAX_TAG_EVENTS]


def tag_panel(events) -> list[dict]:
    """Group events by kind, preserving the closed kind order."""
    events = [event for event in islice(events or (), MAX_TAG_EVENTS)
              if isinstance(event, TagEvent)]
    out: list[dict] = []
    for kind in TAG_KINDS:
        rows = [event.to_dict() for event in events if event.kind == kind]
        if rows:
            out.append({
                "kind": kind,
                "count": len(rows),
                "events": sorted(rows, key=lambda row: (row["value"],
                                                        row["source_rule"])),
            })
    return out


def tag_convergence(events, min_kinds: int = 4) -> dict | None:
    """The bounded escalation: N distinct tag kinds on one diff.

    Returns the INFO ledger entry's evidence, or ``None``.  Weight 0: this
    is a pointer to look once, never a score.
    """
    kinds = sorted({
        event.kind for event in islice(events or (), MAX_TAG_EVENTS)
        if isinstance(event, TagEvent) and event.kind in TAG_KINDS
    })
    if len(kinds) < max(1, int(min_kinds)):
        return None
    return {
        "kinds": kinds,
        "count": len(kinds),
        "threshold": max(1, int(min_kinds)),
    }
