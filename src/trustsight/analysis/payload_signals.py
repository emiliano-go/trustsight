"""Specific payload rules and the bounded URL extraction they feed.

The G-series joins findings, not only artifacts.  A rule qualifies for that
join when its firing is a *specific* payload claim rather than a broad
practice: ``R001`` is "a remote script is piped to a shell", while ``R010`` is
"the recipe mentions curl".  The allowlist below is the membership test, so a
new broad heuristic cannot silently widen the campaign join.

URLs are extracted from the finding's already-bounded ``reason`` and
``evidence`` text.  Nothing is fetched, nothing is resolved, and a URL that
cannot be parsed is simply not joined.  A per-package cap bounds an
attacker-influenced member list.
"""

from __future__ import annotations

import re
from itertools import islice
from urllib.parse import urlsplit, urlunsplit

__all__ = [
    "MAX_PAYLOAD_ENTRIES",
    "MAX_PAYLOAD_TEXT",
    "MAX_PAYLOAD_URLS",
    "MAX_PAYLOAD_URL_LENGTH",
    "SHARED_PAYLOAD_RULES",
    "canonical_campaign_url",
    "canonical_payload_url",
    "payload_urls",
]

#: Rules whose firing is a specific payload/execution claim.  Broad rules
#: (R010 "uses curl", H001 "checksum SKIP", H016 "hidden fetch", H024 "GPG
#: removed") are deliberately absent: they are common enough that joining on
#: them would turn ordinary ecosystem churn into a campaign.
SHARED_PAYLOAD_RULES = frozenset({
    "R001", "R002", "R003", "R008", "X011", "X017",
    "H017", "H035", "H041", "H075", "H090",
    "C016", "C032",
    "S001", "S002", "S003", "S004", "S005", "S006", "S007", "S008",
})

#: Per-package bounds.  The member set is attacker-influenced, so the join
#: work must not grow with the number of URLs in one finding.
MAX_PAYLOAD_URLS = 8
MAX_PAYLOAD_URL_LENGTH = 2048
MAX_PAYLOAD_TEXT = 4096
MAX_PAYLOAD_ENTRIES = 256
_MAX_CONTAINER_ITEMS = 32

_URL_RE = re.compile(r"https?://[^\s\"'<>`]+", re.IGNORECASE)
_TRAILING = ".,;:!?)]}"


def _strings(value, depth: int = 0):
    """Bounded strings from a string, mapping or short sequence."""
    if depth > 2:
        return
    if isinstance(value, str):
        yield value[:MAX_PAYLOAD_TEXT]
    elif isinstance(value, dict):
        for item in islice(value.values(), _MAX_CONTAINER_ITEMS):
            yield from _strings(item, depth + 1)
    elif isinstance(value, (list, tuple)):
        for item in islice(value, _MAX_CONTAINER_ITEMS):
            yield from _strings(item, depth + 1)


def _entry_texts(entry):
    """The bounded text fields a finding carries, dict or dataclass."""
    if isinstance(entry, dict):
        fields = (
            entry.get("reason"), entry.get("match"),
            entry.get("evidence"), entry.get("params"),
        )
        rule_id = str(entry.get("rule_id", ""))
    else:
        fields = (
            getattr(entry, "reason", ""), getattr(entry, "evidence", None),
            getattr(entry, "params", None),
        )
        rule_id = str(getattr(entry, "rule_id", ""))
    if rule_id not in SHARED_PAYLOAD_RULES:
        return
    for field in fields:
        yield from _strings(field)


def _norm_host(host: str) -> str:
    host = (host or "").lower().rstrip(".")
    if ":" in host:
        try:
            import ipaddress
            return f"[{ipaddress.ip_address(host).compressed}]"
        except ValueError:
            return f"[{host}]"
    try:
        return host.encode("idna").decode("ascii")
    except UnicodeError:
        return host


def _norm_path(path: str) -> str:
    """Remove RFC 3986 dot segments without collapsing double slashes."""
    if not path:
        return "/"
    absolute = path.startswith("/")
    out: list[str] = []
    for segment in path.split("/"):
        if segment in ("", "."):
            continue
        if segment == "..":
            if out:
                out.pop()
            continue
        out.append(segment)
    value = "/" + "/".join(out)
    if path.endswith("/") and not value.endswith("/"):
        value += "/"
    return value if absolute else value.lstrip("/")


def canonical_payload_url(url: str) -> str:
    """A join key for *url*, or ``""`` when it is unusable.

    The scheme, lower-cased host, non-default port and path are kept.  The
    query and fragment are dropped: they are the part an attacker can vary
    for free, and two packages pointing at the same endpoint should meet.
    """
    if not url or len(url) > MAX_PAYLOAD_URL_LENGTH:
        return ""
    try:
        parts = urlsplit(url)
        scheme = parts.scheme.lower()
        host = _norm_host(parts.hostname or "")
        port = parts.port
    except (ValueError, UnicodeError):
        return ""
    if scheme not in ("http", "https") or not host:
        return ""
    host_key = host
    default_port = 80 if scheme == "http" else 443
    netloc = (host_key if port in (None, default_port)
              else f"{host_key}:{port}")
    return urlunsplit((scheme, netloc, _norm_path(parts.path or "/"), "", ""))


def canonical_campaign_url(url: str) -> str:
    """A campaign endpoint: scheme and non-default port do not split it."""
    if not url or len(url) > MAX_PAYLOAD_URL_LENGTH:
        return ""
    try:
        parts = urlsplit(url)
        host = _norm_host(parts.hostname or "")
    except (ValueError, UnicodeError):
        return ""
    if not host:
        return ""
    return urlunsplit(("", host, _norm_path(parts.path or "/"), "", ""))


def payload_urls(entries) -> list[str]:
    """Canonical URLs carried by payload findings, deduplicated and bounded.

    *entries* are ``ScoreEntry`` objects or finding dictionaries.  A truncated
    URL is dropped rather than guessed at; ``MAX_PAYLOAD_URLS`` caps one
    package's contribution to the cross-package join.
    """
    if entries is None or isinstance(entries, (str, bytes, dict)):
        return []
    out: list[str] = []
    seen: set[str] = set()
    for entry in islice(entries, MAX_PAYLOAD_ENTRIES):
        for text in _entry_texts(entry):
            for match in _URL_RE.finditer(text):
                url = canonical_payload_url(match.group(0).rstrip(_TRAILING))
                if not url or url in seen:
                    continue
                seen.add(url)
                out.append(url)
                if len(out) >= MAX_PAYLOAD_URLS:
                    return out
    return out
