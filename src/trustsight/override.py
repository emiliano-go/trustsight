import json
import os
import re
import tempfile
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path

from .config import CONFIG_DIR

OVERRIDES_PATH: Path = CONFIG_DIR / "overrides.json"
FATAL_RULES = frozenset({"R012", "R013"})


@dataclass
class RuleOverride:
    rule_id: str
    reason: str
    package: str | None = None
    created_at: str = ""


@dataclass
class SourceUrlAck:
    """One source URL acknowledged for one package.

    A rule override is too coarse for a URL: suppressing SOURCE_BUCKET for
    a package hides the *next* URL the package adds, which is exactly the
    swap TrustSight exists to catch.  An ack names the URL, and only that
    URL in that package stops scoring; a different URL, or the same URL in
    another package, is judged as before.
    """

    package: str
    url: str
    reason: str
    created_at: str = ""


def _now() -> str:
    """return the current UTC time as an ISO-8601 string"""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _validate(rule_id: str, reason: str) -> None:
    """raise ValueError if the reason is empty or the rule is non-overridable"""
    if not reason or not reason.strip():
        raise ValueError("Override reason must be non-empty")
    if rule_id in FATAL_RULES:
        raise ValueError(
            f"Cannot override {rule_id}: FATAL rules are non-overridable"
        )


def _ensure_file() -> None:
    """create the overrides JSON file if it does not exist"""
    if not OVERRIDES_PATH.exists():
        OVERRIDES_PATH.parent.mkdir(parents=True, exist_ok=True)
        OVERRIDES_PATH.write_text(
            json.dumps({"overrides": [], "url_acks": []}, indent=2) + "\n"
        )


def _load_file() -> dict:
    """The overrides file as a dict, or an empty one when unreadable.

    The file is documented as hand-editable, so damage at the file level
    (invalid JSON, an unreadable file, non-UTF-8 text) loads as "nothing
    configured" rather than crashing every analysis.  Rule overrides and
    URL acks share the file, so every writer has to preserve the other
    key; reading through one loader is what keeps them from erasing each
    other.
    """
    _ensure_file()
    try:
        data = json.loads(OVERRIDES_PATH.read_text())
    except (json.JSONDecodeError, OSError, UnicodeDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def _save_file(data: dict) -> None:
    """Write the overrides file atomically."""
    _ensure_file()
    content = json.dumps(data, indent=2) + "\n"
    fd, tmp = tempfile.mkstemp(dir=OVERRIDES_PATH.parent, suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(content)
        os.replace(tmp, OVERRIDES_PATH)
    except Exception:
        Path(tmp).unlink(missing_ok=True)
        raise


_OVERRIDE_FIELDS = frozenset({"rule_id", "reason", "package", "created_at"})
_URL_ACK_FIELDS = frozenset({"package", "url", "reason", "created_at"})


def load_overrides() -> list[RuleOverride]:
    """Load overrides from the overrides JSON file.

    An entry carrying an unexpected key or missing ``rule_id`` is skipped
    rather than allowed to raise: a single typo used to abort every command
    with a TypeError.
    """
    entries = _load_file().get("overrides", [])
    if not isinstance(entries, list):
        return []
    loaded: list[RuleOverride] = []
    for entry in entries:
        if not isinstance(entry, dict) or not entry.get("rule_id"):
            continue
        known = {k: v for k, v in entry.items() if k in _OVERRIDE_FIELDS}
        # Null reason/created_at from a hand edit must not crash the
        # rendering path (strip_ansi(None) raises); coerce to "" instead.
        if known.get("reason") is None:
            known["reason"] = ""
        if known.get("created_at") is None:
            known["created_at"] = ""
        try:
            loaded.append(RuleOverride(**known))
        except TypeError:
            continue
    return loaded


def save_overrides(overrides: list[RuleOverride]) -> None:
    """Save overrides to the overrides JSON file atomically"""
    data = _load_file()
    data["overrides"] = [asdict(o) for o in overrides]
    _save_file(data)


def load_url_acks() -> list[SourceUrlAck]:
    """Load acknowledged source URLs, skipping malformed entries."""
    entries = _load_file().get("url_acks", [])
    if not isinstance(entries, list):
        return []
    loaded: list[SourceUrlAck] = []
    for entry in entries:
        if not isinstance(entry, dict) or not entry.get("url") or not entry.get("package"):
            continue
        known = {k: v for k, v in entry.items() if k in _URL_ACK_FIELDS}
        if known.get("reason") is None:
            known["reason"] = ""
        if known.get("created_at") is None:
            known["created_at"] = ""
        try:
            loaded.append(SourceUrlAck(**known))
        except TypeError:
            continue
    return loaded


def save_url_acks(acks: list[SourceUrlAck]) -> None:
    """Save acknowledged source URLs to the overrides JSON file atomically"""
    data = _load_file()
    data["url_acks"] = [asdict(a) for a in acks]
    _save_file(data)


def _ack_key(url: str) -> str:
    """The comparison form of a URL: cleaned, then normalised.

    Normalisation is what makes an ack survive a routine version bump:
    ``.../v2.0.0.tar.gz`` and ``.../v2.0.1.tar.gz`` are the same source
    URL, so acknowledging one acknowledges the other.  A different path,
    host or package is still a different URL.
    """
    from .differ import _clean_url
    from .novelty import normalize_url

    return normalize_url(_clean_url(url.strip()))


def add_url_ack(package: str, url: str, reason: str) -> SourceUrlAck:
    """Acknowledge *url* for *package* and persist it."""
    if not package or not package.strip():
        raise ValueError("An acknowledged URL needs a package")
    if not url or not url.strip():
        raise ValueError("An acknowledged URL needs a URL")
    if not reason or not reason.strip():
        raise ValueError("Acknowledgement reason must be non-empty")
    acks = load_url_acks()
    ack = SourceUrlAck(
        package=package.strip(),
        url=_OVERRIDE_SANITIZE.sub(" ", url.strip()),
        reason=_OVERRIDE_SANITIZE.sub(" ", reason.strip()),
        created_at=_now(),
    )
    # An identical ack already present is replaced, not duplicated, so
    # adding twice is idempotent and a stale reason cannot linger.
    key = _ack_key(ack.url)
    kept = [
        a for a in acks
        if not (a.package == ack.package and _ack_key(a.url) == key)
    ]
    kept.append(ack)
    save_url_acks(kept)
    return ack


def remove_url_ack(package: str, url: str) -> bool:
    """Remove the ack matching *url* for *package*; False when none did."""
    key = _ack_key(url)
    acks = load_url_acks()
    before = len(acks)
    acks = [
        a for a in acks
        if not (a.package == package and _ack_key(a.url) == key)
    ]
    if len(acks) == before:
        return False
    save_url_acks(acks)
    return True


def list_url_acks() -> list[SourceUrlAck]:
    """Return all acknowledged source URLs."""
    return load_url_acks()


def match_url_acks(
    package: str, urls: "list[str]"
) -> dict[str, SourceUrlAck]:
    """Map each URL in *urls* to the ack that covers it, if any.

    The returned dict is keyed by the URL as it was passed in, so the
    caller can filter the original list without re-normalising.
    """
    acks = [a for a in load_url_acks() if a.package == package]
    if not acks:
        return {}
    by_key = {_ack_key(a.url): a for a in acks}
    matched: dict[str, SourceUrlAck] = {}
    for url in urls:
        ack = by_key.get(_ack_key(url))
        if ack is not None:
            matched[url] = ack
    return matched


def acknowledged_url_rows(
    matched: dict[str, SourceUrlAck]
) -> list[dict]:
    """The report rows for acknowledged URLs, visible and non-scoring."""
    return [
        {"url": url, "reason": ack.reason}
        for url, ack in sorted(matched.items())
    ]


_OVERRIDE_SANITIZE = re.compile(r"[\x00-\x1F\x7F]")


def add_override(
    rule_id: str, reason: str, package: str | None = None
) -> RuleOverride:
    """Add a new override and persist it to disk"""
    _validate(rule_id, reason)
    overrides = load_overrides()
    override = RuleOverride(
        rule_id=rule_id.upper(),
        reason=_OVERRIDE_SANITIZE.sub(" ", reason.strip()),
        package=package,
        created_at=_now(),
    )
    # An identical override already present is replaced, not duplicated:
    # adding twice is idempotent and a stale reason cannot linger.
    kept = [
        o
        for o in overrides
        if not (o.rule_id == override.rule_id and o.package == override.package)
    ]
    kept.append(override)
    save_overrides(kept)
    return override


def remove_override(rule_id: str, package: str | None = None) -> bool:
    """Remove matching overrides and persist the change"""
    overrides = load_overrides()
    before = len(overrides)
    overrides = [
        o
        for o in overrides
        if not (o.rule_id == rule_id and o.package == package)
    ]
    if len(overrides) == before:
        return False
    save_overrides(overrides)
    return True


def list_overrides() -> list[RuleOverride]:
    """Return all stored overrides"""
    return load_overrides()


def get_active_overrides(
    rule_id: str | None = None, package: str | None = None
) -> list[RuleOverride]:
    """Return overrides matching the given rule_id and/or package"""
    all_ = load_overrides()
    result = []
    for o in all_:
        if rule_id is not None and o.rule_id != rule_id:
            continue
        if package is not None and o.package is not None and o.package != package:
            continue
        result.append(o)
    return result


def filter_triggered_rules(
    triggered_rules: list[dict], package: str | None = None
) -> tuple[list[dict], list[dict]]:
    """Drop overridden rules from *triggered_rules*.

    Returns ``(kept, suppressed)``.  Suppressed findings are returned
    rather than discarded so the report can state what was hidden and
    why: a silent suppression is indistinguishable from a missed
    detection.

    A FATAL finding is never suppressed, whatever the overrides file
    says.  :func:`add_override` refuses to create one, but the file is
    user-editable, and prompt injection and unicode deception are the
    two things an attacker would most want switched off.
    """
    overrides = load_overrides()
    if not overrides:
        return triggered_rules, []

    active = [
        o for o in overrides
        if o.package is None or (package is not None and o.package == package)
    ]
    by_id = {o.rule_id: o for o in active}

    kept: list[dict] = []
    suppressed: list[dict] = []
    for rule in triggered_rules:
        override = by_id.get(rule["rule_id"])
        if override is None or rule.get("severity") == "FATAL":
            kept.append(rule)
            continue
        suppressed.append({**rule, "override_reason": override.reason,
                           "override_package": override.package})
    return kept, suppressed
