import json
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


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _validate(rule_id: str, reason: str) -> None:
    if not reason or not reason.strip():
        raise ValueError("Override reason must be non-empty")
    if rule_id in FATAL_RULES:
        raise ValueError(
            f"Cannot override {rule_id}: FATAL rules are non-overridable"
        )


def _ensure_file() -> None:
    if not OVERRIDES_PATH.exists():
        OVERRIDES_PATH.parent.mkdir(parents=True, exist_ok=True)
        OVERRIDES_PATH.write_text(json.dumps({"overrides": []}, indent=2) + "\n")


def load_overrides() -> list[RuleOverride]:
    _ensure_file()
    try:
        data = json.loads(OVERRIDES_PATH.read_text())
    except (json.JSONDecodeError, OSError):
        return []
    return [RuleOverride(**o) for o in data.get("overrides", [])]


def save_overrides(overrides: list[RuleOverride]) -> None:
    _ensure_file()
    OVERRIDES_PATH.write_text(
        json.dumps({"overrides": [asdict(o) for o in overrides]}, indent=2) + "\n"
    )


def add_override(
    rule_id: str, reason: str, package: str | None = None
) -> RuleOverride:
    _validate(rule_id, reason)
    overrides = load_overrides()
    override = RuleOverride(
        rule_id=rule_id.upper(),
        reason=reason.strip(),
        package=package,
        created_at=_now(),
    )
    overrides.append(override)
    save_overrides(overrides)
    return override


def remove_override(rule_id: str, package: str | None = None) -> bool:
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
    return load_overrides()


def get_active_overrides(
    rule_id: str | None = None, package: str | None = None
) -> list[RuleOverride]:
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
