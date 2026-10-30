"""Shared helpers for the private temporal finding emitters."""

from __future__ import annotations

from ..findings import stamp

_SEVERITY = {
    "H045": "HIGH", "H052": "HIGH", "H055": "MEDIUM", "H073": "MEDIUM",
    "H044": "MEDIUM", "H074": "MEDIUM", "H026": "HIGH",
    "H053": "MEDIUM", "H058": "MEDIUM", "H059": "MEDIUM",
}


def _threshold(rule: str, key: str, default):
    # Resolve through the engine at call time so its threshold patching and
    # configuration surface remain authoritative for every extracted emitter.
    from .temporal_engine import _threshold as engine_threshold

    return engine_threshold(rule, key, default)


def _maintainer(entry: dict | None) -> str:
    if not entry:
        return ""
    return (entry.get("Maintainer") or "").strip().lower()


def _last_modified(entry: dict | None) -> int | None:
    if not entry:
        return None
    lm = entry.get("LastModified")
    return int(lm) if isinstance(lm, (int, float)) and lm else None


def _package_base(entry: dict | None) -> str:
    if not entry:
        return ""
    return (entry.get("PackageBase") or entry.get("Name") or "").strip()


def _host_of(url: str) -> str:
    rest = url.split("://", 1)[-1]
    return rest.split("/", 1)[0].split("?")[0].split("#")[0].lower()


def _repo_owner(url: str) -> tuple[str, str] | None:
    """``(host, first path segment)`` for a normalized source URL.

    One upstream org often publishes differently named packages from one
    repository owner; grouping a batch by name alone missed that shape.
    """
    rest = url.split("://", 1)[-1]
    rest = rest.split("?", 1)[0].split("#", 1)[0]
    if "/" not in rest:
        return None
    host, path = rest.split("/", 1)
    owner = path.strip("/").split("/", 1)[0]
    if not host or not owner:
        return None
    if owner.endswith(".git"):
        owner = owner[:-4]
    return host.lower(), owner.lower()


def _cluster(rule: str, name: str, match: str, members: list[str],
             severity: str | None = None, category: str = "adoption",
             **extra) -> dict:
    finding = {
        "rule_id": rule,
        "name": name,
        "severity": severity or _SEVERITY.get(rule, "MEDIUM"),
        "category": category,
        "match": match,
        "params": {"members": members, "member_count": len(members), **extra},
    }
    return stamp(finding)
