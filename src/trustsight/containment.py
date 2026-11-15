"""Read the runtime containment controls this process actually sees."""

from __future__ import annotations

import os
from pathlib import Path

__all__ = ["status"]


def _read(path: str) -> str:
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _seccomp(path: str) -> bool:
    for line in _read(path).split("\n"):
        if line.startswith("Seccomp:"):
            return line.split(":", 1)[1].strip() == "2"
    return False


def _apparmor(path: str) -> str:
    text = _read(path).strip()
    return text.split(" ", 1)[0] if text else ""


def _has_default_route(route: str, route6: str) -> bool:
    for line in _read(route).split("\n")[1:]:
        parts = line.split()
        if (len(parts) > 7 and parts[0] != "lo"
                and parts[1] == "00000000" and parts[7] == "00000000"):
            return True
    for line in _read(route6).split("\n"):
        parts = line.split()
        if (len(parts) > 1 and parts[-1] != "lo"
                and set(parts[0]) == {"0"} and parts[1] == "00"):
            return True
    return False


def _root_readonly(mountinfo: str) -> bool:
    for line in _read(mountinfo).split("\n"):
        parts = line.split()
        if len(parts) < 7 or parts[4] != "/":
            continue
        options = {option for option in parts[5].split(",")}
        return "ro" in options
    return False


def status(*, status_path: str = "/proc/self/status",
           attr_path: str = "/proc/self/attr/current",
           route_path: str = "/proc/net/route",
           route6_path: str = "/proc/net/ipv6_route",
           mountinfo_path: str = "/proc/self/mountinfo",
           euid: int | None = None) -> dict:
    """Return the controls that are actually active in this process."""
    return {
        "uid": os.geteuid() if euid is None else euid,
        "root_readonly": _root_readonly(mountinfo_path),
        "seccomp_filter": _seccomp(status_path),
        "apparmor_profile": _apparmor(attr_path),
        "default_route": _has_default_route(route_path, route6_path),
    }
