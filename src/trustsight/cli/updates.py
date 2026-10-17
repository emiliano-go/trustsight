"""The once-a-command "a newer TrustSight exists" notice.

TrustSight is an evidence tool: a version behind may simply not know about a
detection its next release adds.  So every command checks the published
release tag against the running version and, when a newer one exists, warns -
and offers to abort so the operator can update first.

The check is deliberately cheap and quiet:

* the result is cached on disk for a few hours, so the notice shows on every
  command without a network request on every command;
* it is skipped when ``TRUSTSIGHT_OFFLINE`` or ``TRUSTSIGHT_NO_UPDATE_CHECK``
  is set, and on any failure (offline, rate-limited, unparseable) it says
  nothing rather than guessing;
* it never prompts when stdin or stderr is not a terminal, so a pipeline is
  never blocked and ``--json`` output is never polluted (the notice goes to
  stderr).
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

import typer

#: How long a fetched release tag is trusted before it is checked again.  The
#: notice still prints on every command; only the network call is throttled.
_TTL_SECONDS = 6 * 60 * 60

#: Set to disable the check entirely (e.g. in a reproducible CI run).
_DISABLE_ENV = "TRUSTSIGHT_NO_UPDATE_CHECK"

#: Shown when the operator chooses to abort and update.
_UPDATE_HINT = (
    "Update with:\n"
    "  git pull && (cd packaging/aur && makepkg -si)\n"
    "  # or your AUR helper:  paru -Syu trustsight   (yay -Syu trustsight)"
)


def _disabled() -> bool:
    return os.environ.get(_DISABLE_ENV, "").strip().lower() in ("1", "true", "yes")


def _cache_path() -> Path:
    from ..config import CACHE_DIR

    return CACHE_DIR / "update-check.json"


def _read_cache(max_age: float) -> str | None:
    """The cached release tag when it is *max_age* seconds old or newer."""
    try:
        data = json.loads(_cache_path().read_text(encoding="utf-8"))
        if time.time() - float(data.get("checked_at", 0)) <= max_age:
            return str(data.get("latest", "") or "") or None
    except Exception:  # noqa: BLE001 - a missing or corrupt cache is a miss
        return None
    return None


def _write_cache(latest: str | None) -> None:
    try:
        from ..config import ensure_dirs

        ensure_dirs()
        _cache_path().write_text(
            json.dumps({"checked_at": time.time(), "latest": latest or ""}),
            encoding="utf-8",
        )
    except Exception:  # noqa: BLE001 - the cache is best-effort
        pass


def newer_version() -> tuple[str, str] | None:
    """``(current, latest)`` when a newer release exists, else ``None``.

    *latest* has no leading ``v``.  Returns ``None`` when the check is
    disabled, offline, or cannot determine the release tag.
    """
    if _disabled():
        return None
    from .. import __version__
    from .. import release

    latest = _read_cache(_TTL_SECONDS)
    if latest is None:
        # Offline: use no network and write nothing, so the next online run
        # still checks.  A cached tag is used regardless, which is the whole
        # point of caching it.
        if release.offline():
            return None
        latest = release.latest_release_tag() or ""
        # Cache a negative result too, so a rate-limited or unreachable host
        # costs one attempt per TTL rather than one per command.
        _write_cache(latest)
    if latest and release.is_newer(latest, __version__):
        return __version__, latest.lstrip("v")
    return None


def _interactive() -> bool:
    """True only when a prompt is safe: both stdin and stderr are terminals."""
    return sys.stdin.isatty() and sys.stderr.isatty()


def check_and_warn() -> None:
    """Warn when a newer release exists, and offer to abort.

    Stays silent on every failure, and the only exception it can raise is the
    deliberate ``typer.Exit(2)`` when the operator chooses to abort.
    """
    try:
        found = newer_version()
    except Exception:  # noqa: BLE001 - the notice never breaks a command
        return
    if not found:
        return
    current, latest = found
    print(
        f"trustsight: a newer release is available: v{latest} "
        f"(you are running v{current}).",
        file=sys.stderr,
    )
    if not _interactive():
        print(
            "trustsight: update with `git pull && makepkg -si`, or "
            "`paru -Syu trustsight`.",
            file=sys.stderr,
        )
        return
    try:
        answer = input("Abort this command to update first? [y/N] ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print(file=sys.stderr)
        return
    if answer in ("y", "yes"):
        print(_UPDATE_HINT, file=sys.stderr)
        raise typer.Exit(code=2)
