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

from ..bounded_io import read_file_capped

MAX_UPDATE_CACHE_BYTES = 1024 * 1024

#: How long a fetched release tag is trusted before it is checked again.  The
#: notice still prints on every command; only the network call is throttled.
_TTL_SECONDS = 6 * 60 * 60

#: Set to disable the check entirely (e.g. in a reproducible CI run).
_DISABLE_ENV = "TRUSTSIGHT_NO_UPDATE_CHECK"

#: Set to disable only the baseline/IOC pending notice.
_PENDING_DISABLE_ENV = "TRUSTSIGHT_NO_PENDING_CHECK"

#: Shown when the operator chooses to abort and update.
_UPDATE_HINT = (
    "Update with:\n"
    "  git pull && (cd packaging/aur && makepkg -si)\n"
    "  # or your AUR helper:  paru -Syu trustsight   (yay -Syu trustsight)"
)


def _disabled() -> bool:
    return os.environ.get(_DISABLE_ENV, "").strip().lower() in ("1", "true", "yes")


def _pending_disabled() -> bool:
    # The master switch disables every update check, the pending notice
    # included; `TRUSTSIGHT_NO_PENDING_CHECK` silences only the pending one.
    if _disabled():
        return True
    return os.environ.get(_PENDING_DISABLE_ENV, "").strip().lower() in (
        "1", "true", "yes",
    )


def _cache_path() -> Path:
    from ..config import CACHE_DIR

    return CACHE_DIR / "update-check.json"


def _read_cache(max_age: float) -> str | None:
    """The cached release tag when it is *max_age* seconds old or newer."""
    try:
        data = json.loads(read_file_capped(
            _cache_path(), MAX_UPDATE_CACHE_BYTES, "update cache"))
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


def _pending_cache_path() -> Path:
    from ..config import CACHE_DIR

    return CACHE_DIR / "channel-check.json"


def _read_json_cache(path: Path, max_age: float) -> dict | None:
    try:
        data = json.loads(read_file_capped(
            path, MAX_UPDATE_CACHE_BYTES, "update cache"))
        if time.time() - float(data.get("checked_at", 0)) <= max_age:
            return data
    except Exception:  # noqa: BLE001 - a missing or corrupt cache is a miss
        return None
    return None


def _write_json_cache(path: Path, data: dict) -> None:
    try:
        from ..config import ensure_dirs

        ensure_dirs()
        data = {**data, "checked_at": time.time()}
        path.write_text(json.dumps(data), encoding="utf-8")
    except Exception:  # noqa: BLE001 - the cache is best-effort
        pass


def _watchlist_configured() -> bool:
    """True when the operator has the imported watchlist feed enabled."""
    try:
        from ..config import load_config

        section = load_config().get("baselines", {}).get("watchlist", {})
        return bool(section.get("enabled", True))
    except Exception:  # noqa: BLE001
        return True


def _ioc_feeds_configured() -> bool:
    """True when the operator has at least one enabled IOC feed."""
    try:
        from ..config import load_config

        section = load_config().get("baselines", {}).get("ioc", {})
        if not bool(section.get("enabled", True)):
            return False
        feeds = section.get("feeds", [])
        return any(
            isinstance(feed, dict) and feed.get("enabled", True) for feed in feeds
        )
    except Exception:  # noqa: BLE001
        return False


def _channel_tags() -> dict:
    """The newest baseline/IOC tag on the followed channels, disk-cached."""
    cached = _read_json_cache(_pending_cache_path(), _TTL_SECONDS)
    if cached is not None:
        return cached
    from .. import release

    if release.offline():
        return {}
    data: dict = {}
    try:
        baseline_channel = release.active_baseline_channel()
    except Exception:  # noqa: BLE001 - a bad channel config is not a crash
        baseline_channel = release.official_channel()
    data["baseline"] = release.resolve_baseline_tag(baseline_channel)
    data["baseline_channel"] = baseline_channel.repo
    data["ioc"] = (
        release.resolve_ioc_tag() if _ioc_feeds_configured() else None
    )
    data["watchlist"] = (
        release.resolve_watchlist_tag(baseline_channel)
        if _watchlist_configured() else None
    )
    _write_json_cache(_pending_cache_path(), data)
    return data


def pending_channels() -> list[tuple[str, str, str]]:
    """``(kind, tag, channel)`` for each channel with an unpulled release.

    ``kind`` is ``"baseline"`` or ``"ioc"``.  Empty when the check is
    disabled, offline, or every discovered release has been pulled (recorded
    in :mod:`trustsight.channel_state`).
    """
    if _pending_disabled():
        return []
    tags = _channel_tags()
    if not tags:
        return []
    from .. import channel_state

    pending: list[tuple[str, str, str]] = []
    baseline_channel = str(tags.get("baseline_channel") or "official")
    baseline_tag = tags.get("baseline")
    if baseline_tag and not channel_state.pulled_matches(
            channel_state.BASELINE, str(baseline_tag), baseline_channel):
        pending.append(("baseline", str(baseline_tag), baseline_channel))
    ioc_tag = tags.get("ioc")
    if ioc_tag:
        from .. import release

        # IOC discovery always resolves the official ``ioc-*`` channel, so the
        # notice names it by slug rather than the vague word "official".
        if not channel_state.pulled_matches(
                channel_state.IOC, str(ioc_tag), release.OFFICIAL_REPO):
            pending.append(("ioc", str(ioc_tag), release.OFFICIAL_REPO))
    watchlist_tag = tags.get("watchlist")
    if watchlist_tag and not channel_state.pulled_matches(
            channel_state.WATCHLIST, str(watchlist_tag), baseline_channel):
        pending.append(("watchlist", str(watchlist_tag), baseline_channel))
    return pending


#: Commands that pull the very data the pending notice would offer.  Asking
#: them to pull first would run the same fetch twice in one invocation.
_PULL_COMMANDS = {("seed", "fetch"), ("ioc", "update"),
                  ("watchlist", "update")}


def _is_pull_command() -> bool:
    argv = sys.argv[1:]
    return len(argv) >= 2 and (argv[0], argv[1]) in _PULL_COMMANDS


def _pull_pending(kinds: set[str]) -> None:
    """Pull the pending baseline/IOC data through the shared verified path."""
    from .. import channels

    try:
        notes = channels.auto_pull(
            baselines="baseline" in kinds, iocs="ioc" in kinds,
            watchlists="watchlist" in kinds)
    except Exception as exc:  # noqa: BLE001 - a failed pull must not abort
        print(f"trustsight: pull failed: {exc}", file=sys.stderr)
        return
    for note in notes:
        print(f"trustsight: {note}", file=sys.stderr)


def check_and_warn_pending() -> None:
    """Warn when a newer baseline or IOC release is waiting to be pulled.

    Interactive operators are offered a one-key pull through the same
    verified download/import path as ``seed fetch`` and ``ioc update``.  The
    prompt is skipped when stdin/stderr is not a terminal (so a pipeline is
    never blocked) and when the running command is itself a pull.  Goes
    silent once the pull is recorded, and on every failure.
    """
    try:
        pending = pending_channels()
    except Exception:  # noqa: BLE001 - the notice never breaks a command
        return
    for kind, tag, channel in pending:
        if kind == "baseline":
            print(
                f"trustsight: a newer baseline is available: {tag} "
                f"on {channel}. Pull with 'trustsight seed fetch'.",
                file=sys.stderr,
            )
        elif kind == "ioc":
            print(
                f"trustsight: newer IOCs are available: {tag} "
                f"on {channel}. Pull with 'trustsight ioc update'.",
                file=sys.stderr,
            )
        else:
            print(
                f"trustsight: a newer watchlist is available: {tag} "
                f"on {channel}. Pull with 'trustsight watchlist update'.",
                file=sys.stderr,
            )
    if not pending or not _interactive() or _is_pull_command():
        return
    try:
        print("trustsight: pull now? [y/N] ", file=sys.stderr, end="",
              flush=True)
        answer = input().strip().lower()
    except (EOFError, KeyboardInterrupt):
        print(file=sys.stderr)
        return
    if answer in ("y", "yes"):
        _pull_pending({kind for kind, _tag, _channel in pending})


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
