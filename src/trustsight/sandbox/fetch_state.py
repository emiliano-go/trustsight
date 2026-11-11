"""Parent-owned fetch state (A16).

The worker owns the repository on disk, so anything it can write inside that
repository is attacker-controlled once libgit2 is compromised.  The freshness
marker used to live there and was read by the parent with ``read_text`` - a
symlink, FIFO or huge file created by the worker could therefore be followed,
blocked on, or read unbounded by the *unconfined* side.

This module keeps that state outside the worker's Landlock view: a small JSON
record per package, in a parent-created ``.fetch-state`` directory.  Reads use
``O_NOFOLLOW | O_NONBLOCK`` and a fixed cap; writes are atomic and mode 0600.
The record also carries the advertised and actual HEAD so a compromised fetch
worker cannot substitute a different commit without the parent noticing.
"""

from __future__ import annotations

import json
import os
import stat
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path

__all__ = ["FetchState", "load", "store", "state_dir"]

_STATE_DIRECTORY = ".fetch-state"
_MAX_STATE_BYTES = 8192
_STATE_VERSION = 1
_PKG_CHARS = frozenset("abcdefghijklmnopqrstuvwxyz"
                       "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@._+-")
_HEX = frozenset("0123456789abcdefABCDEF")


@dataclass(frozen=True)
class FetchState:
    head: str
    advertised_head: str
    fetched_at: int
    upstream_mtime: int | None
    verified: bool


def _valid_pkg(pkg: object) -> bool:
    return (
        isinstance(pkg, str)
        and bool(pkg)
        and pkg not in (".", "..")
        and all(character in _PKG_CHARS for character in pkg)
    )


def _is_oid(value: object) -> bool:
    return (isinstance(value, str) and len(value) in (40, 64)
            and all(character in _HEX for character in value))


def state_dir(cache_root: str | Path) -> Path:
    return Path(cache_root) / _STATE_DIRECTORY


def _ensure_state_dir(cache_root: str | Path) -> Path:
    directory = state_dir(cache_root)
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        os.chmod(directory, 0o700)
    except OSError:
        pass
    return directory


def _state_path(cache_root: str | Path, pkg: str) -> Path:
    return state_dir(cache_root) / f"{pkg}.json"


def _read_bounded(fd: int) -> bytes:
    data = bytearray()
    while len(data) <= _MAX_STATE_BYTES:
        chunk = os.read(fd, _MAX_STATE_BYTES + 1 - len(data))
        if not chunk:
            break
        data.extend(chunk)
    return bytes(data)


def load(cache_root: str | Path, pkg: str) -> FetchState | None:
    """Read a trusted state record, or None when it is absent or unusable.

    The file is never followed through a symlink and never read past the cap.
    A FIFO is opened non-blocking and then rejected as a non-regular file.
    """
    if not _valid_pkg(pkg):
        return None
    path = _state_path(cache_root, pkg)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
                     | os.O_CLOEXEC)
    except OSError:
        return None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > _MAX_STATE_BYTES:
            return None
        raw = _read_bounded(fd)
    except OSError:
        return None
    finally:
        os.close(fd)
    if len(raw) > _MAX_STATE_BYTES:
        return None
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None
    if not isinstance(document, dict) or document.get("version") != _STATE_VERSION:
        return None
    try:
        state = FetchState(
            head=str(document["head"]),
            advertised_head=str(document["advertised_head"]),
            fetched_at=int(document["fetched_at"]),
            upstream_mtime=(None if document.get("upstream_mtime") is None
                            else int(document["upstream_mtime"])),
            verified=document["verified"] is True,
        )
    except (KeyError, TypeError, ValueError):
        return None
    if not state.verified:
        return None
    if not _is_oid(state.head) or not _is_oid(state.advertised_head):
        return None
    if document.get("package") not in (None, pkg):
        return None
    return state


def store(cache_root: str | Path, pkg: str, state: FetchState) -> None:
    """Write *state* atomically in the parent-owned state directory."""
    if not _valid_pkg(pkg):
        raise ValueError(f"invalid package name: {pkg!r}")
    if not state.verified or not _is_oid(state.head) \
            or not _is_oid(state.advertised_head):
        raise ValueError("refusing to store an unverified or malformed fetch state")
    directory = _ensure_state_dir(cache_root)
    document = {"version": _STATE_VERSION, "package": pkg, **asdict(state)}
    payload = json.dumps(document, sort_keys=True,
                         separators=(",", ":")).encode("utf-8")
    descriptor, temporary = tempfile.mkstemp(
        dir=directory, prefix=f".{pkg}.", suffix=".tmp")
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, _state_path(cache_root, pkg))
    except Exception:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise
