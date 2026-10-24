"""Reads that refuse rather than truncate.

A4 says every read is bounded, and A14 says no package-controlled input
decides how much memory this process uses.  A read with no size argument
breaks both: the amount allocated is then whatever the other end declares,
and the other end is the party under review.  A tar member declaring thirty
gigabytes costs nothing to write and is read into memory in full.

Two rules, and the second is the one that keeps A5 and A6 honest:

* The limit is a constant the caller passes in, never a value derived from
  the stream being read.
* Exceeding the limit is a **refusal**, never a truncation.  A truncated
  read looks like a complete one with its tail quietly removed, which is
  the silent-skip class B2 exists to prevent.  The caller decides what a
  refusal means; it never gets handed a short buffer that reads as whole.
"""

from pathlib import Path
from typing import BinaryIO

#: Chunk size for a capped read.  Not a security bound: it only decides how
#: often the running total is checked, and the total is what refuses.
_CHUNK_BYTES = 1024 * 1024


class ReadTooLarge(Exception):
    """Raised when a bounded read would materialise more than its limit."""


class ReadTimedOut(Exception):
    """Raised when a bounded read runs past its total wall-clock deadline."""


def read_capped(fh: BinaryIO, limit: int, what: str) -> bytes:
    """Read *fh* to EOF, refusing past *limit* bytes.

    *what* names the source in the refusal, because the operator needs to
    know which artifact was rejected, not merely that something was.
    """
    out = bytearray()
    while True:
        chunk = fh.read(_CHUNK_BYTES)
        if not chunk:
            break
        out.extend(chunk)
        if len(out) > limit:
            raise ReadTooLarge(
                f"{what} exceeds {limit} bytes; refusing to read it"
            )
    return bytes(out)


def _bound_socket_timeout(fh: BinaryIO, remaining: float) -> None:
    """Cap the underlying socket wait at the remaining wall-clock budget.

    A logical deadline checked only between reads is not a deadline:
    ``HTTPResponse.read(n)`` blocks until it has ``n`` bytes, so one slow
    chunk can outlive the budget.  This lowers the socket timeout when the
    response exposes a real socket and leaves synthetic readers untouched.
    """
    sock = getattr(getattr(getattr(fh, "fp", None), "raw", None), "_sock", None)
    if sock is None:
        return
    try:
        current = sock.gettimeout()
        if current is None or current > remaining:
            sock.settimeout(remaining)
    except (OSError, ValueError):
        # A synthetic or already-closed transport: the logical deadline below
        # still refuses, and the caller's per-op timeout remains the bound.
        pass


def read_capped_with_deadline(
    fh: BinaryIO, limit: int, what: str, deadline_seconds: float
) -> bytes:
    """Read *fh* to EOF under a byte cap *and* a total wall-clock deadline.

    ``urlopen(timeout=...)`` bounds a single socket operation, not the
    download: a slow-drip server resets it on every chunk, so a response
    can be held open indefinitely while staying under the byte cap.  This
    charges the whole transfer one deadline, checks it before every read,
    and lowers the socket timeout to the remaining budget.  ``read1`` is
    preferred when available so one call cannot demand the whole remaining
    body; a reader without it still gets the between-read deadline check.
    """
    import time

    deadline = time.monotonic() + deadline_seconds
    out = bytearray()
    read1 = getattr(fh, "read1", None)
    reader = read1 if callable(read1) else fh.read
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ReadTimedOut(
                f"{what} exceeded its {deadline_seconds:g}s deadline; refusing "
                "to keep reading"
            )
        _bound_socket_timeout(fh, remaining)
        chunk = reader(_CHUNK_BYTES)
        if not chunk:
            break
        out.extend(chunk)
        if len(out) > limit:
            raise ReadTooLarge(
                f"{what} exceeds {limit} bytes; refusing to read it"
            )
    return bytes(out)


def read_file_capped(path: Path, limit: int, what: str) -> bytes:
    """Read *path* whole, refusing past *limit* bytes.

    The size on disk is checked first so an oversized file is refused
    without being read at all, and the streaming read still applies: a file
    that grows between the stat and the read is bounded by the loop.
    """
    try:
        declared = path.stat().st_size
    except OSError:
        declared = -1
    if declared > limit:
        raise ReadTooLarge(
            f"{what} is {declared} bytes, over the {limit}-byte limit; "
            "refusing to read it"
        )
    with open(path, "rb") as fh:
        return read_capped(fh, limit, what)
