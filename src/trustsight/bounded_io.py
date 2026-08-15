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
