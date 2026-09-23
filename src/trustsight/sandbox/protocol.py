"""Length-prefixed JSON frames for the tokenizer sandbox.

A serialisation boundary between two parsers is itself a parser reading
input it did not produce, so it is kept deliberately trivial: a four-byte
big-endian length, then that many UTF-8 bytes of JSON.  Never ``pickle``:
the ``no interpreter or shell execution`` gate forbids unpickling for
exactly this reason, and a sandbox whose channel is a deserialiser has
moved the problem rather than solved it.

Every read carries a size and every frame is capped, so neither side can
make the other allocate an amount it chose (A4, A14).  See
``bounded_io`` for the same rule applied to streams the operator hands in.
"""

import json
import struct

#: One request.  Sized to the *escaping* worst case, not the raw diff:
#: ``json.dumps`` still spells every C0 control byte as a six-byte
#: ``\u00XX`` even with ``ensure_ascii=False``, so a 5 MiB diff of control
#: bytes serialises to about 30 MiB.  At 8 MiB the cap was reachable with
#: ~1.4 MiB of control bytes, which turned a hostile PKGBUILD into a
#: repeatable ``TokenizerUnavailable`` (alarm fatigue).  This carries the
#: largest configured diff however it is encoded.
MAX_FRAME_BYTES = 6 * (5 * 1024 * 1024) + 1024 * 1024

#: One response.  A resolved line is capped at 64 KiB and the line count at
#: 20,000, so the worst case is well under this; the cap refuses rather
#: than buffers.
MAX_RESPONSE_BYTES = 32 * 1024 * 1024

_HEADER = struct.Struct(">I")

#: Public alias: the client unpacks a header after a ``select``-bounded read.
HEADER = _HEADER


class FrameError(Exception):
    """A frame was short, oversize, or not framed at all."""


def encode(obj: object) -> bytes:
    """Serialise *obj* as one frame.  ``ensure_ascii`` is off so the diff
    round-trips byte-for-byte; the analysis decodes with ``errors=replace``,
    so there are no lone surrogates to fail UTF-8 encoding."""
    return frame(json.dumps(
        obj, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8"))


def frame(body: bytes) -> bytes:
    """Length-prefix one already-serialised body."""
    return _HEADER.pack(len(body)) + body


def read_exact(fh, n: int) -> bytes:
    """Read exactly *n* bytes from binary *fh*, or raise."""
    out = bytearray()
    while len(out) < n:
        chunk = fh.read(n - len(out))
        if not chunk:
            raise FrameError(f"short read: wanted {n}, got {len(out)}")
        out.extend(chunk)
    return bytes(out)


def read_frame(fh, limit: int = MAX_FRAME_BYTES) -> bytes:
    """Read one frame body from *fh*, refusing past *limit* bytes."""
    (n,) = _HEADER.unpack(read_exact(fh, _HEADER.size))
    if n > limit:
        raise FrameError(f"frame of {n} bytes exceeds the {limit}-byte cap")
    return read_exact(fh, n)


def read_header(fh) -> int:
    """Read just a frame length; the caller enforces the cap."""
    (n,) = _HEADER.unpack(read_exact(fh, _HEADER.size))
    return n
