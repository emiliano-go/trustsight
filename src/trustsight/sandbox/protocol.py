"""Length-prefixed JSON frames for the tokenizer sandbox.

A serialisation boundary between two parsers is itself a parser reading
input it did not produce, so it is kept deliberately trivial: a four-byte
big-endian length, then that many UTF-8 bytes of JSON.  Never ``pickle``:
the ``no interpreter or shell execution`` gate forbids unpickling for
exactly this reason, and a sandbox whose channel is a deserialiser has
moved the problem rather than solved it.

Every read carries a size and every frame is capped, so neither side can
make the other allocate an amount it chose (A4, A14).  A write is bounded by
the same deadline as the response read, so a child that stops reading cannot
block the parent in ``write``.  See ``bounded_io`` for the same rule applied
to streams the operator hands in.
"""

import json
import os
import select
import struct
import time

#: One request.  Sized to the *escaping* worst case, not the raw diff:
#: ``json.dumps`` still spells every C0 control byte as a six-byte
#: ``\u00XX`` even with ``ensure_ascii=False``, so a 5 MiB diff of control
#: bytes serialises to about 30 MiB.  A smaller cap is reachable with far
#: less than a full diff of control bytes, which turns a hostile PKGBUILD
#: into a repeatable refusal.  This carries the largest configured diff
#: however it is encoded.
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


def encode_response(obj: object, max_bytes: int | None = None) -> bytes:
    """Serialise *obj* under the response byte cap; return the body.

    The cap is applied *while* the body is built, not to the finished
    string: ``iterencode`` yields the projection in chunks and the
    accumulator stops as soon as the running total passes the ceiling.  An
    over-cap projection therefore costs the cap plus one chunk, rather than
    materialising the whole reply and then refusing it.  The parent's
    response-read cap remains the backstop for a worker that bypasses this.

    A body that cannot be encoded is a named error body, and a lone
    surrogate is replaced rather than raising: both turn a defect into a
    refusal frame instead of a dead worker.
    """
    cap = MAX_RESPONSE_BYTES if max_bytes is None else min(
        max_bytes, MAX_RESPONSE_BYTES)
    if not isinstance(cap, int) or isinstance(cap, bool) or cap < 1:
        raise ValueError("max_bytes must be a positive integer")
    encoder = json.JSONEncoder(ensure_ascii=False, separators=(",", ":"))
    out = bytearray()
    try:
        for chunk in encoder.iterencode(obj):
            out.extend(chunk.encode("utf-8", errors="replace"))
            if len(out) > cap:
                return _response_too_large()
    except Exception as exc:  # a defect here is a refusal, not a dead worker
        return json.dumps(
            {"error": f"response could not be serialised: "
                      f"{type(exc).__name__}"},
            separators=(",", ":"),
        ).encode("ascii")
    return bytes(out)


def _response_too_large() -> bytes:
    """The small body both workers send when a response passes the cap."""
    return json.dumps(
        {"error": "response exceeds the response byte cap"},
        separators=(",", ":"),
    ).encode("utf-8")


def encode(obj: object) -> bytes:
    """Serialise *obj* as one capped frame.

    ``ensure_ascii`` is off so the diff round-trips byte-for-byte; the
    analysis decodes with ``errors=replace``, so there are no lone
    surrogates to fail UTF-8 encoding.  The capped body is what is framed,
    so this convenience path cannot bypass :func:`encode_response`.
    """
    return frame(encode_response(obj))


def frame(body: bytes) -> bytes:
    """Length-prefix one already-serialised body."""
    return _HEADER.pack(len(body)) + body


def write_frame(fd: int, body: bytes, deadline: float) -> None:
    """Write one framed body to *fd* without blocking past *deadline*.

    A length bound alone does not bound the *time* a write takes: a child
    that stops reading its stdin leaves a frame larger than the pipe buffer
    blocked in ``write`` while the parent holds a pool slot.  The descriptor
    is non-blocking and every wait is a ``select`` bounded by the same
    deadline used for the response.

    Raises :class:`FrameError` on timeout, a closed descriptor, or a
    zero-byte write.
    """
    payload = memoryview(frame(body))
    try:
        os.set_blocking(fd, False)
    except OSError:
        pass
    while payload:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise FrameError("timed out writing frame")
        try:
            _, writable, _ = select.select([], [fd], [], remaining)
        except OSError as exc:
            raise FrameError(str(exc)) from exc
        if not writable:
            raise FrameError("timed out writing frame")
        try:
            written = os.write(fd, payload)
        except BlockingIOError:
            continue
        except OSError as exc:
            raise FrameError(f"write failed: {exc}") from exc
        if written <= 0:
            raise FrameError("write made no progress")
        payload = payload[written:]


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


