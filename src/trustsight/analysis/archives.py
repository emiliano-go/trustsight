"""R122 — archive trailer anomaly (pure function).

``check_archive_trailer(data)`` decides whether *data* carries bytes past
the end of the archive it contains, returning a stamped finding when it
does.  The function is deliberately pure: it takes bytes, returns a finding
or None, and knows nothing about where the bytes came from.  That keeps it
offline-testable with fixtures and lets it compose with any future byte
source — a corpus-side fetch on your own infrastructure, a user-supplied
local file, or a cached tarball.

Threat-model note (see the plan spec §4): fetching attacker-declared
``source=`` URLs must never happen in the ``review`` path.  Downloading
arbitrary URLs at analysis time turns the reviewer into an SSRF probe, tells
the attacker who scanned them, and is a DoS vector.  If R122 ever runs live,
the bytes belong to a corpus-side fetch where downloads are centralised,
rate-limited, and distributed as facts — never to a user's review.
"""

import gzip
import io
import struct
import zlib

from ..findings import stamp

_GZIP_HEADER = b"\x1f\x8b\x08"
_TAR_END_BLOCK = b"\x00" * 1024
_ZIP_EOCD = b"PK\x05\x06"

_MIN_GZIP_TRAILER = 8  # CRC32 + ISIZE


def _gzip_member_end(data: bytes, start: int) -> int | None:
    """Offset just past the trailer of the gzip member beginning at *start*.

    Returns None when the member is malformed (a corrupted header, an
    unterminated deflate stream, or a header that runs off the buffer).
    """
    if data[start : start + 3] != _GZIP_HEADER:
        return None
    if len(data) < start + 10:
        return None
    flag = data[start + 3]
    if (flag & 0x04) and len(data) >= start + 12:  # FEXTRA
        xlen = struct.unpack("<H", data[start + 10 : start + 12])[0]
        header_end = start + 12 + xlen
    else:
        header_end = start + 10
    for extra in (0x08, 0x10):  # FNAME, FCOMMENT — null-terminated
        if flag & extra:
            if header_end >= len(data):
                return None
            nul = data.find(b"\x00", header_end)
            if nul == -1:
                return None
            header_end = nul + 1
    if flag & 0x02:  # FHCRC
        header_end += 2
    if header_end >= len(data):
        return None

    decompressor = zlib.decompressobj(-zlib.MAX_WBITS)
    try:
        decompressor.decompress(data[header_end:])
    except zlib.error:
        return None
    consumed = len(data[header_end:]) - len(decompressor.unused_data)
    return header_end + consumed + _MIN_GZIP_TRAILER


def _gzip_trailing_bytes(data: bytes) -> int | None:
    """Offset where trailing non-member data begins, or None when clean."""
    pos = 0
    while pos < len(data):
        end = _gzip_member_end(data, pos)
        if end is None:
            # A byte run past the last valid member that is not a gzip
            # header is appended data.
            if data[pos : pos + 3] != _GZIP_HEADER:
                return pos
            return None
        pos = end
    return None


def _tar_trailing_bytes(data: bytes) -> int | None:
    """Offset where data past the end-of-archive marker begins, or None."""
    idx = data.rfind(_TAR_END_BLOCK)
    if idx == -1:
        # No end-of-archive zero blocks: either truncated, or trailing
        # garbage was appended after them.  Only flag when the tail is
        # not itself a clean block boundary.
        return None
    end = idx + len(_TAR_END_BLOCK)
    if data[end:].strip(b"\x00"):
        return end
    return None


def _zip_trailing_bytes(data: bytes) -> int | None:
    """Offset where bytes after the end-of-central-directory begin, or None.

    Appended data after the EOCD is a classic polyglot form.  The EOCD
    record is 22 fixed bytes (signature plus 18) followed by an optional
    comment; a normal zip has the record as its last bytes, so any non-empty
    tail is anomalous.
    """
    idx = data.rfind(_ZIP_EOCD)
    if idx == -1:
        return None
    comment_len = struct.unpack("<H", data[idx + 20 : idx + 22])[0]
    end = idx + 22 + comment_len
    if end > len(data):
        return None
    if data[end:]:
        return end
    return None


def check_archive_trailer(data: bytes) -> dict | None:
    """Return an R122 finding when *data* carries bytes past its trailer.

    Recognised containers: gzip (including concatenated members), plain
    tar, and zip.  A clean archive returns None.  Malformed input returns
    None rather than a guess — a truncated or corrupt archive is reported
    by the extraction step, not by this rule.
    """
    if not isinstance(data, (bytes, bytearray)):
        return None
    data = bytes(data)
    if len(data) < 12:
        return None

    if data[:3] == _GZIP_HEADER:
        offset = _gzip_trailing_bytes(data)
        if offset is not None:
            return stamp({
                "rule_id": "R122", "name": "Archive Trailer Anomaly",
                "severity": "HIGH", "category": "integrity",
                "match": f"{len(data) - offset} trailing bytes past the gzip trailer",
                "params": {"kind": "gzip", "trailing_bytes": len(data) - offset,
                           "offset": offset},
            })
        return None

    if data.startswith(b"PK\x03\x04") or data.startswith(_ZIP_EOCD):
        offset = _zip_trailing_bytes(data)
        if offset is not None:
            return stamp({
                "rule_id": "R122", "name": "Archive Trailer Anomaly",
                "severity": "HIGH", "category": "integrity",
                "match": f"{len(data) - offset} bytes after the end-of-central-directory",
                "params": {"kind": "zip", "trailing_bytes": len(data) - offset,
                           "offset": offset},
            })
        return None

    if _TAR_END_BLOCK in data:
        offset = _tar_trailing_bytes(data)
        if offset is not None:
            return stamp({
                "rule_id": "R122", "name": "Archive Trailer Anomaly",
                "severity": "HIGH", "category": "integrity",
                "match": f"{len(data) - offset} bytes past the tar end-of-archive marker",
                "params": {"kind": "tar", "trailing_bytes": len(data) - offset,
                           "offset": offset},
            })

    return None


def _gzip_bytes(payload: bytes) -> bytes:
    """Compress *payload* as a single gzip member (test helper)."""
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb", mtime=0) as gz:
        gz.write(payload)
    return buf.getvalue()
