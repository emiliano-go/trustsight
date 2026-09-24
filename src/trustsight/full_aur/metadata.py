"""AUR metadata dump fetch and diff.

Downloads ``packages-meta-ext-v1.json.gz`` from the AUR to discover which
packages have changed since the last observation.  One request gives the
full metadata state (maintainer, version, LastModified, depends, provides)
for every package.
"""

import gzip
import io
import json
import logging
import os
import threading
import time
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

log = logging.getLogger(__name__)

_METADATA_URL = "https://aur.archlinux.org/packages-meta-ext-v1.json.gz"

# Ceiling on anything gunzipped from the network or from an imported
# artifact.  The real dump is ~250 MB of JSON; a gzip member is free to
# claim far more, and decompressing it to find out is the whole attack.
#
# Chosen against the *parsed* size, not the wire size, which is the part
# that was previously missed. `json.loads` turns a byte string into Python
# objects at roughly a 6x amplification for dump-shaped data - many small
# dicts and short strings - so a 1 GiB ceiling permitted about 6 GiB of
# live objects and would take most machines out of memory. At 512 MiB the
# worst case is ~3 GiB, which is twice what today's legitimate dump already
# costs to parse, so there is room for the AUR to grow without the ceiling
# becoming the thing that decides how much RAM this process uses.
MAX_DECOMPRESSED_BYTES = 512 * 1024 * 1024

#: Measured amplification from serialised JSON to live Python objects for
#: dump-shaped data. Documented so the ceiling above can be re-derived
#: rather than guessed at if the shape changes.
JSON_OBJECT_AMPLIFICATION = 6

# A stalled connection is a hang with no upper bound, and this fetch sits
# on the default `review` path, so it is the one that would hang.  The
# value is generous because the dump is tens of megabytes: it bounds a
# dead socket, not a slow one.
HTTP_TIMEOUT = 300

#: Total wall-clock budget for the metadata download.  ``HTTP_TIMEOUT`` is a
#: per-socket-operation timeout and resets on every chunk, so a slow server
#: can hold the response open indefinitely under the byte cap.
DOWNLOAD_DEADLINE_SECONDS = 900

# The compressed dump is ~60 MB.  Reading a response with no ceiling lets
# the remote end decide how much of this machine's memory to use, which is
# the same reason full_aur/fetch.py caps its own reads.
MAX_RESPONSE_BYTES = 512 * 1024 * 1024

# How long a saved snapshot may be compared against before it is refetched.
# The AUR regenerates the dump every few minutes, so an old snapshot does not
# report "no data" - it reports every installed package as current, which is
# the one wrong answer this tool must never give quietly.  An hour matches
# ``[discovery] cache_ttl_minutes``, which bounds the RPC fallback the same
# way; it is overridable as ``[discovery] metadata_ttl_minutes``.
DEFAULT_TTL_MINUTES = 60


class ResponseTooLarge(Exception):
    """Raised when the metadata response exceeds MAX_RESPONSE_BYTES."""


class DecompressionTooLarge(Exception):
    """Raised when a gzip stream exceeds MAX_DECOMPRESSED_BYTES."""


def default_metadata_path() -> Path:
    """The one place the metadata snapshot lives.

    It used to be resolved relative to the working directory in the
    pipeline and the exporter but under the config directory in ``review``,
    so a bootstrap run from a different shell wrote a snapshot the review
    path never read.
    """
    from ..config import CONFIG_DIR

    return CONFIG_DIR / "full-aur-meta.json"


#: One parsed snapshot, keyed by ``(path, mtime_ns, size)``.  ``review``
#: loads the snapshot once per package through ``depth.default_metadata``;
#: without this the 81 MB JSON was re-parsed for every package in the batch.
#: The cache holds a single entry, so it never pins an old snapshot's memory.
_snapshot_cache: dict[tuple[str, int, int], tuple[dict, int | None] | None] = {}
_snapshot_cache_lock = threading.Lock()


def _stat_key(path: Path) -> tuple[str, int, int] | None:
    try:
        st = path.stat()
    except OSError:
        return None
    return (str(path), st.st_mtime_ns, st.st_size)


def _validators_path() -> Path:
    """A small sidecar beside the snapshot, so reading it is cheap.

    Reading the snapshot itself for its HTTP validators would parse the
    whole 81 MB file for two strings.
    """
    base = default_metadata_path()
    return base.with_name(base.name + ".http.json")


def _read_validators() -> tuple[str | None, str | None]:
    """The ``(ETag, Last-Modified)`` of the last download, best-effort."""
    try:
        data = json.loads(_validators_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None, None
    etag = data.get("etag")
    last_modified = data.get("last_modified")
    return (
        etag if isinstance(etag, str) else None,
        last_modified if isinstance(last_modified, str) else None,
    )


def _write_validators(etag: str | None, last_modified: str | None) -> None:
    if not (etag or last_modified):
        return
    path = _validators_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(path.name + ".tmp")
        tmp.write_text(
            json.dumps({"etag": etag, "last_modified": last_modified}),
            encoding="utf-8",
        )
        os.replace(tmp, path)
    except OSError:
        log.debug("could not persist metadata validators", exc_info=True)


def gunzip_capped(raw: bytes, limit: int = MAX_DECOMPRESSED_BYTES) -> bytes:
    """Decompress *raw*, refusing to materialise more than *limit* bytes."""
    out = bytearray()
    with gzip.GzipFile(fileobj=io.BytesIO(raw)) as fh:
        while True:
            chunk = fh.read(1024 * 1024)
            if not chunk:
                break
            out.extend(chunk)
            if len(out) > limit:
                raise DecompressionTooLarge(
                    f"gzip stream exceeds {limit} bytes decompressed"
                )
    return bytes(out)


def fetch_metadata(on_progress=None) -> dict:
    """Download and decompress the AUR metadata dump.

    Returns a dict keyed by package name, where each value contains
    ``Name``, ``Version``, ``Description``, ``Maintainer``, ``Depends``,
    ``MakeDepends``, ``OptDepends``, ``CheckDepends``, ``Provides``,
    ``License``, ``NumVotes``, ``Popularity``, ``LastModified``, etc.

    If *on_progress* is a callable ``(pos, total) -> None`` it is called
    periodically during the download with the number of bytes received
    and the expected content length.
    """
    log.info("fetching AUR metadata from %s", _METADATA_URL)
    # Conditional GET: the dump is ~60 MB gzipped and is refreshed every few
    # minutes, so a refresh that changed nothing should not move it again.
    etag, last_modified = _read_validators()
    headers: dict[str, str] = {}
    if etag:
        headers["If-None-Match"] = etag
    if last_modified:
        headers["If-Modified-Since"] = last_modified
    try:
        resp = urlopen(Request(_METADATA_URL, headers=headers), timeout=HTTP_TIMEOUT)
    except HTTPError as exc:
        if exc.code == 304:
            log.info("AUR metadata unchanged (304); reusing the stored snapshot")
            existing = load_metadata()
            return existing if existing is not None else {}
        raise RuntimeError(
            f"cannot reach the AUR metadata dump ({_METADATA_URL}): {exc}"
        ) from exc
    except Exception as exc:
        raise RuntimeError(
            f"cannot reach the AUR metadata dump ({_METADATA_URL}): {exc}"
        ) from exc
    try:
        import time
        total = int(resp.headers.get("Content-Length", 0))
        response_etag = resp.headers.get("ETag")
        response_last_modified = resp.headers.get("Last-Modified")
        buf = bytearray()
        deadline = time.monotonic() + DOWNLOAD_DEADLINE_SECONDS
        while True:
            if time.monotonic() > deadline:
                raise RuntimeError(
                    "AUR metadata download exceeded its "
                    f"{DOWNLOAD_DEADLINE_SECONDS:g}s deadline"
                )
            chunk = resp.read(65536)
            if not chunk:
                break
            buf.extend(chunk)
            if len(buf) > MAX_RESPONSE_BYTES:
                raise ResponseTooLarge(
                    f"metadata response exceeds {MAX_RESPONSE_BYTES} bytes"
                )
            if on_progress:
                on_progress(len(buf), total)
    finally:
        if hasattr(resp, "close"):
            resp.close()
    data = json.loads(gunzip_capped(bytes(buf)))
    metadata: dict[str, dict] = {}
    for entry in data:
        metadata[entry["Name"]] = entry
    _write_validators(response_etag, response_last_modified)
    log.info("loaded metadata for %d packages", len(metadata))
    return metadata


def diff_metadata(old: dict, new: dict) -> dict[str, str]:
    """Compare two metadata snapshots.

    Returns a dict mapping package name to ``"added"``, ``"removed"``,
    or ``"modified"`` based on whether the package appeared, disappeared,
    or changed (by ``LastModified`` or ``Version``).
    """
    changes: dict[str, str] = {}
    for name, entry in new.items():
        if name not in old:
            changes[name] = "added"
        elif (entry.get("LastModified") != old[name].get("LastModified")
              or entry.get("Version") != old[name].get("Version")):
            changes[name] = "modified"
    for name in old:
        if name not in new:
            changes[name] = "removed"
    return changes


def save_metadata(metadata: dict, path: Path | None = None) -> Path:
    """Persist a metadata snapshot to disk.

    Written with compact separators and through a temp file: the snapshot is
    tens of megabytes, and the default separators spend a byte on every
    colon and comma.  ``os.replace`` keeps a crash from leaving a
    half-written snapshot that the next run would read as a smaller,
    complete-looking corpus.
    """
    path = path or default_metadata_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"snapshot_time": int(time.time()), "packages": metadata}
    tmp = path.with_name(path.name + ".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(payload, f, separators=(",", ":"))
    os.replace(tmp, path)
    with _snapshot_cache_lock:
        _snapshot_cache.clear()
    log.info("saved metadata snapshot (%d packages) to %s", len(metadata), path)
    return path


def load_metadata(path: Path | None = None) -> dict | None:
    """Load a previously saved metadata snapshot, or return None."""
    snapshot = load_snapshot(path)
    return None if snapshot is None else snapshot[0]


def load_snapshot(path: Path | None = None) -> tuple[dict, int | None] | None:
    """Load a snapshot as ``(packages, snapshot_time)``, or None if absent.

    ``load_metadata`` drops the timestamp, which is how a snapshot could be
    read forever without anyone asking how old it was.  A caller that
    compares installed versions against it needs both halves.

    ``snapshot_time`` is None for a file written before it was recorded, or
    one whose value is not an integer; callers treat that as "unknown age",
    which for a TTL check means stale.
    """
    path = path or default_metadata_path()
    key = _stat_key(path)
    if key is None:
        return None
    with _snapshot_cache_lock:
        if key in _snapshot_cache:
            return _snapshot_cache[key]
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        result = None
    else:
        stamp = data.get("snapshot_time")
        result = (data.get("packages", {}), stamp if isinstance(stamp, int) else None)
    with _snapshot_cache_lock:
        _snapshot_cache.clear()
        _snapshot_cache[key] = result
    return result


def snapshot_age_seconds(snapshot_time: int | None, now: float | None = None) -> float | None:
    """Age of a snapshot in seconds, or None when it cannot be determined.

    A timestamp in the future (a clock that moved backwards, a copied
    snapshot) reads as age 0 rather than negative, so a nonsensical stamp
    can never look *fresher* than a real one in a comparison.
    """
    if snapshot_time is None:
        return None
    return max(0.0, (time.time() if now is None else now) - snapshot_time)
