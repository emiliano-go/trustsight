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
import time
from pathlib import Path
from urllib.request import urlopen

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

# The compressed dump is ~60 MB.  Reading a response with no ceiling lets
# the remote end decide how much of this machine's memory to use, which is
# the same reason full_aur/fetch.py caps its own reads.
MAX_RESPONSE_BYTES = 512 * 1024 * 1024


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
    try:
        resp = urlopen(_METADATA_URL, timeout=HTTP_TIMEOUT)
    except Exception as exc:
        raise RuntimeError(
            f"cannot reach the AUR metadata dump ({_METADATA_URL}): {exc}"
        ) from exc
    total = int(resp.headers.get("Content-Length", 0))
    buf = bytearray()
    while True:
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
    data = json.loads(gunzip_capped(bytes(buf)))
    metadata: dict[str, dict] = {}
    for entry in data:
        metadata[entry["Name"]] = entry
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
    """Persist a metadata snapshot to disk."""
    path = path or default_metadata_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        json.dump({"snapshot_time": int(time.time()), "packages": metadata}, f)
    log.info("saved metadata snapshot (%d packages) to %s", len(metadata), path)
    return path


def load_metadata(path: Path | None = None) -> dict | None:
    """Load a previously saved metadata snapshot, or return None."""
    path = path or default_metadata_path()
    if not path.exists():
        return None
    with open(path) as f:
        data = json.load(f)
    return data.get("packages", {})
