"""AUR metadata dump fetch and diff.

Downloads ``packages-meta-ext-v1.json.gz`` from the AUR to discover which
packages have changed since the last observation.  One request gives the
full metadata state (maintainer, version, LastModified, depends, provides)
for every package.
"""

import gzip
import json
import logging
import time
from pathlib import Path
from urllib.request import urlopen

log = logging.getLogger(__name__)

_METADATA_URL = "https://aur.archlinux.org/packages-meta-ext-v1.json.gz"
_META_SNAPSHOT_PATH = Path("full-aur-meta.json")


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
    resp = urlopen(_METADATA_URL)
    total = int(resp.headers.get("Content-Length", 0))
    buf = bytearray()
    while True:
        chunk = resp.read(65536)
        if not chunk:
            break
        buf.extend(chunk)
        if on_progress:
            on_progress(len(buf), total)
    data = json.loads(gzip.decompress(buf))
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
    path = path or _META_SNAPSHOT_PATH
    with open(path, "w") as f:
        json.dump({"snapshot_time": int(time.time()), "packages": metadata}, f)
    log.info("saved metadata snapshot (%d packages) to %s", len(metadata), path)
    return path


def load_metadata(path: Path | None = None) -> dict | None:
    """Load a previously saved metadata snapshot, or return None."""
    path = path or _META_SNAPSHOT_PATH
    if not path.exists():
        return None
    with open(path) as f:
        data = json.load(f)
    return data.get("packages", {})
