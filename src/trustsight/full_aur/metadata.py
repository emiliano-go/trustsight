"""AUR metadata snapshot fetch and diff.

The AUR publishes a gzipped JSON array of package objects at
``https://aur.archlinux.org/packages-meta-ext-v1.json.gz``.
Each entry has fields such as ``Name``, ``Version``, ``Maintainer``,
``FirstSubmitted``, ``LastModified``, ``Depends``, etc.

We normalise this into a ``dict[str, dict]`` keyed by ``Name`` for
fast lookups and diffs.
"""

import gzip
import json
import logging
import time
import urllib.request
from pathlib import Path
from typing import Optional

log = logging.getLogger(__name__)

_META_URL = "https://aur.archlinux.org/packages-meta-ext-v1.json.gz"
_HTTP_TIMEOUT = 120


def _parse(raw: bytes) -> dict[str, dict]:
    """Convert the raw JSON response into a name-keyed dict."""
    data: list[dict] = json.loads(gzip.decompress(raw).decode("utf-8"))
    return {pkg["Name"]: pkg for pkg in data}


def fetch_metadata() -> dict[str, dict]:
    """Download the AUR metadata snapshot.

    Returns a dict mapping package name to its metadata:
        {name: {Version, Maintainer, LastModified, FirstSubmitted, ...}}
    """
    req = urllib.request.Request(_META_URL, headers={"User-Agent": "trustsight/1.0"})
    resp = urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT)
    raw = resp.read()
    try:
        return _parse(raw)
    except Exception:
        # urllib may transparently decompress content-encoding: gzip
        data: dict[str, dict] = json.loads(raw.decode("utf-8"))
        return data


def load_metadata_snapshot(path: Path) -> Optional[dict[str, dict]]:
    """Load a previously saved metadata snapshot from disk."""
    if not path.exists():
        return None
    raw = path.read_bytes()
    try:
        return _parse(raw)
    except Exception:
        try:
            data: dict[str, dict] = json.loads(raw.decode("utf-8"))
            return data
        except Exception:
            log.warning("corrupt metadata snapshot at %s", path)
            return None


def save_metadata_snapshot(data: dict[str, dict], path: Path) -> None:
    """Save a metadata snapshot to disk."""
    raw = json.dumps(list(data.values()), separators=(",", ":")).encode("utf-8")
    compressed = gzip.compress(raw)
    path.write_bytes(compressed)


def diff_metadata(
    old: dict[str, dict],
    new: dict[str, dict],
) -> tuple[list[str], list[str], list[str]]:
    """Compare two metadata snapshots.

    Returns (added, changed, removed) lists of package names.
    A package is "changed" if its version or LastModified differs.
    """
    old_names = set(old)
    new_names = set(new)
    added = sorted(new_names - old_names)
    removed = sorted(old_names - new_names)
    changed: list[str] = []
    for name in sorted(new_names & old_names):
        o = old[name]
        n = new[name]
        if o.get("Version") != n.get("Version") or o.get("LastModified") != n.get("LastModified"):
            changed.append(name)
    return added, changed, removed
