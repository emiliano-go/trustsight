"""Silent, fixed-shape worker death records.

A worker that dies mid-request must leave one bounded record behind so a
supervisor can distinguish a retired worker from a crash loop.  The record is
deliberately inert JSON: no traceback, no attacker-controlled text, no
cascading findings.  This is the corpse contract, not an alert channel.
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
import time
from pathlib import Path

__all__ = ["CORPSE_DIR", "MAX_CORPSE_BYTES", "write_corpse"]

_log = logging.getLogger(__name__)

#: Fixed directory.  It is intentionally not configurable from analysed
#: content; a caller may monkeypatch the module constant in tests.
CORPSE_DIR = Path(tempfile.gettempdir()) / "trustsight-worker-corpse"

#: A corpse is a diagnostic, not a data dump.
MAX_CORPSE_BYTES = 4096


def write_corpse(record: dict) -> Path | None:
    """Write one corpse JSON file, or return None without raising.

    Failure to write a corpse is not allowed to break the teardown that is
    already in progress.  The directory is created 0700 and each file 0600;
    an existing file is never overwritten.
    """
    try:
        CORPSE_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
        payload = json.dumps(record, sort_keys=True, default=str)
        if len(payload.encode("utf-8")) > MAX_CORPSE_BYTES:
            record = dict(record)
            record["truncated"] = True
            payload = json.dumps(record, sort_keys=True, default=str)
        name = f"worker-{record.get('pid', 'unknown')}-{time.time_ns()}.json"
        path = CORPSE_DIR / name
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(fd, payload.encode("utf-8"))
        finally:
            os.close(fd)
        return path
    except (OSError, ValueError, TypeError) as exc:
        _log.debug("worker corpse not written: %s", exc)
        return None
