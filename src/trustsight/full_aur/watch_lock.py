"""One watcher per data directory.

Two --watch processes sharing a database serialise their writes but race on
the snapshot, resume file and alert state.  An exclusive advisory lock makes
the second start fail with a clear message instead of interleaving cycles.
"""

from __future__ import annotations

import fcntl
import os
from contextlib import contextmanager

from ..db import get_db_path


class WatchAlreadyRunning(RuntimeError):
    """Another process owns the watcher lock."""


@contextmanager
def watch_lock():
    path = get_db_path().parent / "watch.lock"
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise WatchAlreadyRunning(
                f"another watcher already owns {path}"
            ) from exc
        os.write(fd, str(os.getpid()).encode("ascii"))
        os.ftruncate(fd, len(str(os.getpid())))
        yield
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)
