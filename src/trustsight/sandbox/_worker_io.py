"""Shared plumbing for the parent-side sandbox worker clients.

Every client needs the same three operations: read an exact framed reply under
a deadline, drain the child's stderr, and kill the child's process group.  They
were four near-identical copies, so a deadline or descriptor-leak fix could
land in one path and miss the others.  This module is that one place.
"""

from __future__ import annotations

import os
import select
import signal
import time
from typing import Callable


def read_exact(stream, n: int, deadline: float, error: type[Exception]) -> bytes:
    """Read exactly *n* bytes from *stream* before *deadline*.

    *stream* is an integer descriptor or anything with ``fileno()``.  A
    timeout, EOF, or interrupted wait is raised as *error* so each client keeps
    its own refusal type.
    """
    fd = stream if isinstance(stream, int) else stream.fileno()
    out = bytearray()
    while len(out) < n:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise error("worker timed out")
        try:
            ready, _, _ = select.select([fd], [], [], remaining)
        except InterruptedError:
            continue
        if not ready:
            raise error("worker timed out")
        chunk = os.read(fd, n - len(out))
        if not chunk:
            raise error("worker closed the channel")
        out.extend(chunk)
    return bytes(out)


def drain_stderr(proc, on_line: Callable[[str], None]) -> None:
    """Pass each decoded stderr line of *proc* to *on_line*, bounded by EOF."""
    if proc is None or proc.stderr is None:
        return
    try:
        for line in proc.stderr:
            on_line(line.decode("utf-8", "replace").rstrip())
    except (OSError, ValueError):
        pass


def kill_process_group(proc) -> None:
    """SIGKILL the worker's process group, falling back to the process."""
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        try:
            proc.kill()
        except OSError:
            pass


def stop_process(proc) -> None:
    """Kill *proc*, reap it, and close every pipe it left open.

    The child's death does not close the parent's ends; a retired worker that
    leaves stdin/stdout/stderr open leaks descriptors across a long run.
    """
    if proc is None:
        return
    kill_process_group(proc)
    try:
        proc.wait(timeout=2)
    except Exception:
        pass
    for pipe in (proc.stdin, proc.stdout, proc.stderr):
        if pipe is not None:
            try:
                pipe.close()
            except OSError:
                pass
