"""Live progress drawn by the worker on an inherited terminal fd."""

from __future__ import annotations

import os
import sys

_TASKS: dict[str, tuple] = {}
_STREAM = None


def _stream():
    global _STREAM
    if _STREAM is not None:
        return _STREAM
    fd = None
    if len(sys.argv) > 1:
        try:
            fd = int(sys.argv[1])
        except ValueError:
            fd = None
    if fd is None:
        return None
    try:
        _STREAM = os.fdopen(fd, "w", buffering=1, closefd=False)
    except OSError:
        return None
    return _STREAM


def _columns(kind: str):
    from rich.progress import (
        BarColumn,
        DownloadColumn,
        MofNCompleteColumn,
        SpinnerColumn,
        TextColumn,
        TimeElapsedColumn,
        TimeRemainingColumn,
        TransferSpeedColumn,
    )

    if kind == "download":
        return (
            TextColumn("[progress.description]{task.description}"),
            BarColumn(), DownloadColumn(), TransferSpeedColumn(),
            TimeElapsedColumn(),
        )
    if kind == "spinner":
        return (
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
        )
    return (
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(), MofNCompleteColumn(),
        TextColumn("elapsed"), TimeElapsedColumn(),
        TextColumn("eta"), TimeRemainingColumn(),
    )


def start(*, id, description, total=None, kind="analysis", transient=False):
    stream = _stream()
    if stream is None:
        return
    from rich.console import Console
    from rich.progress import Progress

    progress = Progress(
        *_columns(kind),
        console=Console(file=stream, force_terminal=True, stderr=True),
        transient=transient,
    )
    progress.start()
    task = progress.add_task(description, total=total)
    _TASKS[id] = (progress, task)


def update(*, id, completed=None, total=None, description=None):
    entry = _TASKS.get(id)
    if entry is None:
        return
    progress, task = entry
    kwargs = {}
    if completed is not None:
        kwargs["completed"] = completed
    if total is not None:
        kwargs["total"] = total
    if description is not None:
        kwargs["description"] = description
    progress.update(task, refresh=True, **kwargs)


def stop(*, id):
    entry = _TASKS.pop(id, None)
    if entry is None:
        return
    progress, _task = entry
    transient = bool(getattr(progress, "transient", False))
    progress.stop()
    # Rich leaves the cursor at the end of the bar.  Without a newline the
    # next notice or prompt starts on the same line as the completed bar.
    if not transient:
        stream = _stream()
        if stream is not None:
            stream.write("\n")
            stream.flush()
