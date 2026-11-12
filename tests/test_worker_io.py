"""Shared sandbox worker I/O contracts.

The four worker clients used to carry near-identical copies of frame reads,
stderr draining and process teardown. Every copy had to remember the same
deadline, EOF and descriptor rules, so a fix could land in one client and miss
the others. These tests pin the one shared implementation.
"""

from __future__ import annotations

import io
import os
import subprocess
import time

import pytest

from trustsight.sandbox import _worker_io


class _WorkerError(RuntimeError):
    pass


def test_read_exact_returns_the_requested_bytes():
    read_fd, write_fd = os.pipe()
    try:
        os.write(write_fd, b"abcdef")
    finally:
        os.close(write_fd)
    try:
        assert _worker_io.read_exact(read_fd, 6, time.monotonic() + 2,
                                     _WorkerError) == b"abcdef"
    finally:
        os.close(read_fd)


def test_read_exact_times_out_with_the_callers_error_type():
    read_fd, write_fd = os.pipe()
    try:
        with pytest.raises(_WorkerError, match="timed out"):
            _worker_io.read_exact(read_fd, 1, time.monotonic() + 0.05,
                                  _WorkerError)
    finally:
        os.close(read_fd)
        os.close(write_fd)


def test_read_exact_reports_a_closed_channel():
    read_fd, write_fd = os.pipe()
    os.close(write_fd)
    try:
        with pytest.raises(_WorkerError, match="closed"):
            _worker_io.read_exact(read_fd, 1, time.monotonic() + 2,
                                  _WorkerError)
    finally:
        os.close(read_fd)


def test_drain_stderr_forwards_each_decoded_line():
    class _Proc:
        stderr = io.BytesIO(b"first\nsecond\n")

    lines: list[str] = []
    _worker_io.drain_stderr(_Proc(), lines.append)
    assert lines == ["first", "second"]


def test_stop_process_kills_the_group_and_closes_every_pipe():
    proc = subprocess.Popen(
        ["sleep", "60"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    pipes = [proc.stdin, proc.stdout, proc.stderr]
    _worker_io.stop_process(proc)

    assert proc.poll() is not None
    assert all(pipe.closed for pipe in pipes)
