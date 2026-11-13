"""Parent-side client for the Rich rendering sandbox."""

from __future__ import annotations

import atexit
import json
import os
import sys
import threading
import time

from . import _worker_io, protocol
from ._spawn import spawn_isolated

WORKER_MODULE = "trustsight.sandbox.render_worker"
REQUEST_TIMEOUT_SECONDS = 10.0
MAX_REQUESTS_PER_WORKER = 256


class RenderUnavailable(RuntimeError):
    """The render sandbox could not answer."""


class _Worker:
    def __init__(self) -> None:
        self.proc = None
        self.requests = 0
        self.stderr: list[str] = []

    def start(self) -> None:
        tty_fd = None
        extra_argv: tuple = ()
        pass_fds: tuple = ()
        try:
            tty_fd = os.dup(sys.stderr.fileno())
            extra_argv = (str(tty_fd),)
            pass_fds = (tty_fd,)
        except (AttributeError, OSError, ValueError):
            tty_fd = None
        try:
            self.proc = spawn_isolated(
                WORKER_MODULE, extra_argv=extra_argv, pass_fds=pass_fds)
        finally:
            if tty_fd is not None:
                try:
                    os.close(tty_fd)
                except OSError:
                    pass
        self.requests = 0
        self.stderr = []
        threading.Thread(target=self._drain, daemon=True).start()

    def _drain(self) -> None:
        _worker_io.drain_stderr(
            self.proc,
            lambda text: self.stderr.append(text)
            if len(self.stderr) < 20 else None,
        )

    def alive(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def stop(self) -> None:
        proc, self.proc = self.proc, None
        _worker_io.stop_process(proc)

    def request(self, body: bytes) -> bytes:
        if self.proc is None or self.proc.stdin is None or self.proc.stdout is None:
            raise RenderUnavailable("render worker is not running")
        if self.proc.poll() is not None:
            detail = "; ".join(self.stderr) or f"exit {self.proc.returncode}"
            raise RenderUnavailable(f"render worker exited: {detail}")
        deadline = time.monotonic() + REQUEST_TIMEOUT_SECONDS
        try:
            protocol.write_frame(self.proc.stdin.fileno(), body, deadline)
            header = _worker_io.read_exact(
                self.proc.stdout, protocol.HEADER.size, deadline,
                RenderUnavailable)
            (length,) = protocol.HEADER.unpack(header)
            if length > protocol.MAX_RESPONSE_BYTES:
                raise RenderUnavailable("render response exceeds its cap")
            return _worker_io.read_exact(
                self.proc.stdout, length, deadline, RenderUnavailable)
        except (BrokenPipeError, OSError, protocol.FrameError) as exc:
            detail = "; ".join(self.stderr)
            raise RenderUnavailable(
                f"render worker channel failed: {exc}"
                + (f" ({detail})" if detail else "")) from exc


_lock = threading.Lock()
_worker: _Worker | None = None


def _get_worker() -> _Worker:
    global _worker
    if _worker is None or not _worker.alive() \
            or _worker.requests >= MAX_REQUESTS_PER_WORKER:
        if _worker is not None:
            _worker.stop()
        _worker = _Worker()
        _worker.start()
    return _worker


def _close() -> None:
    global _worker
    if _worker is not None:
        _worker.stop()
        _worker = None


atexit.register(_close)


def _after_fork() -> None:
    """Drop the inherited worker and lock after ``fork``."""
    global _worker, _lock
    _worker = None
    _lock = threading.Lock()


os.register_at_fork(after_in_child=_after_fork)


def _color_enabled() -> bool:
    """Whether rendered text should carry Rich ANSI styles."""
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR") or os.environ.get("TRUSTSIGHT_FORCE_RICH"):
        return True
    try:
        return bool(sys.stdout.isatty())
    except (AttributeError, OSError, ValueError):
        return False


def _request(op: str, payload: dict) -> str:
    global _worker
    with _lock:
        worker = _get_worker()
        body = json.dumps(
            {"op": op, "payload": payload, "color": _color_enabled()},
            ensure_ascii=False, separators=(",", ":"),
        ).encode("utf-8")
        try:
            raw = worker.request(body)
            worker.requests += 1
            try:
                response = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise RenderUnavailable(
                    "render worker returned invalid JSON") from exc
            if not isinstance(response, dict) or "result" not in response:
                raise RenderUnavailable(
                    response.get("error", "render worker returned no result")
                    if isinstance(response, dict)
                    else "render worker returned no result")
            return response["result"]
        except RenderUnavailable:
            worker.stop()
            _worker = None
            raise


def render(op: str, payload: dict) -> str:
    """Render *op* in the sandbox and return the text."""
    return _request(op, payload)


def start_progress(task_id: str, description: str, total=None,
                   kind: str = "analysis", transient: bool = False) -> None:
    _request("progress_start", {
        "id": task_id, "description": description, "total": total,
        "kind": kind, "transient": transient,
    })


def update_progress(task_id: str, completed=None, total=None,
                    description=None) -> None:
    _request("progress_update", {
        "id": task_id, "completed": completed, "total": total,
        "description": description,
    })


def stop_progress(task_id: str) -> None:
    _request("progress_stop", {"id": task_id})
