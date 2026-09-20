"""Parent-side client for the sandboxed tokenizer.

A bounded pool of child processes, each running ``expand_worker``.  A
request is one length-prefixed JSON frame out and one back; a worker that
times out, dies, or answers with an error is killed, removed, and the call
raises :class:`TokenizerUnavailable`, which the analysis reports as a
package that was NOT vetted.

The pool is persistent because a fresh interpreter per diff costs 26-48 ms
against a 0.5 ms tokenizer, and recycled because a worker that has parsed
hostile input should not parse an unbounded amount of it.  Two things make
the per-request cost bearable: the pool amortises interpreter startup, and
the identity cache collapses the ~97 entry-point calls a diff makes into
about a dozen round-trips.

Nothing here imports the engine.  The parent process never runs tokenizer
code on package-controlled text; ``sandbox/expand_worker.py`` is the only
module that does.
"""

import atexit
import json
import os
import queue
import select
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

from . import protocol

#: Wall-clock ceiling for one request, enforced by the parent's ``select``.
#: The engine's own worst case is milliseconds; this is the backstop for a
#: worker wedged by a defect.
REQUEST_TIMEOUT_SECONDS = 5.0

#: A worker is retired after this many requests so residual state and
#: fragmentation cannot accumulate across a whole ``full-aur`` run.
MAX_REQUESTS_PER_WORKER = 512

#: Concurrent children.  The analysis itself runs a thread pool; these are
#: serialised per worker, and the queue bounds the fan-out.  A source
#: constant, not derived from the machine, so the `every input bound is a
#: source constant` gate can hold it.
WORKER_POOL_SIZE = 4

_WORKER_PATH = Path(__file__).with_name("expand_worker.py")


class TokenizerUnavailable(RuntimeError):
    """The sandboxed tokenizer could not answer for this input.

    Raised rather than degraded: the whole tokenizer is isolated, so there
    is no in-process parser to fall back to, and an analysis that guessed
    would be guessing with the one component whose job is to read the text
    the guess is about.  The caller reports the package as NOT vetted.
    """


class _WorkerError(Exception):
    """The child died, timed out, or closed the channel."""


class _Worker:
    def __init__(self):
        self.proc = None
        self.requests = 0

    def start(self) -> None:
        self.proc = subprocess.Popen(
            [sys.executable, str(_WORKER_PATH)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            close_fds=True,
            start_new_session=True,
            cwd="/",
            env=_child_env(),
        )
        self.requests = 0

    def alive(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def stop(self) -> None:
        proc = self.proc
        self.proc = None
        if proc is None:
            return
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError, OSError):
            try:
                proc.kill()
            except OSError:
                pass
        try:
            proc.wait(timeout=2)
        except Exception:
            pass

    def request(self, body: bytes) -> bytes:
        if self.proc is None or self.proc.stdin is None or self.proc.stdout is None:
            raise _WorkerError("worker is not running")
        try:
            self.proc.stdin.write(protocol.frame(body))
            self.proc.stdin.flush()
        except (BrokenPipeError, OSError) as exc:
            raise _WorkerError(f"worker closed the channel: {exc}") from exc
        deadline = time.monotonic() + REQUEST_TIMEOUT_SECONDS
        header = _read_with_deadline(
            self.proc.stdout, protocol.HEADER.size, deadline
        )
        (length,) = protocol.HEADER.unpack(header)
        if length > protocol.MAX_RESPONSE_BYTES:
            raise _WorkerError(
                f"response of {length} bytes exceeds the "
                f"{protocol.MAX_RESPONSE_BYTES}-byte cap"
            )
        return _read_with_deadline(self.proc.stdout, length, deadline)


def _read_with_deadline(fh, n: int, deadline: float) -> bytes:
    """Read exactly *n* bytes or raise, refusing to block past *deadline*.

    Uses ``os.read`` on the raw descriptor so a ``select`` timeout is the
    real bound; a buffered ``read`` could return a short read and block on
    the next one.
    """
    fd = fh.fileno()
    out = bytearray()
    while len(out) < n:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise _WorkerError("timed out")
        try:
            ready, _, _ = select.select([fd], [], [], remaining)
        except OSError as exc:
            raise _WorkerError(str(exc)) from exc
        if not ready:
            raise _WorkerError("timed out")
        chunk = os.read(fd, n - len(out))
        if not chunk:
            raise _WorkerError("worker closed the channel")
        out.extend(chunk)
    return bytes(out)


def _child_env() -> dict:
    """A minimal environment that still finds this package.

    The source root is added to ``PYTHONPATH`` so a dev checkout's child
    imports the same tree; an installed package needs no ``PYTHONPATH`` and
    ignores the extra entry.
    """
    root = str(Path(__file__).resolve().parents[2])
    env = os.environ.copy()
    pythonpath = env.get("PYTHONPATH", "")
    return {
        "PATH": env.get("PATH", ""),
        "PYTHONPATH": os.pathsep.join(p for p in (root, pythonpath) if p),
    }


# --- pool -------------------------------------------------------------------

_pool: queue.Queue = queue.Queue()
_all: list[_Worker] = []
_lock = threading.Lock()
_shutdown = threading.Event()


def _acquire() -> _Worker:
    try:
        return _pool.get_nowait()
    except queue.Empty:
        pass
    with _lock:
        if len(_all) < WORKER_POOL_SIZE:
            worker = _Worker()
            try:
                worker.start()
            except OSError as exc:
                raise TokenizerUnavailable(
                    f"tokenizer_unavailable: could not start the child: {exc}"
                ) from exc
            _all.append(worker)
            return worker
    # Saturate at the pool size: wait for a checked-out worker, which is
    # bounded because every holder returns or kills within the request
    # timeout.
    worker = _pool.get()
    if worker.alive():
        return worker
    worker.stop()
    return _acquire()


def _release(worker: _Worker) -> None:
    if _shutdown.is_set():
        worker.stop()
        _forget(worker)
        return
    if worker.alive() and worker.requests < MAX_REQUESTS_PER_WORKER:
        _pool.put(worker)
        return
    worker.stop()
    _forget(worker)


def _forget(worker: _Worker) -> None:
    with _lock:
        if worker in _all:
            _all.remove(worker)


def _terminate_all() -> None:
    _shutdown.set()
    with _lock:
        workers = list(_all)
        _all.clear()
    for worker in workers:
        worker.stop()


atexit.register(_terminate_all)


# --- identity cache ---------------------------------------------------------

_cache = threading.local()
_CACHE_MAX = 16


def _cache_get(key, payload):
    store = getattr(_cache, "entries", None)
    if not store:
        return None
    for cached_key, cached_input, value in store:
        if cached_key == key and cached_input is payload:
            return value
    return None


def _cache_put(key, payload, value) -> None:
    store = getattr(_cache, "entries", None)
    if store is None:
        store = []
        _cache.entries = store
    store.append((key, payload, value))
    del store[:-_CACHE_MAX]


def _copy(value):
    """Return a caller-owned structure; the cache keeps the original.

    The old in-process memo did the same for the same reason: a shared list
    would turn any in-place edit by one rule into a bug in an unrelated one.
    The cache still collapses the repeated whole-diff calls, because those
    are keyed on the diff object, not on the (copied) result.
    """
    if isinstance(value, list):
        return [_copy(item) for item in value]
    if isinstance(value, tuple):
        return tuple(_copy(item) for item in value)
    if isinstance(value, dict):
        return {key: _copy(item) for key, item in value.items()}
    return value


# --- request ----------------------------------------------------------------


def request(op: str, payload):
    """Run *op* on *payload* in the sandbox, or raise TokenizerUnavailable.

    The response is cached by the identity of the *input*, so the many call
    sites that pass the same diff object share one round-trip, and a fresh
    copy is returned so no caller can edit the cached value.
    """
    key = (op, id(payload))
    cached = _cache_get(key, payload)
    if cached is not None:
        return _copy(cached)
    value = _send(op, payload)
    _cache_put(key, payload, value)
    return _copy(value)


def _send(op: str, payload):
    body = json.dumps(
        {"op": op, "input": payload}, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    if len(body) > protocol.MAX_FRAME_BYTES:
        raise TokenizerUnavailable(
            "tokenizer_unavailable: request exceeds the "
            f"{protocol.MAX_FRAME_BYTES}-byte frame cap"
        )
    worker = _acquire()
    try:
        raw = worker.request(body)
        worker.requests += 1
        response = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        worker.stop()
        _forget(worker)
        raise TokenizerUnavailable(f"tokenizer_unavailable: {exc}") from exc
    _release(worker)
    if "error" in response:
        raise TokenizerUnavailable(f"tokenizer_unavailable: {response['error']}")
    return response["result"]
