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
the content cache collapses the ~126 entry-point calls a diff makes into the
~27 distinct inputs they ask about.

Nothing here imports the engine.  The parent process never runs tokenizer
code on package-controlled text; ``sandbox/expand_worker.py`` is the only
module that does.
"""

import atexit
import json
import logging
import os
import queue
import select
import threading
import time
from collections import OrderedDict

from . import _worker_io, protocol
from ._spawn import launch_args, spawn_isolated
from ..subproc import minimal_env

#: The worker module the client launches; ``_spawn`` imports and calls its
#: ``main``.
_WORKER_MODULE = "trustsight.sandbox.expand_worker"

_log = logging.getLogger(__name__)

#: Wall-clock ceiling for one request, enforced by the parent's ``select``.
#: The engine's own worst case is milliseconds; this is the backstop for a
#: worker wedged by a defect.
REQUEST_TIMEOUT_SECONDS = 5.0

#: A worker is retired after this many requests so residual state and
#: fragmentation cannot accumulate across a whole ``full-aur`` run.
MAX_REQUESTS_PER_WORKER = 512

#: Retire a worker once it has burned this much CPU, below the child's own
#: ``RLIMIT_CPU`` of 5 s.  CPU accumulates across every request a worker
#: serves, so without this a slow drip from one package spends the budget
#: meant for the whole worker and the *next* package's request is the one
#: killed by SIGXCPU - a failure attributed to the wrong input.
CPU_RETIRE_SECONDS = 3.5

#: Concurrent children.  The analysis itself runs a thread pool; these are
#: serialised per worker, and the queue bounds the fan-out.  A source
#: constant, not derived from the machine, so the `every input bound is a
#: source constant` gate can hold it.
WORKER_POOL_SIZE = 4


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
        self.degraded: list = []
        self._degraded_reported = False
        self._stderr_thread = None

    def start(self) -> None:
        self.proc = spawn_isolated(_WORKER_MODULE)
        self.requests = 0
        self._stderr_thread = threading.Thread(
            target=self._drain_stderr, daemon=True
        )
        self._stderr_thread.start()

    def _drain_stderr(self) -> None:
        _worker_io.drain_stderr(
            self.proc,
            lambda text: _log.debug("tokenizer worker: %s", text),
        )

    def alive(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def stop(self) -> None:
        proc = self.proc
        self.proc = None
        _worker_io.stop_process(proc)

    def request(self, body: bytes) -> bytes:
        if self.proc is None or self.proc.stdin is None or self.proc.stdout is None:
            raise _WorkerError("worker is not running")
        if self.proc.poll() is not None:
            raise _WorkerError(
                "worker exited during startup" if not self.requests
                else "worker exited"
            )
        deadline = time.monotonic() + REQUEST_TIMEOUT_SECONDS
        try:
            protocol.write_frame(
                self.proc.stdin.fileno(), body, deadline
            )
        except (BrokenPipeError, OSError, protocol.FrameError) as exc:
            raise _WorkerError(f"worker closed the channel: {exc}") from exc
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


def _launch_args() -> list[str]:
    """The child command line: isolated interpreter, trusted root inserted.

    ``-I`` is isolated mode: it ignores ``PYTHONPATH`` and every other
    ``PYTHON*`` variable, drops the user site directory, and does not put the
    current directory on ``sys.path``.  ``-s`` alone was not enough - it
    leaves ``PYTHONPATH`` searched at startup, so a writable directory on it
    let an attacker drop a ``sitecustomize.py`` that Python imports during
    interpreter startup, *before* the worker applies its limits or its
    best-effort network drop.

    The launch lives in :mod:`trustsight.sandbox._spawn`, shared with the git
    worker, so the fix cannot reach only one sandbox.
    """
    return launch_args(_WORKER_MODULE)


def _child_env() -> dict:
    """A minimal environment with no inherited import path.

    ``PYTHONPATH`` is deliberately not copied.  The worker is launched ``-I``
    and its import path is set by :func:`_launch_args`, so no environment
    variable in this process - writable by an attacker, inherited at spawn -
    can choose what the child imports or executes at startup.  A shared
    allowlist covers the loader-injection variables too (``LD_PRELOAD`` and
    friends); the child needs none of them.
    """
    return minimal_env()


# --- pool -------------------------------------------------------------------

_pool: queue.Queue = queue.Queue()
_all: list[_Worker] = []
_lock = threading.Condition()
_shutdown = threading.Event()

def _acquire() -> _Worker:
    deadline = time.monotonic() + REQUEST_TIMEOUT_SECONDS
    with _lock:
        while not _shutdown.is_set():
            try:
                worker = _pool.get_nowait()
            except queue.Empty:
                worker = None
            if worker is not None:
                if worker.alive():
                    return worker
                # A worker that died while idle is not capacity.  Retire it
                # and keep looking rather than handing it back: the request
                # would fail and mark the package NOT vetted while an empty
                # slot was available.
                try:
                    worker.stop()
                finally:
                    _forget(worker)
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
            # Saturate at the pool size: wait for capacity, but only for one
            # request timeout.  Every holder returns or kills within that
            # bound, so exceeding it means a wedged holder, and refusing is
            # safer than blocking the whole review on it.
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TokenizerUnavailable(
                    "tokenizer_unavailable: worker pool timed out"
                )
            _lock.wait(remaining)
    raise TokenizerUnavailable("tokenizer_unavailable: worker pool is shutting down")


def _worker_cpu_seconds(worker: _Worker) -> float:
    """Cumulative user+system CPU of *worker*, in seconds.

    Read from ``/proc`` rather than ``getrusage``: ``RUSAGE_CHILDREN`` is
    process-wide across every child, so it cannot say which worker is close
    to the limit.  Returns 0.0 when the reading is unavailable, which errs
    toward keeping the worker (the request-count and RLIMIT_CPU bounds
    still apply).
    """
    if worker.proc is None:
        return 0.0
    try:
        with open(f"/proc/{worker.proc.pid}/stat", "rb") as handle:
            # Bounded: /proc stat is small, and the read-bound gate is a
            # structural check on every read() in the source.
            fields = handle.read(4096).rsplit(b")", 1)[-1].split()
        ticks = int(fields[11]) + int(fields[12])  # utime, stime (1-based 14,15)
    except (OSError, IndexError, ValueError):
        return 0.0
    return ticks / os.sysconf("SC_CLK_TCK")


def _release(worker: _Worker) -> None:
    with _lock:
        if (
            not _shutdown.is_set()
            and worker.alive()
            and worker.requests < MAX_REQUESTS_PER_WORKER
            and _worker_cpu_seconds(worker) < CPU_RETIRE_SECONDS
        ):
            _pool.put(worker)
            _lock.notify()
            return
    try:
        worker.stop()
    finally:
        _forget(worker)


def _forget(worker: _Worker) -> None:
    with _lock:
        if worker in _all:
            _all.remove(worker)
        _lock.notify_all()


def _terminate_all() -> None:
    with _lock:
        _shutdown.set()
        workers = list(_all)
        _all.clear()
        _lock.notify_all()
    for worker in workers:
        worker.stop()


atexit.register(_terminate_all)


def reset_after_fork() -> None:
    """Drop the inherited pool after ``fork``; the child starts its own.

    The parent's workers are *not* stopped here: the pids name the same
    processes in the child's table, and stopping one would kill the
    parent's pool.  Only this process's bookkeeping and content cache are
    cleared, so the first request in the child spawns a fresh pool.
    """
    global _pool
    with _lock:
        _pool = queue.Queue()
        _all.clear()
        _shutdown.clear()
        _lock.notify_all()
    if getattr(_cache, "entries", None) is not None:
        _cache.entries.clear()
        _cache.bytes = 0


# --- content cache ----------------------------------------------------------
#
# Every request is a few milliseconds of child work plus IPC; the analysis
# asks the same pure questions repeatedly (measured: ~126 calls per diff,
# only ~27 distinct inputs).  The cache is content-keyed so equal diffs built
# by different call sites share one round-trip.  The previous cache keyed on
# ``id(payload)`` with 16 FIFO entries and missed almost always: readers
# rebuild equal line lists constantly and the working set is larger than 16.

_MISSING = object()
_cache = threading.local()

#: Entries per thread.  Sized for one diff's working set plus the handful of
#: text variants (raw, clamped, pre, post) readers ask about.
_CACHE_MAX_ENTRIES = 64

#: Byte budget for the *inputs* retained by the cache.  Diffs are already
#: capped (``apply_diff_caps``), but a handful of multi-megabyte inputs must
#: not accumulate in a long-lived watcher.
_CACHE_MAX_BYTES = 32 * 1024 * 1024


def _cache_key(op: str, payload):
    """A hashable key for a pure request, or ``None`` to skip caching.

    A string is its own key (Python caches a str's hash); a list payload is
    one of the reader-rebuilt line lists, so it is keyed by content.  An
    unexpected shape is not cached rather than guessed at.
    """
    if isinstance(payload, str):
        return (op, "s", payload)
    if isinstance(payload, (list, tuple)):
        if not all(isinstance(item, str) for item in payload):
            return None
        return (op, "l", tuple(payload))
    return None


def _payload_bytes(payload) -> int:
    if isinstance(payload, str):
        return len(payload)
    if isinstance(payload, (list, tuple)):
        return sum(len(item) for item in payload if isinstance(item, str))
    return 0


def _value_bytes(value) -> int:
    """A cheap size estimate for a cached result, bounded by the same cap.

    The input budget alone would let a small request cache a large expansion
    (the engine caps one at 1 MiB), so the result counts too.
    """
    if isinstance(value, str):
        return len(value)
    if isinstance(value, (list, tuple)):
        return sum(_value_bytes(item) for item in value)
    if isinstance(value, dict):
        return sum(_value_bytes(key) + _value_bytes(item)
                   for key, item in value.items())
    return 0


def _cache_get(key):
    store = getattr(_cache, "entries", None)
    if not store:
        return _MISSING
    entry = store.get(key)
    if entry is None:
        return _MISSING
    store.move_to_end(key)
    return entry[1]


def _cache_put(key, payload, value) -> None:
    store = getattr(_cache, "entries", None)
    if store is None:
        store = OrderedDict()
        _cache.entries = store
        _cache.bytes = 0
    size = _payload_bytes(payload) + _value_bytes(value)
    previous = store.pop(key, None)
    if previous is not None:
        _cache.bytes -= previous[0]
    store[key] = (size, value)
    _cache.bytes += size
    while store and (len(store) > _CACHE_MAX_ENTRIES
                     or _cache.bytes > _CACHE_MAX_BYTES):
        _old_key, (old_size, _old_value) = store.popitem(last=False)
        _cache.bytes -= old_size


def _copy(value):
    """Return a caller-owned structure; the cache keeps the original.

    A shared list would turn any in-place edit by one rule into a bug in an
    unrelated one.  The cache still collapses the repeated whole-diff calls,
    because those are keyed on the input content, not on the copied result.
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

    The response is cached by the *content* of the input, so the many call
    sites that pass an equal diff or an equal line list share one round-trip,
    and a fresh copy is returned so no caller can edit the cached value.
    """
    key = _cache_key(op, payload)
    cached = _cache_get(key) if key is not None else _MISSING
    if cached is not _MISSING:
        return _copy(cached)
    value = _send(op, payload)
    if key is not None:
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
        if not isinstance(response, dict):
            raise _WorkerError("malformed response from the tokenizer worker")
        if "error" not in response and "result" not in response:
            raise _WorkerError("response carried neither result nor error")
    except Exception as exc:
        worker.stop()
        _forget(worker)
        raise TokenizerUnavailable(f"tokenizer_unavailable: {exc}") from exc
    degraded = response.get("degraded")
    if degraded:
        worker.degraded = list(degraded)
        if not worker._degraded_reported:
            worker._degraded_reported = True
            _log.warning(
                "tokenizer sandbox protection degraded: %s",
                "; ".join(str(item) for item in degraded),
            )
    _release(worker)
    if "error" in response:
        raise TokenizerUnavailable(f"tokenizer_unavailable: {response['error']}")
    return response["result"]
