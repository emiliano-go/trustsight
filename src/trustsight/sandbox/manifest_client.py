"""Parent-side client for the manifest parser sandbox.

One persistent worker is enough for the manifest reads in a review; requests
are serialised and cached by ``(path, text-hash)``.  A worker that dies,
times out, or answers with an error is a named refusal, never a local
fallback: the whole point is that the parent does not parse hostile bytes.
"""

from __future__ import annotations

import atexit
import base64
import hashlib
import json
import os
import threading
import time

from . import _worker_io, protocol
from ._spawn import spawn_isolated

WORKER_MODULE = "trustsight.sandbox.manifest_worker"
REQUEST_TIMEOUT_SECONDS = 10.0
MAX_REQUESTS_PER_WORKER = 1024
MAX_CACHE_ENTRIES = 512

#: A snapshot is base64-encoded inside a framed JSON request.  The protocol
#: caps one frame at ~31 MiB, so 16 MiB of raw bytes is the largest snapshot
#: that fits with its escaping overhead.  A larger archive is a refusal, not
#: an unbounded allocation on the channel.
MAX_SNAPSHOT_PAYLOAD_BYTES = 16 * 1024 * 1024


class ManifestUnavailable(RuntimeError):
    """The manifest sandbox could not answer for this input."""


class _Worker:
    def __init__(self) -> None:
        self.proc = None
        self.requests = 0
        self.degraded: list = []
        self.stderr: list[str] = []
        self._stderr_thread = None

    def start(self) -> None:
        self.proc = spawn_isolated(WORKER_MODULE)
        self.requests = 0
        self.stderr = []
        self._stderr_thread = threading.Thread(
            target=self._drain_stderr, daemon=True)
        self._stderr_thread.start()

    def _drain_stderr(self) -> None:
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
            raise ManifestUnavailable("manifest worker is not running")
        if self.proc.poll() is not None:
            detail = "; ".join(self.stderr) or f"exit {self.proc.returncode}"
            raise ManifestUnavailable(f"manifest worker exited: {detail}")
        deadline = time.monotonic() + REQUEST_TIMEOUT_SECONDS
        try:
            protocol.write_frame(self.proc.stdin.fileno(), body, deadline)
            header = _worker_io.read_exact(
                self.proc.stdout, protocol.HEADER.size, deadline,
                ManifestUnavailable)
            (length,) = protocol.HEADER.unpack(header)
            if length > protocol.MAX_RESPONSE_BYTES:
                raise ManifestUnavailable("manifest response exceeds its cap")
            return _worker_io.read_exact(
                self.proc.stdout, length, deadline, ManifestUnavailable)
        except (BrokenPipeError, OSError, protocol.FrameError) as exc:
            detail = "; ".join(self.stderr)
            raise ManifestUnavailable(
                f"manifest worker channel failed: {exc}"
                + (f" ({detail})" if detail else "")) from exc


_lock = threading.Lock()
_worker: _Worker | None = None
_cache: dict[tuple, dict | None] = {}
_cache_bytes = 0
MAX_CACHE_BYTES = 32 * 1024 * 1024


def _get_worker() -> _Worker:
    global _worker
    if _worker is None or not _worker.alive()             or _worker.requests >= MAX_REQUESTS_PER_WORKER:
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
    """Drop inherited worker bookkeeping; the child starts its own worker.

    The parent's worker pid is still valid in the child's table, but the
    parent's threads are not, and the inherited lock may have been held at
    fork time.  Replacing both without taking the old lock is what makes the
    first request in a forked corpus worker safe.
    """
    global _worker, _lock, _cache_bytes
    _worker = None
    _lock = threading.Lock()
    _cache.clear()
    _cache_bytes = 0


os.register_at_fork(after_in_child=_after_fork)


def _ask(payload: bytes):
    """Send one frame and decode the result; kill a wedged worker.

    Called with ``_lock`` held.  A timeout, closed channel or invalid reply
    leaves a worker that cannot be trusted for the next request, so it is
    stopped and the caller sees the named refusal.
    """
    global _worker, _cache_bytes
    worker = _get_worker()
    try:
        raw = worker.request(payload)
        worker.requests += 1
        try:
            response = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ManifestUnavailable(
                "manifest worker returned invalid JSON") from exc
        if not isinstance(response, dict) or "result" not in response:
            raise ManifestUnavailable(
                response.get("error", "manifest worker returned no result")
                if isinstance(response, dict)
                else "manifest worker returned no result")
        return response["result"]
    except ManifestUnavailable as exc:
        detail = "; ".join(worker.stderr)
        worker.stop()
        _worker = None
        if detail:
            raise ManifestUnavailable(f"{exc} ({detail})") from exc
        raise


def _remember(key: tuple, result) -> None:
    """Cache a projection under a byte budget, not only an entry count."""
    global _cache_bytes
    try:
        size = len(json.dumps(result, separators=(",", ":")))
    except (TypeError, ValueError):
        return
    if size > MAX_CACHE_BYTES:
        return
    if key in _cache:
        return
    if len(_cache) >= MAX_CACHE_ENTRIES or _cache_bytes + size > MAX_CACHE_BYTES:
        _cache.clear()
        _cache_bytes = 0
    _cache[key] = result
    _cache_bytes += size


def parse_srcinfo(text: str) -> dict[str, list[str]]:
    """Parse .SRCINFO in the sandboxed worker."""
    digest = hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()
    key = ("__srcinfo__", digest)
    with _lock:
        if key in _cache:
            return _cache[key]
        payload = json.dumps(
            {"path": "__srcinfo__", "text": text}, ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        result = _ask(payload)
        _remember(key, result)
        return result


def request_tokenizer(op: str, value):
    """Run one tokenizer operation in the content worker.

    The analysis path uses this instead of a second tokenizer process: the
    worker already loads the engine locally and has no nested sandbox to
    spawn.  A dead or timed-out worker is a named refusal.  Results are not
    cached here; the tokenizer facade memoises and this avoids retaining
    multi-megabyte resolved diffs.
    """
    with _lock:
        payload = json.dumps(
            {"path": "__tokenizer__", "token_op": op, "input": value},
            ensure_ascii=False, separators=(",", ":"),
        ).encode("utf-8")
        return _ask(payload)


def parse_snapshot(name: str, data: bytes, *, max_members: int = 10_000,
                   max_member_bytes: int = 8 * 1024 * 1024,
                   max_total_bytes: int = 256 * 1024 * 1024) -> dict:
    """Parse an AUR snapshot tarball in the sandboxed worker.

    ``data`` is base64-encoded inside the framed JSON request; the worker
    never opens the network or the filesystem.
    """
    if len(data) > MAX_SNAPSHOT_PAYLOAD_BYTES:
        raise ManifestUnavailable(
            f"snapshot of {len(data)} bytes exceeds the "
            f"{MAX_SNAPSHOT_PAYLOAD_BYTES}-byte worker input cap")
    with _lock:
        payload = json.dumps(
            {"path": "__snapshot__", "text": name,
             "data": base64.b64encode(data).decode("ascii"),
             "max_members": max_members,
             "max_member_bytes": max_member_bytes,
             "max_total_bytes": max_total_bytes},
            ensure_ascii=False, separators=(",", ":"),
        ).encode("utf-8")
        return _ask(payload)


def parse_upstream_archive(name: str, data: bytes, *,
                           max_members: int = 10_000,
                           max_file_bytes: int = 512 * 1024,
                           max_total_bytes: int = 64 * 1024 * 1024,
                           max_files: int = 64) -> dict:
    """Extract manifests from a declared source archive in the sandboxed worker."""
    if len(data) > MAX_SNAPSHOT_PAYLOAD_BYTES:
        raise ManifestUnavailable(
            f"archive of {len(data)} bytes exceeds the "
            f"{MAX_SNAPSHOT_PAYLOAD_BYTES}-byte worker input cap")
    with _lock:
        payload = json.dumps(
            {"path": "__upstream_archive__", "text": name,
             "data": base64.b64encode(data).decode("ascii"),
             "max_members": max_members,
             "max_file_bytes": max_file_bytes,
             "max_total_bytes": max_total_bytes,
             "max_files": max_files},
            ensure_ascii=False, separators=(",", ":"),
        ).encode("utf-8")
        return _ask(payload)


def parse_manifest(path: str, text: str) -> dict | None:
    """Parse one manifest in the sandboxed worker.

    Returns the serialised :class:`ManifestDoc` projection, or ``None`` when
    the path is not a manifest.  A refusal raises :class:`ManifestUnavailable`;
    the caller records a coverage gap.
    """
    digest = hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()
    key = (path, digest)
    with _lock:
        if key in _cache:
            return _cache[key]
        payload = json.dumps(
            {"path": path, "text": text}, ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        result = _ask(payload)
        _remember(key, result)
        return result
