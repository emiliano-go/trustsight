"""Parent-side client for the isolated git sandbox (A16).

The parent never imports ``pygit2``: it asks a bounded child
(``sandbox/git_worker.py``) for projections and works on the returned JSON.
A ``GitSession`` owns one exclusive worker for the package it serves; a
worker that times out, dies, or answers with an error is killed and the call
raises :class:`GitSandboxUnavailable`, which the fetcher maps to the existing
"fetch did not complete" handling so a failed sandbox can never read as a
clean analysis (B2).

One worker per package, not a shared pool: the git worker's input is an
attacker-authored repository on disk, a larger blast radius than a diff
string, so a poisoned repository can only retire its own session's worker.
"""

from __future__ import annotations

import atexit
import base64
import json
import logging
import os
import select
import signal
import threading
import time
import weakref
from collections import namedtuple
from pathlib import Path

from ..schema import DiffSummary
from . import protocol
from ._spawn import spawn_isolated
from .git_bounds import GIT_FETCH_TIMEOUT_SECONDS, GIT_OP_TIMEOUT_SECONDS

_log = logging.getLogger(__name__)

_WORKER_MODULE = "trustsight.sandbox.git_worker"

_live: set["GitSession"] = set()
_live_lock = threading.Lock()


class GitSandboxUnavailable(RuntimeError):
    """The git sandbox could not answer for this request."""


class GitOpError(RuntimeError):
    """The worker answered with an operation error (not a transport failure)."""


def _read_exact(fd: int, n: int, deadline: float) -> bytes:
    out = bytearray()
    while len(out) < n:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise GitSandboxUnavailable("timed out")
        ready, _, _ = select.select([fd], [], [], remaining)
        if not ready:
            raise GitSandboxUnavailable("timed out")
        chunk = os.read(fd, n - len(out))
        if not chunk:
            raise GitSandboxUnavailable("worker closed the channel")
        out.extend(chunk)
    return bytes(out)


class GitSession:
    """One isolated worker, exclusive to a package's requests."""

    def __init__(self) -> None:
        self.proc = spawn_isolated(_WORKER_MODULE)
        self._closed = False
        #: Limit failures the worker reported.  Empty means the worker's
        #: resource bounds and NO_NEW_PRIVS were all applied.
        self.degraded: list = []
        self._degraded_reported = False
        # Drain stderr, or a child that writes a warning or a traceback
        # blocks on a full pipe.  The worker prints nothing by design, but
        # libgit2 or the interpreter can, and a wedged worker is a hang.
        self._stderr_thread = threading.Thread(
            target=self._drain_stderr, daemon=True
        )
        self._stderr_thread.start()
        with _live_lock:
            _live.add(self)

    def _drain_stderr(self) -> None:
        proc = self.proc
        if proc is None or proc.stderr is None:
            return
        try:
            for line in proc.stderr:
                _log.debug("git worker: %s",
                           line.decode("utf-8", "replace").rstrip())
        except (OSError, ValueError):
            pass

    def request(self, op: str, payload: dict,
                timeout: float = GIT_OP_TIMEOUT_SECONDS) -> dict:
        if self._closed or self.proc.stdin is None or self.proc.stdout is None:
            raise GitSandboxUnavailable("session is not running")
        body = json.dumps({"op": op, **payload}, separators=(",", ":"),
                          ensure_ascii=False).encode("utf-8")
        deadline = time.monotonic() + timeout
        try:
            self.proc.stdin.write(protocol.frame(body))
            self.proc.stdin.flush()
            header = _read_exact(self.proc.stdout.fileno(),
                                 protocol.HEADER.size, deadline)
            (length,) = protocol.HEADER.unpack(header)
            if length > protocol.MAX_RESPONSE_BYTES:
                raise GitSandboxUnavailable(
                    f"response of {length} bytes exceeds the "
                    f"{protocol.MAX_RESPONSE_BYTES}-byte cap")
            raw = _read_exact(self.proc.stdout.fileno(), length, deadline)
            response = json.loads(raw.decode("utf-8"))
        except GitSandboxUnavailable:
            self.close()
            raise
        except Exception as exc:  # noqa: BLE001 - any transport fault is a refusal
            self.close()
            raise GitSandboxUnavailable(str(exc)) from exc
        if not isinstance(response, dict):
            self.close()
            raise GitSandboxUnavailable("malformed response from the git worker")
        if "error" in response:
            raise GitOpError(response["error"])
        degraded = response.get("degraded")
        if degraded:
            # A limit that failed to apply weakens the isolation, but the
            # analysis is still complete.  Report it once, loudly, rather
            # than letting a swallowed setrlimit read as full protection.
            self.degraded = list(degraded)
            if not self._degraded_reported:
                self._degraded_reported = True
                _log.warning(
                    "git sandbox protection degraded: %s",
                    "; ".join(str(d) for d in degraded))
        if "result" not in response:
            self.close()
            raise GitSandboxUnavailable("response carried neither result nor error")
        return response["result"]

    def open_fetch(self, pkg: str, cache_dir: str, upstream_mtime,
                   offline: bool, connect_timeout: int,
                   transfer_timeout: int) -> dict:
        return self.request("open_fetch", {
            "pkg": pkg, "cache_dir": cache_dir,
            "upstream_mtime": upstream_mtime, "offline": offline,
            "connect_timeout": connect_timeout,
            "transfer_timeout": transfer_timeout,
        }, timeout=GIT_FETCH_TIMEOUT_SECONDS)

    def head(self, pkg: str, cache_dir: str) -> str:
        return self.request("head", {"pkg": pkg, "cache_dir": cache_dir})["head"]

    def file_at(self, pkg: str, cache_dir: str, oid: str, name: str,
                max_bytes: int) -> str:
        return self.request("file_at", {
            "pkg": pkg, "cache_dir": cache_dir, "oid": oid,
            "name": name, "max_bytes": max_bytes,
        })["text"]

    def diff(self, pkg: str, cache_dir: str, old: str, new: str,
             context_lines: int = 3, max_bytes: int | None = None) -> dict:
        return self.request("diff", {
            "pkg": pkg, "cache_dir": cache_dir, "old": old, "new": new,
            "context_lines": context_lines, "max_bytes": max_bytes,
        })

    def tree_files(self, pkg: str, cache_dir: str, oid: str):
        """``([(path, head_bytes)], complete)`` for a commit's tree."""
        result = self.request("tree_files", {
            "pkg": pkg, "cache_dir": cache_dir, "oid": oid,
        })
        files = [(name, base64.b64decode(data))
                 for name, data in result["files"]]
        return files, result["complete"]

    def companion_hunks(self, pkg: str, cache_dir: str, oid: str,
                        max_bytes: int | None = None):
        return self.request("companion_hunks", {
            "pkg": pkg, "cache_dir": cache_dir, "oid": oid,
            "max_bytes": max_bytes,
        })

    def opaque_changed(self, pkg: str, cache_dir: str, old: str, new: str):
        return self.request("opaque_changed", {
            "pkg": pkg, "cache_dir": cache_dir, "old": old, "new": new,
        })["names"]

    def binary_meta(self, pkg: str, cache_dir: str, old: str, new: str):
        return self.request("binary_meta", {
            "pkg": pkg, "cache_dir": cache_dir, "old": old, "new": new,
        })["paths"]

    def walk(self, pkg: str, cache_dir: str, head: str,
             limit: int | None = None) -> list[dict]:
        """Commits under *head*, newest first: ``{id, commit_time, parents}``."""
        return self.request("walk", {
            "pkg": pkg, "cache_dir": cache_dir, "head": head, "limit": limit,
        })["commits"]

    def commit_meta(self, pkg: str, cache_dir: str, oids) -> list[dict]:
        return self.request("commit_meta", {
            "pkg": pkg, "cache_dir": cache_dir, "oids": list(oids),
        })["commits"]

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        proc = self.proc
        self.proc = None
        if proc is not None:
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
            for pipe in (proc.stdin, proc.stdout, proc.stderr):
                if pipe is not None:
                    try:
                        pipe.close()
                    except OSError:
                        pass
        with _live_lock:
            _live.discard(self)

    def __enter__(self) -> "GitSession":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


_Commit = namedtuple("Commit", "id commit_time parents message")

#: The fetch marker filename.  Repeated here rather than imported from
#: ``git_project`` so the parent never pulls libgit2 into the process.
_FETCH_MARKER = "trustsight-last-fetch"


class GitProject:
    """A ``GitSession`` bound to one package: the parent's read handle.

    The parent holds this instead of a ``pygit2.Repository`` and asks it for
    bounded projections.  Nothing here imports libgit2; each call is a framed
    request to the isolated child.
    """

    def __init__(self, session: "GitSession", pkg: str, cache_dir: str) -> None:
        self._session = session
        self.pkg = pkg
        self.cache_dir = cache_dir
        # Retire the worker when this handle is collected, so a caller that
        # forgets ``close()`` cannot accumulate children over a long walk.
        self._finalizer = weakref.finalize(self, session.close)

    @property
    def path(self) -> str:
        return str(Path(self.cache_dir) / self.pkg)

    def _commit(self, record: dict) -> "_Commit":
        return _Commit(
            id=record.get("id", ""),
            commit_time=record.get("commit_time", 0),
            parents=list(record.get("parents", ())),
            message=record.get("message", ""),
        )

    def head_commit(self) -> str:
        return self._session.head(self.pkg, self.cache_dir)

    def file_at(self, oid: str, name: str, max_bytes: int | None = None) -> str:
        from .git_bounds import GIT_FILE_AT_MAX_BYTES

        if not oid:
            return ""
        cap = GIT_FILE_AT_MAX_BYTES if max_bytes is None else max_bytes
        try:
            return self._session.file_at(self.pkg, self.cache_dir, oid, name, cap)
        except GitOpError:
            return ""

    def walk(self, head: str, limit: int | None = None) -> list["_Commit"]:
        return [self._commit(r)
                for r in self._session.walk(self.pkg, self.cache_dir, head, limit)]

    def commit_meta(self, oids) -> list["_Commit"]:
        return [self._commit(r)
                for r in self._session.commit_meta(self.pkg, self.cache_dir, oids)]

    def parent_commit(self, head: str) -> str:
        if not head:
            return ""
        try:
            records = self.commit_meta([head])
        except (GitSandboxUnavailable, GitOpError):
            return ""
        if not records or not records[0].parents:
            return ""
        return records[0].parents[0]

    def diff_bounded(self, old: str, new: str, context_lines: int = 3,
                     max_bytes: int | None = None):
        result = self._session.diff(
            self.pkg, self.cache_dir, old, new, context_lines, max_bytes)
        summary = result["summary"]
        diff_summary = DiffSummary(
            lines_added=summary["lines_added"],
            lines_removed=summary["lines_removed"],
            files_changed=list(summary["files_changed"]),
            file_changes=[dict(entry) for entry in summary["file_changes"]],
        )
        return result["unified"], diff_summary, bool(result["truncated"])

    def tree_files(self, oid: str):
        return self._session.tree_files(self.pkg, self.cache_dir, oid)

    def companion_hunks(self, oid: str, max_bytes: int | None = None):
        result = self._session.companion_hunks(
            self.pkg, self.cache_dir, oid, max_bytes)
        return result["text"], result["truncated"]

    def opaque_changed(self, old: str, new: str) -> list[str]:
        return self._session.opaque_changed(self.pkg, self.cache_dir, old, new)

    def binary_meta(self, old: str, new: str) -> list[str]:
        return self._session.binary_meta(self.pkg, self.cache_dir, old, new)

    def last_fetch_time(self):
        try:
            return int((Path(self.path) / _FETCH_MARKER).read_text().strip())
        except (OSError, ValueError):
            return None

    def close(self) -> None:
        self._session.close()

    def __enter__(self) -> "GitProject":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


def run_op(op: str, payload: dict, timeout: float = GIT_OP_TIMEOUT_SECONDS):
    """One operation in a fresh, exclusive worker (short-lived callers)."""
    session = GitSession()
    try:
        return session.request(op, payload, timeout=timeout)
    finally:
        session.close()


def _terminate_all() -> None:
    with _live_lock:
        sessions = list(_live)
    for session in sessions:
        session.close()


def reset_after_fork() -> None:
    """Drop inherited session bookkeeping after ``fork``.

    The parent's workers are *not* stopped here: their pids name the same
    processes in the child's table, so stopping one would kill the parent's
    session.  Clearing the registry only keeps the child's ``atexit`` from
    tearing down the parent's workers.
    """
    with _live_lock:
        _live.clear()


atexit.register(_terminate_all)
