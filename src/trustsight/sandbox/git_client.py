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

from ..coverage import note_stage_failure
from ..schema import DiffSummary
from . import protocol
from ._spawn import spawn_isolated
from .git_bounds import (
    GIT_COMMIT_META_MAX_OIDS,
    GIT_FETCH_TIMEOUT_SECONDS,
    GIT_OP_TIMEOUT_SECONDS,
    GIT_WORKER_RETIRE_CPU_SECONDS,
)

_log = logging.getLogger(__name__)

_WORKER_MODULE = "trustsight.sandbox.git_worker"

_live: set["GitSession"] = set()
_live_lock = threading.Lock()


class GitSandboxUnavailable(RuntimeError):
    """The git sandbox could not answer for this request."""


class GitOpError(RuntimeError):
    """The worker answered with an operation error (not a transport failure)."""

    def __init__(self, message: str, received_bytes: int = 0) -> None:
        super().__init__(message)
        #: Bytes a failed transfer still wrote, for the run-wide budget.
        self.received_bytes = received_bytes


class GitTransferTooLargeError(GitOpError):
    """The worker aborted a transfer at its per-transfer byte ceiling."""


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


def _worker_cpu_seconds(pid: int) -> float:
    """Cumulative user+system CPU of *pid*, or 0.0 when unavailable.

    Read from ``/proc`` rather than ``getrusage``: ``RUSAGE_CHILDREN`` is
    process-wide across every child, so it cannot say which worker is close
    to the limit.  An unavailable reading errs toward keeping the worker;
    its request and ``RLIMIT_CPU`` bounds still apply.
    """
    try:
        with open(f"/proc/{pid}/stat", "rb") as handle:
            fields = handle.read(4096).rsplit(b")", 1)[-1].split()
        ticks = int(fields[11]) + int(fields[12])  # utime, stime
    except (OSError, IndexError, ValueError):
        return 0.0
    return ticks / os.sysconf("SC_CLK_TCK")


class GitSession:
    """One isolated worker, exclusive to a package's requests."""

    def __init__(self) -> None:
        self.proc = spawn_isolated(_WORKER_MODULE)
        self._closed = False
        #: Why this worker was retired, so the refusal names the cause.
        self._retired = ""
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
            raise GitSandboxUnavailable(self._retired or "session is not running")
        if self.proc.poll() is not None:
            self.close()
            raise GitSandboxUnavailable("git worker exited during startup")
        body = json.dumps({"op": op, **payload}, separators=(",", ":"),
                          ensure_ascii=False).encode("utf-8")
        # The worker refuses an over-cap frame by exiting, which the parent
        # would see as an opaque EOF.  Refuse it here, where the reason is
        # still known, the way the tokenizer client does.
        if len(body) > protocol.MAX_FRAME_BYTES:
            raise GitSandboxUnavailable(
                f"request of {len(body)} bytes exceeds the "
                f"{protocol.MAX_FRAME_BYTES}-byte cap")
        deadline = time.monotonic() + timeout
        try:
            protocol.write_frame(self.proc.stdin.fileno(), body, deadline)
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
        self._maybe_retire()
        if not isinstance(response, dict):
            self.close()
            raise GitSandboxUnavailable("malformed response from the git worker")
        if "error" in response:
            received = response.get("received_bytes", 0)
            if not isinstance(received, int) or isinstance(received, bool):
                received = 0
            if response.get("too_large"):
                raise GitTransferTooLargeError(response["error"], received)
            raise GitOpError(response["error"], received)
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

    def _maybe_retire(self) -> None:
        """Retire a worker that has burned its CPU allowance.

        ``RLIMIT_CPU`` kills the child mid-request, which the caller cannot
        tell apart from a defect in the repository it just asked about.  The
        ceiling here is lower, so the worker is retired *between* requests
        and the failure is attributed to the package that spent the budget.
        """
        if self.proc is None:
            return
        if _worker_cpu_seconds(self.proc.pid) >= GIT_WORKER_RETIRE_CPU_SECONDS:
            self._retired = (
                "git worker retired after "
                f"{GIT_WORKER_RETIRE_CPU_SECONDS} cpu seconds")
            self.close()

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
                        max_bytes: int | None = None,
                        baseline_oid: str = "",
                        present_before: bool = False):
        return self.request("companion_hunks", {
            "pkg": pkg, "cache_dir": cache_dir, "oid": oid,
            "max_bytes": max_bytes, "baseline": baseline_oid,
            "present_before": present_before,
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
        """Commits under *head*, newest first, with their identities."""
        return self.request("walk", {
            "pkg": pkg, "cache_dir": cache_dir, "head": head, "limit": limit,
        })["commits"]

    def commit_meta(self, pkg: str, cache_dir: str, oids) -> list[dict]:
        oids = list(oids)
        if len(oids) > GIT_COMMIT_META_MAX_OIDS:
            raise GitOpError(
                f"too many commit ids: {len(oids)} > "
                f"{GIT_COMMIT_META_MAX_OIDS}")
        return self.request("commit_meta", {
            "pkg": pkg, "cache_dir": cache_dir, "oids": oids,
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


_Commit = namedtuple(
    "Commit",
    "id commit_time parents message author_name author_email "
    "committer_name committer_email",
)

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
            author_name=record.get("author_name", ""),
            author_email=record.get("author_email", ""),
            committer_name=record.get("committer_name", ""),
            committer_email=record.get("committer_email", ""),
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
            # The worker's normal "no such member" answer is an empty text,
            # not an error: an error means the file exists but could not be
            # read (oversize, unavailable repository).  Collapsing that to
            # "" would let current-state rules skip it while the run still
            # looks complete (B2).
            note_stage_failure("git-file-read")
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
            # "No parent" is a real shape (a root commit); "could not ask"
            # is a skipped stage.  They must not both read as "".
            note_stage_failure("git-parent-read")
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

    def companion_hunks(self, oid: str, max_bytes: int | None = None,
                        baseline_oid: str = ""):
        result = self._session.companion_hunks(
            self.pkg, self.cache_dir, oid, max_bytes, baseline_oid)
        return result["text"], result["truncated"]

    def companion_hunks_with_present_before(
            self, oid: str, max_bytes: int | None = None,
            baseline_oid: str = ""):
        result = self._session.companion_hunks(
            self.pkg, self.cache_dir, oid, max_bytes, baseline_oid,
            present_before=True)
        return (
            result["text"], result["truncated"],
            result.get("present_before", ""),
        )

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
