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
import stat
import threading
import time
import weakref
from collections import namedtuple
from pathlib import Path

from ..coverage import note_stage_failure
from ..schema import DiffSummary
from . import protocol
from ._aur_proxy import AurFetchProxy
from ._spawn import spawn_isolated
from .git_bounds import (
    GIT_COMMIT_META_MAX_OIDS,
    GIT_FETCH_TIMEOUT_SECONDS,
    GIT_OP_TIMEOUT_SECONDS,
    GIT_WORKER_MAX_FILES,
    GIT_WORKER_MONITOR_SECONDS,
    GIT_WORKER_RETIRE_CPU_SECONDS,
    GIT_WORKER_WRITE_BYTES,
)

_log = logging.getLogger(__name__)

_WORKER_MODULE = "trustsight.sandbox.git_worker"

_live: set["GitSession"] = set()
_live_lock = threading.Lock()
_roots_cleaned = False
_roots_lock = threading.Lock()


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


def _cleanup_stale_sandbox_roots() -> None:
    """Remove empty root directories left by crashed workers.

    The worker creates a host-visible mount-namespace root under /tmp and
    pivots into it.  When the worker exits, the mount namespace disappears but
    the empty host directory remains; clean old ones once per process.
    """
    global _roots_cleaned
    with _roots_lock:
        if _roots_cleaned:
            return
        _roots_cleaned = True
    cutoff = time.time() - 3600
    try:
        entries = os.scandir("/tmp")
    except OSError:
        return
    with entries:
        for entry in entries:
            if not entry.name.startswith("trustsight-root-"):
                continue
            try:
                if not entry.is_dir(follow_symlinks=False):
                    continue
                if entry.stat(follow_symlinks=False).st_mtime > cutoff:
                    continue
                os.rmdir(entry.path)
            except OSError:
                pass


def _worker_write_bytes(pid: int) -> int:
    """Kernel-accounted bytes this worker has written to storage."""
    try:
        with open(f"/proc/{pid}/io", "rb") as handle:
            for line in handle:
                if line.startswith(b"write_bytes:"):
                    return int(line.split(b":", 1)[1])
    except (OSError, ValueError, IndexError):
        return 0
    return 0


def _repo_usage(cache_dir: str, pkg: str | None, cap: int) -> tuple[int, int]:
    """``(entries, bytes)`` under the package repository, stopping at *cap*."""
    if not pkg:
        return 0, 0
    root = Path(cache_dir) / pkg
    try:
        info = os.lstat(root)
    except OSError:
        return 0, 0
    if not stat.S_ISDIR(info.st_mode):
        return 0, 0
    stack = [root]
    entries = 0
    total = 0
    while stack and entries <= cap:
        directory = stack.pop()
        try:
            iterator = os.scandir(directory)
        except OSError:
            continue
        with iterator:
            for entry in iterator:
                entries += 1
                if entries > cap:
                    return entries, total
                try:
                    info = entry.stat(follow_symlinks=False)
                    total += max(info.st_size, info.st_blocks * 512)
                except OSError:
                    pass
                try:
                    if entry.is_dir(follow_symlinks=False):
                        stack.append(Path(entry.path))
                except OSError:
                    pass
    return entries, total


class GitSession:
    """One isolated worker, exclusive to a package's requests.

    The worker is started lazily for the role the next request needs.  A
    ``fetch`` request gets a worker that may reach the AUR only through the
    parent proxy; every other request gets a worker with no network path at
    all.  After a fetch, the next read restarts the session in ``read`` role
    and tears the proxy down, so the process that parsed downloaded objects
    no longer has even the loopback bridge.
    """

    def __init__(self) -> None:
        self.proc = None
        self._closed = False
        self._role = None
        self._cache_dir = None
        self._pkg = None
        self._proxy: AurFetchProxy | None = None
        #: Why this worker was retired, so the refusal names the cause.
        self._retired = ""
        #: Limit failures the worker reported.  Empty means the worker's
        #: resource bounds, NO_NEW_PRIVS and OS sandbox were all applied.
        self.degraded: list = []
        self._degraded_reported = False
        self._stderr_thread = None
        self._monitor_stop = threading.Event()
        self._monitor_thread = None
        _cleanup_stale_sandbox_roots()
        with _live_lock:
            _live.add(self)

    def _start(self, role: str, cache_dir: str, pkg: str) -> None:
        """Replace any current worker with one confined for *role*."""
        self._teardown_worker()
        self._role = role
        self._cache_dir = cache_dir
        self._pkg = pkg
        self._retired = ""
        proxy_fds: tuple = ()
        proxy_argument = ""
        if role == "fetch":
            try:
                self._proxy = AurFetchProxy(pkg)
            except Exception as exc:  # no proxy means no fetch
                self._proxy = None
                raise GitSandboxUnavailable(
                    f"git fetch proxy could not start: {exc}") from exc
            proxy_fds = tuple(self._proxy.child_fds)
            proxy_argument = ",".join(str(fd) for fd in proxy_fds)
        try:
            self.proc = spawn_isolated(
                _WORKER_MODULE, role=role,
                extra_argv=(proxy_argument,), pass_fds=proxy_fds,
            )
        except Exception as exc:
            self._close_proxy()
            raise GitSandboxUnavailable(
                f"git worker could not start: {exc}") from exc
        if self._proxy is not None:
            self._proxy.release_child_fds()
        # Drain stderr, or a child that writes a warning or a traceback
        # blocks on a full pipe.  The worker prints nothing by design, but
        # libgit2 or the interpreter can, and a wedged worker is a hang.
        self._stderr_thread = threading.Thread(
            target=self._drain_stderr, daemon=True
        )
        self._stderr_thread.start()
        self._monitor_stop = threading.Event()
        self._monitor_thread = threading.Thread(
            target=self._monitor_resources,
            args=(self.proc.pid,),
            daemon=True,
        )
        self._monitor_thread.start()

    def _ensure_worker(self, role: str, cache_dir: str, pkg: str) -> None:
        current_role = getattr(self, "_role", None)
        current_cache = getattr(self, "_cache_dir", None)
        current_pkg = getattr(self, "_pkg", None)
        if self.proc is not None and current_role in (None, role) \
                and current_cache in (None, cache_dir) \
                and current_pkg in (None, pkg):
            return
        self._start(role, cache_dir, pkg)

    def _close_proxy(self) -> None:
        proxy = getattr(self, "_proxy", None)
        self._proxy = None
        if proxy is not None:
            proxy.close()

    def _teardown_worker(self) -> None:
        proc = self.proc
        self.proc = None
        monitor = getattr(self, "_monitor_thread", None)
        stop = getattr(self, "_monitor_stop", None)
        if stop is not None:
            stop.set()
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
        if monitor is not None and monitor is not threading.current_thread():
            monitor.join(timeout=1)
        self._monitor_thread = None
        self._close_proxy()

    def _monitor_resources(self, pid: int) -> None:
        """Kill a worker that exceeds its disk/inode budget.

        ``RLIMIT_FSIZE`` is per file, so it cannot stop a defect from filling
        the disk with many files.  The parent owns the repository path and can
        read the kernel's write accounting; this watchdog is the aggregate
        bound the worker cannot forge.
        """
        interval = GIT_WORKER_MONITOR_SECONDS
        scan_every = max(1, int(1.0 / interval))
        iteration = 0
        while not self._monitor_stop.wait(interval):
            proc = self.proc
            if proc is None or proc.poll() is not None:
                return
            if _worker_write_bytes(pid) > GIT_WORKER_WRITE_BYTES:
                self._retire_for_budget(
                    "git worker exceeded its disk write budget")
                return
            if iteration % scan_every == 0:
                entries, size = _repo_usage(
                    self._cache_dir, self._pkg, GIT_WORKER_MAX_FILES)
                if entries > GIT_WORKER_MAX_FILES \
                        or size > GIT_WORKER_WRITE_BYTES:
                    self._retire_for_budget(
                        "git worker exceeded its repository write budget")
                    return
            iteration += 1

    def _retire_for_budget(self, reason: str) -> None:
        self._retired = reason
        proc = self.proc
        if proc is None:
            return
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError, OSError):
            try:
                proc.kill()
            except OSError:
                pass

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
        if self._closed:
            raise GitSandboxUnavailable(self._retired or "session is not running")
        cache_dir = payload.get("cache_dir")
        if not isinstance(cache_dir, str) or not cache_dir:
            raise GitSandboxUnavailable("request has no cache directory")
        pkg = payload.get("pkg")
        if not isinstance(pkg, str) or not pkg:
            raise GitSandboxUnavailable("request has no package name")
        role = "fetch" if op == "open_fetch" else "read"
        self._ensure_worker(role, cache_dir, pkg)
        if self.proc is None or self.proc.stdin is None \
                or self.proc.stdout is None:
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
                   transfer_timeout: int, force: bool = False,
                   previous_head: str = "") -> dict:
        return self.request("open_fetch", {
            "pkg": pkg, "cache_dir": cache_dir,
            "upstream_mtime": upstream_mtime, "offline": offline,
            "connect_timeout": connect_timeout,
            "transfer_timeout": transfer_timeout, "force": force,
            "previous_head": previous_head,
        }, timeout=GIT_FETCH_TIMEOUT_SECONDS)

    def advertised_head(self) -> str | None:
        proxy = self._proxy
        return proxy.advertised_head if proxy is not None else None

    def received_bytes(self) -> int:
        proxy = self._proxy
        return proxy.received_bytes if proxy is not None else 0

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
        self._teardown_worker()
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

class GitProject:
    """A ``GitSession`` bound to one package: the parent's read handle.

    The parent holds this instead of a ``pygit2.Repository`` and asks it for
    bounded projections.  Nothing here imports libgit2; each call is a framed
    request to the isolated child.
    """

    def __init__(self, session: "GitSession", pkg: str, cache_dir: str,
                 fetch_time: int | None = None) -> None:
        self._session = session
        self.pkg = pkg
        self.cache_dir = cache_dir
        self._fetch_time = fetch_time
        # Retire the worker when this handle is collected, so a caller that
        # forgets ``close()`` cannot accumulate children over a long walk.
        self._finalizer = weakref.finalize(self, session.close)

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
        return self._fetch_time

    def close(self) -> None:
        self._session.close()

    def __enter__(self) -> "GitProject":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


def run_op(op: str, payload: dict, timeout: float = GIT_OP_TIMEOUT_SECONDS):
    """One operation in a fresh, exclusive worker (short-lived callers).

    ``open_fetch`` is deliberately excluded: a fetch that bypasses
    ``fetcher.clone_or_fetch`` would skip parent state and advertised-HEAD
    verification, so it must go through the verified path.
    """
    if op == "open_fetch":
        raise ValueError(
            "open_fetch must go through fetcher.clone_or_fetch")
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
