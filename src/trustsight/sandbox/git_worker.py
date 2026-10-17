"""Child entry point for the isolated git sandbox (A16).

The only module under ``src/`` that imports ``pygit2``.  It is started by
``trustsight.sandbox.git_client`` as ``python -I -c <bootstrap>`` with a
minimal environment; it owns every libgit2 handle and answers a small set of
projection requests over the framed JSON protocol.  The parent never calls
libgit2, so a memory-safety defect in libgit2 (or in the bundled pack/delta
code) exhausts or kills this bounded child instead of the analysis.

Confinement, all fixed constants from :mod:`trustsight.sandbox.git_bounds`:

* ``RLIMIT_AS`` caps the address space, so a delta-result-size amplification
  exhausts the child, not the analysis process.
* ``RLIMIT_CPU`` and ``RLIMIT_FSIZE`` cap work and disk (unlike the tokenizer
  worker, this one writes the clone and the fetch marker).
* ``PR_SET_NO_NEW_PRIVS`` makes a defect here unable to gain privilege.
* The network is *kept* - the worker must reach the A3 AUR host - but the
  remote URL is built here from a validated package name, never received.
* libgit2 is configured with no user home, strict object creation and strict
  hash verification, and a fixed pack object ceiling.
"""

import atexit
import base64
import ctypes
import json
import os
import re
import resource
import shutil
import sys
import tempfile
import time
from pathlib import Path

import pygit2

from trustsight.sandbox import protocol
from trustsight.sandbox.git_bounds import (
    GIT_COMMIT_META_MAX_OIDS,
    GIT_DIFF_MAX_CONTEXT_LINES,
    GIT_FILE_AT_MAX_BYTES,
    GIT_PACK_MAX_OBJECTS,
    GIT_TREE_MAX_ENTRIES,
    GIT_WORKER_CPU_SECONDS,
    GIT_WORKER_FSIZE_BYTES,
    GIT_WORKER_MEMORY_BYTES,
    GIT_WORKER_NOFILE,
    MAX_TRANSFER_BYTES,
)

_PR_SET_NO_NEW_PRIVS = 38

#: Package names, matching ``fetcher``.  Repeated rather than imported so the
#: worker's path validation does not depend on the parent's module state.
_VALID_PKG_NAME = re.compile(r"^[a-zA-Z0-9@._+\-]+$")
_RESERVED_PKG_NAMES = frozenset({".", ".."})
_OID_RE = re.compile(r"^[0-9a-fA-F]{40}$")

_FETCH_MARKER = "trustsight-last-fetch"

_AUR_HOST = "https://aur.archlinux.org"


class _UnknownOp(Exception):
    """The request named an operation the worker does not implement."""


class _OpError(Exception):
    """A worker operation could not complete."""


#: Readable names for the limits, so a failure names *which* protection was
#: lost rather than a bare errno.
_LIMIT_NAMES = {
    resource.RLIMIT_AS: "RLIMIT_AS (address space)",
    resource.RLIMIT_CPU: "RLIMIT_CPU (cpu seconds)",
    resource.RLIMIT_FSIZE: "RLIMIT_FSIZE (file size)",
    resource.RLIMIT_NOFILE: "RLIMIT_NOFILE (open files)",
}

#: Limit/protection failures from startup.  Set once in :func:`main` and
#: attached to every response, so the parent can surface the weaker
#: isolation instead of it vanishing into a swallowed exception.
_DEGRADED: list[str] = []


def _apply_limits() -> list[str]:
    """Apply the worker's fixed resource limits; return what could not be set.

    A limit that fails to apply is **reported, not swallowed**: the isolation
    is weaker than the design intends (this is a resource-bounded subprocess,
    not an OS sandbox), and an operator must be able to see that rather than
    infer it from the absence of a crash.
    """
    failures: list[str] = []
    for which, value in (
        (resource.RLIMIT_AS, GIT_WORKER_MEMORY_BYTES),
        (resource.RLIMIT_CPU, GIT_WORKER_CPU_SECONDS),
        (resource.RLIMIT_FSIZE, GIT_WORKER_FSIZE_BYTES),
        (resource.RLIMIT_NOFILE, GIT_WORKER_NOFILE),
    ):
        try:
            resource.setrlimit(which, (value, value))
        except (ValueError, OSError) as exc:
            failures.append(
                f"{_LIMIT_NAMES.get(which, str(which))} not applied: "
                f"{type(exc).__name__}")
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        if libc.prctl(_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
            failures.append("PR_SET_NO_NEW_PRIVS not applied: prctl failed")
    except (OSError, AttributeError) as exc:
        failures.append(
            f"PR_SET_NO_NEW_PRIVS not applied: {type(exc).__name__}")
    return failures


def _harden_libgit2() -> str:
    """Configure libgit2 once; return the throwaway HOME directory used.

    ``pygit2.settings`` has no setter for the config ``search_path`` in the
    pinned release, so system/XDG git config cannot be cleared from here; the
    user's own ``~/.gitconfig`` is removed by pointing ``homedir`` at an empty
    directory.  That still sits inside the model's trusted-local-filesystem
    assumption for the system path (recorded as a drift note).
    """
    home = tempfile.mkdtemp(prefix="trustsight-git-home-")
    atexit.register(shutil.rmtree, home, ignore_errors=True)
    try:
        pygit2.settings.homedir = home
    except (AttributeError, pygit2.GitError, ValueError):
        pass
    try:
        pygit2.settings.pack_max_objects = GIT_PACK_MAX_OBJECTS
    except (AttributeError, pygit2.GitError, ValueError):
        pass
    for enable in (
        pygit2.settings.enable_strict_object_creation,
        pygit2.settings.enable_strict_hash_verification,
    ):
        try:
            enable(True)
        except (AttributeError, pygit2.GitError, ValueError, TypeError):
            pass
    return home


def _contained_repo_path(cache_dir: str, pkg: str):
    """The repo path for *pkg* under *cache_dir*, or raise.

    The parent has already validated the name, but this is the value the
    worker ``rmtree``s and writes to, so it is checked again here.
    """
    if not isinstance(pkg, str) or not _VALID_PKG_NAME.match(pkg) \
            or pkg in _RESERVED_PKG_NAMES:
        raise _OpError(f"invalid package name: {pkg!r}")
    root = Path(cache_dir).resolve()
    path = (root / pkg).resolve()
    if path.parent != root:
        raise _OpError(f"package path escapes cache directory: {pkg!r}")
    return path


def _head_commit_id(repo) -> str:
    try:
        return str(repo.head.peel().id)
    except pygit2.GitError:
        pass
    if repo.head_is_unborn or repo.is_empty:
        return ""
    for name in ("main", "master"):
        try:
            return str(repo.branches[name].peel().id)
        except (KeyError, pygit2.GitError):
            pass
    for ref_name in repo.references:
        try:
            return str(repo.references[ref_name].peel().id)
        except (TypeError, pygit2.GitError):
            pass
    raise _OpError("cannot resolve HEAD to a commit")


def _last_fetch_time(repo):
    try:
        return int((Path(repo.path) / _FETCH_MARKER).read_text().strip())
    except (OSError, ValueError):
        return None


def _marker_path(repo):
    return Path(repo.path) / _FETCH_MARKER


def _record_fetch(repo):
    stamp = int(time.time())
    try:
        _marker_path(repo).write_text(str(stamp))
    except OSError:
        return None
    return stamp


def _is_current(repo, upstream_mtime) -> bool:
    fetched = _last_fetch_time(repo)
    if fetched is not None:
        try:
            return fetched >= int(upstream_mtime)
        except (TypeError, ValueError):
            return False
    try:
        return int(repo.head.peel().commit_time) >= int(upstream_mtime)
    except (AttributeError, pygit2.GitError, KeyError, TypeError, ValueError):
        return False


def _advance_to_fetched_head(repo) -> None:
    try:
        if repo.head_is_unborn or repo.head_is_detached:
            local_name = None
        else:
            local_name = repo.head.shorthand
    except pygit2.GitError:
        local_name = None
    remote_ref_name = None
    if local_name:
        candidate = f"refs/remotes/origin/{local_name}"
        if candidate in repo.references:
            remote_ref_name = candidate
    if remote_ref_name is None:
        origin_head = repo.references.get("refs/remotes/origin/HEAD")
        symbolic = getattr(origin_head, "symbolic_target", None) if origin_head else None
        if symbolic:
            remote_ref_name = symbolic
    if remote_ref_name is None:
        return
    remote_ref = repo.references.get(remote_ref_name)
    target = getattr(remote_ref, "target", None)
    if target is None:
        return
    branch_ref = (
        repo.references.get(f"refs/heads/{local_name}") if local_name else None
    )
    if branch_ref is not None:
        branch_ref.set_target(target)
    else:
        repo.set_head(remote_ref_name)


class _Callbacks(pygit2.RemoteCallbacks):
    """Abort a transfer that runs past its deadline or its byte ceiling.

    libgit2 invokes these as data arrives, so raising from one cancels the
    operation mid-transfer.  The byte ceiling is the bound the deadline does
    not give: a fast link moves gigabytes inside a 120-second window.
    ``received_bytes`` is cumulative for the transfer, so the last value is
    what the parent charges to the run budget.
    """

    def __init__(self, seconds: int):
        super().__init__()
        self._deadline = time.monotonic() + seconds
        self.received_bytes = 0

    def _check(self):
        if time.monotonic() > self._deadline:
            raise _OpError("fetch timed out")

    def transfer_progress(self, stats):
        self._check()
        received = getattr(stats, "received_bytes", 0) or 0
        if received > MAX_TRANSFER_BYTES:
            raise _OpError(
                f"transfer exceeded {MAX_TRANSFER_BYTES} bytes"
            )
        self.received_bytes = max(self.received_bytes, received)

    def sideband_progress(self, string):
        self._check()


def _open_fetch(payload: dict) -> dict:
    pkg = payload.get("pkg", "")
    cache_dir = payload.get("cache_dir", "")
    upstream_mtime = payload.get("upstream_mtime")
    offline = payload.get("offline") is True
    connect = _positive_int(payload.get("connect_timeout"), 10)
    transfer = _positive_int(payload.get("transfer_timeout"), 30)

    path = _contained_repo_path(cache_dir, pkg)
    try:
        pygit2.settings.server_connect_timeout = connect * 1000
        pygit2.settings.server_timeout = transfer * 1000
    except (AttributeError, pygit2.GitError, ValueError):
        pass

    if path.exists():
        cached = None
        try:
            cached = pygit2.Repository(str(path))
            if not _head_commit_id(cached):
                raise pygit2.GitError("cached clone has no commits")
        except (pygit2.GitError, _OpError):
            shutil.rmtree(path, ignore_errors=True)
            cached = None
        if cached is not None:
            if upstream_mtime is not None and _is_current(cached, upstream_mtime):
                return {"path": str(path), "head": _head_commit_id(cached),
                        "fetched": False, "marker_time": _last_fetch_time(cached),
                        "received_bytes": 0}
            if offline:
                return {"path": str(path), "head": _head_commit_id(cached),
                        "fetched": False, "marker_time": _last_fetch_time(cached),
                        "received_bytes": 0}
            callbacks = _Callbacks(120)
            cached.remotes["origin"].fetch(callbacks=callbacks)
            _advance_to_fetched_head(cached)
            return {"path": str(path), "head": _head_commit_id(cached),
                    "fetched": True, "marker_time": _record_fetch(cached),
                    "received_bytes": callbacks.received_bytes}

    if offline:
        raise _OpError(
            "TRUSTSIGHT_OFFLINE is set and no cached clone exists for "
            f"{pkg!r}: refusing to clone from the AUR"
        )
    os.makedirs(path.parent, exist_ok=True)
    url = f"{_AUR_HOST}/{pkg}.git"
    callbacks = _Callbacks(120)
    repo = pygit2.clone_repository(url, str(path), bare=True,
                                   callbacks=callbacks)
    return {"path": str(path), "head": _head_commit_id(repo),
            "fetched": True, "marker_time": _record_fetch(repo),
            "received_bytes": callbacks.received_bytes}


def _head(payload: dict) -> dict:
    repo = _open_repo(payload.get("cache_dir", ""), payload.get("pkg", ""))
    return {"head": _head_commit_id(repo)}


def _file_at(payload: dict) -> dict:
    """The body of one named top-level file at a commit, as text."""
    name = payload.get("name", "")
    if name not in ("PKGBUILD", ".SRCINFO"):
        raise _OpError(f"file_at refuses unknown member: {name!r}")
    oid = _require_oid(payload.get("oid"), "commit id")
    max_bytes = _positive_int(payload.get("max_bytes"), GIT_FILE_AT_MAX_BYTES)
    max_bytes = min(max_bytes, GIT_FILE_AT_MAX_BYTES)
    repo = _open_repo(payload.get("cache_dir", ""), payload.get("pkg", ""))
    commit = repo.get(oid) if oid else None
    if not isinstance(commit, pygit2.Commit):
        return {"text": ""}
    try:
        blob = commit.tree[name]
    except (KeyError, AttributeError):
        return {"text": ""}
    if getattr(blob, "size", 0) > max_bytes:
        raise _OpError(f"{name} exceeds {max_bytes} bytes")
    return {"text": blob.data.decode("utf-8", errors="replace")}


def _diff(payload: dict) -> dict:
    """Two commits' metadata-file diff, as text plus a serialised summary.

    Reuses ``differ.generate_diff_bounded`` so the parent's current in-process
    result and the isolated one cannot drift: the same code builds the patch
    text, applies the same caps, and selects the same files.
    """
    from trustsight.sandbox.git_project import generate_diff_bounded

    old = _require_oid(payload.get("old"), "commit id")
    new = _require_oid(payload.get("new"), "commit id")
    if not new:
        raise _OpError("missing new commit")
    try:
        context = int(payload.get("context_lines", 3))
    except (TypeError, ValueError, OverflowError):
        context = 3
    context = max(0, min(context, GIT_DIFF_MAX_CONTEXT_LINES))
    max_bytes = payload.get("max_bytes")
    if max_bytes is not None:
        try:
            max_bytes = int(max_bytes)
        except (TypeError, ValueError, OverflowError):
            max_bytes = None
    repo = _open_repo(payload.get("cache_dir", ""), payload.get("pkg", ""))
    text, summary, truncated = generate_diff_bounded(
        repo, old, new, context_lines=context, max_bytes=max_bytes)
    return {
        "unified": text,
        "summary": {
            "lines_added": summary.lines_added,
            "lines_removed": summary.lines_removed,
            "files_changed": list(summary.files_changed),
            "file_changes": [dict(entry) for entry in summary.file_changes],
        },
        "truncated": bool(truncated),
    }


def _require_oid(value, name: str) -> str:
    oid = value or ""
    if not isinstance(oid, str):
        raise _OpError(f"invalid {name}: {type(value).__name__}")
    if oid and not _OID_RE.match(oid):
        raise _OpError(f"invalid {name}: {oid!r}")
    return oid


def _positive_int(value, default: int) -> int:
    """*value* as a positive int, or *default* when absent or nonsensical.

    ``OverflowError`` is caught too: JSON accepts ``Infinity``/``NaN``, and
    ``int(float("inf"))`` raises rather than returning a number.
    """
    try:
        number = int(value)
    except (TypeError, ValueError, OverflowError):
        return default
    return number if number > 0 else default


def _open_repo(cache_dir: str, pkg: str):
    """Open a cached repository, refusing cleanly when it is unavailable."""
    path = _contained_repo_path(cache_dir, pkg)
    try:
        return pygit2.Repository(str(path))
    except pygit2.GitError as exc:
        raise _OpError(f"repository unavailable: {pkg!r}") from exc


def _tree_files(payload: dict) -> dict:
    """The committed tree's file heads, as ``(path, base64 bytes)`` pairs.

    Reuses ``git_project.collect_tree_files`` so the isolated read applies the
    same per-file and total caps as the in-process one.
    """
    from trustsight.sandbox.git_project import collect_tree_files

    oid = _require_oid(payload.get("oid"), "commit id")
    repo = _open_repo(payload.get("cache_dir", ""), payload.get("pkg", ""))
    files, complete = collect_tree_files(repo, oid)
    if len(files) > GIT_TREE_MAX_ENTRIES:
        # The byte budget bounds companion *content*, not the entry count, so
        # a repository of millions of tiny files would build an unbounded
        # list.  Truncating is a real skip, so it reports incomplete.
        files = files[:GIT_TREE_MAX_ENTRIES]
        complete = False
    return {
        "files": [[name, base64.b64encode(data).decode("ascii")]
                  for name, data in files],
        "complete": complete,
    }


def _companion_hunks(payload: dict) -> dict:
    from trustsight.sandbox.git_project import companion_source_hunks

    oid = _require_oid(payload.get("oid"), "commit id")
    repo = _open_repo(payload.get("cache_dir", ""), payload.get("pkg", ""))
    max_bytes = _positive_int(payload.get("max_bytes"), 0)
    if max_bytes:
        text, truncated = companion_source_hunks(repo, oid, max_bytes=max_bytes)
    else:
        text, truncated = companion_source_hunks(repo, oid)
    return {"text": text, "truncated": truncated}


def _opaque_changed(payload: dict) -> dict:
    from trustsight.sandbox.git_project import changed_opaque_members

    old = _require_oid(payload.get("old"), "commit id")
    new = _require_oid(payload.get("new"), "commit id")
    repo = _open_repo(payload.get("cache_dir", ""), payload.get("pkg", ""))
    return {"names": changed_opaque_members(repo, old, new)}


def _binary_meta(payload: dict) -> dict:
    from trustsight.sandbox.git_project import binary_metadata_paths

    old = _require_oid(payload.get("old"), "commit id")
    new = _require_oid(payload.get("new"), "commit id")
    repo = _open_repo(payload.get("cache_dir", ""), payload.get("pkg", ""))
    return {"paths": binary_metadata_paths(repo, old, new)}


def _commit_record(commit) -> dict:
    try:
        message = commit.message or ""
    except (AttributeError, UnicodeDecodeError):
        message = ""
    return {
        "id": str(commit.id),
        "commit_time": int(commit.commit_time),
        "parents": [str(parent.id) for parent in commit.parents],
        "message": message,
    }


def _walk(payload: dict) -> dict:
    """Commits under *head*, newest first, as lightweight records.

    Reuses ``git_project.walk_bounded`` so the same commit ceiling applies in
    the worker; only ``id``, ``commit_time`` and ``parents`` cross the
    boundary, never a libgit2 handle.
    """
    from trustsight.sandbox.git_project import MAX_HISTORY_COMMITS, walk_bounded

    head = _require_oid(payload.get("head"), "commit id")
    raw_limit = payload.get("limit")
    if raw_limit is None:
        limit = None
    else:
        try:
            limit = int(raw_limit)
        except (TypeError, ValueError, OverflowError):
            raise _OpError("invalid walk limit") from None
        if limit <= 0:
            # ``walk_bounded`` yields the first commit before testing its cap,
            # so a zero or negative limit must be answered here, not passed on.
            return {"commits": []}
        limit = min(limit, MAX_HISTORY_COMMITS)
    if not head:
        return {"commits": []}
    repo = _open_repo(payload.get("cache_dir", ""), payload.get("pkg", ""))
    try:
        commits = [_commit_record(c) for c in walk_bounded(repo, head, limit=limit)]
    except pygit2.GitError:
        return {"commits": []}
    return {"commits": commits}


def _commit_meta(payload: dict) -> dict:
    """Time and parents for a bounded list of commit ids."""
    oids = payload.get("oids") or []
    if not isinstance(oids, list) or len(oids) > GIT_COMMIT_META_MAX_OIDS:
        raise _OpError("too many or malformed commit ids")
    repo = _open_repo(payload.get("cache_dir", ""), payload.get("pkg", ""))
    out = []
    for raw in oids:
        oid = _require_oid(raw, "commit id")
        commit = repo.get(oid) if oid else None
        if isinstance(commit, pygit2.Commit):
            out.append(_commit_record(commit))
    return {"commits": out}


_DISPATCH = {
    "open_fetch": _open_fetch,
    "head": _head,
    "file_at": _file_at,
    "diff": _diff,
    "tree_files": _tree_files,
    "companion_hunks": _companion_hunks,
    "opaque_changed": _opaque_changed,
    "binary_meta": _binary_meta,
    "walk": _walk,
    "commit_meta": _commit_meta,
}


def _handle(body: bytes) -> dict:
    try:
        request = json.loads(body.decode("utf-8"))
        fn = _DISPATCH.get(request.get("op"))
        if fn is None:
            raise _UnknownOp(f"unknown op: {request.get('op')!r}")
        return {"result": fn(request)}
    except _UnknownOp as exc:
        return {"error": str(exc)}
    except _OpError as exc:
        return {"error": str(exc)}
    except Exception as exc:  # a defect is a refusal, not a crash
        return {"error": f"{type(exc).__name__}: {exc}"}


def _encode_response(response: dict) -> bytes:
    """Serialise *response*, refusing one past the response byte cap.

    Refusing here, before framing, means a wide projection cannot make the
    parent read a frame it must reject, nor this worker hold an unbounded
    reply (A4/A14).
    """
    payload = json.dumps(
        response, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    if len(payload) > protocol.MAX_RESPONSE_BYTES:
        payload = json.dumps(
            {"error": "response exceeds the response byte cap"},
            separators=(",", ":"),
        ).encode("utf-8")
    return payload


def _attach_degraded(response: dict) -> dict:
    """Attach the startup limit failures to a response, when there are any.

    The parent reads it once and reports the degraded protection; leaving it
    only in the worker's stderr would let a swallowed ``setrlimit`` read as
    full isolation.
    """
    if _DEGRADED:
        response["degraded"] = list(_DEGRADED)
    return response


def main() -> int:
    global _DEGRADED
    _DEGRADED = _apply_limits()
    _harden_libgit2()
    try:
        os.chdir("/")
    except OSError:
        pass
    stdin = sys.stdin.buffer
    stdout = sys.stdout.buffer
    while True:
        try:
            body = protocol.read_frame(stdin)
        except protocol.FrameError:
            return 0
        response = _attach_degraded(_handle(body))
        stdout.write(protocol.frame(_encode_response(response)))
        stdout.flush()


if __name__ == "__main__":
    raise SystemExit(main())
