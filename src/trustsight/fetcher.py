import os
import re
import shutil
import signal
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Optional

import pygit2

from .config import CACHE_DIR

_VALID_PKG_NAME = re.compile(r"^[a-zA-Z0-9@._+\-]+$")

# "." and ".." satisfy _VALID_PKG_NAME but are directory references, not
# names.  CACHE_DIR / ".." escapes the cache root, and clone_or_fetch
# rmtree()s that path when it fails to open as a repository, so allowing
# them turns a bad package name into a recursive delete of the parent.
_RESERVED_PKG_NAMES = frozenset({".", ".."})


class _TimeoutError(Exception):
    pass


@contextmanager
def _timeout(seconds: int):
    """context manager that sets a SIGALRM timeout"""
    # signal.alarm is only legal on the main thread, and packages are
    # fetched from a worker pool.  Off the main thread the deadline is
    # enforced by _DeadlineCallbacks instead, which works anywhere.
    if not hasattr(signal, "SIGALRM") or (
        threading.current_thread() is not threading.main_thread()
    ):
        yield
        return

    def _handler(_sig, _frame):
        """signal handler that raises _TimeoutError"""
        raise _TimeoutError(f"operation timed out after {seconds}s")

    old = signal.signal(signal.SIGALRM, _handler)
    signal.alarm(seconds)
    try:
        yield
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old)


_NETWORK_TIMEOUTS_LOCK = threading.Lock()
_NETWORK_TIMEOUTS_APPLIED = False

# Fallbacks used when config.toml carries no [limits] entry.
DEFAULT_CONNECT_TIMEOUT = 10
DEFAULT_TRANSFER_TIMEOUT = 30


def _apply_network_timeouts() -> None:
    """Bound libgit2's own socket timeouts, once per process.

    _DeadlineCallbacks below can only fire while libgit2 is handing us
    progress, so a connection that stalls *before* any byte arrives is never
    cancelled by it and the fetch blocks forever.  These two settings are
    enforced inside libgit2's transport, which is the only layer that sees a
    silent socket.  Python's socket.setdefaulttimeout() has no effect here:
    libgit2 does its own networking in C.
    """
    global _NETWORK_TIMEOUTS_APPLIED
    if _NETWORK_TIMEOUTS_APPLIED:
        return
    with _NETWORK_TIMEOUTS_LOCK:
        if _NETWORK_TIMEOUTS_APPLIED:
            return
        try:
            from .config import load_config

            limits = load_config().get("limits", {})
        except Exception:
            limits = {}

        def _seconds(key: str, default: int) -> int:
            try:
                value = int(limits.get(key, default))
            except (TypeError, ValueError):
                return default
            return value if value > 0 else default

        connect = _seconds("network_connect_timeout", DEFAULT_CONNECT_TIMEOUT)
        transfer = _seconds("network_transfer_timeout", DEFAULT_TRANSFER_TIMEOUT)
        try:
            pygit2.settings.server_connect_timeout = connect * 1000
            pygit2.settings.server_timeout = transfer * 1000
        except (AttributeError, pygit2.GitError, ValueError):
            # pygit2 < 1.14 / libgit2 < 1.7 has no server timeout options.
            # The deadline callbacks remain as the only guard there.
            pass
        _NETWORK_TIMEOUTS_APPLIED = True


#: Bytes one clone or fetch may pull. The deadline below bounds how *long*
#: a transfer runs, which on a fast link is not a bound on how much arrives:
#: 120 seconds is gigabytes, written straight to the cache directory. An AUR
#: repository holds a recipe and occasionally a patch, so a few MiB is the
#: honest size and this is two orders of magnitude above it.
MAX_TRANSFER_BYTES = 256 * 1024 * 1024

#: Bytes every transfer in this process may pull between them. The per-repo
#: cap alone is not a disk bound, because the dependency walk multiplies it
#: by `depth.MAX_DEPTH_NODES` (200) - a ceiling that was chosen when a node
#: cost a recipe-sized clone, not a quarter-gigabyte one. A full-depth run
#: over real packages moves a few hundred MiB, so this leaves ~10x headroom
#: while keeping the worst case off the same order as a disk.
MAX_TOTAL_TRANSFER_BYTES = 2 * 1024 * 1024 * 1024

_transfer_lock = threading.Lock()
_transferred_bytes = 0


class _TransferTooLargeError(_TimeoutError):
    """A transfer exceeded its byte budget.

    Deliberately a `_TimeoutError` subclass: every call site already treats
    that as "this fetch did not complete", and an oversized transfer means
    the same thing. A separate exception type would be a second path for
    callers to handle, and one of them would forget.
    """


def reset_transfer_budget() -> None:
    """Return the process-wide budget to full.

    For tests and for long-lived hosts that run more than one analysis; a
    single CLI invocation never needs it.
    """
    global _transferred_bytes
    with _transfer_lock:
        _transferred_bytes = 0


def _charge_transfer(received: int, previous: int) -> None:
    """Charge the delta since this transfer's last progress callback."""
    global _transferred_bytes
    delta = received - previous
    if delta <= 0:
        return
    with _transfer_lock:
        _transferred_bytes += delta
        total = _transferred_bytes
    if total > MAX_TOTAL_TRANSFER_BYTES:
        raise _TransferTooLargeError(
            f"transfers exceeded the {MAX_TOTAL_TRANSFER_BYTES} byte budget "
            f"for this run"
        )


class _DeadlineCallbacks(pygit2.RemoteCallbacks):
    """Abort a transfer that runs past *seconds* or past its byte budget.

    libgit2 invokes these callbacks as data arrives, so raising from one
    cancels the operation.  Unlike SIGALRM this works on any thread, which
    is what the concurrent prefetch needs.
    """

    def __init__(self, seconds: int):
        super().__init__()
        self._deadline = time.monotonic() + seconds
        self._seconds = seconds
        self._received = 0

    def _check(self):
        if time.monotonic() > self._deadline:
            raise _TimeoutError(
                f"operation timed out after {self._seconds}s"
            )

    def transfer_progress(self, stats):
        self._check()
        received = getattr(stats, "received_bytes", 0) or 0
        if received > MAX_TRANSFER_BYTES:
            raise _TransferTooLargeError(
                f"transfer exceeded {MAX_TRANSFER_BYTES} bytes"
            )
        _charge_transfer(received, self._received)
        self._received = received

    def sideband_progress(self, string):
        self._check()


#: Commits any single history walk will visit. Repository history is
#: attacker-authored: a package can carry a million commits as easily as
#: ten, and every walk that ran to exhaustion turned that into unbounded
#: work. Walks are newest-first, so a bound keeps the commits that carry
#: signal and drops the tail no rule reads.
MAX_HISTORY_COMMITS = 5_000

#: Ceiling on ``--last N``: the most content-bearing diffs a single
#: inspect run may produce.  A repository of a thousand ``.SRCINFO``-only
#: commits would otherwise decide how far this machine walks in order to
#: find five real diffs.
MAX_HISTORY_DIFFS = 50

#: Assembled diff text retained across *all* results in a single
#: ``--last N`` run.  N per-diff caps compose to N × the cap; the
#: budget is charged to the run rather than the repository, the way
#: ``MAX_TOTAL_TRANSFER_BYTES`` charges the run rather than a single
#: clone.  When exhausted the walk stops and fewer than N results are
#: produced.
# Inlined from differ.py to avoid a circular import (fetcher ->
# analysis.pipeline -> fetcher).  Keep in sync with differ.MAX_DIFF_BYTES.
_MAX_DIFF_BYTES = 5 * 1024 * 1024
MAX_RUN_DIFF_BYTES = _MAX_DIFF_BYTES * 8


def walk_bounded(repo: pygit2.Repository, head, *, sort=None, limit=None):
    """Yield at most *limit* commits from *head*, newest first.

    One implementation rather than a counter at each call site: the review
    notes name "a control applied at one of several equivalent call sites"
    as the recurring failure here, and unbounded walks were spread across
    three modules.
    """
    cap = MAX_HISTORY_COMMITS if limit is None else limit
    walker = repo.walk(head) if sort is None else repo.walk(head, sort)
    for seen, commit in enumerate(walker, start=1):
        yield commit
        if seen >= cap:
            return


def _head_commit_id(repo: pygit2.Repository) -> str:
    """Resolve HEAD to a commit OID, handling empty and unborn repos."""
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
            ref = repo.references[ref_name]
            return str(ref.peel().id)
        except (TypeError, pygit2.GitError):
            pass
    raise pygit2.GitError("cannot resolve HEAD to a commit")


def _validate_pkg_name(pkg_name: str) -> None:
    """validate package name format and reject reserved names"""
    if not _VALID_PKG_NAME.match(pkg_name) or pkg_name in _RESERVED_PKG_NAMES:
        raise ValueError(f"Invalid package name: {pkg_name!r}")


def repo_path(pkg_name: str) -> Path:
    """Return the cache directory path for *pkg_name*, validating it."""
    _validate_pkg_name(pkg_name)
    path = (CACHE_DIR / pkg_name).resolve()
    # Belt and braces: the name has already been checked, but this is the
    # value that later gets rmtree()d, so confirm it really is contained
    # in the cache root before anyone acts on it.
    if path.parent != CACHE_DIR.resolve():
        raise ValueError(f"Package path escapes cache directory: {pkg_name!r}")
    return path


# When the last successful fetch happened, recorded next to the repository.
# Deliberately not derived from the HEAD commit's timestamp: a commit's date
# is chosen by whoever authored it, so a maintainer who dates a commit in the
# future would make the clone look permanently current and trustsight would
# never fetch that package again; silently blinding it to every later
# update, which is precisely what it exists to inspect.  A local record of
# our own fetch cannot be influenced from the other end.
_FETCH_MARKER = "trustsight-last-fetch"


def _marker_path(repo: pygit2.Repository) -> Path:
    """Location of the last-fetch marker for *repo*."""
    return Path(repo.path) / _FETCH_MARKER


def _record_fetch(repo: pygit2.Repository) -> Optional[int]:
    """Note that *repo* has just been brought up to date."""
    stamp = int(time.time())
    try:
        _marker_path(repo).write_text(str(stamp))
    except OSError:
        return None
    return stamp


def last_fetch_time(repo: pygit2.Repository) -> Optional[int]:
    """When this clone was last fetched, or None if that is unknown."""
    try:
        return int(_marker_path(repo).read_text().strip())
    except (OSError, ValueError):
        return None


def _is_current(repo: pygit2.Repository, upstream_mtime: int) -> bool:
    """True when this clone was fetched after the upstream last changed.

    Falls back to checking the local HEAD commit time so that clones
    created by an earlier version (which have no marker file) avoid an
    unnecessary network fetch.
    """
    fetched = last_fetch_time(repo)
    if fetched is not None:
        try:
            if fetched >= int(upstream_mtime):
                return True
        except (TypeError, ValueError):
            pass

    try:
        head = repo.head
        if head.is_remote:
            return False
        commit = head.peel()
        return int(commit.commit_time) >= int(upstream_mtime)
    except (AttributeError, pygit2.GitError, KeyError, TypeError, ValueError):
        return False


def clone_or_fetch(
    pkg_name: str, upstream_mtime: Optional[int] = None
) -> pygit2.Repository:
    """Clone or update the AUR git repo for *pkg_name*, returning the repo.

    *upstream_mtime* is the AUR's ``LastModified`` for the package.  When
    the cached clone already holds a commit that recent the fetch is
    skipped, which on a repeat run removes the slowest single step of the
    analysis for every package that has not actually changed.
    """
    path = repo_path(pkg_name)
    _apply_network_timeouts()
    if path.exists():
        cached = None
        try:
            cached = pygit2.Repository(str(path))
            _head_commit_id(cached)
        except (_TimeoutError, pygit2.GitError):
            # The clone itself is unreadable, so rebuild it below.  A failing
            # *fetch* is not grounds for deleting a good clone: under the
            # network stall that makes fetches fail, the re-clone fails too,
            # and the cache is gone for the next run as well.
            shutil.rmtree(path)
            cached = None
        if cached is not None:
            if upstream_mtime is not None and _is_current(cached, upstream_mtime):
                return cached
            with _timeout(120):
                cached.remotes["origin"].fetch(callbacks=_DeadlineCallbacks(120))
            _record_fetch(cached)
            return cached
    os.makedirs(path.parent, exist_ok=True)
    url = f"https://aur.archlinux.org/{pkg_name}.git"
    with _timeout(120):
        repo = pygit2.clone_repository(
            url, str(path), callbacks=_DeadlineCallbacks(120)
        )
    _record_fetch(repo)
    return repo


def get_head_commit(repo: pygit2.Repository) -> str:
    """Return the OID of HEAD for *repo*."""
    return _head_commit_id(repo)


def get_pkgver_from_head(repo: pygit2.Repository) -> Optional[str]:
    """Extract pkgver from the HEAD PKGBUILD, or None."""
    try:
        blob = repo[_head_commit_id(repo)].tree["PKGBUILD"]
        pkgbuild = blob.data.decode()
        match = re.search(
            r'^pkgver\s*=\s*["\']?([^\s"\']+)', pkgbuild, re.MULTILINE
        )
        if match:
            return match.group(1)
    except (KeyError, AttributeError, ValueError):
        pass
    return None


# The maintainer is a PKGBUILD comment, not a .SRCINFO field.  makepkg
# does not propagate it: checked against the AUR mirror, 0 of 200
# .SRCINFO files carry a `maintainer =` line, while every PKGBUILD opens
# with `# Maintainer: Name <email>`.  Reading .SRCINFO therefore always
# returned None, which silently disabled maintainer_changed, the
# maintainer novelty weight, and C006.
_MAINTAINER_COMMENT_RE = re.compile(
    r"^#\s*Maintainer\s*:\s*(.+?)\s*$", re.MULTILINE | re.IGNORECASE
)
_MAINTAINER_SRCINFO_RE = re.compile(
    r"^\s*maintainer\s*=\s*(.+)", re.MULTILINE | re.IGNORECASE
)


def extract_maintainer(pkgbuild: str = "", srcinfo: str = "") -> Optional[str]:
    """Return the maintainer name, preferring the PKGBUILD comment.

    ``.SRCINFO`` is still consulted as a fallback: some tooling does
    write the field, and it costs nothing to accept it.
    """
    match = _MAINTAINER_COMMENT_RE.search(pkgbuild)
    if match:
        return match.group(1).strip()
    match = _MAINTAINER_SRCINFO_RE.search(srcinfo)
    if match:
        return match.group(1).strip()
    return None


def _read_blob(tree, name: str) -> str:
    """read and decode a named blob from a git tree, returning empty string on failure"""
    try:
        return tree[name].data.decode("utf-8", errors="replace")
    except (KeyError, AttributeError, ValueError, TypeError):
        return ""


def get_pkgbuild_at_commit(repo: pygit2.Repository, commit_oid: str) -> str:
    """Return the PKGBUILD text at *commit_oid*, or "" when unavailable.

    Rules that describe the package's *current* state (H056) need the file
    as it now stands, not only the lines this revision touched.
    """
    try:
        commit = repo.get(commit_oid)
        tree = commit.tree
    except (KeyError, AttributeError, TypeError, ValueError):
        return ""
    if tree is None:
        return ""
    return _read_blob(tree, "PKGBUILD")


def get_maintainer_from_repo(repo: pygit2.Repository) -> Optional[str]:
    """Return the maintainer from *repo*'s HEAD PKGBUILD or .SRCINFO."""
    try:
        tree = repo[_head_commit_id(repo)].tree
    except (KeyError, AttributeError, ValueError, TypeError):
        return None
    return extract_maintainer(_read_blob(tree, "PKGBUILD"), _read_blob(tree, ".SRCINFO"))


def get_maintainer_from_commit(repo: pygit2.Repository, commit_oid: str) -> Optional[str]:
    """Return the maintainer from *repo* at a specific *commit_oid*."""
    try:
        commit = repo.get(commit_oid)
        tree = commit.tree
    except (KeyError, AttributeError, TypeError):
        return None
    if tree is None:
        return None
    return extract_maintainer(_read_blob(tree, "PKGBUILD"), _read_blob(tree, ".SRCINFO"))
