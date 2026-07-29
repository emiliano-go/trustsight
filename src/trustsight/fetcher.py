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


class _DeadlineCallbacks(pygit2.RemoteCallbacks):
    """Abort a transfer that runs past *seconds*.

    libgit2 invokes these callbacks as data arrives, so raising from one
    cancels the operation.  Unlike SIGALRM this works on any thread, which
    is what the concurrent prefetch needs.
    """

    def __init__(self, seconds: int):
        super().__init__()
        self._deadline = time.monotonic() + seconds
        self._seconds = seconds

    def _check(self):
        if time.monotonic() > self._deadline:
            raise _TimeoutError(
                f"operation timed out after {self._seconds}s"
            )

    def transfer_progress(self, stats):
        self._check()

    def sideband_progress(self, string):
        self._check()


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
    if path.exists():
        try:
            repo = pygit2.Repository(str(path))
            _head_commit_id(repo)
            if upstream_mtime is not None and _is_current(repo, upstream_mtime):
                return repo
            with _timeout(120):
                repo.remotes["origin"].fetch(callbacks=_DeadlineCallbacks(120))
            _record_fetch(repo)
            return repo
        except (_TimeoutError, pygit2.GitError):
            shutil.rmtree(path)
    os.makedirs(path.parent, exist_ok=True)
    url = f"https://aur.archlinux.org/{pkg_name}.git"
    with _timeout(120):
        repo = pygit2.clone_repository(
            url, str(path), callbacks=_DeadlineCallbacks(120)
        )
    _record_fetch(repo)
    return repo


def get_commit_for_version(
    repo: pygit2.Repository, version: str
) -> Optional[str]:
    """Find the commit whose PKGBUILD has the given *version*, or None."""
    head = _head_commit_id(repo)
    if not head:
        return None
    for commit in repo.walk(head, pygit2.GIT_SORT_TIME):
        try:
            blob = repo[commit.tree]["PKGBUILD"]
            pkgbuild = blob.data.decode()
            match = re.search(
                r'^pkgver\s*=\s*["\']?([^\s"\']+)', pkgbuild, re.MULTILINE
            )
            if match and match.group(1) == version:
                return str(commit.id)
        except (KeyError, AttributeError):
            pass
    return None


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
