import functools
import re
import shutil
import signal
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Optional

from .config import CACHE_DIR
from .coverage import note_stage_failure
from .sandbox.git_bounds import MAX_TOTAL_TRANSFER_BYTES

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
    # enforced by the isolated worker instead, which works anywhere.
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


# Fallbacks used when config.toml carries no [limits] entry.
DEFAULT_CONNECT_TIMEOUT = 10
DEFAULT_TRANSFER_TIMEOUT = 30


def _network_timeout_values() -> tuple[int, int]:
    """The configured (connect, transfer) timeouts, with safe fallbacks."""
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

    return (
        _seconds("network_connect_timeout", DEFAULT_CONNECT_TIMEOUT),
        _seconds("network_transfer_timeout", DEFAULT_TRANSFER_TIMEOUT),
    )


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
    """Charge the delta since this transfer's last progress callback.

    The per-transfer ceiling (``MAX_TRANSFER_BYTES``) is enforced inside the
    isolated worker, which is where the bytes actually arrive.  This charges
    the process-wide run budget across packages, the bound the per-repo
    ceiling cannot give: a dependency walk visits up to ``MAX_DEPTH_NODES``
    repositories, each under its own ceiling.
    """
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


def _discard_cached_repo(pkg_name: str) -> None:
    """Remove a repo that failed parent-side HEAD verification.

    The next fetch starts from a clone again.  The path is the already
    validated cache path; rmtree does not follow symlinked directories.
    """
    try:
        path = repo_path(pkg_name)
        if path.is_symlink() or not path.is_dir():
            path.unlink()
        else:
            shutil.rmtree(path, ignore_errors=True)
    except (OSError, ValueError):
        pass


_repo_locks: dict[str, threading.Lock] = {}
_repo_locks_guard = threading.Lock()


def _repo_lock(name: str) -> threading.Lock:
    """One clone/fetch lock per AUR repository, including split packages."""
    with _repo_locks_guard:
        return _repo_locks.setdefault(name, threading.Lock())


def _serialise_repo_fetch(function):
    """Serialize clone/fetch for one repository, including split packages."""

    @functools.wraps(function)
    def wrapper(pkg_name, upstream_mtime=None):
        with _repo_lock(pkg_name):
            return function(pkg_name, upstream_mtime)

    return wrapper


@_serialise_repo_fetch
def clone_or_fetch(pkg_name: str, upstream_mtime: Optional[int] = None):
    """Clone or update the AUR git repo for *pkg_name*, returning a handle.

    The clone/fetch runs in the isolated worker; the returned
    :class:`~trustsight.sandbox.git_client.GitProject` owns that worker and
    answers every later read through it.  *upstream_mtime* is the AUR's
    ``LastModified`` for the package; when the cached clone already holds a
    commit that recent the worker skips the fetch.
    """
    repo_path(pkg_name)  # validate the name and its containment before any child runs
    from .release import offline
    from .sandbox import fetch_state
    from .sandbox.git_client import (
        GitOpError,
        GitProject,
        GitSandboxUnavailable,
        GitSession,
        GitTransferTooLargeError,
    )

    offline_mode = offline()
    try:
        upstream_value = (None if upstream_mtime is None
                          else int(upstream_mtime))
    except (TypeError, ValueError, OverflowError):
        upstream_value = None
    previous = fetch_state.load(CACHE_DIR, pkg_name)
    if offline_mode and previous is None:
        raise _TimeoutError(
            f"offline mode has no verified fetch state for {pkg_name!r}; "
            "refusing to analyse an unverified cache")
    force = False if offline_mode else (
        previous is None
        or previous.upstream_mtime is None
        or upstream_value is None
        or previous.upstream_mtime != upstream_value
    )

    connect, transfer = _network_timeout_values()
    session = GitSession()
    try:
        result = session.open_fetch(
            pkg_name, str(CACHE_DIR), upstream_mtime, offline_mode,
            connect, transfer, force=force,
            previous_head=(previous.head if previous is not None else ""),
        )
    except GitSandboxUnavailable as exc:
        # A sandbox that cannot answer is the same class as a timed-out
        # fetch: the package was not brought up to date, so callers record a
        # coverage gap rather than analysing a stale or empty tree (B2).
        proxy_received = getattr(session, "received_bytes", lambda: 0)()
        session.close()
        if proxy_received > 0:
            _charge_transfer(proxy_received, 0)
        raise _TimeoutError(f"git sandbox unavailable: {exc}") from exc
    except GitOpError as exc:
        # The worker answered with an error, but a failed transfer may still
        # have written bytes before it stopped.  Charge what the parent proxy
        # actually relayed; the worker's count is only a fallback.
        proxy_received = getattr(session, "received_bytes", lambda: 0)()
        session.close()
        received = proxy_received if proxy_received > 0 else getattr(
            exc, "received_bytes", 0)
        if isinstance(received, int) and received > 0:
            _charge_transfer(received, 0)
        if isinstance(exc, GitTransferTooLargeError):
            raise _TransferTooLargeError(
                f"git transfer exceeded its byte ceiling: {exc}") from exc
        raise _TimeoutError(f"git fetch did not complete: {exc}") from exc
    except Exception:
        proxy_received = getattr(session, "received_bytes", lambda: 0)()
        session.close()
        if proxy_received > 0:
            _charge_transfer(proxy_received, 0)
        raise
    proxy_received = getattr(session, "received_bytes", lambda: 0)()
    received = proxy_received if proxy_received > 0 else (
        result.get("received_bytes", 0) if isinstance(result, dict) else 0)
    if isinstance(received, int) and received > 0:
        _charge_transfer(received, 0)
    fetched = isinstance(result, dict) and result.get("fetched") is True
    if force and not fetched:
        session.close()
        raise _TimeoutError(
            "the isolated worker did not perform a required git fetch")
    advertised = session.advertised_head() if fetched else (
        previous.advertised_head if previous is not None else None)
    try:
        actual = session.head(pkg_name, str(CACHE_DIR))
    except (GitSandboxUnavailable, GitOpError) as exc:
        session.close()
        raise _TimeoutError(
            f"git verification did not complete: {exc}") from exc
    if fetched:
        if not advertised or actual != advertised:
            session.close()
            _discard_cached_repo(pkg_name)
            raise _TimeoutError(
                "git fetch HEAD does not match the AUR advertisement")
        state = fetch_state.FetchState(
            head=actual,
            advertised_head=advertised,
            fetched_at=int(time.time()),
            upstream_mtime=upstream_value,
            verified=True,
        )
    else:
        if previous is None or actual != previous.head:
            session.close()
            if not offline_mode:
                _discard_cached_repo(pkg_name)
            raise _TimeoutError(
                "cached git repository is not the verified HEAD")
        state = previous
    if not offline_mode:
        try:
            fetch_state.store(CACHE_DIR, pkg_name, state)
        except OSError:
            # The next run will force a fetch; the current result is already
            # verified against the AUR advertisement.
            pass
    return GitProject(session, pkg_name, str(CACHE_DIR),
                      fetch_time=state.fetched_at)


def get_head_commit(project) -> str:
    """Return the OID of HEAD for *project*, or "" when it has none."""
    from .sandbox.git_client import GitOpError

    try:
        return project.head_commit()
    except GitOpError:
        # "No HEAD" and "the worker could not answer" look identical to a
        # caller that only sees "".  The latter is a skipped stage, so it is
        # recorded rather than read as a repository with no commits.
        note_stage_failure("git-head-read")
        return ""


def get_pkgver_from_head(project) -> Optional[str]:
    """Extract pkgver from the HEAD PKGBUILD, or None."""
    head = get_head_commit(project)
    if not head:
        return None
    text = project.file_at(head, "PKGBUILD")
    if not text:
        return None
    match = re.search(
        r'^pkgver\s*=\s*["\']?([^\s"\']+)', text, re.MULTILINE
    )
    return match.group(1) if match else None


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


def get_pkgbuild_at_commit(project, commit_oid: str) -> str:
    """Return the PKGBUILD text at *commit_oid*, or "" when unavailable.

    Rules that describe the package's *current* state (H056) need the file
    as it now stands, not only the lines this revision touched.
    """
    return project.file_at(commit_oid, "PKGBUILD") if commit_oid else ""


def get_srcinfo_at_commit(project, commit_oid: str) -> str:
    """Return the .SRCINFO text at *commit_oid*, or "" when unavailable.

    H092 compares the generated metadata against the recipe on the review
    path, the same comparison the full-AUR corpus path has always run.
    """
    return project.file_at(commit_oid, ".SRCINFO") if commit_oid else ""


def get_maintainer_from_commit(project, commit_oid: str) -> Optional[str]:
    """Return the maintainer from *project* at a specific *commit_oid*."""
    if not commit_oid:
        return None
    return extract_maintainer(
        project.file_at(commit_oid, "PKGBUILD"),
        project.file_at(commit_oid, ".SRCINFO"),
    )
