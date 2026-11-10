"""PKGBUILD fetcher via cgit with snapshot fallback."""

import errno
import json
import logging
import random
import tarfile
import threading
import time
import urllib.request
import urllib.error
from urllib.parse import quote, urlsplit
from pathlib import Path
from typing import Optional

from ..bounded_io import ReadTooLarge
from ..analysis import archive_snapshot as _archive

log = logging.getLogger(__name__)

_CGIT_URL = "https://aur.archlinux.org/cgit/aur.git/plain/PKGBUILD"
_CGIT_SRCINFO_URL = "https://aur.archlinux.org/cgit/aur.git/plain/.SRCINFO"
_SNAPSHOT_URL = "https://aur.archlinux.org/cgit/aur.git/snapshot"

# The read-only GitHub AUR mirror carries one branch per package and serves
# the same tip tree through its CDN (the layout is a single leading
# ``<dir>/``, which the parsers below already accept).  It is tried first:
# the AUR's own cgit snapshot endpoint rate-limits and, in practice,
# returned empty bodies under a full bootstrap, holding the drain to about
# one package per second, while codeload answered in ~0.3s.  cgit is kept
# as the fallback, so a package the mirror no longer carries (a deleted
# branch answers 404 here) still resolves.
_GITHUB_SNAPSHOT_URL = "https://codeload.github.com/archlinux/aur/tar.gz/refs/heads"

_RESUME_FILE = "full-aur-resume.json"

_HTTP_TIMEOUT = 60

#: Total wall-clock budget for one response; ``_HTTP_TIMEOUT`` only bounds a
#: single socket operation and resets on every chunk.
_DOWNLOAD_DEADLINE_SECONDS = 120

# The AUR's cgit sits behind rate limiting and Anubis anti-scraping, and it
# will 429, 5xx, or reset the connection when hit too fast; a bootstrap makes
# ~120k requests, so being a good citizen is not optional.  Two mechanisms
# keep it polite:
#
# 1. A single global minimum interval between request *starts*, shared across
#    every worker thread.  This caps the aggregate rate regardless of how many
#    fetches run concurrently: raising ``corpus_fetch_workers`` fills the
#    pipeline up to this ceiling, it does not exceed it.
# 2. Retry with exponential backoff on the errors that mean "slow down"
#    (429, 500/502/503/504, connection reset), honouring a ``Retry-After``
#    header when the server sends one.
_MIN_REQUEST_INTERVAL = 0.2  # seconds; ~5 requests/second aggregate

#: Per-host overrides of the minimum start spacing.  The GitHub mirror is a
#: CDN, not the rate-limited cgit, so a much smaller interval lets the worker
#: pool set the real concurrency; the aggregate cap still applies to the AUR.
_MIN_REQUEST_INTERVAL_BY_HOST = {
    "codeload.github.com": 0.02,
}
_MAX_RETRIES = 5
_BACKOFF_BASE = 1.0
_BACKOFF_MAX = 60.0
_RETRYABLE_STATUS = frozenset({429, 500, 502, 503, 504})

_rate_lock = threading.Lock()
_last_request_at: dict[str, float] = {}


def _throttle(url: str) -> None:
    """Block until the host's minimum inter-request interval has elapsed.

    Spacing is per host and shared across worker threads: the AUR keeps its
    polite aggregate cap, while the GitHub mirror is not throttled to it.
    """
    host = urlsplit(url).hostname or ""
    interval = _MIN_REQUEST_INTERVAL_BY_HOST.get(host, _MIN_REQUEST_INTERVAL)
    with _rate_lock:
        now = time.monotonic()
        wait = _last_request_at.get(host, 0.0) + interval - now
        if wait > 0:
            time.sleep(wait)
        _last_request_at[host] = time.monotonic()


def _backoff_delay(attempt: int) -> float:
    return min(_BACKOFF_BASE * (2 ** attempt) + random.uniform(0, 0.5), _BACKOFF_MAX)


def _retry_after(http_error) -> Optional[float]:
    headers = getattr(http_error, "headers", None)
    value = headers.get("Retry-After") if headers else None
    if not value:
        return None
    try:
        return min(float(value), _BACKOFF_MAX)
    except (TypeError, ValueError):
        return None


def _is_transient_urlerror(reason) -> bool:
    if isinstance(reason, (ConnectionResetError, ConnectionRefusedError, TimeoutError)):
        return True
    return getattr(reason, "errno", None) in (errno.ECONNRESET, errno.ECONNREFUSED, errno.ETIMEDOUT)

# An AUR snapshot tarball is a few kilobytes and a PKGBUILD smaller still.
# The ceiling is not about the AUR behaving badly - it is that a response
# read with no bound is the remote end choosing how much of this machine's
# memory to use.
MAX_RESPONSE_BYTES = 32 * 1024 * 1024

# A snapshot tarball holds a handful of files.  ``getmembers()`` parses the
# whole archive into memory before returning, so a crafted tar declaring
# millions of members is a memory bomb even when only 64 bytes of each are
# read; the members are walked lazily instead, and the walk stops here.
MAX_TAR_MEMBERS = 10_000

# MAX_RESPONSE_BYTES caps the *compressed* body.  A member is read out of
# the decompressed stream, and gzip on compressible content runs to roughly
# a thousand to one, so 32 MiB on the wire is tens of gigabytes of member
# to allocate.  The member's declared size is the attacker's number, so it
# is not the bound; this is.  A PKGBUILD past this is not a PKGBUILD.
MAX_TAR_MEMBER_BYTES = 8 * 1024 * 1024

#: Total bytes the archive may *declare* across every member.  A tar header
#: states a member's size, so a 32 MiB gzip can declare gigabytes and make
#: the walker seek (and decompress) to the end of a member it never reads.
#: The count is on declarations, checked before any member body is touched,
#: so a bomb is refused at its header rather than expanded.
MAX_TAR_TOTAL_BYTES = 256 * 1024 * 1024


def _http_get(url: str) -> Optional[bytes]:
    """Perform a GET request with a polite User-Agent.

    The body is read in chunks and abandoned past ``MAX_RESPONSE_BYTES``.
    """
    for attempt in range(_MAX_RETRIES + 1):
        _throttle(url)
        resp = None
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "trustsight/1.0"})
            resp = urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT)
            from ..bounded_io import (
                ReadTimedOut,
                read_capped_with_deadline,
            )
            try:
                return read_capped_with_deadline(
                    resp, MAX_RESPONSE_BYTES, f"response from {url}",
                    _DOWNLOAD_DEADLINE_SECONDS,
                )
            except ReadTimedOut:
                log.warning(
                    "response from %s exceeded its %gs deadline; abandoning",
                    url, _DOWNLOAD_DEADLINE_SECONDS,
                )
                return None
        except ReadTooLarge:
            raise
        except urllib.error.HTTPError as e:
            if e.code in _RETRYABLE_STATUS and attempt < _MAX_RETRIES:
                delay = _retry_after(e)
                if delay is None:
                    delay = _backoff_delay(attempt)
                log.debug("HTTP %d fetching %s; backing off %.1fs (attempt %d/%d)",
                          e.code, url, delay, attempt + 1, _MAX_RETRIES)
                time.sleep(delay)
                continue
            log.warning("HTTP %d fetching %s", e.code, url)
            return None
        except urllib.error.URLError as e:
            if _is_transient_urlerror(e.reason) and attempt < _MAX_RETRIES:
                delay = _backoff_delay(attempt)
                log.debug("URL error fetching %s: %s; backing off %.1fs (attempt %d/%d)",
                          url, e.reason, delay, attempt + 1, _MAX_RETRIES)
                time.sleep(delay)
                continue
            log.warning("URL error fetching %s: %s", url, e.reason)
            return None
        except Exception as e:
            log.warning("unexpected error fetching %s: %s", url, e)
            return None
        finally:
            if resp is not None:
                try:
                    resp.close()
                except Exception:
                    pass
    return None


def _is_anubis_challenge(body: bytes) -> bool:
    """Heuristic: the cgit page returned an Anubis challenge instead of content."""
    text = body[:2000].lower()
    return b"anubis" in text or b"challenge" in text or b"just a moment" in text


def fetch_pkgbuild(name: str) -> Optional[str]:
    """Download a PKGBUILD for the given package.

    Tries the AUR cgit endpoint first.  If that returns an Anubis
    challenge, falls back to the snapshot tarball.
    Returns the PKGBUILD text, or None on failure.
    """
    url = f"{_CGIT_URL}?h={quote(name, safe='')}"
    body = _http_get(url)
    if body is not None and not _is_anubis_challenge(body):
        return body.decode("utf-8", errors="replace")
    if body is not None and _is_anubis_challenge(body):
        log.debug("cgit returned challenge for %s; trying snapshot", name)
    else:
        log.debug("cgit returned no data for %s; trying snapshot", name)

    return _pkgbuild_from_snapshot(name)


def fetch_srcinfo(name: str) -> Optional[str]:
    """Download .SRCINFO for the given package via cgit."""
    url = f"{_CGIT_SRCINFO_URL}?h={quote(name, safe='')}"
    body = _http_get(url)
    if body is not None and not _is_anubis_challenge(body):
        return body.decode("utf-8", errors="replace")
    return None


def _pkgbuild_from_tarfile(tf: tarfile.TarFile, name: str) -> Optional[str]:
    """Extract the PKGBUILD text from an open snapshot tarball."""
    return _archive.pkgbuild_from_tarfile(
        tf, name, max_members=MAX_TAR_MEMBERS,
        max_member_bytes=MAX_TAR_MEMBER_BYTES,
        max_total_bytes=MAX_TAR_TOTAL_BYTES,
    )


def _install_from_tarfile(
    tf: tarfile.TarFile, name: str,
) -> Optional[tuple[str, str]]:
    """The first top-level ``*.install`` scriptlet in the snapshot, or None."""
    return _archive.install_from_tarfile(
        tf, name, max_members=MAX_TAR_MEMBERS,
        max_member_bytes=MAX_TAR_MEMBER_BYTES,
        max_total_bytes=MAX_TAR_TOTAL_BYTES,
    )


def _pkgbuild_from_snapshot(name: str) -> Optional[str]:
    """Download the snapshot tarball and extract PKGBUILD."""
    url = f"{_SNAPSHOT_URL}/{quote(name, safe='')}.tar.gz"
    body = _http_get(url)
    if body is None:
        return None

    from ..sandbox import manifest_client
    try:
        parsed = manifest_client.parse_snapshot(
            name, body, max_members=MAX_TAR_MEMBERS,
            max_member_bytes=MAX_TAR_MEMBER_BYTES,
            max_total_bytes=MAX_TAR_TOTAL_BYTES)
    except manifest_client.ManifestUnavailable as e:
        log.warning("snapshot for %s refused: %s", name, e)
        return None
    if parsed.get("refused"):
        log.warning("snapshot for %s refused by a read bound", name)
        return None
    if parsed.get("malformed"):
        log.warning("error extracting snapshot for %s", name)
        return None
    return parsed.get("pkgbuild")


def _snapshot_manifest(
    tf: tarfile.TarFile, max_members: int = MAX_TAR_MEMBERS,
) -> tuple[list[tuple[str, bytes]], list[tuple[str, str]], bool]:
    """Heads, bounded manifest text, and whether the text is complete."""
    return _archive.snapshot_manifest(
        tf, max_members=max_members,
        max_member_bytes=MAX_TAR_MEMBER_BYTES,
        max_total_bytes=MAX_TAR_TOTAL_BYTES,
    )


def _fetch_snapshot_tarball(name: str) -> Optional[bytes]:
    """The package's snapshot tarball, from the GitHub mirror or the AUR.

    The GitHub AUR mirror (one branch per package) is tried first, then the
    AUR's cgit snapshot endpoint as the fallback.  Returns None when neither
    answers; a body that is not a usable tarball is handled by the caller,
    exactly as before.
    """
    quoted = quote(name, safe="")
    for url in (
        # codeload already names the format (``tar.gz``) before the ref, so
        # the branch is appended bare, with no further suffix.
        f"{_GITHUB_SNAPSHOT_URL}/{quoted}",
        f"{_SNAPSHOT_URL}/{quoted}.tar.gz",
    ):
        body = _http_get(url)
        if body is not None:
            return body
    return None


def fetch_pkgbuild_with_tree(
    name: str,
) -> tuple[
    Optional[str], Optional[list[tuple[str, bytes]]], Optional[dict], bool,
    Optional[str], Optional[str], Optional[list[tuple[str, str]]], bool,
]:
    """PKGBUILD text, the tree manifest, an H070 finding, a refusal flag,
    the ``.install`` scriptlet text (or None), that scriptlet's real
    basename (or None), bounded manifest text (or None), and whether that
    text is complete.

    Downloads the snapshot tarball directly (GitHub's AUR mirror first, the
    AUR's own cgit second) so the corpus path sees the same committed file
    tree the git path does (H066-tree).  The tarball is fetched from an AUR
    mirror - never from a PKGBUILD-declared URL - so this is consistent with
    the "static, offline" review claim.  Falls back to the cgit text-only
    fetch when the tarball cannot be read.

    The full tarball bytes are handed to ``check_archive_trailer`` (H070):
    the corpus side is the one place AUR content is downloaded, so it is
    also where the archive container is inspected.  A trailer anomaly is
    returned as a stamped finding; a clean archive returns None.

    The fourth element says the snapshot was **refused by a read bound**, as
    opposed to being absent or malformed.  The two fall back to the same
    place, so without the distinction a bound that dropped content would be
    indistinguishable from a package that simply has no snapshot - and A14
    requires the bound to be visible as a bound.  The caller turns it into
    the ``snapshot_refused`` coverage gap.
    """
    from ..sandbox import manifest_client

    refused = False
    try:
        body = _fetch_snapshot_tarball(name)
    except ReadTooLarge as e:
        log.warning("snapshot for %s refused: %s", name, e)
        body = None
        refused = True
    if body is not None:
        try:
            parsed = manifest_client.parse_snapshot(
            name, body, max_members=MAX_TAR_MEMBERS,
            max_member_bytes=MAX_TAR_MEMBER_BYTES,
            max_total_bytes=MAX_TAR_TOTAL_BYTES)
        except manifest_client.ManifestUnavailable as e:
            log.warning("snapshot for %s refused: %s", name, e)
            refused = True
        else:
            if parsed.get("refused"):
                log.warning("snapshot for %s refused by a read bound", name)
                refused = True
            elif not parsed.get("malformed") and parsed.get("pkgbuild") is not None:
                manifest = [
                    (path, bytes.fromhex(head))
                    for path, head in parsed.get("manifest") or ()
                ]
                manifest_texts = [
                    (path, text) for path, text in parsed.get("manifest_texts") or ()
                ]
                return (parsed["pkgbuild"], manifest, parsed.get("trailer"),
                        False, parsed.get("install_text"),
                        parsed.get("install_name"), manifest_texts,
                        bool(parsed.get("manifest_complete", True)))
            elif parsed.get("malformed"):
                log.debug("snapshot tarball for %s unusable", name)
    try:
        text = fetch_pkgbuild(name)
    except ReadTooLarge as e:
        # The snapshot raised, and the cgit fallback refused too.  A bound
        # dropped content; keep the refusal visible instead of letting it
        # escape as a generic fetch failure.
        log.warning("PKGBUILD for %s refused: %s", name, e)
        text = None
        refused = True
    return text, None, None, refused, None, None, None, True


def default_resume_path() -> Path:
    """Where bootstrap progress lives.

    Under the config directory, not the working directory: a bootstrap
    started in one shell and resumed from another used to silently begin
    again from zero.
    """
    from ..config import CONFIG_DIR

    return CONFIG_DIR / _RESUME_FILE


def save_resume_state(state: dict, path: Path | None = None) -> None:
    """Persist bootstrap progress so it can be resumed."""
    path = path or default_resume_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state, separators=(",", ":")))


def load_resume_state(path: Path | None = None) -> Optional[dict]:
    """Load saved bootstrap progress."""
    path = path or default_resume_path()
    if not path.exists():
        return None
    try:
        from ..bounded_io import read_file_capped
        return json.loads(read_file_capped(path, 1024 * 1024, "resume state"))
    except Exception:  # noqa: BLE001 - a bad resume file is a miss
        return None


def clear_resume_state(path: Path | None = None) -> None:
    """Remove the resume file after successful completion."""
    path = path or default_resume_path()
    if path.exists():
        path.unlink()
