"""The release channel: verified downloads of ``baseline-*`` release assets.

Baselines (the novelty seed, IOC federation baselines, the corpus baseline)
are distributed as signed release assets in the TrustSight repository,
named with the ``baseline-`` prefix.  This module is the only place in the
program that talks to the release host.  A download is bounded, carries an
explicit timeout, and is accepted only when its detached Ed25519 signature
verifies against the pinned distribution key.  Anything that fails any of
those checks is refused; there is no fallback that accepts an unverified
download.

Security model note: the release channel (``api.github.com`` for release
discovery, ``github.com`` for asset downloads) is the second declared
endpoint of the program, beside the AUR.  It is confined to this module by
``scripts/security_gates.py``, it is reached by explicit commands
(``seed fetch``, ``corpus fetch``, ``ioc update``, first-run auto-import) and
by the throttled, read-only version check described below, and never during
analysis.  Its payloads are signature-checked before they are read; the
version check reads only a release tag and sends nothing of the operator's.
"""

from __future__ import annotations

import json
import logging
import os
import re
import urllib.request
from collections.abc import Callable
from pathlib import Path

from .full_aur.export import _load_trusted_pubkey, verify_artifact

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# The declared endpoint
# ---------------------------------------------------------------------------

#: The release asset endpoint.  ``latest`` follows GitHub's redirect to the
#: newest release; a tag pins the exact release an operator asked for.
RELEASE_BASE_URL = "https://github.com/emiliano-go/trustsight/releases"

#: The GitHub REST API, used once per process to discover the newest
#: asset-bearing ``baseline-*`` release.  The second declared release host.
GITHUB_API_URL = "https://api.github.com"

#: Every outbound request carries an explicit timeout (security gate A4).
_REQUEST_TIMEOUT_SECONDS = 60

#: Total wall-clock budget for one asset download.  The per-op timeout above
#: resets on every chunk, so it does not bound a slow-drip transfer; this is
#: the bound on the transfer as a whole.
_DOWNLOAD_DEADLINE_SECONDS = 300

#: The releases listing is small JSON, but the read is still capped so a
#: hostile or malfunctioning response cannot be materialised whole (A4).
_MAX_RELEASES_JSON_BYTES = 1 * 1024 * 1024

#: A release asset is never read past this bound (security gate A5-style
#: bound on hostile input; the corpus baseline is the largest asset).
_MAX_RELEASE_BYTES = 512 * 1024 * 1024

#: The pinned distribution key ships inside the package.
PINNED_PUBKEY_PATH = Path(__file__).parent / "full_aur" / "baseline_pubkey.pem"

#: A descriptive User-Agent for release discovery.  GitHub's API asks for
#: one, and it keeps the request identifiable in rate-limit accounting.
_USER_AGENT = "trustsight-release (+https://docs.trustsight.org)"


class ReleaseError(Exception):
    """Base class for release-channel failures."""


class ReleaseFetchError(ReleaseError):
    """The asset could not be downloaded."""


class ReleaseTooLargeError(ReleaseError):
    """The asset exceeded the download bound and was refused."""


class ReleaseSignatureError(ReleaseError):
    """The asset failed verification against the pinned distribution key."""


def offline() -> bool:
    """Return True when the operator has forbidden outbound requests.

    Anything that would touch the release channel checks this first, so a
    CI run or an air-gapped machine can pin the program to what is already
    on disk.
    """
    return os.environ.get("TRUSTSIGHT_OFFLINE", "").strip().lower() in (
        "1", "true", "yes",
    )


def is_release_url(value: str) -> bool:
    """Return True when *value* names the TrustSight release channel."""
    return value.rstrip("/") == RELEASE_BASE_URL or value.startswith(
        RELEASE_BASE_URL + "/"
    )


_BASELINE_TAG_CACHE: str | None = None
_BASELINE_TAG_RESOLVED = False


def _resolve_baseline_tag() -> str | None:
    """Find the most recent ``baseline-*`` release tag that carries assets.

    Queries the GitHub releases API once per process and caches the result.
    Returns ``None`` when offline, on network failure, or when no baseline
    release exists.
    """
    global _BASELINE_TAG_CACHE, _BASELINE_TAG_RESOLVED
    if _BASELINE_TAG_RESOLVED:
        return _BASELINE_TAG_CACHE
    _BASELINE_TAG_RESOLVED = True
    if offline():
        return None
    try:
        url = f"{GITHUB_API_URL}/repos/emiliano-go/trustsight/releases?per_page=30"
        req = urllib.request.Request(
            url,
            headers={
                "Accept": "application/vnd.github+json",
                "User-Agent": _USER_AGENT,
            },
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = resp.read(_MAX_RELEASES_JSON_BYTES + 1)
        # A truncated JSON body must not be parsed as if it were complete:
        # fall back to ``latest`` instead of reading a cut-off listing.
        if len(body) > _MAX_RELEASES_JSON_BYTES:
            return None
        releases = json.loads(body)
        for release in releases:
            tag = release.get("tag_name", "")
            if tag.startswith("baseline-") and release.get("assets"):
                _BASELINE_TAG_CACHE = tag
                return tag
    except Exception:
        log.debug("failed to resolve baseline tag via GitHub API", exc_info=True)
    return None


_VERSION_RE = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)")


def _parse_version(value: str) -> tuple[int, int, int] | None:
    """``X.Y.Z`` (with an optional leading ``v``) as a comparable tuple."""
    match = _VERSION_RE.match(str(value or "").strip())
    if not match:
        return None
    return (int(match.group(1)), int(match.group(2)), int(match.group(3)))


def is_newer(latest_tag: str, current_version: str) -> bool:
    """True when *latest_tag* names a strictly newer release than *current*.

    A tag that is not ``X.Y.Z`` (a ``baseline-*`` tag, a malformed string)
    compares as not newer, so an unexpected value can never nag.
    """
    latest = _parse_version(latest_tag)
    current = _parse_version(current_version)
    if latest is None or current is None:
        return False
    return latest > current


def _newest_semver_tag(releases) -> str | None:
    """The highest ``vX.Y.Z`` tag among non-draft, non-prerelease releases.

    A ``baseline-*`` release, a draft or a prerelease is skipped: the version
    check compares semver, and GitHub's own ``/releases/latest`` can name a
    baseline release published after the newest version.
    """
    best: tuple[int, int, int] | None = None
    best_tag: str | None = None
    for release in releases or ():
        if not isinstance(release, dict):
            continue
        if release.get("draft") or release.get("prerelease"):
            continue
        tag = str(release.get("tag_name", ""))
        parsed = _parse_version(tag)
        if parsed is None:
            continue
        if best is None or parsed > best:
            best, best_tag = parsed, tag
    return best_tag


_LATEST_TAG_CACHE: str | None = None
_LATEST_TAG_RESOLVED = False


def latest_release_tag() -> str | None:
    """The newest published ``vX.Y.Z`` release tag, or ``None``.

    Lists the most recent releases through the GitHub API and takes the
    highest semver tag once per process.  Returns ``None`` when offline, on
    any network or parse failure, or when no versioned release exists - the
    caller treats that as "cannot tell", never as "up to date".
    """
    global _LATEST_TAG_CACHE, _LATEST_TAG_RESOLVED
    if _LATEST_TAG_RESOLVED:
        return _LATEST_TAG_CACHE
    _LATEST_TAG_RESOLVED = True
    if offline():
        return None
    try:
        url = f"{GITHUB_API_URL}/repos/emiliano-go/trustsight/releases?per_page=30"
        req = urllib.request.Request(
            url,
            headers={
                "Accept": "application/vnd.github+json",
                "User-Agent": _USER_AGENT,
            },
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = resp.read(_MAX_RELEASES_JSON_BYTES + 1)
        # A truncated body must not be parsed as if complete.
        if len(body) > _MAX_RELEASES_JSON_BYTES:
            return None
        _LATEST_TAG_CACHE = _newest_semver_tag(json.loads(body))
    except Exception:
        log.debug("failed to resolve the latest release tag", exc_info=True)
    return _LATEST_TAG_CACHE


def asset_url(asset_name: str, tag: str | None = None) -> str:
    """Return the download URL for *asset_name*.

    Without *tag* the ``latest`` release is used; GitHub redirects to the
    newest tag.  For ``baseline-*`` assets, the most recent ``baseline-*``
    release is discovered automatically.  With *tag* the download is pinned
    to that exact release.

    A ``baseline-*`` asset never falls back to ``latest``: the seed and the
    other baselines live only on ``baseline-*`` releases, so a version tag
    cannot carry them.  When discovery fails, the configured fallback tag
    (:func:`_configured_baseline_tag`) is used; when there is none, the
    function fails closed rather than building a URL that cannot resolve.
    """
    if tag:
        return f"{RELEASE_BASE_URL}/download/{tag}/{asset_name}"
    if asset_name.startswith("baseline-"):
        baseline_tag = _resolve_baseline_tag() or _configured_baseline_tag()
        if baseline_tag:
            return f"{RELEASE_BASE_URL}/download/{baseline_tag}/{asset_name}"
        raise ReleaseFetchError(
            f"no {asset_name} is reachable: the release API is unavailable "
            "and no fallback baseline tag is configured; pass --tag "
            "(e.g. --tag baseline-2026-09-24) or set [seed] baseline_tag"
        )
    return f"{RELEASE_BASE_URL}/latest/download/{asset_name}"


def _configured_baseline_tag() -> str | None:
    """The shipped or operator-configured fallback baseline tag, or None.

    Read without writing any config file, because this runs while a URL is
    being built.  Returns ``None`` when the operator has turned the
    fallback off.
    """
    from .config import configured_baseline_tag

    try:
        return configured_baseline_tag()
    except Exception:
        log.debug("could not read the configured baseline tag", exc_info=True)
        return None


class _ProgressReader:
    """A response wrapper that reports download progress.

    ``read_capped_with_deadline`` is handed this instead of the response
    when a callback is present.  It forwards ``read`` untouched and calls
    ``on_progress(bytes_read, total)`` after each chunk; the byte cap and
    the deadline stay in the bounded reader, so progress reporting cannot
    loosen either bound.
    """

    def __init__(self, fh, on_progress: Callable[[int, int | None], None],
                 total: int | None):
        self._fh = fh
        self._on_progress = on_progress
        self._total = total
        self._pos = 0

    def read(self, n: int = -1) -> bytes:
        chunk = self._fh.read(n)
        if chunk:
            self._pos += len(chunk)
            self._on_progress(self._pos, self._total)
        return chunk


def _declared_length(resp, max_bytes: int) -> int | None:
    """The response's ``Content-Length`` for display, or ``None``.

    The value is remote-declared and drives nothing: it is the denominator
    of a progress bar, never a bound.  An absent, malformed or implausible
    length (over the byte cap) reads as unknown rather than drawing a bar
    that cannot be right.
    """
    declared = resp.headers.get("Content-Length")
    if not declared or not declared.isdigit():
        return None
    value = int(declared)
    return value if 0 < value <= max_bytes else None


def download_asset(
    asset_name: str,
    tag: str | None = None,
    max_bytes: int = _MAX_RELEASE_BYTES,
    on_progress: Callable[[int, int | None], None] | None = None,
) -> bytes:
    """Download *asset_name* from the release channel, bounded.

    Raises ``ReleaseFetchError`` on any transport failure and
    ``ReleaseTooLargeError`` when the asset exceeds *max_bytes*.

    If *on_progress* is a callable ``(pos, total) -> None`` it is called
    with the bytes received so far and the declared content length, or
    ``None`` when that length is absent or implausible.  The declared
    length is display-only; the byte cap and the deadline are unchanged.
    """
    if offline():
        raise ReleaseFetchError(
            "the release channel is disabled (TRUSTSIGHT_OFFLINE is set); "
            "no download attempted"
        )
    url = asset_url(asset_name, tag)
    try:
        with urllib.request.urlopen(url, timeout=_REQUEST_TIMEOUT_SECONDS) as resp:
            # The per-op timeout does not bound the transfer; a slow-drip
            # server resets it every chunk.  Charge the whole download one
            # wall-clock deadline as well.
            from .bounded_io import (
                ReadTimedOut,
                ReadTooLarge,
                read_capped_with_deadline,
            )
            source = resp
            if on_progress is not None:
                total = _declared_length(resp, max_bytes)
                on_progress(0, total)
                source = _ProgressReader(resp, on_progress, total)
            try:
                return read_capped_with_deadline(
                    source, max_bytes, asset_name, _DOWNLOAD_DEADLINE_SECONDS
                )
            except ReadTooLarge as exc:
                raise ReleaseTooLargeError(str(exc)) from exc
            except ReadTimedOut as exc:
                raise ReleaseFetchError(str(exc)) from exc
    except ReleaseTooLargeError:
        raise
    except Exception as exc:
        raise ReleaseFetchError(f"could not download {asset_name}: {exc}") from exc


def fetch_verified_asset(
    asset_name: str,
    tag: str | None = None,
    pubkey_path: Path | None = None,
    max_bytes: int = _MAX_RELEASE_BYTES,
    on_progress: Callable[[int, int | None], None] | None = None,
) -> bytes:
    """Download *asset_name* and refuse it unless its signature verifies.

    The sibling ``<asset_name>.sig`` carries the raw 64-byte Ed25519
    detached signature over the exact asset bytes.  The signature is
    checked against the pinned distribution key before anything else sees
    the payload; a mismatch raises ``ReleaseSignatureError``.

    *on_progress* reports the asset download only; the 64-byte signature
    download is not worth a second bar.
    """
    pubkey_path = pubkey_path or PINNED_PUBKEY_PATH
    data = download_asset(
        asset_name, tag=tag, max_bytes=max_bytes, on_progress=on_progress
    )
    try:
        signature = download_asset(
            f"{asset_name}.sig", tag=tag, max_bytes=64 * 1024
        )
    except ReleaseError as exc:
        raise ReleaseSignatureError(
            f"no signature to verify {asset_name} against: {exc}"
        ) from exc
    try:
        pubkey = _load_trusted_pubkey(pubkey_path)
    except Exception as exc:
        raise ReleaseSignatureError(str(exc)) from exc
    if not verify_artifact(data, signature, pubkey):
        raise ReleaseSignatureError(
            f"{asset_name} failed Ed25519 verification against the pinned key; "
            "refused"
        )
    return data


def _download_url(url: str, max_bytes: int = _MAX_RELEASE_BYTES) -> bytes:
    """Download *url* with the same byte cap and wall-clock deadline."""
    try:
        with urllib.request.urlopen(
                url, timeout=_REQUEST_TIMEOUT_SECONDS) as resp:
            from .bounded_io import (
                ReadTimedOut,
                ReadTooLarge,
                read_capped_with_deadline,
            )
            try:
                return read_capped_with_deadline(
                    resp, max_bytes, url, _DOWNLOAD_DEADLINE_SECONDS)
            except ReadTooLarge as exc:
                raise ReleaseTooLargeError(str(exc)) from exc
            except ReadTimedOut as exc:
                raise ReleaseFetchError(str(exc)) from exc
    except (ReleaseTooLargeError, ReleaseFetchError):
        raise
    except Exception as exc:
        raise ReleaseFetchError(f"could not download {url}: {exc}") from exc


def fetch_verified_url(
    base_url: str, asset_name: str, *, pubkey_path: Path,
) -> bytes:
    """Fetch *asset_name* from an arbitrary *base_url*, signature-verified.

     (federation sketch): the same detached-Ed25519 path the
    release channel uses, against a publisher key the operator pins.  The
    sibling ``<asset_name>.sig`` must verify over the exact bytes before the
    payload is returned; an unsigned or mismatched asset is refused.
    """
    if offline():
        raise ReleaseFetchError(
            "federation fetches are disabled (TRUSTSIGHT_OFFLINE is set)")
    base = base_url.rstrip("/")
    data = _download_url(f"{base}/{asset_name}")
    signature = _download_url(f"{base}/{asset_name}.sig", max_bytes=64 * 1024)
    try:
        pubkey = _load_trusted_pubkey(pubkey_path)
    except Exception as exc:
        raise ReleaseSignatureError(str(exc)) from exc
    if not verify_artifact(data, signature, pubkey):
        raise ReleaseSignatureError(
            f"{asset_name} failed Ed25519 verification against the publisher "
            "key; refused")
    return data