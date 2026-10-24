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
from dataclasses import dataclass
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

#: The browser base for issue and release pages.  It is not a fetch target;
#: it lives here so the declared-host audit keeps one place for the host.
GITHUB_WEB = "https://github.com"

#: The canonical, always-followed channel.  Its key is pinned inside the
#: package; an operator can follow other channels but cannot un-follow this one.
OFFICIAL_REPO = "emiliano-go/trustsight"

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


class ReleaseManifestError(ReleaseError):
    """The signed baseline manifest is missing, malformed, or mismatched."""


class ReleaseRollbackError(ReleaseError):
    """The signed baseline is older than the version already imported."""


class ReleaseExpiredError(ReleaseError):
    """The signed baseline's own expiry has passed."""


def offline() -> bool:
    """Return True when the operator has forbidden outbound requests.

    Anything that would touch the release channel checks this first, so a
    CI run or an air-gapped machine can pin the program to what is already
    on disk.
    """
    return os.environ.get("TRUSTSIGHT_OFFLINE", "").strip().lower() in (
        "1", "true", "yes",
    )


#: An ``owner/repo`` slug becomes a URL path segment; a configured value with
#: a slash, ``..`` or a space is refused rather than interpolated.
_REPO_RE = re.compile(r"^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$")


@dataclass(frozen=True)
class Channel:
    """A release channel: a repo, its asset base URL and its pinned key.

    The official channel is the one this package ships for; every other
    channel is operator-configured and its key is operator-pinned, so an
    import from it is trusting that publisher.
    """

    repo: str
    base_url: str
    api_url: str
    key_path: Path | None
    key_bytes: bytes | None
    official: bool

    @property
    def label(self) -> str:
        return self.repo or self.base_url


def official_channel() -> Channel:
    """The canonical channel, whose key is pinned inside the package."""
    return Channel(
        repo=OFFICIAL_REPO,
        base_url=RELEASE_BASE_URL,
        api_url=f"{GITHUB_API_URL}/repos/{OFFICIAL_REPO}",
        key_path=PINNED_PUBKEY_PATH,
        key_bytes=None,
        official=True,
    )


def _parse_pinned_key(value: str | None) -> tuple[Path | None, bytes | None]:
    """A configured channel key as ``(path, bytes)``.

    A 64-character hex string is the raw key; anything else names a file that
    holds the raw 32-byte key.  The two are returned separately so the caller
    can pick the right loader; a value that is neither is left as a path so
    the loader raises its own (descriptive) refusal.
    """
    if not value:
        return None, None
    candidate = value.strip()
    if re.fullmatch(r"[0-9a-fA-F]{64}", candidate):
        try:
            return None, bytes.fromhex(candidate)
        except ValueError:  # pragma: no cover - fullmatch already guarantees it
            return Path(candidate), None
    return Path(candidate), None


def active_baseline_channel(channel: str | None = None) -> Channel:
    """The channel baselines (seed, corpus) are pulled from.

    *channel* is an ``owner/repo`` override (from ``--channel``); with none,
    the configured ``[release] channel`` selects it.  Empty, the official
    slug, or the official repo returns the official channel; any other repo is
    validated and paired with the operator-pinned key.
    """
    from .config import configured_release_channel, configured_release_key

    try:
        repo = (channel or configured_release_channel() or "").strip()
    except Exception:
        repo = (channel or "").strip()
    if not repo or repo == OFFICIAL_REPO:
        return official_channel()
    if not _REPO_RE.match(repo):
        raise ReleaseFetchError(
            f"invalid release channel {repo!r}: use a GitHub 'owner/repo' slug"
        )
    try:
        key_value = configured_release_key()
    except Exception:
        key_value = None
    key_path, key_bytes = _parse_pinned_key(key_value)
    return Channel(
        repo=repo,
        base_url=f"https://github.com/{repo}/releases",
        api_url=f"{GITHUB_API_URL}/repos/{repo}",
        key_path=key_path,
        key_bytes=key_bytes,
        official=False,
    )


def channel_for_url(url: str) -> Channel | None:
    """The channel whose base URL *url* names, or ``None``.

    Matches the official channel and the configured baseline channel.  Used to
    decide whether a feed URL is a release-channel URL and which key verifies
    it.
    """
    base = url.rstrip("/")
    official = official_channel()
    if base == official.base_url or base.startswith(official.base_url + "/"):
        return official
    # A configured non-official channel: compare against its base URL without
    # requiring network I/O, so a bad config never raises here.
    from .config import configured_release_channel

    try:
        repo = (configured_release_channel() or "").strip()
    except Exception:
        repo = ""
    if repo and repo != OFFICIAL_REPO and _REPO_RE.match(repo):
        base_url = f"https://github.com/{repo}/releases"
        if base == base_url or base.startswith(base_url + "/"):
            try:
                return active_baseline_channel(repo)
            except ReleaseError:
                return None
    return None


def is_release_url(value: str) -> bool:
    """Return True when *value* names a followed release channel."""
    return channel_for_url(value) is not None


_TAG_CACHE: dict[tuple[str, str], str | None] = {}
_TAGS_RESOLVED: set[tuple[str, str]] = set()


def _read_releases_json(resp) -> bytes | None:
    """Read a release-listing response under the byte cap and total deadline.

    ``None`` means the listing could not be read whole (too large or too
    slow), which every caller already treats as "cannot tell", never as an
    empty or up-to-date answer.
    """
    from .bounded_io import ReadTimedOut, ReadTooLarge, read_capped_with_deadline

    try:
        return read_capped_with_deadline(
            resp, _MAX_RELEASES_JSON_BYTES, "GitHub releases listing",
            _DOWNLOAD_DEADLINE_SECONDS,
        )
    except (ReadTimedOut, ReadTooLarge):
        return None


def _resolve_channel_tag(prefix: str, channel: Channel | None = None) -> str | None:
    """Find the most recent ``<prefix>*`` release tag that carries assets.

    Queries the channel's GitHub releases API once per process per
    ``(channel, prefix)`` and caches the result.  Returns ``None`` when
    offline, on network failure, or when no matching release exists.
    """
    channel = channel or official_channel()
    cache_key = (channel.repo, prefix)
    if cache_key in _TAGS_RESOLVED:
        return _TAG_CACHE.get(cache_key)
    _TAGS_RESOLVED.add(cache_key)
    if offline():
        return None
    try:
        url = f"{channel.api_url}/releases?per_page=30"
        req = urllib.request.Request(
            url,
            headers={
                "Accept": "application/vnd.github+json",
                "User-Agent": _USER_AGENT,
            },
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = _read_releases_json(resp)
        # A truncated or timed-out JSON body must not be parsed as if it were
        # complete: fall back to ``latest`` instead of reading a cut-off listing.
        if body is None:
            return None
        releases = json.loads(body)
        for release in releases:
            tag = release.get("tag_name", "")
            if tag.startswith(prefix) and release.get("assets"):
                _TAG_CACHE[cache_key] = tag
                return tag
    except Exception:
        log.debug("failed to resolve %s* tag on %s via GitHub API", prefix,
                  channel.repo, exc_info=True)
    return None


def _resolve_baseline_tag(channel: Channel | None = None) -> str | None:
    """Find the most recent ``baseline-*`` release tag that carries assets.

    The seed and corpus baselines live only on ``baseline-*`` releases; this
    deliberately ignores the dedicated ``ioc-*`` channel.
    """
    return _resolve_channel_tag("baseline-", channel)


def _resolve_ioc_tag(channel: Channel | None = None) -> str | None:
    """Find the most recent ``ioc-*`` release tag that carries assets.

    The IOC indicators are federated separately from the bulk ``baseline-*``
    family so a time-sensitive set can be republished without cutting a full
    baseline release.  ``_resolve_baseline_tag`` never matches these tags, so
    a seed or corpus fetch cannot be pointed at one.
    """
    return _resolve_channel_tag("ioc-", channel)


def _resolve_watchlist_tag(channel: Channel | None = None) -> str | None:
    """Find the most recent ``watchlist-*`` release tag that carries assets.

    The watchlist ships on its own channel so a curated subject list can be
    republished without a baseline or IOC cut; neither ``baseline-`` nor
    ``ioc-`` resolution matches these tags, so a seed, corpus or IOC fetch
    can never be pointed at one.
    """
    return _resolve_channel_tag("watchlist-", channel)


def resolve_baseline_tag(channel: Channel | None = None) -> str | None:
    """Public: the newest asset-bearing ``baseline-*`` tag, or ``None``."""
    return _resolve_baseline_tag(channel)


def resolve_ioc_tag(channel: Channel | None = None) -> str | None:
    """Public: the newest asset-bearing ``ioc-*`` tag, or ``None``."""
    return _resolve_ioc_tag(channel)


def resolve_watchlist_tag(channel: Channel | None = None) -> str | None:
    """Public: the newest asset-bearing ``watchlist-*`` tag, or ``None``."""
    return _resolve_watchlist_tag(channel)


def clear_tag_cache() -> None:
    """Forget the per-process tag cache.

    A long-running watcher must re-query the channel each cycle; without this
    the first resolution of a process is the only one it ever sees.
    """
    _TAG_CACHE.clear()
    _TAGS_RESOLVED.clear()


def tag_from_asset_url(url: str) -> str | None:
    """The release tag embedded in a ``.../download/<tag>/<asset>`` URL.

    Returns ``None`` for a ``latest`` URL or anything that does not carry a
    tag, so a caller records a pull only when it actually learned the tag.
    """
    marker = "/download/"
    idx = url.find(marker)
    if idx < 0:
        return None
    rest = url[idx + len(marker):]
    tag = rest.split("/", 1)[0]
    if tag in ("", "latest"):
        return None
    return tag


_VERSION_RE = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)")

# A release tag becomes a URL path segment; the channel only ever serves
# tags in this set.  A configured or operator tag outside it is refused
# rather than interpolated into a URL.
_TAG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


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
            body = _read_releases_json(resp)
        # A truncated or timed-out body must not be parsed as if complete.
        if body is None:
            return None
        _LATEST_TAG_CACHE = _newest_semver_tag(json.loads(body))
    except Exception:
        log.debug("failed to resolve the latest release tag", exc_info=True)
    return _LATEST_TAG_CACHE


def asset_url(asset_name: str, tag: str | None = None,
              channel: Channel | None = None) -> str:
    """Return the download URL for *asset_name* on *channel*.

    Without *tag* the ``latest`` release is used; GitHub redirects to the
    newest tag.  A ``baseline-ioc-*`` asset resolves the newest ``ioc-*``
    release (the dedicated, fast-moving IOC channel); the seed, the corpus
    and every other ``baseline-*`` asset resolve the newest ``baseline-*``
    release.  With *tag* the download is pinned to that exact release.

    Neither channel falls back to ``latest``: the IOC pairs live only on
    ``ioc-*`` releases and the seed/corpus only on ``baseline-*`` releases,
    so a ``v*`` version tag can never carry them.  When discovery fails, the
    configured fallback tag (:func:`_configured_baseline_tag` for the
    baseline family, :func:`_configured_ioc_tag` for the IOC pairs) is used;
    when there is none, the function fails closed rather than building a URL
    that cannot resolve.  A non-official channel has no configured fallback:
    its tag must come from discovery or an explicit *tag*.
    """
    channel = channel or official_channel()
    if tag:
        if not _TAG_RE.match(tag):
            raise ReleaseFetchError(
                f"refusing release tag {tag!r}: a tag is a URL path segment "
                "([A-Za-z0-9][A-Za-z0-9._-]*)"
            )
        return f"{channel.base_url}/download/{tag}/{asset_name}"
    fallback_ioc = _configured_ioc_tag() if channel.official else None
    fallback_baseline = _configured_baseline_tag() if channel.official else None
    if asset_name.startswith("baseline-ioc-"):
        ioc_tag = _resolve_ioc_tag(channel) or fallback_ioc
        if ioc_tag:
            return f"{channel.base_url}/download/{ioc_tag}/{asset_name}"
        # The pairs live only on the ioc-* channel; there is no baseline copy
        # to fall back to, so a missing channel is a refusal.
        raise ReleaseFetchError(
            f"no {asset_name} is reachable: the release API is unavailable "
            "and no fallback IOC tag is configured; pass --tag "
            "(e.g. --tag ioc-2026-10-18) or set [baselines.ioc] tag"
        )
    if asset_name.startswith("baseline-"):
        baseline_tag = _resolve_baseline_tag(channel) or fallback_baseline
        if baseline_tag:
            return f"{channel.base_url}/download/{baseline_tag}/{asset_name}"
        raise ReleaseFetchError(
            f"no {asset_name} is reachable: the release API is unavailable "
            "and no fallback baseline tag is configured; pass --tag "
            "(e.g. --tag baseline-2026-10-22) or set [seed] baseline_tag"
        )
    if asset_name.startswith("watchlist-"):
        watchlist_tag = _resolve_watchlist_tag(channel) or (
            _configured_watchlist_tag() if channel.official else None
        )
        if watchlist_tag:
            return f"{channel.base_url}/download/{watchlist_tag}/{asset_name}"
        raise ReleaseFetchError(
            f"no {asset_name} is reachable: the release API is unavailable "
            "and no fallback watchlist tag is configured; pass --tag "
            "(e.g. --tag watchlist-2026-10-20) or set [baselines.watchlist] tag"
        )
    return f"{channel.base_url}/latest/download/{asset_name}"


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


def _configured_ioc_tag() -> str | None:
    """The operator-configured fallback IOC channel tag, or ``None``.

    Read without writing any config file, because this runs while a URL is
    being built.  ``None`` means "use the live channel"; it is never a
    ``latest`` guess.
    """
    from .config import configured_ioc_tag

    try:
        return configured_ioc_tag()
    except Exception:
        log.debug("could not read the configured IOC tag", exc_info=True)
        return None


def _configured_watchlist_tag() -> str | None:
    """The operator-configured fallback watchlist channel tag, or ``None``."""
    from .config import configured_watchlist_tag

    try:
        return configured_watchlist_tag()
    except Exception:
        log.debug("could not read the configured watchlist tag", exc_info=True)
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

    def read1(self, n: int = -1) -> bytes:
        """Forward ``read1`` so the bounded reader can avoid a blocking read."""
        inner = getattr(self._fh, "read1", None)
        chunk = inner(n) if callable(inner) else self._fh.read(n)
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
    channel: Channel | None = None,
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
    url = asset_url(asset_name, tag, channel)
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


def _channel_pubkey(channel: Channel, pubkey_path: Path | None) -> bytes:
    """The key *channel*'s assets must verify against.

    An explicit *pubkey_path* (``--key``) wins; then the channel's own key
    (raw bytes from a hex config value, or a file).  A non-official channel
    with no pinned key is refused rather than falling back to the official
    key, which would verify a foreign asset against the wrong publisher.
    """
    if pubkey_path is not None:
        return _load_trusted_pubkey(Path(pubkey_path))
    if channel.key_bytes is not None:
        if len(channel.key_bytes) != 32:
            raise ReleaseSignatureError(
                f"the pinned key for channel {channel.label!r} is "
                f"{len(channel.key_bytes)} bytes, not a 32-byte ed25519 key"
            )
        return channel.key_bytes
    if channel.key_path is not None:
        return _load_trusted_pubkey(channel.key_path)
    raise ReleaseSignatureError(
        f"no key is pinned for release channel {channel.label!r}; set "
        "[release] key to that publisher's ed25519 public key"
    )


def fetch_verified_asset(
    asset_name: str,
    tag: str | None = None,
    pubkey_path: Path | None = None,
    max_bytes: int = _MAX_RELEASE_BYTES,
    on_progress: Callable[[int, int | None], None] | None = None,
    channel: Channel | None = None,
) -> bytes:
    """Download *asset_name* and refuse it unless its signature verifies.

    The sibling ``<asset_name>.sig`` carries the raw 64-byte Ed25519
    detached signature over the exact asset bytes.  The signature is
    checked against the channel's pinned key before anything else sees
    the payload; a mismatch raises ``ReleaseSignatureError``.

    *on_progress* reports the asset download only; the 64-byte signature
    download is not worth a second bar.
    """
    channel = channel or official_channel()
    data = download_asset(
        asset_name, tag=tag, max_bytes=max_bytes, on_progress=on_progress,
        channel=channel,
    )
    try:
        signature = download_asset(
            f"{asset_name}.sig", tag=tag, max_bytes=64 * 1024, channel=channel
        )
    except ReleaseError as exc:
        raise ReleaseSignatureError(
            f"no signature to verify {asset_name} against: {exc}"
        ) from exc
    try:
        pubkey = _channel_pubkey(channel, pubkey_path)
    except ReleaseError:
        raise
    except Exception as exc:
        raise ReleaseSignatureError(str(exc)) from exc
    if not verify_artifact(data, signature, pubkey):
        raise ReleaseSignatureError(
            f"{asset_name} failed Ed25519 verification against the pinned key "
            f"for channel {channel.label!r}; refused"
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
    base_url: str, asset_name: str, *, pubkey_path: Path | None = None,
    pubkey: bytes | None = None,
) -> bytes:
    """Fetch *asset_name* from an arbitrary *base_url*, signature-verified.

    The federation counterpart of :func:`fetch_verified_asset`: the same
    detached-Ed25519 path, against a publisher key the operator pins.  The key
    is either raw *pubkey* bytes or a *pubkey_path* to a file holding them (a
    feed ``key`` may be given as 64 hex characters or a path).  The sibling
    ``<asset_name>.sig`` must verify over the exact bytes before the payload is
    returned; an unsigned or mismatched asset is refused.
    """
    if offline():
        raise ReleaseFetchError(
            "federation fetches are disabled (TRUSTSIGHT_OFFLINE is set)")
    if pubkey is None and pubkey_path is None:
        raise ReleaseSignatureError(
            "no publisher key given to verify the federation asset against")
    base = base_url.rstrip("/")
    data = _download_url(f"{base}/{asset_name}")
    signature = _download_url(f"{base}/{asset_name}.sig", max_bytes=64 * 1024)
    if pubkey is None:
        try:
            pubkey = _load_trusted_pubkey(pubkey_path)
        except Exception as exc:
            raise ReleaseSignatureError(str(exc)) from exc
    if not verify_artifact(data, signature, pubkey):
        raise ReleaseSignatureError(
            f"{asset_name} failed Ed25519 verification against the publisher "
            "key; refused")
    return data