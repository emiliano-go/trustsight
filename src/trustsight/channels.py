"""Verified baseline and IOC pulls, shared by the CLI and the watcher.

``seed fetch``, ``corpus fetch``, ``ioc update`` and the watcher's
``--auto-pull-*`` options all do the same three things: download a signed
asset from a release channel (or a publisher's federation directory), verify
its detached ed25519 signature against the channel's pinned key, and import
the result.  This module is that path once, so an auto-pull from an unattended
watcher is byte-for-byte the same verified import an operator gets by hand -
never a second, weaker code path.

Nothing here draws anything or decides policy; the caller prints and records.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import shutil
import sys
import tempfile
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path

from . import channel_state, release

log = logging.getLogger(__name__)

#: A feed's ``asset``/``name`` becomes part of an asset name.
_ASSET_PREFIX_RE = re.compile(r"^[a-z0-9][a-z0-9.-]*$")

#: A tag becomes a URL path segment; refused unless it is a safe one.
_TAG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")

#: The seed asset pulled by ``--auto-pull-baselines`` and ``seed fetch``.
SEED_ASSET_NAME = "baseline-seed.tar.gz"

#: The corpus baseline asset.
CORPUS_ASSET_NAME = "baseline-corpus.tar.zst"

#: The imported watchlist release asset.
WATCHLIST_ASSET_NAME = "watchlist-official.json"

#: The signed inventory of a baseline release.  It binds each asset's name,
#: SHA-256 and size, plus the release version and expiry.
BASELINE_MANIFEST_ASSET = "baseline-manifest.json"

#: A progress factory: given a description, a context manager yielding an
#: ``on_progress(pos, total)`` callback.  The CLI passes a Rich factory; the
#: watcher passes nothing (no terminal to draw on).
ProgressFactory = Callable[[str], object]


def _manifest_expired(expires_at: str) -> bool:
    if not expires_at:
        return False
    try:
        moment = datetime.fromisoformat(expires_at)
    except (TypeError, ValueError):
        return False
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment < datetime.now(timezone.utc)


def _manifest_version(manifest: dict) -> int | None:
    value = manifest.get("version")
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise release.ReleaseManifestError(
            "the signed baseline manifest has a non-integer version"
        ) from exc


def fetch_baseline_manifest(
    channel: release.Channel,
    tag: str | None = None,
    pubkey_path: Path | None = None,
) -> dict | None:
    """Fetch and verify the signed baseline inventory, or ``None``.

    ``None`` means the release predates the inventory (or the channel does
    not carry one).  The download itself is still signature-checked; a
    malformed or mismatched inventory is a refusal, never a silent skip.
    """
    try:
        data = _verified_download(
            BASELINE_MANIFEST_ASSET, tag=tag, channel=channel,
            progress=None, pubkey_path=pubkey_path,
        )
    except release.ReleaseFetchError:
        return None
    try:
        manifest = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise release.ReleaseManifestError(
            f"the signed baseline manifest is not a JSON object: {exc}"
        ) from exc
    if not isinstance(manifest, dict):
        raise release.ReleaseManifestError(
            "the signed baseline manifest must be a JSON object"
        )
    return manifest


def check_baseline_manifest(manifest: dict) -> int | None:
    """Refuse an expired or replayed inventory; return its version.

    A manifest without a version (an older release) is accepted as unknown;
    the caller still verifies the asset hash, and the next versioned release
    becomes the floor.
    """
    expires_at = str(manifest.get("expires_at") or "")
    if _manifest_expired(expires_at):
        raise release.ReleaseExpiredError(
            f"the signed baseline expired at {expires_at}; refusing it"
        )
    version = _manifest_version(manifest)
    if version is not None:
        from .db import BASELINE_MANIFEST_VERSION_KEY, get_metadata

        stored = get_metadata(BASELINE_MANIFEST_VERSION_KEY)
        try:
            stored_version = int(stored) if stored is not None else None
        except (TypeError, ValueError):
            stored_version = None
        if stored_version is not None and version < stored_version:
            raise release.ReleaseRollbackError(
                f"the signed baseline is release {version}, older than the "
                f"imported {stored_version}; refusing a replay"
            )
    return version


def verify_manifest_asset(manifest: dict, asset_name: str, data: bytes) -> None:
    """Require *data* to match the signed inventory's entry for *asset_name*."""
    assets = manifest.get("assets")
    if not isinstance(assets, list):
        raise release.ReleaseManifestError(
            "the signed baseline manifest has no asset inventory"
        )
    entry = next(
        (item for item in assets
         if isinstance(item, dict) and item.get("name") == asset_name),
        None,
    )
    if entry is None:
        raise release.ReleaseManifestError(
            f"the signed baseline manifest does not list {asset_name}"
        )
    expected = str(entry.get("sha256") or "").lower()
    if expected and hashlib.sha256(data).hexdigest() != expected:
        raise release.ReleaseManifestError(
            f"{asset_name} does not match the signed manifest's SHA-256"
        )
    try:
        size = int(entry.get("size"))
    except (TypeError, ValueError):
        size = None
    if size is not None and size != len(data):
        raise release.ReleaseManifestError(
            f"{asset_name} does not match the signed manifest's size"
        )


def record_baseline_manifest_version(manifest: dict) -> None:
    """Record the accepted manifest version as the rollback floor."""
    version = _manifest_version(manifest)
    if version is None:
        return
    from .db import BASELINE_MANIFEST_VERSION_KEY, set_metadata

    set_metadata(BASELINE_MANIFEST_VERSION_KEY, str(version))


def channel_key_fingerprint(channel: release.Channel) -> str | None:
    """``sha256:<hex16>`` of a channel's raw pinned key, or ``None``.

    The key material itself is never logged or shown; the fingerprint is
    enough to tell two publishers apart, matching the convention in
    ``docs/reference/baseline-keys.md``.
    """
    try:
        if channel.key_bytes is not None:
            raw = channel.key_bytes
        elif channel.key_path is not None:
            from .bounded_io import read_file_capped
            raw = read_file_capped(Path(channel.key_path), 1024, "channel key")
        else:
            return None
    except OSError:
        return None
    if len(raw) != 32:
        return None
    return "sha256:" + hashlib.sha256(raw).hexdigest()[:16]


def non_official_warning(channel: release.Channel) -> str | None:
    """The stderr warning for a non-official channel, or ``None``.

    Following a channel other than the shipped one means trusting whoever
    publishes it; every import from one says so, once.
    """
    if channel.official:
        return None
    fingerprint = channel_key_fingerprint(channel)
    where = f" (key {fingerprint})" if fingerprint else ""
    return (
        f"trustsight: WARNING: importing from the non-official release channel "
        f"'{channel.label}'{where}. You are trusting that publisher; the "
        f"official channel is '{release.OFFICIAL_REPO}'."
    )


def publisher_warning(label: str) -> str:
    """The stderr warning for a non-official federation publisher."""
    return (
        f"trustsight: WARNING: importing IOCs from the non-official publisher "
        f"'{label}'. You are trusting that publisher; the official channel is "
        f"'{release.OFFICIAL_REPO}'."
    )


def _emit_warning(channel: release.Channel) -> None:
    message = non_official_warning(channel)
    if message:
        print(message, file=sys.stderr)


def _verified_download(asset_name: str, *, tag: str | None,
                       channel: release.Channel,
                       progress: ProgressFactory | None,
                       pubkey_path: Path | None = None) -> bytes:
    if progress is None:
        return release.fetch_verified_asset(
            asset_name, tag=tag, channel=channel, pubkey_path=pubkey_path
        )
    ctx = progress(f"Downloading {asset_name}...")
    with ctx as on_download:
        return release.fetch_verified_asset(
            asset_name, tag=tag, channel=channel, on_progress=on_download,
            pubkey_path=pubkey_path,
        )


def pull_baseline_seed(
    channel: release.Channel | None = None,
    tag: str | None = None,
    progress: ProgressFactory | None = None,
    pubkey_path: Path | None = None,
) -> dict:
    """Pull, verify and import the novelty seed, recording the pull.

    Raises a ``release.ReleaseError`` subclass on any refusal.  Returns the
    import stats plus ``tag``/``url``/``channel``.
    """
    from .db import import_seed

    channel = channel or release.active_baseline_channel()
    # Refuse a channel with no usable pinned key *before* any network I/O, so
    # an operator pointing at a channel without its key hears "pin the key",
    # not a confusing "no asset is reachable".  This is the same check the
    # signature step would run, only early.
    release._channel_pubkey(channel, pubkey_path)
    _emit_warning(channel)
    # The signed inventory binds the asset name, hash, size, version and
    # expiry.  A release that predates it is accepted as unknown; a release
    # that carries it must match, and an older version is refused.
    manifest = fetch_baseline_manifest(channel, tag=tag, pubkey_path=pubkey_path)
    if manifest is not None:
        check_baseline_manifest(manifest)
    data = _verified_download(
        SEED_ASSET_NAME, tag=tag, channel=channel, progress=progress,
        pubkey_path=pubkey_path,
    )
    if manifest is not None:
        verify_manifest_asset(manifest, SEED_ASSET_NAME, data)
    tmp_dir = Path(tempfile.mkdtemp(prefix="trustsight-seed-fetch-"))
    try:
        path = tmp_dir / SEED_ASSET_NAME
        path.write_bytes(data)
        stats = import_seed(path)
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)
    if manifest is not None:
        record_baseline_manifest_version(manifest)
    url = release.asset_url(SEED_ASSET_NAME, tag, channel)
    resolved = release.tag_from_asset_url(url)
    channel_state.record_pull(channel_state.BASELINE, resolved, channel.repo)
    return {"tag": resolved or tag or "latest", "url": url,
            "channel": channel.repo, **stats}


def pull_watchlist(
    channel: release.Channel | None = None,
    tag: str | None = None,
    progress: ProgressFactory | None = None,
    pubkey_path: Path | None = None,
) -> dict:
    """Pull, verify and import the signed watchlist release, recording the pull.

    The asset is a single JSON document (``watchlist-official.json``) whose
    detached ``.sig`` verifies against the channel's pinned key; it carries
    public package names plus salted maintainer hashes.  Raises a
    ``release.ReleaseError`` subclass on any refusal.  Returns the import
    stats plus ``tag``/``url``/``channel``.
    """
    import json

    from .watchlist import import_release

    channel = channel or release.active_baseline_channel()
    # Refuse a channel with no usable pinned key before any network I/O; see
    # pull_baseline_seed for the reasoning.
    release._channel_pubkey(channel, pubkey_path)
    _emit_warning(channel)
    data = _verified_download(
        WATCHLIST_ASSET_NAME, tag=tag, channel=channel, progress=progress,
        pubkey_path=pubkey_path,
    )
    try:
        document = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise release.ReleaseFetchError(
            f"the watchlist asset is not a JSON document: {exc}"
        ) from exc
    try:
        stats = import_release(document)
    except ValueError as exc:
        raise release.ReleaseFetchError(
            f"the watchlist asset is malformed: {exc}"
        ) from exc
    url = release.asset_url(WATCHLIST_ASSET_NAME, tag, channel)
    resolved = release.tag_from_asset_url(url)
    channel_state.record_pull(channel_state.WATCHLIST, resolved, channel.repo)
    return {"tag": resolved or tag or "latest", "url": url,
            "channel": channel.repo, **stats}


def _release_channel_feed(feed: dict, prefix: str,
                          progress: ProgressFactory | None) -> dict:
    """Update one feed from a followed release channel (the channel flow)."""
    from .ioc_baseline import (
        InvalidSignatureError,
        MalformedBaselineError,
        UnsignedBaselineError,
        import_baseline,
    )

    channel = release.channel_for_url(feed.get("url") or "")
    assert channel is not None  # caller checked
    # Refuse a channel with no usable pinned key before any download; see
    # pull_baseline_seed for the reasoning.
    release._channel_pubkey(channel, None)
    # Every import from a non-official channel says so, before anything is
    # downloaded or imported.
    _emit_warning(channel)
    tag_value = feed.get("tag")
    tag = str(tag_value).strip() if tag_value is not None else ""
    if tag and not _TAG_RE.match(tag):
        return {"status": "error",
                "error": f"invalid release tag {tag!r}; use [A-Za-z0-9._-]"}
    tag = tag or None
    manifest_asset = f"baseline-ioc-{prefix}-manifest.json"
    iocs_asset = f"baseline-ioc-{prefix}-iocs.jsonl"
    tmp_dir = Path(tempfile.mkdtemp(prefix="trustsight-ioc-fetch-"))
    try:
        (tmp_dir / "manifest.json").write_bytes(
            _verified_download(manifest_asset, tag=tag, channel=channel,
                               progress=progress)
        )
        (tmp_dir / "iocs.jsonl").write_bytes(
            _verified_download(iocs_asset, tag=tag, channel=channel,
                               progress=progress)
        )
        result = import_baseline(tmp_dir, source_name=feed.get("name") or "",
                                 trust_manifest_key=True)
        url = release.asset_url(manifest_asset, tag, channel)
        channel_state.record_pull(
            channel_state.IOC, release.tag_from_asset_url(url), channel.repo
        )
        return {"status": "ok", "url": url, "channel": channel.repo, **result}
    except (release.ReleaseError, UnsignedBaselineError, InvalidSignatureError,
            MalformedBaselineError, FileNotFoundError) as exc:
        return {"status": "error", "error": str(exc)}
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def _federation_feed(feed: dict, url: str,
                     progress: ProgressFactory | None) -> dict:
    """Update one feed from a publisher's signed directory (federation)."""
    from .ioc_baseline import (
        InvalidSignatureError,
        MalformedBaselineError,
        UnsignedBaselineError,
        import_baseline,
    )

    key_value = str(feed.get("key") or "").strip()
    if not key_value:
        return {
            "status": "error",
            "error": (
                "a non-release feed URL needs a pinned publisher key: set "
                "`key` to the publisher's ed25519 public key"
            ),
        }
    # A feed `key` is 64 hex characters or a path to a raw key file, the same
    # as a channel `[release] key`; `_parse_pinned_key` tells the two apart.
    key_path, key_bytes = release._parse_pinned_key(key_value)
    label = url.rstrip("/")
    print(publisher_warning(label), file=sys.stderr)
    tmp_dir = Path(tempfile.mkdtemp(prefix="trustsight-ioc-federation-"))
    try:
        # fetch_verified_url has no progress hook; the federation directory is
        # small (a manifest plus an indicator list), so a bar is not missed.
        for asset in ("manifest.json", "iocs.jsonl"):
            (tmp_dir / asset).write_bytes(
                release.fetch_verified_url(url, asset, pubkey_path=key_path,
                                           pubkey=key_bytes)
            )
        result = import_baseline(tmp_dir, source_name=label,
                                 trust_manifest_key=True)
        return {"status": "ok", "url": label, **result}
    except (release.ReleaseError, UnsignedBaselineError, InvalidSignatureError,
            MalformedBaselineError, FileNotFoundError) as exc:
        return {"status": "error", "error": str(exc)}
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def pull_ioc_feed(feed: dict, progress: ProgressFactory | None = None) -> dict:
    """Pull, verify and import one configured IOC feed.

    Two shapes are accepted:

    * a followed release channel (the official one, or the configured
      ``[release] channel``), whose ``baseline-ioc-<prefix>-*`` pair is
      resolved from the newest ``ioc-*`` release; and
    * any other ``http(s)`` URL, treated as a publisher's federation directory
      (``manifest.json`` + ``iocs.jsonl``) whose detached signatures must
      verify against the feed's own pinned ``key``.

    A refusal is returned as ``{"status": "error", ...}``; nothing raises.
    """
    name = feed.get("name") or ""
    url = feed.get("url") or ""
    prefix = feed.get("asset") or name

    result: dict
    if release.channel_for_url(url) is not None:
        if not prefix or not _ASSET_PREFIX_RE.match(prefix):
            return {"status": "error",
                    "error": f"invalid asset prefix {prefix!r}; use [a-z0-9.-]"}
        result = _release_channel_feed(feed, prefix, progress)
    elif url.startswith("https://") or url.startswith("http://"):
        result = _federation_feed(feed, url, progress)
    else:
        result = {
            "status": "error",
            "error": (
                "unsupported feed URL; use a followed release channel or an "
                "https:// publisher directory (use 'ioc import <dir>' for "
                "local baselines)"
            ),
        }
    return {"feed": name, **result}


def enabled_feeds() -> list[dict]:
    """The operator's enabled IOC feeds, from ``[baselines.ioc]``."""
    from .config import load_config

    try:
        section = load_config().get("baselines", {}).get("ioc", {})
    except Exception:  # noqa: BLE001 - an unreadable config means no feeds
        return []
    if not bool(section.get("enabled", True)):
        return []
    feeds = section.get("feeds", [])
    return [f for f in feeds if isinstance(f, dict) and f.get("enabled", True)]


def auto_pull(*, baselines: bool = False, iocs: bool = False,
              watchlists: bool = False) -> list[str]:
    """Pull a newer baseline seed, IOC feeds and/or watchlist, once each.

    Called by the watcher after every cycle.  Only pulls when the channel
    offers a tag the operator has not already pulled (recorded in
    :mod:`trustsight.channel_state`), so a quiet cycle costs one metadata
    query, not a re-download.  Returns human-readable summary lines; it never
    raises, because a failed data pull must not kill the watch.
    """
    notes: list[str] = []
    if not (baselines or iocs or watchlists):
        return notes
    # A watcher process runs for weeks; the per-process tag cache would pin it
    # to the first tag it ever saw.  Re-query every cycle.
    release.clear_tag_cache()
    if baselines:
        try:
            channel = release.active_baseline_channel()
            newest = release.resolve_baseline_tag(channel)
            if newest and newest != channel_state.pulled_tag(channel_state.BASELINE):
                stats = pull_baseline_seed(channel=channel)
                notes.append(
                    f"baseline seed pulled: {stats['tag']} ({stats['channel']})"
                )
        except Exception as exc:  # noqa: BLE001 - never kill the watch
            notes.append(f"baseline auto-pull skipped: {exc}")
    if iocs:
        try:
            newest = release.resolve_ioc_tag()
        except Exception as exc:  # noqa: BLE001
            newest = None
            notes.append(f"ioc auto-pull skipped: {exc}")
        if newest and newest != channel_state.pulled_tag(channel_state.IOC):
            for feed in enabled_feeds():
                name = feed.get("name") or "(unnamed)"
                result = pull_ioc_feed(feed)
                if result.get("status") == "ok":
                    notes.append(
                        f"iocs pulled for {name}: "
                        f"{result.get('entries_imported', 0)} entries"
                    )
                else:
                    notes.append(
                        f"iocs auto-pull skipped for {name}: {result.get('error')}"
                    )
    if watchlists:
        try:
            channel = release.active_baseline_channel()
            newest = release.resolve_watchlist_tag(channel)
            if newest and newest != channel_state.pulled_tag(
                    channel_state.WATCHLIST):
                stats = pull_watchlist(channel=channel)
                notes.append(
                    f"watchlist pulled: {stats['tag']} "
                    f"({stats['packages_imported']} packages)"
                )
        except Exception as exc:  # noqa: BLE001 - never kill the watch
            notes.append(f"watchlist auto-pull skipped: {exc}")
    return notes
