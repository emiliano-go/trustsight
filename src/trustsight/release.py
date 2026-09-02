"""The release channel: verified downloads of ``baseline-*`` release assets.

Baselines (the novelty seed, IOC federation baselines, the corpus baseline)
are distributed as signed release assets in the TrustSight repository,
named with the ``baseline-`` prefix.  This module is the only place in the
program that talks to the release host.  A download is bounded, carries an
explicit timeout, and is accepted only when its detached Ed25519 signature
verifies against the pinned distribution key.  Anything that fails any of
those checks is refused; there is no fallback that accepts an unverified
download.

Security model note: the release host (github.com) is the second declared
endpoint of the program, beside the AUR.  It is confined to this module by
``scripts/security_gates.py``, it is reached only by explicit commands
(``seed fetch``, ``ioc update``, first-run auto-import) and never during
analysis, and its payloads are signature-checked before they are read.
"""

from __future__ import annotations

import json
import logging
import os
import urllib.request
from pathlib import Path

from .full_aur.export import _load_trusted_pubkey, verify_artifact

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# The declared endpoint
# ---------------------------------------------------------------------------

#: The one release endpoint the program is allowed to reach.  ``latest``
#: follows GitHub's redirect to the newest release; a tag pins the exact
#: release an operator asked for.
RELEASE_BASE_URL = "https://github.com/emiliano-go/trustsight/releases"

#: Every outbound request carries an explicit timeout (security gate A4).
_REQUEST_TIMEOUT_SECONDS = 60

#: A release asset is never read past this bound (security gate A5-style
#: bound on hostile input; the corpus baseline is the largest asset).
_MAX_RELEASE_BYTES = 512 * 1024 * 1024

#: The pinned distribution key ships inside the package.
PINNED_PUBKEY_PATH = Path(__file__).parent / "full_aur" / "baseline_pubkey.pem"


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
        url = (
            "https://api.github.com/repos/emiliano-go/trustsight/releases"
            "?per_page=30"
        )
        req = urllib.request.Request(
            url, headers={"Accept": "application/vnd.github+json"}
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            releases = json.loads(resp.read())
        for release in releases:
            tag = release.get("tag_name", "")
            if tag.startswith("baseline-") and release.get("assets"):
                _BASELINE_TAG_CACHE = tag
                return tag
    except Exception:
        pass
    return None


def asset_url(asset_name: str, tag: str | None = None) -> str:
    """Return the download URL for *asset_name*.

    Without *tag* the ``latest`` release is used; GitHub redirects to the
    newest tag.  For ``baseline-*`` assets, the most recent ``baseline-*``
    release is discovered automatically.  With *tag* the download is pinned
    to that exact release.
    """
    if tag:
        return f"{RELEASE_BASE_URL}/download/{tag}/{asset_name}"
    if asset_name.startswith("baseline-"):
        baseline_tag = _resolve_baseline_tag()
        if baseline_tag:
            return f"{RELEASE_BASE_URL}/download/{baseline_tag}/{asset_name}"
    return f"{RELEASE_BASE_URL}/latest/download/{asset_name}"


def download_asset(
    asset_name: str,
    tag: str | None = None,
    max_bytes: int = _MAX_RELEASE_BYTES,
) -> bytes:
    """Download *asset_name* from the release channel, bounded.

    Raises ``ReleaseFetchError`` on any transport failure and
    ``ReleaseTooLargeError`` when the asset exceeds *max_bytes*.
    """
    if offline():
        raise ReleaseFetchError(
            "the release channel is disabled (TRUSTSIGHT_OFFLINE is set); "
            "no download attempted"
        )
    url = asset_url(asset_name, tag)
    try:
        with urllib.request.urlopen(url, timeout=_REQUEST_TIMEOUT_SECONDS) as resp:
            body = bytearray()
            while True:
                chunk = resp.read(max_bytes + 1 - len(body))
                if not chunk:
                    break
                body.extend(chunk)
                if len(body) > max_bytes:
                    raise ReleaseTooLargeError(
                        f"{asset_name} exceeded the {max_bytes} byte download bound"
                    )
            return bytes(body)
    except ReleaseTooLargeError:
        raise
    except Exception as exc:
        raise ReleaseFetchError(f"could not download {asset_name}: {exc}") from exc


def fetch_verified_asset(
    asset_name: str,
    tag: str | None = None,
    pubkey_path: Path | None = None,
    max_bytes: int = _MAX_RELEASE_BYTES,
) -> bytes:
    """Download *asset_name* and refuse it unless its signature verifies.

    The sibling ``<asset_name>.sig`` carries the raw 64-byte Ed25519
    detached signature over the exact asset bytes.  The signature is
    checked against the pinned distribution key before anything else sees
    the payload; a mismatch raises ``ReleaseSignatureError``.
    """
    pubkey_path = pubkey_path or PINNED_PUBKEY_PATH
    data = download_asset(asset_name, tag=tag, max_bytes=max_bytes)
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