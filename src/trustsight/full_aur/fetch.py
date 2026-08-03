"""PKGBUILD fetcher via cgit with snapshot fallback."""

import json
import logging
import tarfile
import urllib.request
import urllib.error
from io import BytesIO
from pathlib import Path
from typing import Optional

log = logging.getLogger(__name__)

_CGIT_URL = "https://aur.archlinux.org/cgit/aur.git/plain/PKGBUILD"
_CGIT_SRCINFO_URL = "https://aur.archlinux.org/cgit/aur.git/plain/.SRCINFO"
_SNAPSHOT_URL = "https://aur.archlinux.org/cgit/aur.git/snapshot"
_RESUME_FILE = "full-aur-resume.json"

_HTTP_TIMEOUT = 60
_REQUEST_DELAY = 0.05  # 50ms between requests to stay polite


def _http_get(url: str) -> Optional[bytes]:
    """Perform a GET request with a polite User-Agent."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "trustsight/1.0"})
        resp = urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT)
        return resp.read()
    except urllib.error.HTTPError as e:
        log.warning("HTTP %d fetching %s", e.code, url)
        return None
    except urllib.error.URLError as e:
        log.warning("URL error fetching %s: %s", url, e.reason)
        return None
    except Exception as e:
        log.warning("unexpected error fetching %s: %s", url, e)
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
    url = f"{_CGIT_URL}?h={name}"
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
    url = f"{_CGIT_SRCINFO_URL}?h={name}"
    body = _http_get(url)
    if body is not None and not _is_anubis_challenge(body):
        return body.decode("utf-8", errors="replace")
    return None


def _pkgbuild_from_tarfile(tf: tarfile.TarFile, name: str) -> Optional[str]:
    """Extract the PKGBUILD text from an open snapshot tarball."""
    pkgbuild_path = f"{name}/PKGBUILD"
    try:
        member = tf.getmember(pkgbuild_path)
    except KeyError:
        # some packages use a different internal directory name
        for m in tf.getmembers():
            if m.name.endswith("/PKGBUILD"):
                member = m
                break
        else:
            log.warning("no PKGBUILD found in snapshot for %s", name)
            return None
    content = tf.extractfile(member)
    if content is None:
        return None
    return content.read().decode("utf-8", errors="replace")


def _pkgbuild_from_snapshot(name: str) -> Optional[str]:
    """Download the snapshot tarball and extract PKGBUILD."""
    url = f"{_SNAPSHOT_URL}/{name}.tar.gz"
    body = _http_get(url)
    if body is None:
        return None

    try:
        tf = tarfile.open(fileobj=BytesIO(body), mode="r:gz")
        return _pkgbuild_from_tarfile(tf, name)
    except Exception as e:
        log.warning("error extracting snapshot for %s: %s", name, e)
        return None


def _snapshot_manifest(tf: tarfile.TarFile, max_members: int = 10_000) -> list[tuple[str, bytes]]:
    """``(member_path, first_bytes)`` for each regular file in the tarball.

    The AUR snapshot tarball comes from the AUR mirror, never from a
    PKGBUILD-declared ``source=`` URL, so reading it keeps the review path's
    "no network, no execution" claim intact.  Only the head of each member
    is read: R118 needs the magic bytes, not the whole file.
    """
    manifest: list[tuple[str, bytes]] = []
    for member in tf.getmembers():
        if len(manifest) >= max_members:
            break
        if not member.isfile():
            continue
        try:
            f = tf.extractfile(member)
        except (tarfile.TarError, OSError):
            continue
        if f is None:
            continue
        head = f.read(64)
        manifest.append((member.name, head))
    return manifest


def fetch_pkgbuild_with_tree(name: str) -> tuple[Optional[str], Optional[list[tuple[str, bytes]]]]:
    """PKGBUILD text plus the snapshot tree manifest when available.

    Downloads the AUR snapshot tarball directly so the corpus path sees the
    same committed file tree the git path does (R118-tree).  The tarball is
    fetched from the AUR mirror - never from a PKGBUILD-declared URL - so
    this is consistent with the "static, offline" review claim.  Falls back
    to the cgit text-only fetch when the tarball cannot be read.
    """
    url = f"{_SNAPSHOT_URL}/{name}.tar.gz"
    body = _http_get(url)
    if body is not None:
        try:
            tf = tarfile.open(fileobj=BytesIO(body), mode="r:gz")
            pkgbuild = _pkgbuild_from_tarfile(tf, name)
            manifest = _snapshot_manifest(tf)
            if pkgbuild is not None:
                return pkgbuild, manifest
        except Exception as e:
            log.warning("snapshot tarball for %s unusable: %s", name, e)
    return fetch_pkgbuild(name), None


def save_resume_state(state: dict, path: Path = Path(_RESUME_FILE)) -> None:
    """Persist bootstrap progress so it can be resumed."""
    path.write_text(json.dumps(state, separators=(",", ":")))


def load_resume_state(path: Path = Path(_RESUME_FILE)) -> Optional[dict]:
    """Load saved bootstrap progress."""
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return None


def clear_resume_state(path: Path = Path(_RESUME_FILE)) -> None:
    """Remove the resume file after successful completion."""
    if path.exists():
        path.unlink()
