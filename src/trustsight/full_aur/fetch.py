"""PKGBUILD fetcher via cgit with snapshot fallback."""

import json
import logging
import tarfile
import urllib.request
import urllib.error
from urllib.parse import quote
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


def _http_get(url: str) -> Optional[bytes]:
    """Perform a GET request with a polite User-Agent.

    The body is read in chunks and abandoned past ``MAX_RESPONSE_BYTES``.
    """
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "trustsight/1.0"})
        resp = urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT)
        buf = bytearray()
        while True:
            chunk = resp.read(65536)
            if not chunk:
                break
            buf.extend(chunk)
            if len(buf) > MAX_RESPONSE_BYTES:
                log.warning(
                    "response from %s exceeds %d bytes; abandoning",
                    url, MAX_RESPONSE_BYTES,
                )
                return None
        return bytes(buf)
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
    pkgbuild_path = f"{name}/PKGBUILD"
    member = None
    # Walked lazily and bounded: a snapshot holds a handful of files, and a
    # tar that says otherwise is not one worth reading to the end.
    for seen, m in enumerate(tf):
        if seen >= MAX_TAR_MEMBERS:
            break
        if m.name == pkgbuild_path:
            member = m
            break
        if member is None and m.name.endswith("/PKGBUILD"):
            member = m  # different internal directory name; keep looking
    if member is None:
        log.warning("no PKGBUILD found in snapshot for %s", name)
        return None
    content = tf.extractfile(member)
    if content is None:
        return None
    return content.read().decode("utf-8", errors="replace")


def _pkgbuild_from_snapshot(name: str) -> Optional[str]:
    """Download the snapshot tarball and extract PKGBUILD."""
    url = f"{_SNAPSHOT_URL}/{quote(name, safe='')}.tar.gz"
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
    for member in tf:  # lazy: getmembers() would parse the whole archive
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
    url = f"{_SNAPSHOT_URL}/{quote(name, safe='')}.tar.gz"
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
        return json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return None


def clear_resume_state(path: Path | None = None) -> None:
    """Remove the resume file after successful completion."""
    path = path or default_resume_path()
    if path.exists():
        path.unlink()
