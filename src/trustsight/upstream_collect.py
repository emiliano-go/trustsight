"""Collect upstream manifests for the opt-in scan lane.

The AUR snapshot only carries files committed beside the recipe, so the U-series
is blind to the manifests inside the declared source archive.  This module
closes that gap for the server-side watcher:

* it reads the recipe's ``source=()`` and the strongest checksum per entry;
* for an allowlisted forge entry with a strong checksum it fetches the archive
  through the bounded transport, verifies the checksum, and extracts the
  manifests in the sandboxed manifest worker;
* it returns ``(f"upstream/{path}", text)`` pairs the caller merges into
  ``manifest_texts``, so the existing U-series state/delta path does the rest.

It is off unless ``[upstream_scan] enabled`` and never runs on the local
default analysis path.  A refusal is returned as a note, not hidden.
"""

from __future__ import annotations

import re

from .upstream_scan import (
    UpstreamScanError,
    choose_fetch_mode,
    checksum_bits,
    configured_hosts,
    verify_archive_checksum,
)
from .upstream_fetch import UpstreamFetchError, fetch_bytes

__all__ = ["collect_upstream_manifest_texts"]

_MAX_ARCHIVES = 4
#: The sandboxed worker accepts at most this many base64 bytes in one frame.
_MAX_ARCHIVE_BYTES = 16 * 1024 * 1024

_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")

#: Strongest first.
_CHECKSUM_ARRAYS = (
    ("b2sums", "b2"),
    ("sha512sums", "sha512"),
    ("sha256sums", "sha256"),
    ("sha1sums", "sha1"),
    ("md5sums", "md5"),
)

_PROVIDER_BY_HOST = {
    "github.com": "github",
    "gitlab.com": "gitlab",
    "codeberg.org": "codeberg",
    "bitbucket.org": "bitbucket",
}


def _checksum_for(recipe, index: int):
    for name, algorithm in _CHECKSUM_ARRAYS:
        values = recipe.arrays.get(name) or ()
        if index >= len(values):
            continue
        value = str(values[index]).strip().lower()
        if value and value not in ("skip", "none") and _HEX_RE.match(value):
            return name, algorithm, value
    return None


def _token_for(host: str):
    provider = _PROVIDER_BY_HOST.get(host)
    if not provider:
        return None
    try:
        from .credentials import CredentialError, resolve_token

        return resolve_token(provider)
    except CredentialError:
        return None


def collect_upstream_manifest_texts(
    recipe_text: str,
    *,
    config: dict | None = None,
    fetcher=None,
    extractor=None,
) -> tuple[list[tuple[str, str]], list[str]]:
    """Return upstream manifest texts and any refusal notes.

    *fetcher* and *extractor* are injectable for tests; the defaults are the
    real bounded transport and the sandboxed archive worker.
    """
    if not recipe_text:
        return [], []
    if config is None:
        from .config import load_config

        config = load_config()
    section = (config or {}).get("upstream_scan") if isinstance(config, dict) else None
    if not isinstance(section, dict) or not section.get("enabled", False):
        return [], []

    from .expansion import resolve_text
    from .recipedoc import parse_recipe
    from .sandbox import manifest_client

    try:
        recipe = parse_recipe(recipe_text)
    except Exception:  # noqa: BLE001 - an unparsable recipe yields no upstream reads
        return [], ["upstream_scan_recipe_unparsed"]

    allowed = configured_hosts(config)
    texts: list[tuple[str, str]] = []
    notes: list[str] = []
    seen = 0
    for index, entry in enumerate(recipe.arrays.get("source") or ()):
        if seen >= _MAX_ARCHIVES:
            break
        raw = str(entry)
        url = _resolve(raw, recipe, resolve_text)
        if not url.lower().startswith("https://"):
            continue
        if url.lower().endswith((".sig", ".asc", ".sign")):
            continue
        checksum = _checksum_for(recipe, index)
        if checksum is None:
            continue
        name, algorithm, expected = checksum
        try:
            from .upstream_scan import parse_forge_target

            target = parse_forge_target(url, allowed_hosts=allowed)
        except UpstreamScanError:
            continue
        mode = choose_fetch_mode(
            config,
            declared_checksum_bits=checksum_bits(name),
            archive_on_allowlisted_host=True,
        )
        if mode.mode != "archive":
            continue
        minimum = int(section.get("min_checksum_bits", 256) or 256)
        deadline = float(section.get("deadline_seconds", 120) or 120)
        try:
            if fetcher is None:
                data = fetch_bytes(
                    url, allowed_hosts=allowed, token=_token_for(target.host),
                    max_bytes=_MAX_ARCHIVE_BYTES, deadline_seconds=deadline)
            else:
                data = fetcher(url, target)
        except (UpstreamFetchError, UpstreamScanError):
            notes.append("upstream_scan_refused")
            continue
        if not verify_archive_checksum(
                data, expected, algorithm=algorithm, min_bits=minimum):
            notes.append("upstream_scan_checksum")
            continue
        try:
            if extractor is None:
                parsed = manifest_client.parse_upstream_archive(
                    target.slug, data)
            else:
                parsed = extractor(target.slug, data)
        except Exception:  # noqa: BLE001 - a sandbox refusal is a boundary
            notes.append("upstream_scan_refused")
            continue
        if parsed.get("refused") or parsed.get("malformed"):
            notes.append("upstream_scan_partial")
        for path, text in parsed.get("manifest_texts") or ():
            texts.append((f"upstream/{path}", text))
        seen += 1
    return texts, sorted(set(notes))


def _resolve(raw: str, recipe, resolve_text) -> str:
    target = raw.split("::", 1)[-1]
    if "$" not in target:
        return target
    try:
        return resolve_text(target, recipe.scalars)
    except Exception:  # noqa: BLE001 - an unresolved entry stays literal
        return target
