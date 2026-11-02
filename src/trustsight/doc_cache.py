"""The document cache - re-scoring without re-parsing.

A :class:`~trustsight.diffdoc.DiffDoc` (and a :class:`RecipeDoc` parsed
from text) serializes to versioned JSON keyed by the text's content hash.
The cache is an optimization, never an authority: a miss, a parser or
tokenizer change, or a malformed entry falls back to a fresh parse, and
the finding replay gate runs exactly as it does without the cache.

Storage is plain files under ``$TRUSTSIGHT_DOC_CACHE`` (default
``$XDG_CACHE_HOME/trustsight/documents``).  JSON only - never pickle: the
document is attacker-derived and a deserialising cache that executes is
the boundary violation the tokenizer sandbox exists to avoid.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path

from .bounded_io import ReadTooLarge, read_file_capped
from .diffdoc import DiffDoc, parse_diff
from .recipedoc import RecipeDoc, parse_recipe

#: Environment override for the cache directory; tests point it at a tmpdir.
CACHE_ENV = "TRUSTSIGHT_DOC_CACHE"

#: A4/A14: a cache entry is a local file derived from attacker text, and the
#: read path must not be the one place that materialises a file without a
#: ceiling.  This bounds the stored JSON, not the objects it parses into; the
#: cache is an optimization, so a document over the cap is simply re-parsed
#: and not stored.  16 MiB is well above the largest entry in the locked
#: benign corpus (about 2 MiB).
MAX_DOC_CACHE_BYTES = 16 * 1024 * 1024


def cache_dir() -> Path:
    """Where documents are cached, without creating anything."""
    env = os.environ.get(CACHE_ENV)
    if env:
        return Path(env)
    base = os.environ.get("XDG_CACHE_HOME") or (Path.home() / ".cache")
    return Path(base) / "trustsight" / "documents"


def document_key(*parts: object) -> str:
    """A content hash over the text (and any provenance that shaped spans)."""
    digest = hashlib.sha256()
    for part in parts:
        digest.update(repr(part).encode("utf-8", "replace"))
        digest.update(b"\x00")
    return digest.hexdigest()


def _load(path: Path, loader):
    """Read a cache entry, or return ``None`` for any reason to re-parse.

    The read is capped before ``json.loads``: an oversized, truncated or
    corrupt entry must be a miss, never the input that decides how much this
    process allocates.  ``RecursionError`` is a miss too - deeply nested JSON
    is exactly the malformed entry the cache must not turn into a crash.
    """
    try:
        if path.is_symlink():
            return None
        raw = read_file_capped(
            path, MAX_DOC_CACHE_BYTES, "document cache entry")
        return loader(json.loads(raw.decode("utf-8")))
    except (OSError, ValueError, ReadTooLarge, RecursionError):
        return None


def _store(path: Path, payload: dict) -> None:
    """Best-effort atomic write; a read-only cache is still a valid cache.

    Encoding is incremental so a payload over ``MAX_DOC_CACHE_BYTES`` is
    abandoned at the cap instead of being materialised and then rejected.
    Nothing is written in that case: an oversized entry would only be refused
    on the next read anyway.
    """
    try:
        # ``ensure_ascii`` keeps every encoded character one byte, so the
        # running character count is the byte count and the cap can be
        # applied before a chunk is encoded.
        encoder = json.JSONEncoder(separators=(",", ":"), ensure_ascii=True)
        encoded = bytearray()
        for chunk in encoder.iterencode(payload):
            if len(encoded) + len(chunk) > MAX_DOC_CACHE_BYTES:
                return
            encoded.extend(chunk.encode("utf-8"))
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(path.parent, 0o700)
        fd, tmp_name = tempfile.mkstemp(
            prefix=path.name + ".", suffix=".tmp", dir=str(path.parent))
        tmp = Path(tmp_name)
        try:
            os.chmod(tmp, 0o600)
            with os.fdopen(fd, "wb") as handle:
                handle.write(encoded)
            os.replace(tmp, path)
            os.chmod(path, 0o600)
        finally:
            tmp.unlink(missing_ok=True)
    except OSError:
        pass


def parse_diff_cached(diff_text: str, directory: Path | None = None) -> DiffDoc:
    """The parsed diff, from cache when a valid entry exists."""
    root = directory or cache_dir()
    path = root / f"diff-{document_key(diff_text)}.json"
    cached = _load(path, DiffDoc.from_dict)
    if cached is not None:
        return cached
    doc = parse_diff(diff_text)
    _store(path, doc.to_dict())
    return doc


def parse_recipe_cached(
    text: str,
    file: str = "",
    origins: list[tuple[str, int, str]] | None = None,
    directory: Path | None = None,
) -> RecipeDoc:
    """The parsed recipe, from cache when a valid entry exists.

    Origins shape only the spans, so they are part of the key: the same
    text read from two diff projections is two documents.
    """
    root = directory or cache_dir()
    path = root / f"recipe-{document_key(text, file, origins)}.json"
    cached = _load(path, RecipeDoc.from_dict)
    if cached is not None:
        return cached
    recipe = parse_recipe(text, file=file, origins=origins)
    _store(path, recipe.to_dict())
    return recipe
