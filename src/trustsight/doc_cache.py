"""Spec §4: the document cache - re-scoring without re-parsing.

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
from pathlib import Path

from .diffdoc import DiffDoc, parse_diff
from .recipedoc import RecipeDoc, parse_recipe

#: Environment override for the cache directory; tests point it at a tmpdir.
CACHE_ENV = "TRUSTSIGHT_DOC_CACHE"


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
    try:
        return loader(json.loads(path.read_text(encoding="utf-8")))
    except (OSError, ValueError):
        return None


def _store(path: Path, payload: dict) -> None:
    """Best-effort atomic write; a read-only cache is still a valid cache."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(path.name + ".tmp")
        tmp.write_text(
            json.dumps(payload, separators=(",", ":")), encoding="utf-8"
        )
        os.replace(tmp, path)
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
