"""Extracted from manifests.py: _parse."""

from __future__ import annotations
import json
import tomllib
from ..manifest_syntax import (
    ManifestSyntaxError,
)
from ._common import MAX_MANIFEST_BYTES, ManifestDoc, manifest_format
from ._formats_d import _text_parser_for

__all__ = ['parse_manifest_local']

def parse_manifest_local(path: str, text: str) -> ManifestDoc | None:
    """Parse *path*'s committed bytes into a :class:`ManifestDoc`.

    Returns None when *path* is not a manifest.  A malformed or oversized
    manifest returns a doc with ``dependencies=()`` and a named ``unresolved``
    entry, never raising and never silently skipping.
    """
    fmt = manifest_format(path)
    if fmt is None:
        return None
    if len(text.encode("utf-8", "replace")) > MAX_MANIFEST_BYTES:
        return ManifestDoc(path, fmt, unresolved=("over the byte cap",))
    if text.startswith("\ufeff"):  # a BOM would break tomllib/json
        text = text.lstrip("\ufeff")
    parser = _text_parser_for(path, text)
    try:
        doc = parser(text)
    except (tomllib.TOMLDecodeError, json.JSONDecodeError, ValueError,
            ManifestSyntaxError, TypeError, KeyError, AttributeError,
            IndexError, RecursionError, OverflowError, MemoryError) as exc:
        return ManifestDoc(path, fmt, unresolved=(f"malformed: {type(exc).__name__}",))
    if doc is None:
        return ManifestDoc(path, fmt, unresolved=("unparsed",))
    doc.path = path
    return doc
