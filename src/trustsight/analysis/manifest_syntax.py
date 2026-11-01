"""Hardened syntax loaders for committed dependency manifests.

Every byte here is package-controlled: a manifest is written by whoever
controls the repository, and the adversary assumption is that they know this
source.  The tokenizer and the manifest byte cap already bound the pipeline,
but a parser is a second, independent attack surface: YAML aliases can build
cycles, XML can carry entity bombs, JSONC hides comments, INI can use
interpolation.  This module is the one place each syntax is loaded, so the
hardening is written once and gated.

Rules, all of them fail-closed:

* **Byte cap first.**  Nothing is handed to a third-party loader before its
  encoded size is checked against ``MAX_MANIFEST_BYTES``.
* **Safe loaders only.**  ``yaml.safe_load`` (never ``load``/``full_load``/
  ``unsafe_load``/custom ``Loader``); ``json``; ``tomllib``; ``ElementTree``
  with entity declarations refused before parsing; ``configparser`` with
  interpolation disabled.
* **Bounded, cycle-safe traversal.**  ``deep_items`` walks a loaded document
  with a depth ceiling and an identity set, so a self-referential YAML anchor
  cannot spin a reader forever, and a billion-laughs shape cannot fan out.
* **Refuse, never raise past us.**  Callers still wrap for format errors; the
  loaders themselves raise only ``ManifestSyntaxError``, which the manifest
  layer turns into a named :class:`ManifestDoc.unresolved` boundary.
"""

from __future__ import annotations

import configparser
import json
import re
import tomllib
import xml.etree.ElementTree as ET

__all__ = [
    "ManifestSyntaxError",
    "MAX_MANIFEST_BYTES",
    "MAX_WALK_DEPTH",
    "deep_items",
    "load_ini",
    "load_json",
    "load_jsonc",
    "load_toml",
    "load_xml",
    "load_yaml",
    "strip_jsonc",
]

#: The existing per-file manifest cap (``manifests.MAX_MANIFEST_BYTES``);
#: repeated here so the syntax layer refuses on the same bound without
#: importing the parser module back.
MAX_MANIFEST_BYTES = 512 * 1024

#: Depth ceiling for ``deep_items``.  A real manifest nests a handful of
#: levels; 64 is generous and still bounds a crafted deep document.
MAX_WALK_DEPTH = 64

#: A DOCTYPE is allowed (Maven POMs carry one), an entity declaration is not:
#: ``<!ENTITY`` is the billion-laughs primitive, and refusing it up front is
#: independent of the expat version bundled with the interpreter.
_XML_ENTITY_RE = re.compile(r"<!\s*ENTITY\b", re.IGNORECASE)


class ManifestSyntaxError(Exception):
    """A manifest could not be loaded safely.  Never escapes the layer."""


def _bounded(text: str) -> str:
    if not isinstance(text, str):
        raise ManifestSyntaxError("not text")
    if len(text.encode("utf-8", "replace")) > MAX_MANIFEST_BYTES:
        raise ManifestSyntaxError("over the byte cap")
    if text.startswith("\ufeff"):
        text = text.lstrip("\ufeff")
    return text


def load_toml(text: str) -> dict:
    data = tomllib.loads(_bounded(text))
    if not isinstance(data, dict):
        raise ManifestSyntaxError("toml is not a table")
    return data


def load_json(text: str) -> object:
    try:
        return json.loads(_bounded(text))
    except RecursionError as exc:
        raise ManifestSyntaxError("json too deep") from exc
    except json.JSONDecodeError as exc:
        raise ManifestSyntaxError("malformed json") from exc


def strip_jsonc(text: str) -> str:
    """Remove ``//`` and ``/* */`` comments outside strings (JSONC/JSON5)."""
    out: list[str] = []
    i, n = 0, len(text)
    in_string = False
    while i < n:
        ch = text[i]
        if in_string:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if ch == '"':
                in_string = False
            i += 1
            continue
        if ch == '"':
            in_string = True
            out.append(ch)
            i += 1
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "/":
            i = text.find("\n", i)
            if i == -1:
                break
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "*":
            end = text.find("*/", i + 2)
            if end == -1:
                raise ManifestSyntaxError("unterminated comment")
            i = end + 2
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def load_jsonc(text: str) -> object:
    return load_json(strip_jsonc(_bounded(text)))


def load_yaml(text: str) -> object:
    text = _bounded(text)
    try:
        import yaml
    except ImportError as exc:  # pragma: no cover - dependency is declared
        raise ManifestSyntaxError("yaml unavailable") from exc
    try:
        # safe_load only: constructs plain types, never arbitrary objects.
        return yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ManifestSyntaxError("malformed yaml") from exc
    except (RecursionError, MemoryError) as exc:
        raise ManifestSyntaxError("yaml too deep") from exc


def load_xml(text: str) -> ET.Element:
    text = _bounded(text)
    if _XML_ENTITY_RE.search(text):
        # Refuse the billion-laughs primitive outright rather than trusting
        # libexpat's mitigation to be present in every build.
        raise ManifestSyntaxError("xml entity declaration refused")
    try:
        parser = ET.XMLParser()
        # No entity resolver and no external fetch: ElementTree already does
        # not resolve external entities, and a declaration was refused above.
        return ET.fromstring(text, parser=parser)
    except ET.ParseError as exc:
        raise ManifestSyntaxError("malformed xml") from exc
    except (RecursionError, MemoryError) as exc:
        raise ManifestSyntaxError("xml too deep") from exc


def load_ini(text: str) -> configparser.ConfigParser:
    parser = configparser.ConfigParser(interpolation=None, strict=False)
    parser.optionxform = str  # keep case: manifest keys are case-sensitive
    try:
        parser.read_string(_bounded(text))
    except configparser.Error as exc:
        raise ManifestSyntaxError("malformed ini") from exc
    except (RecursionError, MemoryError) as exc:
        raise ManifestSyntaxError("ini too deep") from exc
    return parser


def deep_items(root: object, max_depth: int = MAX_WALK_DEPTH):
    """Yield ``(key, value)`` for every mapping entry under *root*.

    Bounded by depth and by object identity, so a self-referential YAML
    anchor (``a: &x {b: *x}``) terminates instead of looping, and a shared
    alias is visited once rather than fanned out.
    """
    seen: set[int] = set()
    stack: list[tuple[object, int]] = [(root, 0)]
    while stack:
        node, depth = stack.pop()
        if depth > max_depth:
            continue
        if isinstance(node, dict):
            if id(node) in seen:
                continue
            seen.add(id(node))
            for key, value in node.items():
                yield key, value
                stack.append((value, depth + 1))
        elif isinstance(node, (list, tuple)):
            if id(node) in seen:
                continue
            seen.add(id(node))
            for value in node:
                stack.append((value, depth + 1))
