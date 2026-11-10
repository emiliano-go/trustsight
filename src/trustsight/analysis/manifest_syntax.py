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
from collections.abc import Hashable

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

#: Untrusted YAML budgets.  ``MAX_MANIFEST_BYTES`` bounds the input, but an
#: 800-byte merge-key document can expand exponentially inside PyYAML before
#: any post-load walk sees it.  These caps are enforced during composition and
#: construction, and the merge-key flattening carries the upstream linearity
#: fix (PyYAML #937) because no released PyYAML contains it yet.
MAX_YAML_NODES = 100_000
MAX_YAML_ALIASES = 64
MAX_YAML_DEPTH = 64
MAX_YAML_MERGE_ENTRIES = 10_000


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


_STRICT_LOADER = None


def _strict_loader():
    """Return the bounded SafeLoader subclass, built once.

    It is a ``SafeLoader`` subclass, not a new loader with object
    construction: plain mappings/sequences/scalars only.  The extra checks
    exist because ``safe_load`` does not bound aliases, node count, depth or
    merge-key fan-out.  PyYAML 6.0.3 is the latest release and does not
    contain the upstream merge-key fix, so the fix is carried here until a
    release does.
    """
    global _STRICT_LOADER
    if _STRICT_LOADER is not None:
        return _STRICT_LOADER

    import yaml
    from yaml.composer import ComposerError
    from yaml.constructor import ConstructorError
    from yaml.events import AliasEvent
    from yaml.nodes import MappingNode, SequenceNode

    class StrictSafeLoader(yaml.SafeLoader):
        def __init__(self, stream):
            super().__init__(stream)
            self._nodes = 0
            self._aliases = 0
            self._depth = 0
            self._merge_entries = 0

        def compose_node(self, parent, index):
            if self.check_event(AliasEvent):
                self._aliases += 1
                if self._aliases > MAX_YAML_ALIASES:
                    raise ComposerError(
                        None, None, "too many YAML aliases", None)
            self._nodes += 1
            if self._nodes > MAX_YAML_NODES:
                raise ComposerError(None, None, "too many YAML nodes", None)
            self._depth += 1
            if self._depth > MAX_YAML_DEPTH:
                raise ComposerError(None, None, "YAML nesting too deep", None)
            try:
                return super().compose_node(parent, index)
            finally:
                self._depth -= 1

        def flatten_mapping(self, node):
            # The upstream #937 shape: de-duplicate merge sources by key
            # identity while flattening, so a repeated alias cannot fan out
            # exponentially.  The entry budget is the backstop for an
            # unusual graph the de-duplication does not collapse.
            merge = []
            merge_key_ids = set()
            index = 0
            while index < len(node.value):
                key_node, value_node = node.value[index]
                if key_node.tag == "tag:yaml.org,2002:merge":
                    del node.value[index]
                    if isinstance(value_node, MappingNode):
                        self.flatten_mapping(value_node)
                        for pair in value_node.value:
                            key_id = id(pair[0].value)
                            if key_id not in merge_key_ids:
                                merge_key_ids.add(key_id)
                                merge.append(pair)
                    elif isinstance(value_node, SequenceNode):
                        for subnode in value_node.value:
                            if not isinstance(subnode, MappingNode):
                                raise ConstructorError(
                                    "while constructing a mapping",
                                    node.start_mark,
                                    "expected a mapping for merging, but found %s"
                                    % subnode.id, subnode.start_mark)
                            self.flatten_mapping(subnode)
                            for pair in subnode.value:
                                key_id = id(pair[0].value)
                                if key_id not in merge_key_ids:
                                    merge_key_ids.add(key_id)
                                    merge.append(pair)
                    else:
                        raise ConstructorError(
                            "while constructing a mapping", node.start_mark,
                            "expected a mapping or list of mappings for "
                            "merging, but found %s" % value_node.id,
                            value_node.start_mark)
                    self._merge_entries += len(merge)
                    if self._merge_entries > MAX_YAML_MERGE_ENTRIES:
                        raise ConstructorError(
                            "while constructing a mapping", node.start_mark,
                            "YAML merge expansion exceeds its budget",
                            node.start_mark)
                elif key_node.tag == "tag:yaml.org,2002:value":
                    key_node.tag = "tag:yaml.org,2002:str"
                    index += 1
                else:
                    index += 1
            if merge:
                node.value = merge + node.value

        def construct_mapping(self, node, deep=False):
            if isinstance(node, MappingNode):
                self.flatten_mapping(node)
            mapping = {}
            for key_node, value_node in node.value:
                key = self.construct_object(key_node, deep=deep)
                if not isinstance(key, Hashable):
                    raise ConstructorError(
                        "while constructing a mapping", node.start_mark,
                        "found unhashable key", key_node.start_mark)
                if key in mapping:
                    raise ConstructorError(
                        "while constructing a mapping", node.start_mark,
                        "found duplicate key %r" % (key,), key_node.start_mark)
                mapping[key] = self.construct_object(value_node, deep=deep)
            return mapping

    _STRICT_LOADER = StrictSafeLoader
    return _STRICT_LOADER


def load_yaml(text: str) -> object:
    text = _bounded(text)
    try:
        import yaml
    except ImportError as exc:  # pragma: no cover - dependency is declared
        raise ManifestSyntaxError("yaml unavailable") from exc
    loader = None
    try:
        # A SafeLoader subclass: plain types only, never arbitrary objects.
        loader = _strict_loader()(text)
        return loader.get_single_data()
    except yaml.YAMLError:
        # Do not retain the PyYAML traceback: its frames hold composed
        # nodes whose ``repr`` recursively walks an alias graph, so logging
        # the chained exception can turn a refused document into a hang.
        raise ManifestSyntaxError("malformed yaml") from None
    except (RecursionError, MemoryError):
        raise ManifestSyntaxError("yaml too deep") from None
    finally:
        if loader is not None:
            loader.dispose()


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
