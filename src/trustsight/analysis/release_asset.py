"""A016: a release asset diverges from the tag tree it claims to represent.

A project that uploads its own dist tarball on a trusted host can ship bytes
that its tag tree does not contain.  The xz 5.6.x shape is the named example:
extra automake fragments existed only in the release tarball.  This module
compares the two bounded inventories produced by the archive parser; it never
downloads, extracts or executes either side.

The rule is report-only at weight 0.  The generated-file model and the
export-ignore list are expected to be wrong at first, so a fire is a review
claim, not a score.
"""

from __future__ import annotations

import os

from ..findings import stamp

__all__ = ["compare_release_asset"]

#: Files an autotools dist step generates; a difference here is ordinary.
_GENERATED = frozenset({
    "configure", "Makefile.in", "aclocal.m4", "config.h.in",
})

#: Build inputs whose absence from the tag tree is the xz shape.
_BUILD_INPUT_SUFFIXES = (".m4", ".in")
_BUILD_INPUT_NAMES = frozenset({"Makefile.am", "configure.ac"})


def _normalise(name: str) -> str:
    return str(name or "").replace("\\", "/").lstrip("./")


def _is_generated(name: str) -> bool:
    base = os.path.basename(name)
    return (
        base in _GENERATED
        or base.endswith(".o")
        or "/.deps/" in f"/{name}"
        or name.endswith(".pyc")
    )


def _is_build_input(name: str) -> bool:
    base = os.path.basename(name)
    return base in _BUILD_INPUT_NAMES or base.endswith(_BUILD_INPUT_SUFFIXES)


def _inventory_map(inventory) -> dict[str, str]:
    entries: list[tuple[str, str]] = []
    for entry in inventory or ():
        if not isinstance(entry, (tuple, list)) or len(entry) < 3:
            continue
        name, _size, digest = entry[0], entry[1], entry[2]
        normalised = _normalise(name)
        if normalised:
            entries.append((normalised, str(digest)))
    if not entries:
        return {}
    roots = {name.split("/", 1)[0] for name, _ in entries if "/" in name}
    if len(roots) == 1 and all("/" in name for name, _ in entries):
        root = roots.pop() + "/"
        entries = [(name[len(root):], digest) for name, digest in entries]
    return dict(entries)


def compare_release_asset(
    asset_inventory,
    tag_inventory,
    *,
    export_ignore=frozenset(),
) -> dict | None:
    """Return an A016 finding when the asset and tag tree disagree.

    *asset_inventory* and *tag_inventory* are the ``(name, size, sha256)``
    lists from :func:`parse_upstream_archive`.  An empty tag inventory is
    "not read", not "empty tree", and stays silent.
    """
    asset = _inventory_map(asset_inventory)
    tag = _inventory_map(tag_inventory)
    if not asset or not tag:
        return None
    ignored = {_normalise(name) for name in export_ignore if name}
    missing = sorted(
        name for name in asset
        if _is_build_input(name)
        and name not in tag
        and name not in ignored
        and not _is_generated(name)
    )
    if missing:
        name = missing[0]
        return stamp({
            "rule_id": "A016",
            "name": "Release Asset Diverges From Its Tag",
            "severity": "HIGH",
            "category": "artifact",
            "weight_override": 0,
            "match": (f"release asset carries build input {name!r} that is "
                      "absent from the tag tree"),
            "params": {"file": name, "missing": ", ".join(missing[:5])},
        })
    changed = sorted(
        name for name, digest in asset.items()
        if name in tag
        and digest != tag[name]
        and not _is_generated(name)
        and name not in ignored
    )
    if changed:
        name = changed[0]
        return stamp({
            "rule_id": "A016",
            "name": "Release Asset Diverges From Its Tag",
            "severity": "HIGH",
            "category": "artifact",
            "weight_override": 0,
            "match": (f"release asset file {name!r} differs from the tag "
                      "tree"),
            "params": {"file": name, "changed": ", ".join(changed[:5])},
        })
    return None
