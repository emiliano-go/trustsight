"""Metadata-vs-recipe consistency beyond hosts (H103).

``.SRCINFO`` is generated from the PKGBUILD and the analysis prefers it
wherever it is richer.  H092 compares the hosts each document names; this
rule compares the fields that decide what the build installs, fetches and
verifies: the install hook, the checksum arrays and the dependency list.
A stale ``.SRCINFO`` is the ordinary benign shape, so a differing
``pkgver`` alone does not fire: only a field that changes what the build
does counts.

Only fields present in both documents and free of unresolved variables
compare.  Anything else reads as "not seen", never as a divergence.
"""

from ..recipedoc import parse_recipe
from ..srcinfo import parse_srcinfo

_CHECKSUM_FIELDS = (
    "sha256sums", "sha512sums", "sha1sums", "sha224sums", "sha384sums",
    "b2sums", "md5sums",
)


def _is_checksum(field: str) -> bool:
    return any(
        field == base or field.startswith(base + "_")
        for base in _CHECKSUM_FIELDS
    )


def _is_source(field: str) -> bool:
    """True for ``source`` and its arch-suffixed variants (``source_x86_64``)."""
    return field == "source" or field.startswith("source_")


def source_divergence(pkgbuild: str, srcinfo: str | None) -> tuple[list[str], list[str]]:
    """Directional source divergence between metadata and recipe (G8).

    Returns ``(only_in_pkgbuild, only_in_srcinfo)``: source entries each
    document declares that the other does not.  ``only_in_pkgbuild`` is the
    executable/metadata split - clean metadata for review tooling, a dirty
    recipe for makepkg - and is the security-relevant direction; the other
    is stale metadata, usually an honest mistake.  Variables on either side
    are skipped (never guess).  Arch-suffixed arrays compare with their
    base so a per-arch source is not lost.
    """
    if not srcinfo:
        return [], []
    metadata = parse_srcinfo(srcinfo)
    recipe = parse_recipe(pkgbuild)
    pkgbuild_only: set[str] = set()
    srcinfo_only: set[str] = set()
    for field in sorted(set(recipe.arrays) | set(metadata)):
        if not _is_source(field):
            continue
        meta_values = metadata.get(field)
        recipe_values = recipe.arrays.get(field)
        if meta_values is None or recipe_values is None:
            continue
        if _has_variable(meta_values) or _has_variable(recipe_values):
            continue
        meta_set = set(meta_values)
        recipe_set = set(recipe_values)
        pkgbuild_only |= recipe_set - meta_set
        srcinfo_only |= meta_set - recipe_set
    return sorted(pkgbuild_only), sorted(srcinfo_only)


def _has_variable(values) -> bool:
    return any("$" in value for value in values)


def metadata_recipe_divergence(pkgbuild: str, srcinfo: str | None) -> list[str]:
    """Security-relevant fields the metadata and the recipe disagree on.

    Returned in a stable order; an empty list means the two documents agree
    on everything this rule compares (or that a field was not visible).
    """
    if not srcinfo:
        return []
    metadata = parse_srcinfo(srcinfo)
    recipe = parse_recipe(pkgbuild)
    divergent: list[str] = []

    install = metadata.get("install", [])
    recipe_install = recipe.scalars.get("install", "")
    if (install and recipe_install and not _has_variable(install)
            and "$" not in recipe_install and install[0] != recipe_install):
        divergent.append("install")

    for field in sorted(set(recipe.arrays) | set(metadata)):
        if not _is_checksum(field):
            continue
        meta_values = metadata.get(field)
        recipe_values = recipe.arrays.get(field)
        if meta_values is None or recipe_values is None:
            continue
        if _has_variable(meta_values) or _has_variable(recipe_values):
            continue
        if set(meta_values) != set(recipe_values):
            divergent.append(field)

    meta_depends = metadata.get("depends")
    recipe_depends = recipe.arrays.get("depends")
    if meta_depends is not None and recipe_depends is not None:
        if not _has_variable(meta_depends) and not _has_variable(recipe_depends):
            if set(meta_depends) != set(recipe_depends):
                divergent.append("depends")

    return divergent
