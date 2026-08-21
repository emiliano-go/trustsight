"""The June 2026 campaign's shape, on the single-package path.

The corpus rules already describe mass adoption (R092, R126) and orphan
reachability (R093, R107, R111), but every one of them needs a ``full-aur``
cycle. Somebody running ``trustsight review`` over their installed packages
sees none of them, and those are the people the campaign actually hit.

Three rules here, and the third is the one that matters:

* **R141** - the AUR reported this package orphaned, and now reports a
  maintainer. That is the campaign's entry point: adoption is how the
  attacker got commit rights to something the reviewer already trusted.
* **R142** - the recipe changed but upstream did not: same ``source=``
  URLs, same checksums, same ``pkgver``, yet dependencies *and* a build
  function both moved.
  This is what made the attack invisible to a reviewer scanning source
  lines, and it is the signature that separates it from an ordinary update,
  which almost always moves ``pkgver`` and the checksums together.
* **R143** - the composition. R141 and R142 are individually survivable:
  packages do get adopted honestly, and recipes do get fixed without an
  upstream release. What is not ordinary is *adopted, then the recipe
  rewritten, and the build now pulling unpinned code from a registry* - the
  three together, in one change. Scoring the composition rather than
  inflating any single rule is how this clears the flag threshold without
  spending benign fire rate, the same reasoning R082 and R117 use.
"""

from __future__ import annotations

import re

from ..tokenizer import split_lines
from ..rules import clamp_text, join_line_continuations
from .buildfetch import BUILD_FUNCTIONS, registry_resolutions

_DEP_FIELDS = ("depends", "makedepends", "checkdepends", "optdepends")

_DEP_ASSIGN_RE = re.compile(
    r"^\s*(?:" + "|".join(_DEP_FIELDS) + r")(?:_[A-Za-z0-9_]+)?\s*(?:\+)?=",
    re.IGNORECASE,
)

_SOURCE_ASSIGN_RE = re.compile(r"^\s*source(?:_[A-Za-z0-9_]+)?\s*(?:\+)?=", re.IGNORECASE)

_CHECKSUM_ASSIGN_RE = re.compile(
    r"^\s*(?:(?:md5|sha1|sha224|sha256|sha384|sha512|b2)sums)"
    r"(?:_[A-Za-z0-9_]+)?\s*(?:\+)?=",
    re.IGNORECASE,
)

_PKGVER_RE = re.compile(r"^\s*pkgver\s*=", re.IGNORECASE)

_FUNCTION_OPEN_RE = re.compile(r"^\s*(\w+)\s*\(\s*\)\s*\{")


def _changed_kinds(diff_text: str) -> dict[str, bool]:
    """Which parts of the recipe this diff touches.

    Read off added *and* removed lines: a checksum that was edited shows as
    one of each, and "the checksums did not move" has to mean neither side
    touched them.
    """
    lines = join_line_continuations(split_lines(clamp_text(diff_text)))
    kinds = {
        "deps": False,
        "source": False,
        "checksums": False,
        "pkgver": False,
        "build_function": False,
    }
    depth = 0
    for line in lines:
        if line.startswith(("+++", "---", "@@")):
            continue
        marker, body = line[:1], line[1:] if line[:1] in ("+", "-", " ") else line
        stripped = body.lstrip()

        opened = _FUNCTION_OPEN_RE.match(stripped)
        inside_build = depth > 0
        if opened:
            depth += 1
            if opened.group(1) in BUILD_FUNCTIONS and marker in ("+", "-"):
                kinds["build_function"] = True
            if stripped.rstrip().endswith("}"):
                depth -= 1
            continue
        if stripped.startswith("}") and depth > 0:
            depth -= 1
            continue

        if marker not in ("+", "-"):
            continue
        if inside_build:
            kinds["build_function"] = True
            continue
        if _DEP_ASSIGN_RE.match(body):
            kinds["deps"] = True
        elif _SOURCE_ASSIGN_RE.match(body):
            kinds["source"] = True
        elif _CHECKSUM_ASSIGN_RE.match(body):
            kinds["checksums"] = True
        elif _PKGVER_RE.match(body):
            kinds["pkgver"] = True
    return kinds


def is_recipe_only_change(diff_text: str) -> bool:
    """True when the recipe gained build inputs *and* build steps, upstream unmoved.

    Two conjunctions, both measured rather than guessed.

    "Upstream did not move" means no ``source=`` edit, no checksum edit and
    no ``pkgver`` edit. Any one of those means the package points at
    different upstream bytes, which is an ordinary update whatever else
    changed with it.

    "The recipe gained capability" means a dependency array changed **and** a
    build function changed. Requiring both is what makes this specific, and
    the numbers are the reason: against the 3,246-diff locked benign corpus,
    ``deps or build`` fires on 11.53%, ``deps only`` on 4.36%, ``build only``
    on 5.75%, and ``deps and build`` on **1.42%**. The disjunction is under
    the 30% ceiling but it is eight times the noise for no extra detection -
    the June 2026 campaign changed both, because new build dependencies are
    useless without a build step that invokes them.

    It also keeps R142 out of two neighbours' territory. A dependency added
    with no build change is a packaging fix. A build function edited with no
    dependency change is R060, which is INFO precisely because it fires on
    21.4% of benign diffs; a MEDIUM twin of it would be the same mistake with
    a different id.
    """
    kinds = _changed_kinds(diff_text)
    upstream_moved = kinds["source"] or kinds["checksums"] or kinds["pkgver"]
    gained_capability = kinds["deps"] and kinds["build_function"]
    return gained_capability and not upstream_moved


def adoption_findings(
    diff_text: str,
    *,
    package_name: str,
    was_orphaned: int,
    currently_maintained: bool,
    add,
) -> None:
    """Emit R141, R142 and the R143 composition.

    *was_orphaned* is the tri-state from :func:`db.get_aur_orphan_state`:
    1 orphaned, 0 maintained, -1 never recorded. R141 requires 1, so a
    database with no prior observation says nothing rather than guessing.
    """
    adopted = was_orphaned == 1 and currently_maintained
    recipe_only = is_recipe_only_change(diff_text)
    resolutions = registry_resolutions(diff_text)

    if adopted:
        add("R141", "Adopted From Orphan", "MEDIUM", "maintainer",
            f"{package_name} was orphaned in the AUR and now has a maintainer",
            package=package_name)

    if recipe_only:
        add("R142", "Recipe Changed Without Upstream", "MEDIUM", "integrity",
            "build recipe changed while source URLs, checksums and pkgver did not",
            package=package_name)

    # The composition. Each part is ordinary alone; together they are the
    # June 2026 chain in one diff, and the whole point of scoring it here is
    # that no single member has to carry a weight its benign fire rate
    # cannot support.
    if adopted and recipe_only and resolutions:
        function, command = resolutions[0]
        add("R143", "Adopted, Recipe Rewritten, Unpinned Fetch", "HIGH", "takeover",
            f"{package_name} was adopted from orphan, its recipe changed with no "
            f"upstream move, and {function}() now resolves dependencies from a "
            f"registry: {command[:80]}",
            package=package_name, position=function, body=command[:80])
