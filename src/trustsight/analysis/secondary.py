"""H109: a build helper is executed from a secondary source.

The 2025 CHAOS RAT packages were ordinary-looking recipes with one extra
source: a patch repository under the uploader's own account.  The recipe
then ran a helper from that checkout during the build.  The helper was not
the declared upstream, and the source was a VCS clone, so no checksum pinned
what would run.

H105 covers the same act after an ownership change.  This rule covers the
case where the package is new or the maintainer did not change: the source
identity alone is secondary, and the build executes it.
"""

from __future__ import annotations

import os
import re

from ..findings import stamp
from ..recipedoc import parse_recipe
from .adoption import _source_identity
from .delivery._common import _unpinned_source_basenames
from .delivery._transitions import _source_urls_by_local_name

__all__ = ["secondary_source_execution_finding"]

#: Findings whose evidence says a path was executed.  H094 and W001 carry
#: the unresolved path; H083 carries the declared-source path.
_EXECUTION_RULES = frozenset({
    "H082", "H083", "H094", "W001", "X033",
})

_VCS_SOURCE_RE = re.compile(
    r"^(?:git|hg|svn|bzr|fossil)\+", re.IGNORECASE)


def _finding_path(finding: dict) -> str:
    path = str(finding.get("path") or "").strip()
    if path:
        return path
    params = finding.get("params")
    if isinstance(params, dict):
        return str(params.get("path") or "").strip()
    return ""


def _source_for_path(path: str, sources: dict[str, tuple[str, object]]) -> str:
    """The declared local source directory or file *path* belongs to."""
    normalised = path.replace('"', "").replace("'", "")
    normalised = normalised.replace("$srcdir/", "").replace("${srcdir}/", "")
    normalised = normalised.lstrip("./")
    first = normalised.split("/", 1)[0]
    if first in sources:
        return first
    if first + ".git" in sources:
        return first + ".git"
    base = os.path.basename(normalised)
    if base in sources:
        return base
    if base + ".git" in sources:
        return base + ".git"
    return ""


def secondary_source_execution_finding(
    *,
    package_name: str,
    findings: list[dict],
    diff_text: str,
    recipe_text: str | None,
) -> dict | None:
    """H109: an unpinned secondary source is executed during the build."""
    if not recipe_text:
        return None
    recipe = parse_recipe(recipe_text, file="PKGBUILD")
    sources = _source_urls_by_local_name(recipe)
    if not sources:
        return None
    upstream = str(recipe.scalars.get("url") or "").strip()
    upstream_identity = _source_identity(upstream)
    if not upstream or not upstream_identity:
        return None

    unpinned = _unpinned_source_basenames(diff_text, recipe_text)
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        if str(finding.get("rule_id")) not in _EXECUTION_RULES:
            continue
        path = _finding_path(finding)
        if not path:
            continue
        local = _source_for_path(path, sources)
        if not local:
            continue
        url, _span = sources[local]
        source_identity = _source_identity(url)
        if not source_identity:
            continue
        # The upstream's own org is still primary (decision 2).  A different
        # repository in the same org is an ordinary fork, not a secondary
        # source.
        if source_identity[:2] == upstream_identity[:2]:
            continue
        # A VCS clone is unpinned by construction: it has no checksum that
        # can freeze the helper's bytes.  For archive sources, the current
        # recipe's SKIP/missing checksum is the same answer.
        if not (_VCS_SOURCE_RE.match(url)
                or local in unpinned
                or os.path.basename(path) in unpinned):
            continue
        return stamp({
            "rule_id": "H109",
            "name": "Build Helper Executed From A Secondary Source",
            "severity": "HIGH",
            "category": "fetch-and-execution",
            "weight_override": 0,
            "match": (f"{package_name} executes {path} from {url}, a "
                      "secondary unpinned source"),
            "params": {"source": url[:200], "path": path[:200]},
        })
    return None
