"""Extracted from pipeline.py: _tree."""

import json
import re
from ...config import (
    config_fingerprint,
)
from ...db import (
    get_last_analysis,
)
from ...findings import stamp
from ...coverage import (
    note_stage_failure,
)
from ...schema import (
    PackageFact,
    fact_from_dict,
)
from ._common import log

__all__ = ['_NOEXTRACT_RE', '_SCRIPTLET_ATTR_RE', '_added_dependency_names', '_adds_a_dependency', '_binary_metadata_finding', '_cached_analysis', '_deps_not_scanned', '_has_noextract', '_parent_commit', '_scriptlet_files_unread']

_SCRIPTLET_ATTR_RE = re.compile(
    r"^\+?\s*(?:install|changelog)\s*=\s*[\"']?([^\"'\s#;]+)",
    re.MULTILINE,
)

def _scriptlet_files_unread(diff_text: str, tree_manifest) -> bool:
    """True when `install=` names a file the manifest does not carry.

    An `.install` scriptlet runs as root on the installing machine, and the
    recipe names it rather than containing it. When a tree was read, the
    absence of `tree_not_analyzed` says the committed files were examined -
    but a manifest that does not hold the named hook means the one file
    whose whole purpose is to run as root was never examined at all, and
    the report said the tree was complete.
    """
    if not tree_manifest:
        return False
    raw_names = {m.group(1).rsplit("/", 1)[-1]
                 for m in _SCRIPTLET_ATTR_RE.finditer(diff_text)}
    if not raw_names:
        return False
    # `install="${pkgname}.install"` is the same file `.SRCINFO` names
    # resolved (`install = foo.install`), and the manifest carries it.
    # Comparing only the raw spelling made a hook that was read report as
    # one that was not, because `$pkgname` never appears in a manifest.
    # A successful resolution pass replaces the unresolved spellings with
    # the literals; a failed one keeps them, so the gap stays closed-fail.
    try:
        from ...tokenizer import resolve_added_lines

        resolved = "\n".join(resolve_added_lines(diff_text))
    except Exception:
        log.debug("scriptlet name resolution failed", exc_info=True)
        note_stage_failure("scriptlet-resolution")
        names = raw_names
    else:
        names = {n for n in raw_names if "$" not in n}
        names |= {m.group(1).rsplit("/", 1)[-1]
                  for m in _SCRIPTLET_ATTR_RE.finditer(resolved)}
    if not names:
        return False
    have = {path.rsplit("/", 1)[-1] for path, _head in tree_manifest}
    return bool(names - have)

_NOEXTRACT_RE = re.compile(
    r"^\+?\s*noextract\s*=\s*\(", re.MULTILINE
)

def _has_noextract(text: str) -> bool:
    """True when the post-state recipe declares noextract=().

    Accept either a raw PKGBUILD or a diff (added/context lines, never a
    removed line).  noextract=() suppresses extraction of source archives,
    whose contents are then unavailable to every analysis path.
    """
    return bool(_NOEXTRACT_RE.search(text))

def _binary_metadata_finding(paths: list[str]) -> dict:
    """A HIGH finding for metadata git refused to diff as text.

    A binary ``PKGBUILD``/``.install`` is never legitimate: the shell still
    sources it normally, and no rule saw a line of it.
    """
    return stamp({
        "rule_id": "C010",
        "name": "Binary Metadata File",
        "severity": "HIGH",
        "category": "integrity",
        "match": (
            "metadata file(s) are binary, so no diff body was emitted and "
            f"their content was not read: {', '.join(paths[:3])}"
        ),
        "file": paths[0], "line": None,
        "params": {"members": ", ".join(paths[:5])},
    })

def _added_dependency_names(diff_text: str) -> set[str]:
    """Non-official dependency names this diff adds, from the walked fields.

    The gap exists for a name this run did not walk, which is an AUR
    dependency; a package from an official repository (``lib32-glibc`` in
    ``[core]``) is resolved by the build system like any other and is not
    unread code.  ``optdepends`` is excluded along with the gap test: it
    is not pulled in by default (the same reason DEPTH_FIELDS excludes
    it), so a name there is not code the run failed to read.

    A tokenizer failure must not read as "no dependency added": that is the
    same neutral value a complete scan returns, and it silently clears
    ``deps_not_scanned``.  A missing tokenizer is a refusal (the package is
    not vetted), so it propagates; any other failure is recorded as a
    degraded stage and the caller fails closed on the stage gap.
    """
    from ...db import is_established_package
    from ...deps import extract_dependency_changes
    from ...tokenizer import TokenizerUnavailable

    try:
        added = extract_dependency_changes(diff_text, "")
    except TokenizerUnavailable:
        raise
    except Exception:
        log.debug("dependency-change scan failed", exc_info=True)
        note_stage_failure("dependency-change-scan")
        return set()
    names = {
        name
        for field in ("depends", "makedepends", "checkdepends")
        for name in added.get(field, ())
    }
    return {name for name in names if not is_established_package(name)}

def _adds_a_dependency(diff_text: str) -> bool:
    """True when the diff adds a dependency that is not a repo package."""
    return bool(_added_dependency_names(diff_text))

def _deps_not_scanned(depth_result, added_names: set[str]) -> bool:
    """Whether this run leaves an added dependency unread.

    Three ways, and only three: the walk was cut short; the metadata
    provider could not answer, so "not in the AUR" is not a fact; or an
    added name the provider *does* know is AUR was not reached.  A name
    the provider reports as not-AUR is resolved by makepkg's normal
    dependency handling and is not a gap.
    """
    return (
        depth_result.truncated
        or (bool(added_names) and depth_result.metadata_unavailable)
        or depth_result.added_aur_unreported
    )

def _parent_commit(project, head_commit: str) -> str:
    """The first parent of *head_commit*, or ``""`` when there is none.

    Used only when no analysis has been recorded: the repository's own
    history supplies the base a read-only first review compares against.
    """
    return project.parent_commit(head_commit)

def _cached_analysis(
    package_id: int,
    head_commit: str,
    head_version: str,
    installed_version: str,
    depth: int | None,
    config: dict,
) -> PackageFact | None:
    """The recorded analysis of *package_id*, when it is this run's answer (#20).

    Served only when everything the run would read is unchanged: the AUR
    HEAD commit, both version strings, the resolved dependency depth, and
    the ruleset fingerprint.  Anything else - a moved commit, a version
    drift, a different ``--depth``, a rules edit, a row written by an older
    version - is a cache miss, and the caller falls through to a fresh
    analysis.  The corpus path stores rows with an empty ``new_commit``, so
    they can never match a real HEAD.
    """
    from ...depth import resolve_depth

    row = get_last_analysis(package_id)
    if row is None:
        return None
    if row.get("new_commit") != head_commit:
        return None
    if row.get("new_version") != head_version:
        return None
    if (row.get("old_version") or "") != (installed_version or ""):
        return None
    try:
        data = json.loads(row.get("fact_json") or "")
    except (ValueError, TypeError):
        return None
    if not isinstance(data, dict):
        return None
    if data.get("config_fingerprint") != config_fingerprint():
        return None
    fact = fact_from_dict(data)
    if fact is None:
        return None
    if fact.depth != resolve_depth(depth, config):
        return None
    fact.cached = True
    fact.cached_at = row.get("timestamp", "") or ""
    return fact
