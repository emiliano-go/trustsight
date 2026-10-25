"""Bounded, normalized upstream-manifest state for the full-AUR watcher.

The snapshot fetcher already reads committed manifests. Persisting their
normalized documents lets the next cycle compare complete old and new states,
so U001-U006/U011/U012 and U009 work outside the PKGBUILD-only diff. A missing
or incomplete state is a baseline, never an empty old tree.
"""

from __future__ import annotations

import json

from ..changes import FileDelta, ManifestDelta, manifest_delta_from_docs
from .manifests import Dep, ManifestDoc, parse_manifest
from .upstream_release import is_ci_workflow_path

_STATE_VERSION = 1


def build_manifest_state(manifest_texts, tree_manifest) -> str | None:
    """Serialize complete current state, or ``None`` when it is incomplete."""
    documents = []
    for path, text in manifest_texts or ():
        doc = parse_manifest(path, text)
        if doc is None:
            continue
        if doc.unresolved:
            return None
        documents.append(doc.to_dict())
    workflows = sorted({
        path for path, _head in tree_manifest or ()
        if is_ci_workflow_path(path)
    })
    return json.dumps({
        "version": _STATE_VERSION,
        "documents": documents,
        "workflows": workflows,
    }, sort_keys=True, separators=(",", ":"))


def _documents(raw: str) -> tuple[dict[str, ManifestDoc], list[str]] | None:
    try:
        data = json.loads(raw)
        if not isinstance(data, dict) or data.get("version") != _STATE_VERSION:
            return None
        documents = {}
        for item in data.get("documents", ()):
            doc = ManifestDoc(
                path=str(item["path"]),
                format=str(item["format"]),
                dependencies=tuple(
                    Dep(
                        name=str(dep["name"]),
                        constraint=dep.get("constraint"),
                        source_kind=str(dep["source_kind"]),
                        remote=dep.get("remote"),
                        origin=dep.get("origin"),
                        integrity=dep.get("integrity"),
                    )
                    for dep in item.get("dependencies", ())
                ),
                unresolved=tuple(item.get("unresolved", ())),
                redirects=tuple(tuple(pair) for pair in item.get("redirects", ())),
            )
            documents[doc.path] = doc
        workflows = [str(path) for path in data.get("workflows", ())]
        return documents, workflows
    except (ValueError, TypeError, KeyError):
        return None


def manifest_state_delta(
    previous: str | None, current: str | None,
) -> tuple[tuple[ManifestDelta, ...], tuple[FileDelta, ...]]:
    """Compare two complete states, returning manifest and workflow deltas."""
    if not previous or not current:
        return (), ()
    old = _documents(previous)
    new = _documents(current)
    if old is None or new is None:
        return (), ()
    old_docs, old_workflows = old
    new_docs, new_workflows = new
    deltas = []
    for path in sorted(old_docs.keys() | new_docs.keys()):
        before, after = old_docs.get(path), new_docs.get(path)
        if before == after:
            continue
        status = "added" if before is None else "removed" if after is None else "modified"
        doc = after or before
        deltas.append(manifest_delta_from_docs(
            path, doc.format, status, before, after,
        ))
    workflow_deltas = tuple(
        FileDelta(path=path, old_path=path, status="added", hunks=())
        for path in sorted(set(new_workflows) - set(old_workflows))
    )
    return tuple(deltas), workflow_deltas
