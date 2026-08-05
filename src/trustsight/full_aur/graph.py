"""Phase 6 - Class D dependency-graph rules (plan §8).

R093/R107/R111/R112 read the *corpus-wide* dependency graph built from the
metadata snapshot's Depends/MakeDepends/CheckDepends fields (edges are kept
only when the dependency is itself an AUR package):

- R093 (additive MEDIUM): a package depends directly on a package that was
  just orphaned or just adopted this cycle.  Fires on the transition, so a
  long-standing orphan dependency never repeats.
- R107 (context, weight 0): a package's transitive closure includes a
  package adopted this cycle from a previous orphan (the takeover vector).
- R111 (context, weight 0): a package's transitive closure includes a
  currently-orphaned package.
- R112 (context, weight 0): dependency-centrality hub, for prioritisation
  only.

All four are silent on a fresh bootstrap (no prior snapshot), matching the
Class D no-baseline gate.
"""

from ..deps import normalize_dependency
from ..findings import stamp

_DEP_FIELDS = ("Depends", "MakeDepends", "CheckDepends")
_CLOSURE_DEPTH = 3


def _threshold(rule: str, key: str, default):
    from ..config import load_thresholds

    return load_thresholds().get(rule, {}).get(key, default)


def dependency_edges(meta: dict) -> dict[str, set[str]]:
    """AUR-internal dependency edges ``{package: {dep, ...}}``.

    Only edges whose target also exists in *meta* are kept; official-repo
    and external dependencies have no AUR node to attach risk to.
    """
    edges: dict[str, set[str]] = {}
    for name, entry in meta.items():
        deps: set[str] = set()
        for field in _DEP_FIELDS:
            for dep in entry.get(field) or []:
                normalized = normalize_dependency(dep)
                if normalized in meta and normalized != name:
                    deps.add(normalized)
        if deps:
            edges[name] = deps
    return edges


def _transitive_closure(name: str, edges: dict[str, set[str]], depth: int) -> dict[str, int]:
    """Shortest hop distance to every node reachable from *name*.

    Returns ``{node: distance}`` for nodes within *depth* hops (excluding
    self).  R107/R111 use the distance so that "transitive" means the risk
    is at least two hops away, keeping them out of R093's direct-dep lane.
    """
    closure: dict[str, int] = {}
    frontier = {name}
    distance = 0
    while frontier and distance < depth:
        nxt: set[str] = set()
        for node in frontier:
            for dep in edges.get(node, set()):
                if dep not in closure and dep != name:
                    closure[dep] = distance + 1
                    nxt.add(dep)
        frontier = nxt
        distance += 1
    return closure


def _cluster(rule: str, name: str, match: str, members: list[str],
             severity: str = "INFO", **extra) -> dict:
    finding = {
        "rule_id": rule,
        "name": name,
        "severity": severity,
        "category": "dependency",
        "match": match,
        "params": {"members": members, "member_count": len(members), **extra},
    }
    return stamp(finding)


def _orphan_dependency_findings(
    changes: dict,
    new_meta: dict,
    edges: dict[str, set[str]],
    transitions: dict,
) -> list[dict]:
    """R093 - direct dependency on a package orphaned/adopted this cycle."""
    out: list[dict] = []
    for dependent, status in changes.items():
        if status == "removed":
            continue
        for dep in edges.get(dependent, set()):
            if dep not in transitions:
                continue
            old_m, new_m = transitions[dep]
            if new_m and old_m != new_m:
                kind = "adopted"
            elif not new_m and old_m:
                kind = "orphaned"
            else:
                continue
            out.append(_cluster(
                "R093",
                "Orphan/Adoption Dependency",
                f"{dependent} depends on {dep}, {kind} this cycle",
                [dependent],
                severity="MEDIUM",
                dep=dep,
                maintainer=new_m,
            ))
    return out


def _transitive_exposure_findings(
    changes: dict,
    edges: dict[str, set[str]],
    transitions: dict,
) -> list[dict]:
    """R107 - transitive closure reaches a package adopted from an orphan."""
    min_hops = int(_threshold("r107", "min_hops", 2))
    out: list[dict] = []
    for name, status in changes.items():
        if status == "removed":
            continue
        closure = _transitive_closure(name, edges, _CLOSURE_DEPTH)
        for dep, distance in closure.items():
            if dep not in transitions or distance < min_hops:
                continue
            old_m, new_m = transitions[dep]
            if not old_m and new_m:  # adopted out of the orphan state
                out.append(_cluster(
                    "R107",
                    "Transitive Exposure",
                    f"{name} transitively depends on {dep}, adopted this cycle",
                    [name],
                    dep=dep,
                    distance=distance,
                ))
                break
    return out


def _transitive_orphan_findings(
    changes: dict,
    new_meta: dict,
    edges: dict[str, set[str]],
) -> list[dict]:
    """R111 - transitive closure includes a currently-orphaned package."""
    min_hops = int(_threshold("r111", "min_hops", 2))
    out: list[dict] = []
    for name, status in changes.items():
        if status == "removed":
            continue
        closure = _transitive_closure(name, edges, _CLOSURE_DEPTH)
        for dep, distance in closure.items():
            if distance < min_hops:
                continue
            if not (new_meta.get(dep) or {}).get("Maintainer"):
                out.append(_cluster(
                    "R111",
                    "Transitive Orphan Risk",
                    f"{name} transitively depends on orphaned {dep}",
                    [name],
                    dep=dep,
                    distance=distance,
                ))
                break
    return out


def _centrality_findings(edges: dict[str, set[str]]) -> list[dict]:
    """R112 - dependency-centrality hubs, prioritisation only."""
    min_dependents = int(_threshold("r112", "min_dependents", 50))
    indegree: dict[str, int] = {}
    for deps in edges.values():
        for dep in deps:
            indegree[dep] = indegree.get(dep, 0) + 1
    out: list[dict] = []
    for hub, count in sorted(indegree.items(), key=lambda kv: -kv[1]):
        if count < min_dependents:
            break
        out.append(_cluster(
            "R112",
            "Dependency Centrality",
            f"{hub} is depended on by {count} AUR packages",
            [hub],
            dependents=count,
        ))
    return out


def run_graph_sweep(
    new_meta: dict,
    old_meta: dict | None,
    changes: dict,
    transitions: dict,
    *,
    edges: dict[str, set[str]] | None = None,
) -> list[dict]:
    """Run the Phase 6 graph detectors for one metadata cycle."""
    if old_meta is None:
        return []
    graph = edges if edges is not None else dependency_edges(new_meta)
    out: list[dict] = []
    out += _orphan_dependency_findings(changes, new_meta, graph, transitions)
    out += _transitive_exposure_findings(changes, graph, transitions)
    out += _transitive_orphan_findings(changes, new_meta, graph)
    out += _centrality_findings(graph)
    return out
