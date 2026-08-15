"""Dependency-closure analysis: depth semantics and its bounds.

The walk analyses AUR dependencies as packages, so the properties that
matter are the ones that stop it becoming either a lie or a resource
primitive: it must terminate on a cycle, it must not let the graph choose
how much work happens, and it must say so when it stopped early.
"""

from dataclasses import dataclass, field

import pytest

from trustsight.depth import (
    MAX_DEPTH_LEVELS,
    MAX_DEPTH_NODES,
    DependencyReport,
    RpcMetadata,
    SnapshotMetadata,
    resolve_depth,
    walk_dependencies,
)


@dataclass
class FakeFact:
    final_score: int = 0
    risk: str = "Low"
    score_breakdown: tuple = ()
    coverage_gaps: tuple = ()


@dataclass
class FakeMeta:
    edges: dict = field(default_factory=dict)
    aur: set = field(default_factory=set)

    def is_aur(self, name):
        return name in self.aur

    def deps_of(self, name):
        return self.edges.get(name, set())


def _meta(edges, aur=None):
    if aur is not None:
        return FakeMeta(edges, set(aur))
    # Default: every name mentioned anywhere is an AUR package, so a leaf
    # dependency is in scope without having to be an edge-map key too.
    everything = set(edges)
    for children in edges.values():
        everything |= set(children)
    return FakeMeta(edges, everything)


def _walk(root, depth, edges, aur=None, analyse=None):
    seen_names = []

    def default(name):
        seen_names.append(name)
        return FakeFact()

    result = walk_dependencies(root, depth=depth, metadata=_meta(edges, aur),
                               analyse=analyse or default)
    return result, seen_names


# ---------------------------------------------------------------------------
# Depth semantics.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("depth,expected", [
    (0, []),
    (1, ["b"]),
    (2, ["b", "c"]),
    (3, ["b", "c", "d"]),
    (-1, ["b", "c", "d"]),
])
def test_depth_selects_levels(depth, expected):
    edges = {"a": {"b"}, "b": {"c"}, "c": {"d"}, "d": set()}
    result, _ = _walk("a", depth, edges)
    assert [r.name for r in result.reports] == expected


def test_depth_zero_analyses_nothing_at_all():
    """Not "analyses and discards" - the clones must not happen."""
    edges = {"a": {"b"}, "b": set()}
    result, analysed = _walk("a", 0, edges)
    assert result.reports == []
    assert analysed == []


def test_a_completed_walk_is_not_a_coverage_gap():
    """Asking for depth 1 and getting depth 1 answers the question asked.

    A level 2 exists, but the operator chose the depth; reporting that as
    incomplete coverage would make every bounded run look broken.
    """
    edges = {"a": {"b"}, "b": {"c"}, "c": set()}
    result, _ = _walk("a", 1, edges)
    assert [r.name for r in result.reports] == ["b"]
    assert result.truncated is False


@pytest.mark.parametrize("requested,config,expected", [
    (None, {}, 1),
    (None, {"depth": {"levels": 3}}, 3),
    (None, {"depth": {"levels": 0}}, 0),
    (2, {"depth": {"levels": 5}}, 2),      # the flag wins
    (-1, {}, -1),
    (-9, {}, -1),                          # clamped, not an error
    ("nonsense", {}, 1),
])
def test_resolve_depth(requested, config, expected):
    assert resolve_depth(requested, config) == expected


# ---------------------------------------------------------------------------
# Termination and bounds: the graph does not choose how much work happens.
# ---------------------------------------------------------------------------


def test_a_dependency_cycle_terminates():
    edges = {"a": {"b"}, "b": {"c"}, "c": {"a", "b"}}
    result, analysed = _walk("a", -1, edges)
    assert sorted(r.name for r in result.reports) == ["b", "c"]
    assert "a" not in analysed             # the root is never re-analysed
    assert len(analysed) == len(set(analysed))


def test_a_dependency_is_analysed_once_per_run():
    """A diamond must not analyse the shared dependency twice."""
    edges = {"a": {"b", "c"}, "b": {"d"}, "c": {"d"}, "d": set()}
    result, analysed = _walk("a", -1, edges)
    assert analysed.count("d") == 1
    assert sorted(r.name for r in result.reports) == ["b", "c", "d"]


def test_the_level_ceiling_bounds_an_exhaustive_walk():
    """-1 cannot mean unbounded: the graph is written by the party reviewed."""
    edges = {f"p{i}": {f"p{i + 1}"} for i in range(MAX_DEPTH_LEVELS + 5)}
    result, _ = _walk("p0", -1, edges, aur=set(edges) | {f"p{MAX_DEPTH_LEVELS + 5}"})
    assert len(result.reports) == MAX_DEPTH_LEVELS
    assert result.truncated is True
    assert "levels" in result.reason


def test_the_node_ceiling_bounds_a_wide_walk():
    """Breadth is as unbounded as depth without a second ceiling."""
    children = {f"w{i}" for i in range(MAX_DEPTH_NODES + 50)}
    result, _ = _walk("root", 1, {"root": children}, aur=children)
    assert len(result.reports) == MAX_DEPTH_NODES
    assert result.truncated is True
    assert str(MAX_DEPTH_NODES) in result.reason


def test_a_finite_depth_is_still_bounded_by_the_level_ceiling():
    """`--depth 999` is not a way around the constant."""
    edges = {f"p{i}": {f"p{i + 1}"} for i in range(MAX_DEPTH_LEVELS + 5)}
    result, _ = _walk("p0", 999, edges, aur=set(edges) | {f"p{MAX_DEPTH_LEVELS + 5}"})
    assert len(result.reports) == MAX_DEPTH_LEVELS


# ---------------------------------------------------------------------------
# What is and is not in scope.
# ---------------------------------------------------------------------------


def test_only_aur_dependencies_are_analysed():
    """An official-repo dependency has no AUR recipe to read."""
    edges = {"a": {"b", "glibc"}}
    result, analysed = _walk("a", -1, edges, aur={"a", "b"})
    assert [r.name for r in result.reports] == ["b"]
    assert "glibc" not in analysed


def test_a_failed_dependency_is_reported_and_is_a_gap():
    """"Not vetted" and "vetted, clean" must never look the same."""
    def boom(name):
        if name == "b":
            raise RuntimeError("clone failed")
        return FakeFact()

    result, _ = _walk("a", -1, {"a": {"b"}, "b": {"c"}}, aur={"a", "b", "c"},
                      analyse=boom)
    failed = [r for r in result.reports if r.failed]
    assert [r.name for r in failed] == ["b"]
    assert "clone failed" in failed[0].error
    assert result.truncated is True


def test_a_dependency_carries_its_own_score_and_band():
    """A dependency is a package, not a component of one."""
    def analyse(name):
        return FakeFact(final_score=40, risk="High")

    result, _ = _walk("a", 1, {"a": {"b"}}, analyse=analyse)
    dep = result.reports[0]
    assert dep.score == 40
    assert dep.risk == "High"
    assert dep.flagged is True
    assert result.flagged == (dep,)


def test_a_clean_dependency_is_not_flagged():
    result, _ = _walk("a", 1, {"a": {"b"}})
    assert result.reports[0].flagged is False
    assert result.flagged == ()


# ---------------------------------------------------------------------------
# Metadata providers.
# ---------------------------------------------------------------------------


def test_the_snapshot_provider_needs_no_network():
    snap = SnapshotMetadata({
        "a": {"Depends": ["b>=1.0"], "MakeDepends": ["npm"]},
        "b": {},
    })
    assert snap.is_aur("a") is True
    assert snap.is_aur("not-in-the-aur") is False
    # Version constraints are stripped; makedepends are in scope.
    assert snap.deps_of("a") == {"b", "npm"}


def test_the_rpc_provider_batches_one_request_per_level():
    """Fifty dependencies is one request, not fifty."""
    calls = []

    def fetch(names):
        calls.append(list(names))
        return {"x": {"Depends": ["y"], "Name": "x"}}

    rpc = RpcMetadata(fetch=fetch)
    rpc.prime(["x", "y", "z"])
    assert calls == [["x", "y", "z"]]

    # A name the RPC does not know is not in the AUR, and is not re-fetched.
    assert rpc.is_aur("x") is True
    assert rpc.is_aur("y") is False
    assert calls == [["x", "y", "z"]]
    assert rpc.deps_of("x") == {"y"}


def test_a_report_serialises_to_plain_data():
    dep = DependencyReport(name="d", depth=2, score=30, risk="Medium",
                           risk_label="Medium", finding_count=1,
                           coverage_gaps=("unpinned_build_deps",))
    body = dep.to_dict()
    assert body["name"] == "d"
    assert body["depth"] == 2
    assert body["coverage_gaps"] == ["unpinned_build_deps"]
    assert body["failed"] is False
