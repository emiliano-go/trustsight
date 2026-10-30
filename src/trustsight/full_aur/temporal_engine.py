"""The temporal engine: the single home for the history-backed H/T rules.

This is the cycle-scope half of the H-series reduction. Before this module the
history-backed rules lived in four places - :mod:`~trustsight.full_aur.corpus`,
:mod:`~trustsight.full_aur.graph`, :mod:`~trustsight.analysis.temporal` and
:mod:`~trustsight.analysis.longitudinal` - each reading the observation
database or the metadata snapshots its own way.  They share one input
(history) and a handful of predicates, so they are one engine:

* :class:`HistorySnapshot` - the cycle's history read **once**, from
  :func:`read_cycle_history` and the two metadata snapshots, and passed to
  every instance rather than each rule querying the database again.
* :data:`CYCLE_INSTANCES` / :data:`PER_PACKAGE_INSTANCES` - one row per rule
  id: its predicate class, scope, severity and category.  A row with an
  ``emitter`` runs in :func:`run_cycle_instances`; the per-package rows name
  the predicate the rule already implements so the whole family is described
  in one table.
* :func:`run_cycle_instances` - the cycle-scope dispatch.

Rule ids, severities and finding text are unchanged: this is a machinery
consolidation, not a behaviour change.  The locked-corpus replay and the
Class-D calibration gate are the proof.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from ..config import load_thresholds
from ..novelty import normalize_url
from ._temporal_adoption import (
    _attribute_burst,
    _introduction_deviation,
    _maintainer_deviation_findings,
    _mass_adoption,
    _shared_repo_cluster,
)
from ._temporal_divergence import (
    _name_host_divergence_findings,
    _name_repo_divergence_findings,
)
from ._temporal_transitions import (
    _adopt_then_modify_findings,
    _ownership_transition_findings,
)
from .graph import run_graph_sweep
from .metadata import diff_metadata

#: Predicate classes the family reduces to.  Every row below is one of these.
PREDICATES = (
    "rate_deviation",     # a count in a window against a baseline
    "gap_revival",        # a clock gap between observations
    "transition",         # old state -> new state (maintainer, orphan)
    "baseline_deviation", # a tracked property against its own stable baseline
    "graph_reachability", # transitive closure over dependency edges
    "consensus",          # a name/host/repo consensus break
)


@dataclass(frozen=True)
class HistorySnapshot:
    """One cycle's history, read once and shared by every instance."""

    new_meta: dict
    old_meta: dict | None
    changes: dict
    transitions: dict
    source_repos: dict[str, set[str]]
    prior_history: list = field(default_factory=list)
    maintainer_history: list = field(default_factory=list)
    edges: dict[str, set[str]] | None = None
    routine_only: frozenset[str] = field(default_factory=frozenset)
    now: int = 0

    @classmethod
    def from_cycle(
        cls,
        new_meta: dict,
        old_meta: dict | None,
        *,
        source_repos: dict[str, set[str]] | None = None,
        prior_history: list | None = None,
        maintainer_history: list | None = None,
        edges: dict[str, set[str]] | None = None,
        routine_only: set[str] | frozenset[str] | None = None,
        now: int = 0,
    ) -> "HistorySnapshot":
        """Capture the cycle's derived history in one object.

        The two metadata snapshots are already in memory; the database reads
        arrive through *prior_history*/*maintainer_history* (see
        :func:`read_cycle_history`), so the snapshot is a pure value and the
        rules never touch the database themselves.
        """
        if old_meta is None:
            changes: dict = {}
            transitions: dict = {}
        else:
            changes = diff_metadata(old_meta, new_meta)
            transitions = _ownership_transitions(old_meta, new_meta)
        return cls(
            new_meta=new_meta,
            old_meta=old_meta,
            changes=changes,
            transitions=transitions,
            source_repos=source_repos or {},
            prior_history=prior_history or [],
            maintainer_history=maintainer_history or [],
            edges=edges,
            routine_only=frozenset(routine_only or ()),
            now=now,
        )


@dataclass(frozen=True)
class TemporalInstance:
    """One rule id's row in the engine's descriptor table.

Each id is a row of *predicate + parameters +
    doc fragment + fixture pair*.  ``parameters`` names the threshold keys
    the predicate reads, ``doc`` is its reference page, and ``fixtures`` are
    the tests that prove it, so the family's specification is the table
    itself rather than prose that can drift from the code.
    """

    rule_id: str
    name: str
    predicate: str
    scope: str  # "cycle" | "package"
    severity: str
    category: str
    emitter: Callable[[HistorySnapshot], list[dict]] | None = None
    parameters: tuple[str, ...] = ()
    doc: str = ""
    fixtures: tuple[str, ...] = ()


#: A shared-cache slot for the once-per-cycle history read.  Keyed by the
#: cycle's timestamp so a new cycle invalidates it; entries from older cycles
#: are dropped by :func:`clear_history_cache`.
_HISTORY_CACHE: dict = {}


def clear_history_cache() -> None:
    """Drop the cached cycle history (new cycle, or a test)."""
    _HISTORY_CACHE.clear()


def read_cycle_history(processed=None, *, refresh: bool = False) -> dict:
    """The shared, cached once-per-cycle history read.

    Reads the two whole-table feeds the rate/baseline predicates need and
    memoises them per cycle.  A caller runs this once per metadata cycle and
    passes the result into :meth:`HistorySnapshot.from_cycle`; individual
    rules no longer each call ``db.introduction_rate_history`` /
    ``db.maintainer_activity_history``.  *refresh* forces a re-read.
    """
    from ..db import (
        introduction_rate_history,
        latest_cycle_time,
        maintainer_activity_history,
    )

    key = latest_cycle_time()
    if refresh or key not in _HISTORY_CACHE:
        _HISTORY_CACHE.clear()
        _HISTORY_CACHE[key] = {
            "prior_history": introduction_rate_history(),
            "maintainer_history": maintainer_activity_history(),
        }
    return _HISTORY_CACHE[key]


def _threshold(rule: str, key: str, default):
    return load_thresholds().get(rule, {}).get(key, default)


def _ownership_transitions(old_meta: dict, new_meta: dict) -> dict[str, tuple[str, str]]:
    """``{name: (old_maintainer, new_maintainer)}`` for maintainer changes."""
    out: dict[str, tuple[str, str]] = {}
    for name, entry in new_meta.items():
        old = old_meta.get(name)
        if old is None:
            continue
        old_m = (old.get("Maintainer") or "").strip().lower()
        new_m = (entry.get("Maintainer") or "").strip().lower()
        if old_m != new_m:
            out[name] = (old_m, new_m)
    return out


#: The cycle-scope instance table: one row per id, its predicate class, and
#: the emitter the engine dispatches to.  The graph ids are executed together
#: by :func:`run_graph_sweep` (their shared producer); they are rows here so
#: the whole family is described in one table.
CYCLE_INSTANCES: tuple[TemporalInstance, ...] = (
    TemporalInstance(
        "H045", "Mass Adoption", "rate_deviation", "cycle", "HIGH", "adoption",
        _mass_adoption,
        parameters=("h045.min_packages", "h045.window_days"),
        doc="docs/reference/rules/count-based.md",
        fixtures=("tests/test_class_d.py",)),
    TemporalInstance(
        "H055", "Attribute Burst", "rate_deviation", "cycle", "MEDIUM", "adoption",
        _attribute_burst,
        parameters=("h055.min_packages", "h055.window_hours"),
        doc="docs/reference/rules/count-based.md",
        fixtures=("tests/test_class_d.py",)),
    TemporalInstance(
        "H052", "Shared Source Repo Cluster", "rate_deviation", "cycle", "HIGH", "corpus",
        _shared_repo_cluster,
        parameters=("h052.min_packages",),
        doc="docs/reference/rules/count-based.md",
        fixtures=("tests/test_class_d.py",)),
    TemporalInstance(
        "H073", "Introduction-Rate Deviation", "baseline_deviation", "cycle", "MEDIUM", "corpus",
        _introduction_deviation,
        parameters=("h073.min_history_cycles", "h073.z_score", "h073.min_introduced"),
        doc="docs/reference/rules/corpus-behavioral.md",
        fixtures=("tests/test_class_d.py",)),
    TemporalInstance(
        "H058", "Maintainer Baseline Deviation", "baseline_deviation", "cycle", "MEDIUM", "adoption",
        _maintainer_deviation_findings,
        parameters=("h058.min_history_cycles", "h058.z_score", "h058.min_activity"),
        doc="docs/reference/rules/maintainer-and-metadata.md",
        fixtures=("tests/test_class_d.py",)),
    TemporalInstance(
        "H044", "Ownership Transition", "transition", "cycle", "MEDIUM", "maintainer",
        _ownership_transition_findings,
        doc="docs/reference/rules/maintainer-and-metadata.md",
        fixtures=("tests/test_class_d.py",)),
    # H026 ships from the same producer as H044 (one transition, two claims);
    # the emitter above emits both, so this row documents the id without a
    # second call.
    TemporalInstance(
        "H026", "New Maintainer Without Prior History", "transition", "cycle", "HIGH", "maintainer",
        doc="docs/reference/rules/maintainer-and-metadata.md",
        fixtures=("tests/test_class_d.py",)),
    TemporalInstance(
        "H074", "Adopt-then-Modify", "transition", "cycle", "MEDIUM", "maintainer",
        _adopt_then_modify_findings,
        parameters=("h074.window_days",),
        doc="docs/reference/rules/maintainer-and-metadata.md",
        fixtures=("tests/test_class_d.py",)),
    TemporalInstance(
        "H053", "Ecosystem/Host Divergence", "consensus", "cycle", "MEDIUM", "naming",
        _name_host_divergence_findings,
        doc="docs/reference/rules/naming-and-dependency.md",
        fixtures=("tests/test_class_d.py",)),
    TemporalInstance(
        "H059", "Name/Repo Divergence", "consensus", "cycle", "MEDIUM", "naming",
        _name_repo_divergence_findings,
        doc="docs/reference/rules/naming-and-dependency.md",
        fixtures=("tests/test_class_d.py",)),
)

#: The graph-scope rows, executed by :func:`run_graph_sweep` as one producer.
GRAPH_INSTANCES: tuple[TemporalInstance, ...] = (
    TemporalInstance(
        "H046", "Orphan/Adoption Dependency", "graph_reachability", "cycle", "MEDIUM", "dependency",
        doc="docs/reference/rules/corpus-behavioral.md",
        fixtures=("tests/test_class_d.py",)),
    TemporalInstance(
        "H057", "Transitive Exposure", "graph_reachability", "cycle", "INFO", "dependency",
        parameters=("h057.min_hops",),
        doc="docs/reference/rules/corpus-behavioral.md",
        fixtures=("tests/test_class_d.py",)),
    TemporalInstance(
        "H060", "Transitive Orphan Risk", "graph_reachability", "cycle", "INFO", "dependency",
        parameters=("h060.min_hops",),
        doc="docs/reference/rules/corpus-behavioral.md",
        fixtures=("tests/test_class_d.py",)),
    TemporalInstance(
        "H061", "Dependency Centrality", "graph_reachability", "cycle", "INFO", "dependency",
        parameters=("h061.min_dependents",),
        doc="docs/reference/rules/corpus-behavioral.md",
        fixtures=("tests/test_class_d.py",)),
)

#: The per-package rows: the rules the single-package path runs against the
#: observation database.  Their emitters live in their own modules (the
#: repo-backed recency half is git-only, which a metadata cycle cannot read);
#: the row records the predicate so the family is described in one place.
PER_PACKAGE_INSTANCES: tuple[TemporalInstance, ...] = (
    TemporalInstance(
        "H020", "Very Recent Update", "gap_revival", "package", "INFO", "temporal",
        parameters=("fixed:72h",),
        doc="docs/reference/rules/temporal.md",
        fixtures=("tests/regressions/test_checksum_and_evasion.py",)),
    TemporalInstance(
        "H021", "Brand New Package", "gap_revival", "package", "INFO", "temporal",
        parameters=("fixed:30d",),
        doc="docs/reference/rules/temporal.md",
        fixtures=("tests/regressions/test_checksum_and_evasion.py",)),
    TemporalInstance(
        "H022", "Stale Package Revived", "gap_revival", "package", "MEDIUM", "temporal",
        parameters=("fixed:365d",),
        doc="docs/reference/rules/temporal.md",
        fixtures=("tests/fixtures/history_corpus.py",)),
    # H028 (recent commit burst) is a metadata flag on the fact, never a
    # scored finding; the row records the predicate without an emitter.
    TemporalInstance(
        "H028", "Commit Burst", "rate_deviation", "package", "INFO", "corpus",
        parameters=("fixed:24h burst",),
        doc="docs/reference/rules/corpus-behavioral.md",
        fixtures=("tests/test_full_aur.py",)),
    TemporalInstance(
        "H026", "New Maintainer Without Prior History", "transition", "package", "HIGH", "maintainer",
        doc="docs/reference/rules/maintainer-and-metadata.md",
        fixtures=("tests/test_class_d.py",)),
    TemporalInstance(
        "H037", "Long-Stable Property Changed", "baseline_deviation", "package", "MEDIUM", "temporal",
        parameters=("longitudinal.stability_floor",),
        doc="docs/reference/rules/temporal.md",
        fixtures=("tests/test_longitudinal.py",)),
    TemporalInstance(
        "H047", "Security-Relevant Build Flag Change", "baseline_deviation", "package", "HIGH", "build",
        parameters=("longitudinal.stability_floor",),
        doc="docs/reference/rules/integrity.md",
        fixtures=("tests/test_longitudinal.py",)),
    TemporalInstance(
        "H048", "Dependency Vendored Into Source", "baseline_deviation", "package", "MEDIUM", "dependency",
        parameters=("longitudinal.stability_floor",),
        doc="docs/reference/rules/naming-and-dependency.md",
        fixtures=("tests/test_longitudinal.py",)),
    TemporalInstance(
        "H049", "Source Host Changed", "baseline_deviation", "package", "MEDIUM", "source",
        parameters=("longitudinal.stability_floor",),
        doc="docs/reference/rules/maintainer-and-metadata.md",
        fixtures=("tests/test_longitudinal.py",)),
    TemporalInstance(
        "H050", "Version Scheme Changed", "baseline_deviation", "package", "INFO", "context",
        parameters=("longitudinal.stability_floor",),
        doc="docs/reference/rules/maintainer-and-metadata.md",
        fixtures=("tests/test_longitudinal.py",)),
    TemporalInstance(
        "H051", "Package Description Changed", "baseline_deviation", "package", "MEDIUM", "integrity",
        parameters=("longitudinal.stability_floor",),
        doc="docs/reference/rules/maintainer-and-metadata.md",
        fixtures=("tests/test_longitudinal.py",)),
    TemporalInstance(
        "H054", "Build System Changed", "baseline_deviation", "package", "MEDIUM", "build",
        parameters=("longitudinal.stability_floor",),
        doc="docs/reference/rules/maintainer-and-metadata.md",
        fixtures=("tests/test_longitudinal.py",)),
    TemporalInstance(
        "H086", "Adopted From Orphan", "transition", "package", "MEDIUM", "maintainer",
        doc="docs/reference/rules/maintainer-and-metadata.md",
        fixtures=("tests/test_june_2026_campaign.py",)),
    TemporalInstance(
        "H087", "Recipe Changed Without Upstream", "baseline_deviation", "package", "MEDIUM", "integrity",
        doc="docs/reference/rules/integrity.md",
        fixtures=("tests/test_june_2026_campaign.py",)),
    TemporalInstance(
        "H088", "Adopted, Recipe Rewritten, Unpinned Fetch", "transition", "package", "HIGH", "takeover",
        doc="docs/reference/rules/maintainer-and-metadata.md",
        fixtures=("tests/test_june_2026_campaign.py",)),
)


def run_cycle_instances(snapshot: HistorySnapshot) -> list[dict]:
    """Dispatch the cycle-scope instances for one metadata cycle.

    A fresh bootstrap (no prior snapshot) has no deviation, transition or
    burst to measure, so nothing fires - the Class-D ``fire_rate(no_baseline)
    == 0`` gate.
    """
    if snapshot.old_meta is None:
        return []
    findings: list[dict] = []
    for instance in CYCLE_INSTANCES:
        if instance.emitter is not None:
            findings += instance.emitter(snapshot)
    findings += run_graph_sweep(
        snapshot.new_meta,
        snapshot.old_meta,
        snapshot.changes,
        snapshot.transitions,
        edges=snapshot.edges,
    )
    return findings


def source_repos_from_pkgbuild(pkgbuild_text: str | None) -> set[str]:
    """Normalized upstream URLs declared by a full PKGBUILD text.

    Variables are resolved first: the raw spelling left ``$_name`` literal
    in the URL, so a package pulling its sdist by a declared variable
    (python-ten-vad-bin: ``${_name}-$pkgver.tar.gz``) had its repo path
    tokenized as ``$_name`` - which shares no token with anything and fired
    H059 on a name the resolved URL matches.
    """
    from ..differ import extract_source_array_urls
    from ..expansion import resolve_text, text_variable_table

    if not pkgbuild_text:
        return set()
    table = text_variable_table(pkgbuild_text)
    wrapped = "\n".join(
        " " + resolve_text(line, table)
        for line in pkgbuild_text.splitlines()
    )
    return {normalize_url(url) for url in extract_source_array_urls(wrapped, side="after")}


def run_corpus_sweep(
    new_meta: dict,
    old_meta: dict | None,
    *,
    source_repos: dict[str, set[str]] | None = None,
    prior_history: list[dict] | None = None,
    maintainer_history: list[dict] | None = None,
    edges: dict[str, set[str]] | None = None,
    routine_only: set[str] | None = None,
    now: int = 0,
) -> list[dict]:
    """Run the cycle-scope temporal instances over one metadata cycle."""
    snapshot = HistorySnapshot.from_cycle(
        new_meta,
        old_meta,
        source_repos=source_repos,
        prior_history=prior_history,
        maintainer_history=maintainer_history,
        edges=edges,
        routine_only=routine_only,
        now=now,
    )
    return run_cycle_instances(snapshot)
