"""The temporal engine: the single home for the history-backed H/T rules.

 of the H-series reduction. Before this module the history-backed
rules lived in four places - :mod:`~trustsight.full_aur.corpus`,
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

import statistics
from dataclasses import dataclass, field
from typing import Callable

from ..config import load_thresholds
from ..findings import stamp
from ..novelty import normalize_url
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

_SEVERITY = {
    "H045": "HIGH", "H052": "HIGH", "H055": "MEDIUM", "H073": "MEDIUM",
    "H044": "MEDIUM", "H074": "MEDIUM", "H026": "HIGH",
    "H053": "MEDIUM", "H058": "MEDIUM", "H059": "MEDIUM",
}

# Hosts where an ecosystem package would be expected to live; a divergence
# from every one of these for a prefixed package is H053's signal.
_FORGE_HOSTS = frozenset({
    "github.com", "gitlab.com", "codeberg.org", "bitbucket.org",
    "sourceforge.net", "gitea.com", "gitea.io", "git.sr.ht",
})

_ECOSYSTEM_HOSTS = {
    "python": {"pypi.org", "pypi.io", "files.pythonhosted.org", "pypi.python.org"},
    "python2": {"pypi.org", "pypi.io", "files.pythonhosted.org", "pypi.python.org"},
    "python3": {"pypi.org", "pypi.io", "files.pythonhosted.org", "pypi.python.org"},
    "perl": {"cpan.org", "metacpan.org"},
    "ruby": {"rubygems.org"},
    "nodejs": {"npmjs.com", "registry.npmjs.org"},
    "node": {"npmjs.com", "registry.npmjs.org"},
    "php": {"packagist.org"},
    "lua": {"luarocks.org"},
    "rust": {"crates.io", "static.crates.io"},
    "haskell": {"hackage.haskell.org"},
    "ocaml": {"opam.ocaml.org"},
    "texlive": {"ctan.org"},
    "r": {"cran.r-project.org", "cloud.r-project.org"},
}


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


def _maintainer(entry: dict | None) -> str:
    if not entry:
        return ""
    return (entry.get("Maintainer") or "").strip().lower()


def _last_modified(entry: dict | None) -> int | None:
    if not entry:
        return None
    lm = entry.get("LastModified")
    return int(lm) if isinstance(lm, (int, float)) and lm else None


def _package_base(entry: dict | None) -> str:
    if not entry:
        return ""
    return (entry.get("PackageBase") or entry.get("Name") or "").strip()


def _host_of(url: str) -> str:
    rest = url.split("://", 1)[-1]
    return rest.split("/", 1)[0].split("?")[0].split("#")[0].lower()


def _repo_path_tokens(url: str) -> set[str]:
    """Meaningful tokens from a source URL's path, minus version noise."""
    rest = url.split("://", 1)[-1]
    path = rest.split("/", 1)[1] if "/" in rest else ""
    tokens: set[str] = set()
    for part in path.split("/"):
        for piece in part.replace(".tar.gz", "").replace(".tgz", "").replace(
            ".tar", "").replace(".zip", "").replace(".git", "").split("."):
            piece = piece.rstrip("0123456789")
            if len(piece) >= 3:
                tokens.add(piece)
    return tokens


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


def _cluster(rule: str, name: str, match: str, members: list[str],
             severity: str | None = None, category: str = "adoption",
             **extra) -> dict:
    finding = {
        "rule_id": rule,
        "name": name,
        "severity": severity or _SEVERITY.get(rule, "MEDIUM"),
        "category": category,
        "match": match,
        "params": {"members": members, "member_count": len(members), **extra},
    }
    return stamp(finding)


def _mass_adoption(snapshot: HistorySnapshot) -> list[dict]:
    """H045: one maintainer files N packages within a short window."""
    new_meta, changes = snapshot.new_meta, snapshot.changes
    min_packages = _threshold("h045", "min_packages", 10)
    window_s = _threshold("h045", "window_days", 7) * 86400
    by_maintainer: dict[str, list[tuple[str, int]]] = {}
    for name, status in changes.items():
        if status != "added":
            continue
        maintainer = _maintainer(new_meta.get(name))
        if not maintainer:
            continue
        by_maintainer.setdefault(maintainer, []).append(
            (name, _last_modified(new_meta.get(name)) or 0)
        )
    findings: list[dict] = []
    for maintainer, pkgs in by_maintainer.items():
        if len(pkgs) < min_packages:
            continue
        timestamps = [ts for _, ts in pkgs]
        if max(timestamps) - min(timestamps) > window_s:
            continue
        members = sorted(pkg for pkg, _ in pkgs)
        findings.append(
            _cluster(
                "H045",
                "Mass Adoption",
                f"maintainer {maintainer} submitted {len(members)} packages within {_threshold('h045', 'window_days', 7)} days",
                members,
                maintainer=maintainer,
            )
        )
    return findings


def _attribute_burst(snapshot: HistorySnapshot) -> list[dict]:
    """H055: N packages sharing an attribute modified in a short window."""
    new_meta, changes = snapshot.new_meta, snapshot.changes
    min_packages = _threshold("h055", "min_packages", 5)
    window_s = _threshold("h055", "window_hours", 24) * 3600
    by_maintainer: dict[str, list[tuple[str, int]]] = {}
    for name, status in changes.items():
        if status != "modified":
            continue
        lm = _last_modified(new_meta.get(name))
        if lm is None:
            continue
        maintainer = _maintainer(new_meta.get(name))
        if not maintainer:
            continue
        by_maintainer.setdefault(maintainer, []).append((name, lm))
    findings: list[dict] = []
    for maintainer, pkgs in by_maintainer.items():
        if len(pkgs) < min_packages:
            continue
        timestamps = sorted(ts for _, ts in pkgs)
        if timestamps[-1] - timestamps[0] > window_s:
            continue
        members = sorted(pkg for pkg, _ in pkgs)
        findings.append(
            _cluster(
                "H055",
                "Attribute Burst",
                f"{len(members)} packages by maintainer {maintainer} modified within {_threshold('h055', 'window_hours', 24)}h",
                members,
                maintainer=maintainer,
            )
        )
    return findings


def _shared_repo_cluster(snapshot: HistorySnapshot) -> list[dict]:
    """H052: >= min_packages unrelated packages share a source repo."""
    new_meta, changes = snapshot.new_meta, snapshot.changes
    source_repos = snapshot.source_repos
    min_packages = _threshold("h052", "min_packages", 3)
    by_repo: dict[str, set[str]] = {}
    for name in changes:
        repos = source_repos.get(name) or set()
        for repo in repos:
            key = repo[:-4] if repo.endswith(".git") else repo
            by_repo.setdefault(key, set()).add(name)
    findings: list[dict] = []
    for repo, members in by_repo.items():
        if len(members) < min_packages:
            continue
        members_sorted = sorted(members)
        bases = {_package_base(new_meta.get(name)) for name in members_sorted}
        if len(bases) < min_packages:
            continue
        findings.append(
            _cluster(
                "H052",
                "Shared Source Repo Cluster",
                f"{len(members_sorted)} unrelated packages share source {repo}",
                members_sorted,
                repo=repo,
            )
        )
    return findings


def _introduction_deviation(snapshot: HistorySnapshot) -> list[dict]:
    """H073: this cycle's introduction rate deviates from the baseline."""
    changes = snapshot.changes
    prior_history = snapshot.prior_history
    min_cycles = _threshold("h073", "min_history_cycles", 3)
    z_score = float(_threshold("h073", "z_score", 3.0))
    min_introduced = _threshold("h073", "min_introduced", 3)
    if len(prior_history) < min_cycles:
        return []
    introduced = sum(1 for status in changes.values() if status == "added")
    if introduced < min_introduced:
        return []
    prior = [int(row["introduced"]) for row in prior_history]
    mean = statistics.mean(prior)
    if len(prior) >= 2 and statistics.stdev(prior) > 0:
        z = (introduced - mean) / statistics.stdev(prior)
    else:
        z = (introduced - mean) / max(mean, 1.0)
    if z < z_score:
        return []
    members = sorted(name for name, status in changes.items() if status == "added")
    return [
        _cluster(
            "H073",
            "Introduction-Rate Deviation",
            f"introduction rate {introduced} vs prior mean {mean:.0f} (z={z:.1f})",
            members,
            introduced=introduced,
            mean=round(mean),
            z_score=round(z, 2),
        )
    ]


def _known_maintainers(old_meta: dict) -> set[str]:
    """Every maintainer the previous snapshot knew of."""
    known: set[str] = set()
    for entry in old_meta.values():
        maintainer = (entry.get("Maintainer") or "").strip().lower()
        if maintainer:
            known.add(maintainer)
    return known


def _ownership_transition_findings(snapshot: HistorySnapshot) -> list[dict]:
    """H044 - a package changed maintainer this cycle, and H026 with it."""
    old_meta = snapshot.old_meta
    transitions = snapshot.transitions
    out: list[dict] = []
    known = _known_maintainers(old_meta or {})
    for name, (old_m, new_m) in sorted(transitions.items()):
        if not new_m:
            continue
        out.append(_cluster(
            "H044",
            "Ownership Transition",
            f"maintainer of {name} changed from '{old_m or 'orphan'}' to '{new_m}'",
            [name],
            severity="MEDIUM",
            category="maintainer",
            old=old_m,
            new=new_m,
        ))
        if new_m not in known:
            out.append(_cluster(
                "H026",
                "Untrusted Maintainer Takeover",
                f"maintainer of {name} changed to '{new_m}', who maintained "
                f"no package in the previous snapshot",
                [name],
                severity="HIGH",
                category="maintainer",
                previous_maintainer=old_m,
                current_maintainer=new_m,
            ))
    return out


def _adopt_then_modify_findings(snapshot: HistorySnapshot) -> list[dict]:
    """H074 - adopt-then-immediately-modify (fires on the first package)."""
    new_meta, old_meta = snapshot.new_meta, snapshot.old_meta
    transitions, now = snapshot.transitions, snapshot.now
    window_s = _threshold("h074", "window_days", 14) * 86400
    by_maintainer: dict[str, list[str]] = {}
    for name, (old_m, new_m) in transitions.items():
        if not new_m:
            continue
        old_v = (old_meta.get(name) or {}).get("Version")
        new_v = (new_meta.get(name) or {}).get("Version")
        if old_v == new_v:
            continue
        lm = _last_modified(new_meta.get(name))
        if lm is not None and now and (now - lm) > window_s:
            continue
        by_maintainer.setdefault(new_m, []).append(name)
    out: list[dict] = []
    for maintainer, members in by_maintainer.items():
        out.append(_cluster(
            "H074",
            "Adopt-then-Modify",
            f"maintainer {maintainer} adopted and immediately modified "
            f"{len(members)} package(s)",
            sorted(members),
            severity="MEDIUM",
            category="maintainer",
            maintainer=maintainer,
        ))
    return out


def _ecosystem_prefix_of(name: str) -> str | None:
    """Ecosystem prefix (with a known canonical host) for *name*, or None."""
    lower = name.lower()
    for prefix in sorted(_ECOSYSTEM_HOSTS, key=len, reverse=True):
        if lower.startswith(prefix + "-"):
            return prefix
    return None


def _name_host_divergence_findings(snapshot: HistorySnapshot) -> list[dict]:
    """H053 - name-token <-> host consensus divergence."""
    changes, source_repos = snapshot.changes, snapshot.source_repos
    out: list[dict] = []
    for name, status in changes.items():
        if status != "added":
            continue
        prefix = _ecosystem_prefix_of(name)
        if not prefix:
            continue
        repos = source_repos.get(name) or set()
        if not repos:
            continue
        hosts = {_host_of(r) for r in repos}
        canonical = _ECOSYSTEM_HOSTS[prefix]
        if hosts & canonical:
            continue
        if hosts & _FORGE_HOSTS:
            continue
        out.append(_cluster(
            "H053",
            "Ecosystem/Host Divergence",
            f"{name} claims the {prefix} ecosystem but sources from "
            f"{', '.join(sorted(hosts)[:3])}",
            [name],
            severity="MEDIUM",
            category="naming",
            prefix=prefix,
            hosts=sorted(hosts),
        ))
    return out


def _name_repo_divergence_findings(snapshot: HistorySnapshot) -> list[dict]:
    """H059 - package name and source repo share no token."""
    from ..deps import _package_stem

    changes, source_repos = snapshot.changes, snapshot.source_repos
    out: list[dict] = []
    for name, status in changes.items():
        if status != "added":
            continue
        repos = source_repos.get(name) or set()
        if not repos:
            continue
        tokens = {t for t in _package_stem(name).split("-") if len(t) >= 3}
        if len(tokens) < 2:
            continue
        repo_tokens = set()
        for repo in repos:
            repo_tokens |= _repo_path_tokens(repo)
        if not repo_tokens:
            continue
        overlapping = any(
            t in rt or rt in t for t in tokens for rt in repo_tokens
        )
        if not overlapping:
            out.append(_cluster(
                "H059",
                "Name/Repo Divergence",
                f"{name} sources from {', '.join(sorted(repos)[:3])}, "
                "sharing no token with its name",
                [name],
                severity="MEDIUM",
                category="naming",
                repos=sorted(repos)[:3],
            ))
    return out


def _maintainer_deviation_findings(snapshot: HistorySnapshot) -> list[dict]:
    """H058 - a maintainer's activity deviates from their own baseline."""
    changes, new_meta = snapshot.changes, snapshot.new_meta
    maintainer_history = snapshot.maintainer_history
    min_cycles = int(_threshold("h058", "min_history_cycles", 3))
    z_score = float(_threshold("h058", "z_score", 2.0))
    min_activity = int(_threshold("h058", "min_activity", 3))
    prior_by_maintainer: dict[str, list[int]] = {}
    for row in maintainer_history:
        m = row.get("maintainer") or ""
        if m:
            prior_by_maintainer.setdefault(m, []).append(int(row.get("activity") or 0))
    activity_now: dict[str, list[str]] = {}
    for name, status in changes.items():
        if status == "removed":
            continue
        m = _maintainer(new_meta.get(name))
        if m:
            activity_now.setdefault(m, []).append(name)
    out: list[dict] = []
    for maintainer, members in activity_now.items():
        if len(members) < min_activity:
            continue
        prior = prior_by_maintainer.get(maintainer, [])
        if len(prior) < min_cycles:
            continue
        mean = statistics.mean(prior)
        if len(prior) >= 2 and statistics.stdev(prior) > 0:
            z = (len(members) - mean) / statistics.stdev(prior)
        else:
            z = (len(members) - mean) / max(mean, 1.0)
        if z < z_score:
            continue
        out.append(_cluster(
            "H058",
            "Maintainer Baseline Deviation",
            f"maintainer {maintainer} active on {len(members)} packages "
            f"vs prior mean {mean:.0f} (z={z:.1f})",
            sorted(members),
            severity="MEDIUM",
            maintainer=maintainer,
            activity=len(members),
            mean=round(mean),
            z_score=round(z, 2),
        ))
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
        "H026", "Untrusted Maintainer Takeover", "transition", "cycle", "HIGH", "maintainer",
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
        "H026", "Untrusted Maintainer Takeover", "transition", "package", "HIGH", "maintainer",
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
    """Normalized upstream URLs declared by a full PKGBUILD text."""
    from ..differ import extract_source_array_urls

    if not pkgbuild_text:
        return set()
    wrapped = "\n".join(" " + line for line in pkgbuild_text.splitlines())
    return {normalize_url(url) for url in extract_source_array_urls(wrapped, side="after")}


def run_corpus_sweep(
    new_meta: dict,
    old_meta: dict | None,
    *,
    source_repos: dict[str, set[str]] | None = None,
    prior_history: list[dict] | None = None,
    maintainer_history: list[dict] | None = None,
    edges: dict[str, set[str]] | None = None,
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
        now=now,
    )
    return run_cycle_instances(snapshot)
