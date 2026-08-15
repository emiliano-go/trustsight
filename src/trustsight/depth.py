"""Analysing a package's AUR dependency closure.

An AUR package's `depends` and `makedepends` can name other AUR packages,
and those are built on the reviewer's machine by the same `makepkg` run. A
review that reads only the package you typed is reading one recipe out of
however many will actually execute. The June 2026 campaign is the argument:
it hijacked orphans, and an orphan is far more often somebody's dependency
than the thing they meant to install.

**Each dependency is analysed exactly as a package.** It gets its own
`PackageFact`, its own score, its own band, its own coverage gaps, and its
own row in the database under its own name. Nothing is folded into the
parent's score, and that is not squeamishness: [B1] promises the same diff
under the same `config_fingerprint` produces the same number, `depth` is
deliberately absent from that fingerprint, and a parent whose score moved
with `--depth` would break the promise for every operator comparing runs.
So the parent reports its dependencies; it does not absorb them.

Depth:

===========  ==========================================================
``0``        Dependencies are not analysed.
``1``        Direct AUR dependencies. The default.
``n``        ``n`` levels.
``-1``       Every level there is, subject to the two ceilings below.
===========  ==========================================================

``-1`` is bounded, and it has to be. The dependency graph is written by the
party under review: a recipe may declare five hundred AUR `makedepends`,
each declaring five hundred more, and a genuinely unbounded walk would let
that recipe decide how many repositories this machine clones. [A14] says no
package-controlled input decides how much CPU, memory, network or disk this
process uses, and [Part D] lists unbounded resource use from a crafted
package as a vulnerability. So ``-1`` means "as deep as it goes" up to
``MAX_DEPTH_LEVELS`` and ``MAX_DEPTH_NODES``, and stopping early is recorded
as the ``deps_not_scanned`` coverage gap rather than passed off as a
finished walk.

A *completed* walk is not a gap. Asking for depth 1 and getting depth 1 is
a complete answer to the question that was asked, even though a level 2
exists; the operator chose the question. Only a walk cut short by a ceiling,
or a dependency whose own analysis failed, leaves something unexamined that
the reader was not told about.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Iterable, Optional, Protocol

#: Hardest ceiling on how many levels ``-1`` will walk.  A real AUR closure
#: is a handful deep; this is the constant that stops a crafted chain from
#: choosing the number for us.
MAX_DEPTH_LEVELS = 8

#: Hardest ceiling on how many dependencies one run will analyse, across
#: every level and every root.  Each one is a clone and an analysis, so this
#: is the bound that matters for wall-clock and disk.
MAX_DEPTH_NODES = 200

#: Dependency fields that describe something built or installed alongside
#: the package.  ``optdepends`` is excluded: it is not pulled in by default,
#: so analysing it would report on software the reviewer is not installing.
#: ``makedepends`` is emphatically included - it is the June 2026 vector.
DEPTH_FIELDS = ("depends", "makedepends", "checkdepends")


class MetadataProvider(Protocol):
    """Whatever can answer "is this in the AUR" and "what does it need".

    Injected rather than imported so the walk is testable offline and so the
    caller decides whether that costs a network round trip: the metadata
    snapshot answers both questions with no request at all.
    """

    def is_aur(self, name: str) -> bool: ...

    def deps_of(self, name: str) -> set[str]: ...


@dataclass(frozen=True)
class DependencyReport:
    """One analysed dependency, as the parent reports it.

    A summary rather than a nested ``PackageFact``: the dependency's full
    analysis is persisted under its own name by the same code that analyses
    any package, so duplicating it inside the parent's stored record would
    bloat ``fact_json`` without adding a fact. This is what a reader needs
    to decide whether to go and look.
    """

    name: str
    depth: int
    score: int = 0
    risk: str = ""
    risk_label: str = ""
    finding_count: int = 0
    coverage_gaps: tuple[str, ...] = ()
    #: Which dependency field of which package brought this in.
    via: str = ""
    parent: str = ""
    #: True when the dependency could not be analysed at all.  Distinct from
    #: a clean result, and the reason the walk reports a gap.
    failed: bool = False
    error: str = ""

    @property
    def flagged(self) -> bool:
        from .scoring import FLAG_THRESHOLD

        return self.score > FLAG_THRESHOLD

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "depth": self.depth,
            "score": self.score,
            "risk": self.risk,
            "risk_label": self.risk_label,
            "finding_count": self.finding_count,
            "coverage_gaps": list(self.coverage_gaps),
            "via": self.via,
            "parent": self.parent,
            "failed": self.failed,
            "error": self.error,
        }


@dataclass
class DepthResult:
    """Everything one closure walk produced."""

    reports: list[DependencyReport] = field(default_factory=list)
    #: The walk stopped before the closure was exhausted, so something the
    #: reader was not shown remains unexamined.  Drives ``deps_not_scanned``.
    truncated: bool = False
    #: Why, for the report text.
    reason: str = ""

    @property
    def flagged(self) -> tuple[DependencyReport, ...]:
        return tuple(r for r in self.reports if r.flagged)


def resolve_depth(requested: Optional[int], config: Optional[dict] = None) -> int:
    """The depth to use: the flag if given, else config, else 1.

    A value below ``-1`` is meaningless rather than dangerous, so it is
    clamped to ``-1`` instead of raising: the operator asked for "deeper
    than everything", and everything is what they get.
    """
    if requested is None:
        section = (config or {}).get("depth") or {}
        value = section.get("levels", 1)
    else:
        value = requested
    try:
        depth = int(value)
    except (TypeError, ValueError):
        return 1
    return -1 if depth < -1 else depth


def _wanted(level: int, depth: int) -> bool:
    """Is *level* inside the requested depth?"""
    if depth == 0:
        return False
    if depth == -1:
        return level <= MAX_DEPTH_LEVELS
    return level <= min(depth, MAX_DEPTH_LEVELS)


def walk_dependencies(
    root: str,
    *,
    depth: int,
    metadata: MetadataProvider,
    analyse: Callable[[str], object],
    already_seen: Optional[set[str]] = None,
) -> DepthResult:
    """Analyse the AUR dependency closure of *root*.

    *analyse* takes a package name and returns something with ``final_score``,
    ``risk``, ``score_breakdown`` and ``coverage_gaps`` - in production a
    ``PackageFact`` from the ordinary analysis path, because a dependency is
    analysed as a package and not by some reduced copy of the pipeline.
    Raising is allowed and is recorded as a failed dependency.

    *already_seen* is shared across roots by a batch run so one dependency
    is analysed once even when twenty packages need it.
    """
    result = DepthResult()
    if depth == 0:
        return result

    seen: set[str] = already_seen if already_seen is not None else set()
    seen.add(root)

    # (name, via, parent) so a report can say how it got here.
    frontier: list[tuple[str, str, str]] = list(_aur_children(root, metadata, seen))
    level = 1

    while frontier and _wanted(level, depth):
        nxt: list[tuple[str, str, str]] = []
        for name, via, parent in frontier:
            if name in seen:
                continue
            if len(result.reports) >= MAX_DEPTH_NODES:
                result.truncated = True
                result.reason = (
                    f"stopped after {MAX_DEPTH_NODES} dependencies; the closure "
                    "is larger than one run analyses"
                )
                return result
            seen.add(name)
            result.reports.append(_analyse_one(name, level, via, parent, analyse))
            if result.reports[-1].failed:
                result.truncated = True
                result.reason = result.reason or (
                    f"{name} could not be analysed, so its own dependencies "
                    "were not reached either"
                )
                continue
            nxt.extend(_aur_children(name, metadata, seen))
        frontier = nxt
        level += 1

    # Only an exhaustive walk can be cut short by a level ceiling: a finite
    # depth that completed answered the question it was asked.
    if frontier and depth == -1 and level > MAX_DEPTH_LEVELS:
        result.truncated = True
        result.reason = (
            f"stopped at {MAX_DEPTH_LEVELS} levels; the closure is deeper than "
            "one run walks"
        )
    return result


def _aur_children(
    name: str, metadata: MetadataProvider, seen: set[str]
) -> Iterable[tuple[str, str, str]]:
    """AUR dependencies of *name* not already visited."""
    from .deps import normalize_dependency

    out: list[tuple[str, str, str]] = []
    try:
        children = metadata.deps_of(name)
    except Exception:
        return out
    for raw in sorted(children):
        dep = normalize_dependency(raw)
        if not dep or dep in seen:
            continue
        try:
            if not metadata.is_aur(dep):
                continue
        except Exception:
            continue
        out.append((dep, "depends", name))
    return out


def _analyse_one(
    name: str, level: int, via: str, parent: str, analyse: Callable[[str], object]
) -> DependencyReport:
    """Analyse one dependency, turning any failure into a reported one.

    A dependency that cannot be analysed is reported as failed rather than
    dropped: "this was not vetted" and "this was vetted and was clean" must
    never look the same, which is the same rule the batch path applies to a
    package it could not read.
    """
    from .scoring import verdict_label, verdict_level

    try:
        fact = analyse(name)
    except Exception as exc:  # noqa: BLE001 - any failure is a failed dep
        return DependencyReport(name=name, depth=level, via=via, parent=parent,
                                failed=True, error=str(exc)[:200])
    if fact is None:
        return DependencyReport(name=name, depth=level, via=via, parent=parent,
                                failed=True, error="analysis returned nothing")

    findings = [
        entry for entry in getattr(fact, "score_breakdown", ())
        if getattr(entry, "weight", 0) > 0
        or getattr(entry, "severity", "") in ("FATAL", "CRITICAL")
    ]
    return DependencyReport(
        name=name,
        depth=level,
        score=getattr(fact, "final_score", 0) or 0,
        risk=verdict_level(fact),
        risk_label=verdict_label(fact),
        finding_count=len(findings),
        coverage_gaps=tuple(getattr(fact, "coverage_gaps", ()) or ()),
        via=via,
        parent=parent,
    )


class SnapshotMetadata:
    """Answers from the corpus metadata snapshot, with no network at all.

    Preferred when a snapshot exists: a full-AUR bootstrap has already
    downloaded every package's dependency arrays, so a closure walk costs
    nothing beyond the analyses themselves.
    """

    def __init__(self, packages: dict):
        self._packages = packages

    def is_aur(self, name: str) -> bool:
        return name in self._packages

    def deps_of(self, name: str) -> set[str]:
        from .deps import normalize_dependency

        entry = self._packages.get(name) or {}
        out: set[str] = set()
        for field_name in DEPTH_FIELDS:
            # The snapshot uses the RPC's capitalisation.
            for key in (field_name, field_name.capitalize(),
                        _RPC_FIELDS.get(field_name, "")):
                for dep in entry.get(key) or []:
                    normalized = normalize_dependency(dep)
                    if normalized:
                        out.add(normalized)
        return out


#: The RPC's names for the fields ``DEPTH_FIELDS`` describes.
_RPC_FIELDS = {
    "depends": "Depends",
    "makedepends": "MakeDepends",
    "checkdepends": "CheckDepends",
}


class RpcMetadata:
    """Answers from the AUR RPC, one batched request per level.

    Batched deliberately: the RPC takes many names per call, so a level of
    fifty dependencies is one request rather than fifty.  Results are
    memoised for the run, and a name the RPC does not know is not in the AUR.
    """

    def __init__(self, fetch=None):
        from .discovery import get_aur_package_info

        self._fetch = fetch or get_aur_package_info
        self._cache: dict[str, dict] = {}

    def prime(self, names: Iterable[str]) -> None:
        """Fetch every unknown name in *names* in one request."""
        wanted = [n for n in dict.fromkeys(names) if n not in self._cache]
        if not wanted:
            return
        try:
            found = self._fetch(wanted)
        except Exception:
            found = {}
        for name in wanted:
            self._cache[name] = found.get(name) or {}

    def is_aur(self, name: str) -> bool:
        if name not in self._cache:
            self.prime([name])
        return bool(self._cache.get(name))

    def deps_of(self, name: str) -> set[str]:
        from .deps import normalize_dependency

        if name not in self._cache:
            self.prime([name])
        entry = self._cache.get(name) or {}
        out: set[str] = set()
        for field_name in DEPTH_FIELDS:
            for dep in entry.get(_RPC_FIELDS[field_name]) or []:
                normalized = normalize_dependency(dep)
                if normalized:
                    out.add(normalized)
        return out


def default_metadata() -> MetadataProvider:
    """The snapshot when there is one, the RPC otherwise."""
    from .full_aur.metadata import load_metadata

    try:
        packages = load_metadata()
    except Exception:
        packages = None
    if packages:
        return SnapshotMetadata(packages)
    return RpcMetadata()
