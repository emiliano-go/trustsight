"""Bounded limits, dependency ordering and progress helpers."""

from collections import deque
from concurrent.futures import ThreadPoolExecutor
import sys

from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)
from rich.console import Console

import logging

from ..config import load_config
from ..db import get_package_profile, get_pkgbuild_snapshot
from ..deps import normalize_dependency
from ..depth import MAX_DEPTH_NODES
from ._pipeline_helpers import _HAS_RICH

log = logging.getLogger("trustsight.full_aur.pipeline")



def _fetch_workers() -> int:
    """How many PKGBUILD fetches run concurrently.

    The bootstrap's cost is dominated by one network fetch per package;
    fetching a window ahead in parallel is the biggest speedup.  It is bounded
    twice over: this worker count, and a per-host rate cap in the fetcher
    (``fetch._MIN_REQUEST_INTERVAL_BY_HOST``).  The GitHub AUR mirror is a CDN
    with a much smaller cap than the AUR's cgit, so more workers there buy
    throughput rather than idling; the cgit fallback stays capped and simply
    idles the surplus.  Tunable via ``limits.corpus_fetch_workers``.
    """
    try:
        configured = int(load_config().get("limits", {}).get("corpus_fetch_workers", 0))
    except (TypeError, ValueError):
        configured = 0
    return configured if configured > 0 else 16


def _max_per_cycle() -> int:
    """Cap on packages processed per invocation, so a large delta or a
    bootstrap advances in bounded, resumable chunks instead of one avalanche.

    Default 2000.  Set ``limits.corpus_max_per_cycle`` to another value, or to
    ``0`` to disable the cap and process the whole delta in one run.
    """
    limits = load_config().get("limits", {})
    if "corpus_max_per_cycle" not in limits:
        return 2000
    try:
        n = int(limits["corpus_max_per_cycle"])
    except (TypeError, ValueError):
        return 2000
    return n if n > 0 else 0


#: Direct dependency fields the AUR metadata dump carries.  Same fields as
#: ``depth.DEPTH_FIELDS``, under the RPC's capitalisation.
_META_DEPENDENCY_FIELDS = ("Depends", "MakeDepends", "CheckDepends")

#: How many distinct dependency names the prefill scan may inspect before it
#: gives up.  The cap on *fetches* is ``MAX_DEPTH_NODES``; this one bounds the
#: database lookups a crafted metadata entry could ask for, and leaves room
#: for many already-stored names before the fetches are chosen.
_MAX_PREFILL_CANDIDATES = MAX_DEPTH_NODES * 10


def _needs_dependency_prefill(name: str) -> bool:
    """True when the corpus has no usable stored result for *name*.

    Mirrors :func:`full_aur.analyze._corpus_dependency_fact`: a profile with
    a score or a PKGBUILD snapshot is enough, and anything less leaves the
    dependency walk unable to read it.
    """
    profile = get_package_profile(name)
    if profile and profile.get("last_score") is not None:
        return False
    row = get_pkgbuild_snapshot(name)
    return not (row and row.get("pkgbuild_text"))


#: Cap on the metadata edges the dependency-first ordering will read.  Above
#: it the cycle keeps the delta's natural order; the cap bounds CPU/memory a
#: crafted metadata dump could ask for, and a missed edge only means a
#: same-cycle dependency may still leave a gap for one run.
_MAX_ORDER_CANDIDATES = MAX_DEPTH_NODES * 50


def _dependencies_first(pending: list[str], new_meta: dict[str, dict]) -> list[str]:
    """Order *pending* so a dependency is analysed before its dependents.

    The full-AUR walk reads a stored result.  When a dependency changed in
    the same cycle as a package that needs it, analysing the dependent first
    would report ``deps_not_scanned`` for a package the cycle is about to
    process anyway.  A stable Kahn ordering removes that transient without
    changing the set or hiding a diff.  A cycle or an over-cap metadata edge
    list falls back to the delta's order.
    """
    from heapq import heappop, heappush

    pending_set = set(pending)
    edges: dict[str, set[str]] = {name: set() for name in pending}
    dependents: dict[str, list[str]] = {}
    examined = 0
    for parent in pending:
        entry = new_meta.get(parent) or {}
        for field_name in _META_DEPENDENCY_FIELDS:
            for raw in entry.get(field_name) or ():
                examined += 1
                if examined > _MAX_ORDER_CANDIDATES:
                    return pending
                dep = normalize_dependency(raw)
                if not dep or dep not in pending_set or dep == parent:
                    continue
                if dep not in edges[parent]:
                    edges[parent].add(dep)
                    dependents.setdefault(dep, []).append(parent)
    ready = [name for name in pending if not edges[name]]
    ready.sort()
    ordered: list[str] = []
    emitted: set[str] = set()
    while ready:
        name = heappop(ready)
        if name in emitted:
            continue
        emitted.add(name)
        ordered.append(name)
        for parent in dependents.get(name, ()):
            edges[parent].discard(name)
            if not edges[parent]:
                heappush(ready, parent)
    if len(ordered) != len(pending):
        # A dependency cycle: keep the deterministic remainder rather than
        # dropping packages from the cycle.
        ordered.extend(sorted(name for name in pending if name not in emitted))
    return ordered


def _missing_direct_dependencies(
    new_meta: dict[str, dict],
    pending: list[str],
    to_process: set[str],
    cap: int,
) -> tuple[list[str], bool]:
    """Dependencies to baseline before this cycle's roots are analysed.

    Only packages *not* in this cycle's delta are eligible.  A dependency
    that is itself pending must be analysed as a root so its own diff is
    recorded; saving its snapshot here first would turn that change into an
    unchanged first observation.  The cap bounds the extra fetch work the
    same way ``MAX_DEPTH_NODES`` bounds one walk, and the scan stops as soon
    as the cap is reached so a hostile metadata entry cannot make this pass
    query the database for an unbounded dependency list.

    Returns ``(missing, capped)``.
    """
    seen: set[str] = set()
    missing: list[str] = []
    for parent in pending:
        entry = new_meta.get(parent) or {}
        for field_name in _META_DEPENDENCY_FIELDS:
            for raw in entry.get(field_name) or ():
                dep = normalize_dependency(raw)
                if not dep or dep in seen:
                    continue
                seen.add(dep)
                if len(seen) > _MAX_PREFILL_CANDIDATES:
                    return missing, True
                if dep not in new_meta or dep in to_process:
                    continue
                if not _needs_dependency_prefill(dep):
                    continue
                if len(missing) >= cap:
                    return missing, True
                missing.append(dep)
    return missing, False


def _iter_prefetched(names, fetch_fn, workers: int):
    """Yield ``(name, fetch_result)`` in *names* order, fetching ahead.

    Analysis stays serial and ordered (novelty reads the observations earlier
    packages recorded), so only the fetch is parallelised: a bounded window of
    fetches is kept in flight and consumed in order.  A fetch that raises
    yields ``(None, None, None, False, None, None, None, True)`` - the same shape ``_fetch_one``
    returns for a vanished package - rather than aborting the run.
    """
    names = list(names)
    window = max(workers * 3, 24)
    with ThreadPoolExecutor(max_workers=workers) as pool:
        inflight: deque = deque()
        idx = 0
        while idx < len(names) and len(inflight) < window:
            inflight.append((names[idx], pool.submit(fetch_fn, names[idx])))
            idx += 1
        while inflight:
            name, future = inflight.popleft()
            try:
                result = future.result()
            except Exception:
                result = (None, None, None, False, None, None, None, True)
            yield name, result
            if idx < len(names):
                inflight.append((names[idx], pool.submit(fetch_fn, names[idx])))
                idx += 1


def _corpus_progress(total: int, json_output: bool):
    """A rich progress bar for the analysis loop, or None when not interactive.

    Renders on stderr so it does not corrupt the artifact or a piped ``--json``
    stream; falls back to periodic log lines when there is no TTY.
    """
    if not (_HAS_RICH and not json_output and sys.stderr.isatty()):
        return None
    progress = Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        TextColumn("elapsed"),
        TimeElapsedColumn(),
        TextColumn("eta"),
        TimeRemainingColumn(),
        console=Console(stderr=True),
    )
    progress.start()
    task = progress.add_task("Analysing packages", total=total)
    return progress, task
