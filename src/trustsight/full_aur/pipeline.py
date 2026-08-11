"""Bootstrap and incremental corpus pipeline."""

import logging
import sys
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

try:
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

    _HAS_RICH = True
except ImportError:  # pragma: no cover - rich is a dependency, but degrade gracefully
    _HAS_RICH = False

from ..analysis.base import _ensure_init
from ..config import load_config
from ..db import (
    get_connection,
    record_alerts,
    get_pkgbuild_snapshot,
    introduction_rate_history,
    latest_cycle_time,
    maintainer_activity_history,
    record_cycle_events,
    is_reserved_name,
    save_package_profile,
    save_pkgbuild_snapshot,
)
from ..schema import TemporalContext
from ..scoring import risk_level
from .analyze import analyze_package_text
from .corpus import run_corpus_sweep, source_repos_from_pkgbuild
from .fetch import (
    clear_resume_state,
    fetch_pkgbuild_with_tree,
    load_resume_state,
    save_resume_state,
)
from .metadata import (
    diff_metadata,
    fetch_metadata,
    load_metadata,
    save_metadata,
)

log = logging.getLogger(__name__)

# Score 40 sits in the upper half of the Medium band (scoring.risk_level:
# Low <= 20, Medium 21-50, High 51-80, Critical 81-100); a cycle names the
# packages that reached it rather than leaving them in the database for
# someone to notice later.
_FLAGGED_SCORE = 40

# How many of them one cycle prints.  A bootstrap analyses the whole AUR,
# and an unbounded list would bury the cluster findings under it.
_FLAGGED_REPORT_LIMIT = 10

def _meta_snapshot_path() -> Path:
    """Where this run reads and writes the metadata snapshot.

    Resolved through metadata.default_metadata_path() so the bootstrap, the
    exporter and ``review`` all agree; it used to be relative to the working
    directory here, which meant a snapshot written by one command was
    invisible to the other.
    """
    from .metadata import default_metadata_path

    return default_metadata_path()


def _pkg_or_base(meta: dict) -> str:
    """Return the package base name for metadata lookups.

    Most AUR packages have the same Name and PackageBase.  For split
    packages the PKGBUILD lives under the PackageBase.
    """
    return meta.get("PackageBase") or meta["Name"]


def _record_cycle_feed(
    new_meta: dict,
    old_meta: Optional[dict],
    added: list[str],
    changed: list[str],
    removed: list[str],
) -> None:
    """Record this cycle's introduction events into the Class D adoption feed.

    The feed is the per-cycle diff stream that R125's introduction-rate
    baseline is derived from.  A fresh bootstrap records the whole corpus as
    cycle 1.
    """
    cycle_ts = latest_cycle_time() + 1
    events: list[dict] = []
    for name in added:
        meta = new_meta.get(name) or {}
        events.append(
            {
                "package_name": name,
                "cycle_time": cycle_ts,
                "status": "added",
                "maintainer": meta.get("Maintainer") or "",
                "last_modified": meta.get("LastModified"),
            }
        )
    for name in changed:
        meta = new_meta.get(name) or {}
        events.append(
            {
                "package_name": name,
                "cycle_time": cycle_ts,
                "status": "modified",
                "maintainer": meta.get("Maintainer") or "",
                "last_modified": meta.get("LastModified"),
            }
        )
    for name in removed:
        meta = (old_meta or {}).get(name) or {}
        events.append(
            {
                "package_name": name,
                "cycle_time": cycle_ts,
                "status": "removed",
                "maintainer": meta.get("Maintainer") or "",
                "last_modified": meta.get("LastModified"),
            }
        )
    if events:
        record_cycle_events(events)


def _profile_score(name: str, scores: dict[str, int]) -> int:
    """Current profile score for *name* from the in-memory map or the DB."""
    if name in scores:
        return scores[name]
    with get_connection() as conn:
        row = conn.execute(
            "SELECT last_score FROM package_profiles WHERE package_name = ?",
            (name,),
        ).fetchone()
    return row[0] if row and row[0] is not None else 0


def _run_corpus_sweep(
    new_meta: dict,
    old_meta: Optional[dict],
    processed: set[str],
    scores: dict[str, int],
) -> list[dict]:
    """Run the Phase 6 Class D detectors and attach their additive weight.

    With no prior snapshot (first bootstrap) the sweep is skipped entirely;
    the Class D calibration gate is ``fire_rate(no_baseline) == 0``.  Each
    cluster finding adds its severity weight to every member's profile score
    (R092/R100/R105/R125 are additive; only R107/R111/R112 are not).
    """
    if old_meta is None:
        return []

    source_repos: dict[str, set[str]] = {}
    for name in processed:
        snapshot = get_pkgbuild_snapshot(name)
        if not snapshot or not snapshot.get("pkgbuild_text"):
            continue
        repos = source_repos_from_pkgbuild(snapshot["pkgbuild_text"])
        if repos:
            source_repos[name] = repos

    findings = run_corpus_sweep(
        new_meta,
        old_meta,
        source_repos=source_repos,
        prior_history=introduction_rate_history(),
        maintainer_history=maintainer_activity_history(),
        now=int(time.time()),
    )

    weights = load_config().get("severity_weights", {})
    for finding in findings:
        delta = int(weights.get(finding.get("severity", ""), 0))
        if delta <= 0:
            continue
        for member in finding["params"]["members"]:
            if is_reserved_name(member):
                continue
            new_score = max(0, min(100, _profile_score(member, scores) + delta))
            save_package_profile(member, new_score, risk_level(new_score))
    return findings


@dataclass
class CycleResult:
    """What one corpus cycle did, for a caller that runs more than one."""

    added: int = 0
    changed: int = 0
    removed: int = 0
    processed: int = 0
    cluster_findings: list[dict] = field(default_factory=list)
    new_alerts: list[tuple[str, str]] = field(default_factory=list)
    flagged: list[tuple[str, int]] = field(default_factory=list)
    elapsed: float = 0.0
    bootstrap: bool = False
    # True when the cycle deliberately did no work and the caller should
    # report a failure (from-scratch bootstrap refused, empty fetch).
    refused: bool = False


def _logger(json_output: bool):
    if json_output:
        import json as _json

        def _log(msg):
            print(_json.dumps({"msg": msg}))
    else:
        def _log(msg):
            log.info(msg)
    return _log


def _fetch_workers() -> int:
    """How many PKGBUILD fetches run concurrently.

    The bootstrap's cost is dominated by one network fetch per package;
    fetching a window ahead in parallel is the biggest speedup.  It is bounded
    twice over: this worker count, and a global aggregate rate cap in the
    fetcher (``fetch._MIN_REQUEST_INTERVAL``).  The rate cap is the real limit,
    because the AUR's cgit rate-limits per IP; more workers than the cap can
    keep busy only idle, so the default is small.  Tunable via
    ``limits.corpus_fetch_workers``.
    """
    try:
        configured = int(load_config().get("limits", {}).get("corpus_fetch_workers", 0))
    except (TypeError, ValueError):
        configured = 0
    return configured if configured > 0 else 5


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


def _iter_prefetched(names, fetch_fn, workers: int):
    """Yield ``(name, fetch_result)`` in *names* order, fetching ahead.

    Analysis stays serial and ordered (novelty reads the observations earlier
    packages recorded), so only the fetch is parallelised: a bounded window of
    fetches is kept in flight and consumed in order.  A fetch that raises
    yields ``(None, None)`` rather than aborting the run.
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
                result = (None, None)
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


def run_baseline_build(
    resume: bool = False,
    export_path: Optional[str] = None,
    sign_key: Optional[str] = None,
    json_output: bool = False,
    bootstrap: bool = False,
) -> CycleResult:
    """Bootstrap or update the full-AUR corpus.

    Fetches the metadata snapshot, diffs against the stored copy, downloads
    the changed PKGBUILDs, analyses each package, stores results, and
    optionally exports a signed baseline artifact.

    A from-scratch bootstrap (no prior snapshot) fetches every PKGBUILD in the
    AUR, which is heavy on a shared community mirror.  It is not done by
    accident: *bootstrap* must be True to start one.  Every cycle, bootstrap
    or delta, is bounded by :func:`_max_per_cycle` and resumes automatically,
    so a large amount of work advances in gentle chunks across invocations
    rather than one avalanche.

    Returns what the cycle did so ``run_watch`` can report on it; the
    single-shot CLI path ignores the value.
    """
    _ensure_init()
    result = CycleResult()
    _log = _logger(json_output)

    _log("Fetching AUR metadata snapshot …")
    try:
        new_meta = fetch_metadata()
    except Exception as exc:
        raise RuntimeError(f"failed to fetch the AUR metadata snapshot: {exc}") from exc
    meta_count = len(new_meta)
    _log(f"Fetched {meta_count} package entries")
    if not new_meta:
        # An empty reply would clobber the stored snapshot on the
        # "Nothing to process" path below; keep the last good one.
        _log("The AUR metadata fetch returned nothing; keeping the previous snapshot")
        result.refused = True
        return result

    old_meta = load_metadata(_meta_snapshot_path())

    # Resume state is loaded unconditionally: a capped or interrupted cycle
    # continues where it left off.  ``--resume`` stays accepted but is implied.
    resume_state = load_resume_state()
    in_progress = bool(resume_state and resume_state.get("processed"))

    if old_meta is None:
        # Refuse to start a whole-AUR bootstrap unless it was asked for.  A
        # continuation of one already under way (resume state present, snapshot
        # not yet advanced) is allowed to proceed without re-passing the flag.
        if not bootstrap and not in_progress:
            _log(
                f"Refusing a from-scratch corpus bootstrap of {meta_count} "
                "packages: it fetches the whole AUR and leans on a shared "
                "mirror. Pass --bootstrap to start one (it is capped per cycle "
                "and resumes automatically), or run 'trustsight review' first "
                "so an incremental snapshot already exists to diff against."
            )
            result.refused = True
            return result
        added = sorted(new_meta)
        changed: list[str] = []
        removed: list[str] = []
        result.bootstrap = True
        _log("Bootstrap: processing the whole AUR in capped, resumable cycles")
    else:
        changes = diff_metadata(old_meta, new_meta)
        added = sorted(n for n, s in changes.items() if s == "added")
        changed = sorted(n for n, s in changes.items() if s == "modified")
        removed = sorted(n for n, s in changes.items() if s == "removed")
        _log(f"Delta: {len(added)} added, {len(changed)} changed, {len(removed)} removed")

    result.added, result.changed, result.removed = len(added), len(changed), len(removed)
    to_process = added + changed

    if not to_process:
        _log("Nothing to process")
        save_metadata(new_meta, _meta_snapshot_path())
        clear_resume_state()
        return result

    processed: set[str] = set(resume_state.get("processed", [])) if resume_state else set()
    scores: dict[str, int] = {}

    # Cap the work per invocation so even a bootstrap advances in bounded,
    # resumable chunks.  The remainder is picked up on the next run.
    cap = _max_per_cycle()
    pending_all = [n for n in to_process if n not in processed]
    pending = pending_all[:cap] if cap else pending_all
    partial = bool(cap) and len(pending_all) > cap
    _log(
        f"Processing {len(pending)} package(s) this cycle "
        f"({len(processed)} already done, {len(pending_all)} pending)"
    )
    batch_start = time.time()

    def _fetch_one(name):
        meta = new_meta.get(name)
        if meta is None:
            return (None, None)
        return fetch_pkgbuild_with_tree(_pkg_or_base(meta))

    def _store(name, fetched) -> str:
        """Analyse and persist one fetched package.  Returns a status string:
        ``ok``, ``vanished``, ``reserved`` or ``fetch_failed``."""
        meta = new_meta.get(name)
        if meta is None:
            log.warning("metadata for %s vanished; skipping", name)
            return "vanished"
        if is_reserved_name(name):
            log.warning("skipping reserved package name %r", name)
            return "reserved"
        new_pkgbuild, tree_manifest = fetched
        if new_pkgbuild is None:
            log.debug("could not fetch PKGBUILD for %s (base: %s)", name, _pkg_or_base(meta))
            return "fetch_failed"

        old_snapshot = get_pkgbuild_snapshot(name)
        old_pkgbuild = old_snapshot["pkgbuild_text"] if old_snapshot else None
        prev_last_modified: Optional[int] = (
            old_snapshot["last_modified"] if old_snapshot else None
        )
        fact = analyze_package_text(
            pkg_name=name,
            old_pkgbuild=old_pkgbuild,
            new_pkgbuild=new_pkgbuild,
            maintainer=meta.get("Maintainer") or "",
            temporal=TemporalContext(
                last_modified=meta.get("LastModified"),
                first_seen=meta.get("FirstSubmitted"),
                previous_modified=prev_last_modified,
                source="aur_metadata",
            ),
            tree_manifest=tree_manifest,
        )
        save_pkgbuild_snapshot(
            package_name=name,
            pkgbuild_text=new_pkgbuild,
            version=fact.new_version or meta.get("Version", ""),
            last_modified=meta.get("LastModified", 0),
        )
        save_package_profile(
            package_name=name,
            last_score=fact.final_score,
            # score_breakdown is a list of ScoreEntry, not a dict: asking it
            # for "risk_label" raised AttributeError on the first package of
            # every bootstrap.  The label is derived from the score.
            last_risk=risk_level(fact.final_score),
        )
        scores[name] = fact.final_score
        return "ok"

    fetch_failures = 0
    progress = _corpus_progress(len(pending), json_output)
    try:
        done = 0
        for name, fetched in _iter_prefetched(pending, _fetch_one, _fetch_workers()):
            status = _store(name, fetched)
            if status == "fetch_failed":
                fetch_failures += 1
            # A fetch failure is marked done too, so a resume does not retry a
            # package the mirror has no snapshot for on every pass.
            processed.add(name)
            done += 1

            if progress is not None:
                progress[0].update(
                    progress[1], advance=1, description=f"Analysing {name[:36]}"
                )
            elif done % 1000 == 0:
                elapsed = time.time() - batch_start
                rate = done / elapsed if elapsed > 0 else 0
                _log(f"Processed {done}/{len(pending)} packages ({rate:.1f}/s)")

            if done % 1000 == 0:
                save_resume_state({"processed": sorted(processed)})
    finally:
        if progress is not None:
            progress[0].stop()

    if fetch_failures:
        _log(f"{fetch_failures} package(s) had no fetchable PKGBUILD this cycle")

    save_resume_state({"processed": sorted(processed)})

    if partial:
        # More of this transition remains.  Do not advance the snapshot, run
        # the corpus sweep, or export a half-built corpus: the next invocation
        # continues from the saved resume state.
        remaining = len(pending_all) - len(pending)
        _log(
            f"Cycle capped at {len(pending)} package(s); {remaining} still "
            "pending. Run 'trustsight full-aur' again to continue."
        )
        result.processed = len(processed)
        return result

    save_metadata(new_meta, _meta_snapshot_path())
    clear_resume_state()

    # The sweep reads the adoption feed as its baseline, so it must run
    # before this cycle's events are recorded.
    cluster_findings = _run_corpus_sweep(new_meta, old_meta, processed, scores)
    _record_cycle_feed(new_meta, old_meta, added, changed, removed)
    result.cluster_findings = cluster_findings
    result.processed = len(processed)
    # What this cycle analysed, worst first.  Cluster findings describe the
    # corpus; these are the individual packages a watcher would otherwise
    # have to go looking for in `trustsight list`.
    result.flagged = sorted(
        ((name, score) for name, score in scores.items() if score >= _FLAGGED_SCORE),
        key=lambda item: (-item[1], item[0]),
    )
    result.new_alerts = record_alerts([
        (member, finding["rule_id"])
        for finding in cluster_findings
        for member in finding["params"]["members"]
    ])
    if cluster_findings:
        _log(f"Corpus sweep: {len(cluster_findings)} cluster finding(s)")
        for finding in cluster_findings:
            _log(
                f"  {finding['rule_id']} ({finding['severity']}) "
                f"{finding['name']}: {finding['match']}"
            )

    total_elapsed = time.time() - batch_start
    result.elapsed = total_elapsed
    _log(
        f"Baseline build complete: {len(processed)} packages processed "
        f"in {total_elapsed:.0f}s"
    )

    if result.flagged:
        shown = result.flagged[:_FLAGGED_REPORT_LIMIT]
        _log(
            f"{len(result.flagged)} package(s) scored {_FLAGGED_SCORE}+ this cycle"
            + (f" (showing {len(shown)})" if len(shown) < len(result.flagged) else "")
        )
        for name, score in shown:
            _log(f"  {score:3d}  {name}")

    if export_path:
        from .export import build_artifact
        build_artifact(
            export_path=export_path,
            private_key_path=sign_key,
        )
    return result


def watch_interval_seconds(requested: Optional[int] = None) -> int:
    """Seconds between watch cycles, clamped to the configured floor.

    The AUR regenerates its metadata dump every few minutes, so a shorter
    interval only re-downloads the same snapshot and re-walks the same
    diff; the floor keeps a mistyped ``--interval 1`` from turning into a
    request loop against someone else's mirror.
    """
    limits = load_config().get("limits", {})
    try:
        default = int(limits.get("watch_interval", 3600))
    except (TypeError, ValueError):
        default = 3600
    try:
        floor = int(limits.get("watch_min_interval", 60))
    except (TypeError, ValueError):
        floor = 60
    if requested is not None:
        try:
            requested = int(requested)
        except (TypeError, ValueError):
            requested = None
    return max(floor, int(requested) if requested is not None else default)


def run_watch(
    interval: Optional[int] = None,
    cycles: int = 0,
    json_output: bool = False,
    sleep: Callable[[float], None] = time.sleep,
) -> list[CycleResult]:
    """Run corpus cycles on an interval until interrupted (plan §6.4).

    Each cycle is exactly what ``run_baseline_build`` does once: refresh
    the metadata snapshot, analyse what changed, run the Class D sweep and
    record the adoption feed.  What ``--watch`` adds is repetition and
    memory - a cluster is announced the first time it is seen and then
    counted, not re-announced, so the second cycle of a quiet night prints
    nothing rather than the same forty-package adoption again.

    *cycles* of 0 means "until interrupted".  Ctrl-C ends the loop between
    or during a cycle; state is already durable at that point, since every
    cycle saves the snapshot and the resume file before it returns.
    """
    delay = watch_interval_seconds(interval)
    _log = _logger(json_output)
    results: list[CycleResult] = []
    _log(
        f"Watching the AUR: one cycle every {delay}s"
        + (f", {cycles} cycle(s)" if cycles else ", until interrupted")
    )
    attempts = 0
    try:
        while True:
            # A transient failure (network blip, rate limit) must not kill an
            # unattended watcher: report, wait, and retry.  The cycle cap
            # still bounds the total, so a persistently broken cycle cannot
            # spin forever either.
            try:
                result = run_baseline_build(json_output=json_output)
            except Exception as exc:
                attempts += 1
                _log(f"Cycle failed ({exc}); retrying in {delay}s")
                if cycles and attempts >= cycles:
                    break
                sleep(delay)
                continue
            attempts = 0
            results.append(result)
            if result.new_alerts:
                _log(f"{len(result.new_alerts)} new alert(s) this cycle")
                for package, rule_id in result.new_alerts:
                    _log(f"  {rule_id}  {package}")
            elif result.cluster_findings:
                _log("No new alerts; every cluster this cycle was already reported")
            if cycles and len(results) >= cycles:
                break
            sleep(delay)
    except KeyboardInterrupt:
        _log(f"Watch stopped after {len(results)} cycle(s)")
    return results



