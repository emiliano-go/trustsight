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
    checkpoint_wal,
    get_connection,
    get_metadata,
    record_alerts,
    get_pkgbuild_snapshot,
    introduction_rate_history,
    latest_cycle_time,
    maintainer_activity_history,
    record_cycle_events,
    is_reserved_name,
    save_package_profile,
    save_pkgbuild_snapshot,
    set_metadata,
)
from ..schema import TemporalContext
from ..scoring import risk_level
from ..tokenizer import TokenizerUnavailable
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

# The benign corpus's p95 (published-figures.json): a score past it is
# outside everything the benign corpus does, which is the bar a watcher's
# urgent notification should use.  `flagged` stays at 40 (the report bar);
# this is the lower, alerting bar.
_OVER_BENIGN_P95 = 30

# One day of AUR time per backfill cycle (see run_baseline_build's *since*).
_SINCE_DAY_SECONDS = 86400
_SINCE_CURSOR_KEY = "since_cursor"
_SINCE_ORIGIN_KEY = "since_origin"

# How many of them one cycle prints.  A bootstrap analyses the whole AUR,
# and an unbounded list would bury the cluster findings under it.
_FLAGGED_REPORT_LIMIT = 10


def _since_cursor() -> Optional[int]:
    """The active backfill cursor (unix seconds), or None when not replaying."""
    raw = get_metadata(_SINCE_CURSOR_KEY)
    if not raw:
        return None
    try:
        return int(raw)
    except (TypeError, ValueError):
        return None


def _set_since_cursor(value: Optional[int]) -> None:
    set_metadata(_SINCE_CURSOR_KEY, "" if value is None else str(value))


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

    The feed is the per-cycle diff stream that H073's introduction-rate
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
    (H045/H052/H055/H073 are additive; only H057/H060/H061 are not).
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
    over_threshold: list[tuple[str, int]] = field(default_factory=list)
    ioc_hits: list[tuple[str, str]] = field(default_factory=list)
    backfilling: bool = False
    # The AUR day (YYYY-MM-DD) this cycle replayed, when backfilling.
    backfill_day: str = ""
    # Per-package alert context: score, version transition, LastModified,
    # firing rules - what a webhook document is built from.
    detail: dict[str, dict] = field(default_factory=dict)
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
    yields ``(None, None, None, False)`` - the same shape ``_fetch_one``
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
                result = (None, None, None, False)
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
    depth: Optional[int] = None,
    over_threshold: Optional[int] = None,
    since: Optional[int] = None,
) -> CycleResult:
    """Bootstrap or update the full-AUR corpus.

    Fetches the metadata snapshot, diffs against the stored copy, downloads
    the changed PKGBUILDs, analyses each package, stores results, and
    optionally exports a signed baseline artifact.

    *over_threshold* is the alerting bar: packages scoring above it land in
    ``CycleResult.over_threshold``.  ``None`` uses the benign corpus's p95
    (published-figures.json), the point past which a score is outside
    everything the benign corpus does.

    *since* (a unix timestamp) starts a backfill: instead of diffing the
    newest metadata against the stored snapshot, the cycle replays change
    history by AUR ``LastModified``, one day per cycle, analysing every
    package that changed in that day's window.  The cursor persists in the
    database, so a backfill resumes after an interruption and joins the
    live delta when it catches up.  The sweep and the adoption feed stay
    out of backfill cycles: they model the live stream, and replaying two
    years into them would only distort the baselines they compute.

    A from-scratch bootstrap (no prior snapshot) fetches every PKGBUILD in the
    AUR, which is heavy on a shared community mirror.  It is not done by
    accident: *bootstrap* must be True to start one.  Every cycle, bootstrap
    or delta, is bounded by :func:`_max_per_cycle` and resumes automatically,
    so a large amount of work advances in gentle chunks across invocations
    rather than one avalanche.

    Returns what the cycle did so ``run_watch`` can report on it; the
    single-shot CLI path ignores the value.
    """
    try:
        return _run_baseline_build(
            resume=resume, export_path=export_path, sign_key=sign_key,
            json_output=json_output, bootstrap=bootstrap, depth=depth,
            over_threshold=over_threshold, since=since,
        )
    finally:
        # A cycle can write thousands of rows; leave the WAL small
        # instead of waiting for the next manual vacuum.
        checkpoint_wal()


def _run_baseline_build(
    resume: bool = False,
    export_path: Optional[str] = None,
    sign_key: Optional[str] = None,
    json_output: bool = False,
    bootstrap: bool = False,
    depth: Optional[int] = None,
    over_threshold: Optional[int] = None,
    since: Optional[int] = None,
) -> CycleResult:
    """The cycle body; the public wrapper checkpoints the WAL."""
    if over_threshold is None:
        over_threshold = _OVER_BENIGN_P95
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

    backfill_day_end = 0
    if since is not None:
        # The flag names the replay's origin; the cursor tracks progress.
        # A service re-passes the flag on every restart, so resetting on
        # the flag alone would replay from the start forever: only a
        # *different* origin starts a new replay.
        if get_metadata(_SINCE_ORIGIN_KEY) != str(since):
            # A fresh replay starts over: any resume set from another flow
            # (a bootstrap in progress) must not subtract names from the bucket.
            clear_resume_state()
            resume_state = None
            in_progress = False
            _set_since_cursor(since)
            set_metadata(_SINCE_ORIGIN_KEY, str(since))
    cursor = _since_cursor()
    if cursor is not None:
        # Backfill: one day of AUR time per cycle.  Days with no changes are
        # skipped inside the cycle, so an empty stretch costs nothing.
        now = int(time.time())
        while True:
            backfill_day_end = cursor + _SINCE_DAY_SECONDS
            bucket = sorted(
                name for name, m in new_meta.items()
                if cursor <= (m.get("LastModified") or 0) < backfill_day_end
            )
            if bucket or backfill_day_end >= now:
                break
            cursor = backfill_day_end
        _set_since_cursor(cursor)
        to_process = bucket
        added, removed = [], []
        changed = list(to_process)
        result.backfilling = True
        result.backfill_day = time.strftime("%Y-%m-%d", time.gmtime(cursor))
        _log(
            f"Backfill since {time.strftime('%Y-%m-%d', time.gmtime(cursor))}: "
            f"{len(to_process)} package(s) changed that day"
        )
    elif old_meta is None:
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
        if result.backfilling:
            # The bucket was empty at the head of history: the replay has
            # caught up with the AUR.  Join the live delta path.
            save_metadata(new_meta, _meta_snapshot_path())
            _set_since_cursor(None)
            set_metadata(_SINCE_ORIGIN_KEY, "")
            clear_resume_state()
            result.backfilling = False
            _log("Backfill caught up; joining the live delta stream")
            return result
        _log("Nothing to process")
        # A removals-only delta takes this path, and the adoption feed still
        # needs it: H073's introduction-rate and H058's maintainer-activity
        # baselines count removals.  Recording here rather than only after the
        # analysis loop keeps the feed complete for every delta shape; the
        # sweep never runs on this path, so its read-the-feed-first ordering
        # is untouched.
        _record_cycle_feed(new_meta, old_meta, added, changed, removed)
        save_metadata(new_meta, _meta_snapshot_path())
        clear_resume_state()
        return result

    processed: set[str] = set(resume_state.get("processed", [])) if resume_state else set()
    scores: dict[str, int] = {}
    # Per-package context for the alert payloads: version transition, the
    # AUR change date and the rules that fired, so a notification can say
    # what happened, not only that it did.
    detail: dict[str, dict] = {}
    ioc_hits: dict[str, list[str]] = {}

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
            return (None, None, None, False)
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
        new_pkgbuild, tree_manifest, trailer_finding, snapshot_refused = fetched
        if new_pkgbuild is None:
            log.debug("could not fetch PKGBUILD for %s (base: %s)", name, _pkg_or_base(meta))
            return "fetch_failed"

        old_snapshot = get_pkgbuild_snapshot(name)
        old_pkgbuild = old_snapshot["pkgbuild_text"] if old_snapshot else None
        prev_last_modified: Optional[int] = (
            old_snapshot["last_modified"] if old_snapshot else None
        )
        try:
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
                archive_trailer_finding=trailer_finding,
                snapshot_refused=snapshot_refused,
                depth=depth,
                # The corpus builder is a writer by definition: it exists to
                # accumulate the observations the read-only default consumes.
                record=True,
            )
        except TokenizerUnavailable as exc:
            # The sandboxed tokenizer could not answer (A6).  The package is
            # not analysed and nothing is persisted, so it cannot enter the
            # corpus as if it had been vetted; the cycle continues.
            log.warning("tokenizer unavailable for %s: %s; not vetted", name, exc)
            return "not_vetted"
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
        if fact.ioc_matches:
            # A known-bad match pages at maximum priority whatever the score:
            # the IOC tier is reported outside the heuristic score, so a clean-
            # looking package on the list would never cross the alerting bar.
            for m in fact.ioc_matches:
                ioc_hits[name].append(f"{m.type}:{m.value}")
        detail[name] = {
            "score": fact.final_score,
            "old_version": old_snapshot["version"] if old_snapshot else "",
            "new_version": fact.new_version or meta.get("Version", ""),
            "last_modified": meta.get("LastModified"),
            "rules": [
                e.rule_id for e in fact.score_breakdown
                if e.weight > 0 or e.severity in ("FATAL", "CRITICAL", "HIGH")
            ],
        }
        return "ok"

    fetch_failures = 0
    not_vetted = 0
    progress = _corpus_progress(len(pending), json_output)
    try:
        done = 0
        for name, fetched in _iter_prefetched(pending, _fetch_one, _fetch_workers()):
            status = _store(name, fetched)
            if status == "fetch_failed":
                fetch_failures += 1
            elif status == "not_vetted":
                not_vetted += 1
            # A fetch failure is marked done too, so a resume does not retry a
            # package the mirror has no snapshot for on every pass.  A
            # not-vetted package is the opposite case: nothing was stored and
            # the tokenizer may answer on a later pass, so it is left out of
            # the resume set and retried.
            if status != "not_vetted":
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

    if not_vetted:
        _log(
            f"{not_vetted} package(s) were NOT vetted this cycle: the "
            "sandboxed tokenizer could not answer and nothing was recorded "
            "for them"
        )

    save_resume_state({"processed": sorted(processed)})

    # Per-cycle scores become the cycle's report and its alerts on EVERY
    # path: a capped chunk used to return without them, which dropped the
    # over_threshold list for every chunk but the last - the worst findings
    # of a multi-cycle bootstrap never notified.
    result.flagged = sorted(
        ((name, score) for name, score in scores.items() if score >= _FLAGGED_SCORE),
        key=lambda item: (-item[1], item[0]),
    )
    result.over_threshold = sorted(
        ((name, score) for name, score in scores.items() if score > over_threshold),
        key=lambda item: (-item[1], item[0]),
    )
    result.ioc_hits = sorted(
        (name, indicator)
        for name, indicators in ioc_hits.items() for indicator in indicators
    )
    result.detail = detail

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

    if result.backfilling:
        # The day is drained.  Advance one day of AUR time; when the next day
        # reaches into the future, the replay has caught up and the snapshot
        # joins the live delta path.  ``now`` is the reading taken when this
        # cycle began, not a second reading here: re-reading the clock let a
        # second boundary falling mid-cycle decide the outcome, so a backfill
        # that had genuinely caught up could advance one more day.  The resume
        # set belongs to the day just finished, so it is cleared either way.
        clear_resume_state()
        if backfill_day_end >= now:
            save_metadata(new_meta, _meta_snapshot_path())
            _set_since_cursor(None)
            set_metadata(_SINCE_ORIGIN_KEY, "")
            result.backfilling = False
            _log("Backfill caught up; joining the live delta stream")
        else:
            _set_since_cursor(backfill_day_end)
        result.processed = len(processed)
        return result

    # The sweep reads the adoption feed as its baseline, so it must run
    # before this cycle's events are recorded.  The feed is recorded before
    # the snapshot advances, as in the removals-only path: a crash between
    # the two used to leave the snapshot at the new state with the cycle's
    # events unrecorded, and the next run diffed the loss away.
    cluster_findings = _run_corpus_sweep(new_meta, old_meta, processed, scores)
    _record_cycle_feed(new_meta, old_meta, added, changed, removed)
    save_metadata(new_meta, _meta_snapshot_path())
    clear_resume_state()
    result.cluster_findings = cluster_findings
    result.processed = len(processed)
    # What this cycle analysed, worst first.  Cluster findings describe the
    # corpus; these are the individual packages a watcher would otherwise
    # have to go looking for in `trustsight list`.  Both lists were computed
    # above the partial-cycle return, so this path only reads them.
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
    depth: Optional[int] = None,
    notify_url: Optional[str] = None,
    over_threshold: Optional[int] = None,
    since: Optional[int] = None,
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
    last_heartbeat = 0.0
    try:
        while True:
            # A transient failure (network blip, rate limit) must not kill an
            # unattended watcher: report, wait, and retry.  The cycle cap
            # still bounds the total, so a persistently broken cycle cannot
            # spin forever either.
            try:
                result = run_baseline_build(json_output=json_output, depth=depth,
                                            over_threshold=over_threshold,
                                            since=since)
            except Exception as exc:
                attempts += 1
                _log(f"Cycle failed ({exc}); retrying in {delay}s")
                if cycles and attempts >= cycles:
                    break
                sleep(delay)
                continue
            attempts = 0
            if result.refused:
                from .metadata import load_metadata

                if load_metadata() is None and _since_cursor() is None:
                    # No snapshot exists to diff against and no replay is in
                    # flight, so every cycle refuses the same way: an
                    # unattended watch would spin forever fetching metadata
                    # and analysing nothing.  A --since replay advances no
                    # snapshot until it catches up, and that is not a
                    # refusal.
                    _log(
                        "No corpus snapshot yet; the watch has nothing to "
                        "diff against. Run 'trustsight full-aur --bootstrap' "
                        "first so an initial snapshot exists."
                    )
                    results.append(result)
                    break
                # A transient refusal (an empty fetch with a snapshot on
                # disk) did no work: it does not consume the cycle budget.
                _log(f"Cycle did no work; retrying in {delay}s")
                sleep(delay)
                continue
            results.append(result)
            if result.new_alerts:
                _log(f"{len(result.new_alerts)} new alert(s) this cycle")
                for package, rule_id in result.new_alerts:
                    _log(f"  {rule_id}  {package}")
            elif result.cluster_findings:
                _log("No new alerts; every cluster this cycle was already reported")
            # An unattended watcher needs a push channel: a cluster alert is
            # announced once here and never again, and an over-threshold
            # package is what the watcher exists for - so the webhook is how
            # either reaches anyone not reading the log.
            from ..notify import HEARTBEAT_SECONDS, maybe_heartbeat, maybe_notify

            if maybe_notify(result, notify_url):
                _log("  alert webhook delivered")
            # Silence is otherwise ambiguous between "nothing found" and
            # "the watcher is dead": one low-priority beat a day.
            if time.time() - last_heartbeat > HEARTBEAT_SECONDS:
                if maybe_heartbeat(result, notify_url):
                    last_heartbeat = time.time()
            if cycles and len(results) >= cycles:
                break
            # A backfill is a queue, not a schedule: the interval governs the
            # live stream, and sleeping it would stretch a one-day replay by
            # a day per day.  A short pause keeps an empty day from becoming
            # a hot loop, and the live interval resumes when the replay
            # catches up.
            sleep(2 if result.backfilling else delay)
    except KeyboardInterrupt:
        _log(f"Watch stopped after {len(results)} cycle(s)")
    return results


