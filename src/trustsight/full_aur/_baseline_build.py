"""Baseline-build implementation, using the facade for patchable globals."""

import uuid
from functools import partial
from datetime import datetime, timezone
from typing import Callable, Optional

from ._cycle import _CycleState, _analyse_and_store, _fetch_one, _store
from ._pipeline_helpers import CycleResult


def _pipeline():
    from . import pipeline
    return pipeline


def _backfill_day(cursor: int, now: int, meta: dict, day_seconds: int):
    """The next AUR day with changes: ``(start, end, names)``.

    Empty days are skipped in one bounded walk. The returned ``start`` is
    the cursor the cycle should persist until the day is drained; ``end``
    is the boundary that tells the caller when the replay has caught up.
    """
    while True:
        end = cursor + day_seconds
        bucket = sorted(
            name for name, entry in meta.items()
            if cursor <= (entry.get("LastModified") or 0) < end
        )
        if bucket or end >= now:
            return cursor, end, bucket
        cursor = end


def _run_baseline_build(
    resume: bool = False,
    export_path: Optional[str] = None,
    sign_key: Optional[str] = None,
    json_output: bool = False,
    bootstrap: bool = False,
    depth: Optional[int] = None,
    over_threshold: Optional[int] = None,
    since: Optional[int] = None,
    should_stop: Optional[Callable[[], bool]] = None,
) -> CycleResult:
    """The cycle body; the public wrapper checkpoints the WAL."""
    p = _pipeline()
    time = p.time
    CycleResult = p.CycleResult
    MAX_DEPTH_NODES = p.MAX_DEPTH_NODES
    _FLAGGED_REPORT_LIMIT = p._FLAGGED_REPORT_LIMIT
    _FLAGGED_SCORE = p._FLAGGED_SCORE
    _IMPERSONATION_GATED_RULES = p._IMPERSONATION_GATED_RULES
    _MAX_PREFILL_CANDIDATES = p._MAX_PREFILL_CANDIDATES
    _NON_ALERTING_CLUSTER_RULES = p._NON_ALERTING_CLUSTER_RULES
    _OVER_BENIGN_P95 = p._OVER_BENIGN_P95
    _SINCE_DAY_SECONDS = p._SINCE_DAY_SECONDS
    _SINCE_ORIGIN_KEY = p._SINCE_ORIGIN_KEY
    _corpus_progress = p._corpus_progress
    _dependencies_first = p._dependencies_first
    _ensure_init = p._ensure_init
    _fetch_workers = p._fetch_workers
    _iter_prefetched = p._iter_prefetched
    _logger = p._logger
    _max_per_cycle = p._max_per_cycle
    _meta_snapshot_path = p._meta_snapshot_path
    _missing_direct_dependencies = p._missing_direct_dependencies
    _persist_metadata = p._persist_metadata
    _popular_candidates = p._popular_candidates
    _record_cycle_feed = p._record_cycle_feed
    _report_expired_campaigns = p._report_expired_campaigns
    _run_corpus_sweep = p._run_corpus_sweep
    _set_since_cursor = p._set_since_cursor
    _since_cursor = p._since_cursor
    upstream_budget = None
    clear_correlation_feeds = p.clear_correlation_feeds
    clear_resume_state = p.clear_resume_state
    diff_metadata = p.diff_metadata
    fetch_metadata = p.fetch_metadata
    get_metadata = p.get_metadata
    load_metadata = p.load_metadata
    load_resume_state = p.load_resume_state
    log = p.log
    record_alerts = p.record_alerts
    save_resume_state = p.save_resume_state
    set_metadata = p.set_metadata

    if over_threshold is None:
        over_threshold = _OVER_BENIGN_P95
    _ensure_init()
    # Every G-series feed is one cycle's transitions, not an append-only log:
    # clear them before any package is processed so a prior cycle's host,
    # literal, adoption or upstream pair cannot meet this cycle's and re-fire
    # the join (or keep a lapsed campaign primed).
    clear_correlation_feeds()
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

    old_meta = load_metadata(_meta_snapshot_path(), slim=True)

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
        cursor, backfill_day_end, bucket = _backfill_day(
            cursor, now, new_meta, _SINCE_DAY_SECONDS)
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
            # caught up with the AUR.  Join the live delta path.  The origin
            # sentinel is kept, not cleared: --since is re-passed on every
            # cycle, so clearing it would make the next cycle look like a
            # different replay and restart the whole backfill.
            _persist_metadata(new_meta)
            _set_since_cursor(None)
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
        _persist_metadata(new_meta)
        clear_resume_state()
        return result

    processed: set[str] = set(resume_state.get("processed", [])) if resume_state else set()
    scores: dict[str, int] = {}
    # Per-package context for the alert payloads: version transition, the
    # AUR change date and the rules that fired, so a notification can say
    # what happened, not only that it did.
    detail: dict[str, dict] = {}
    ioc_hits: dict[str, list[str]] = {}
    refusals: set[str] = set()
    scan_status: dict[str, str] = {}

    # Cap the work per invocation so even a bootstrap advances in bounded,
    # resumable chunks.  The remainder is picked up on the next run.
    cap = _max_per_cycle()
    pending_all = [n for n in to_process if n not in processed]
    pending = pending_all[:cap] if cap else pending_all
    cycle_partial = bool(cap) and len(pending_all) > cap
    process_order = _dependencies_first(pending, new_meta)
    _log(
        f"Processing {len(pending)} package(s) this cycle "
        f"({len(processed)} already done, {len(pending_all)} pending)"
    )
    batch_start = time.time()

    # The AUR-popularity candidate list H029 compares against, built once
    # for the whole cycle.  Without it the corpus typosquat check would see
    # only dependency names and miss every helper/app clone (yay/paru/...).
    popular = _popular_candidates(new_meta)

    # Cycle-scoped inputs and accumulators handed to the package helpers
    # below, so the cycle reads as plan -> analyse -> record instead of
    # threading a dozen mutable locals through three nested closures.
    state = _CycleState(
        new_meta=new_meta,
        old_meta=old_meta,
        depth=depth,
        popular=popular,
        scores=scores,
        detail=detail,
        ioc_hits=ioc_hits,
        refusals=refusals,
    )

    _prefill_missing_dependencies(
        new_meta, pending, to_process, MAX_DEPTH_NODES,
        _missing_direct_dependencies, _log, _iter_prefetched,
        partial(_fetch_one, state), _fetch_workers,
        partial(_analyse_and_store, state), log, _MAX_PREFILL_CANDIDATES,
    )
    fetch_failures = 0
    not_vetted = 0
    stopped = False
    progress = _corpus_progress(len(pending), json_output)
    try:
        done = 0
        for name, fetched in _iter_prefetched(
                process_order, partial(_fetch_one, state), _fetch_workers()):
            if should_stop is not None and should_stop():
                stopped = True
                break
            status = _store(state, name, fetched)
            scan_status[name] = status
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
                progress.update(
                    advance=1, description=f"Analysing {name[:36]}"
                )
            elif done % 1000 == 0:
                elapsed = time.time() - batch_start
                rate = done / elapsed if elapsed > 0 else 0
                _log(f"Processed {done}/{len(pending)} packages ({rate:.1f}/s)")

            if done % 1000 == 0:
                save_resume_state({"processed": sorted(processed)})
    finally:
        if progress is not None:
            progress.stop()

    result.scans = _scan_records(detail, scan_status)
    result.scan_summary = _scan_summary(result.scans, scan_status)
    result.started_at = datetime.fromtimestamp(
        batch_start, timezone.utc).isoformat()
    result.finished_at = datetime.now(timezone.utc).isoformat()
    result.partial = cycle_partial
    result.cycle_id = f"{result.started_at}-{uuid.uuid4().hex[:12]}"

    if fetch_failures:
        _log(f"{fetch_failures} package(s) had no fetchable PKGBUILD this cycle")

    if not_vetted:
        _log(
            f"{not_vetted} package(s) were NOT vetted this cycle: the "
            "sandboxed tokenizer could not answer and nothing was recorded "
            "for them"
        )

    save_resume_state({"processed": sorted(processed)})
    if stopped:
        cycle_partial = True
        result.stopped = True
        _log("Stop requested; progress saved for the next cycle")

    _finish_cycle(
        result=result, scores=scores, over_threshold=over_threshold,
        ioc_hits=ioc_hits, refusals=refusals, detail=detail,
        partial=cycle_partial,
        pending=pending, pending_all=pending_all, processed=processed,
        backfill_day_end=backfill_day_end, now=locals().get("now", 0),
        new_meta=new_meta,
        old_meta=old_meta, added=added, changed=changed, removed=removed,
        popular=popular, _run_corpus_sweep=_run_corpus_sweep,
        _report_expired_campaigns=_report_expired_campaigns,
        _record_cycle_feed=_record_cycle_feed,
        _persist_metadata=_persist_metadata,
        clear_resume_state=clear_resume_state,
        _set_since_cursor=_set_since_cursor, _log=_log,
        record_alerts=record_alerts,
        _NON_ALERTING_CLUSTER_RULES=_NON_ALERTING_CLUSTER_RULES,
        _IMPERSONATION_GATED_RULES=_IMPERSONATION_GATED_RULES,
        _FLAGGED_SCORE=_FLAGGED_SCORE,
        _FLAGGED_REPORT_LIMIT=_FLAGGED_REPORT_LIMIT,
        batch_start=batch_start, export_path=export_path, sign_key=sign_key,
        time=time,
    )
    return result

def _prefill_missing_dependencies(
    new_meta, pending, to_process, MAX_DEPTH_NODES,
    _missing_direct_dependencies, _log, _iter_prefetched, _fetch_one,
    _fetch_workers, _analyse_and_store, log, _MAX_PREFILL_CANDIDATES,
) -> None:
    """Baseline direct dependencies the roots need before the roots run."""
    # A direct AUR dependency missing from the corpus makes the root's walk
    # fail closed as deps_not_scanned.  The watcher analyses only changed
    # packages, so an unchanged dependency that predates the corpus would
    # otherwise stay unread indefinitely.  Baseline those dependencies here,
    # before the roots, with depth 0 so this cannot recurse.  Anything in the
    # current delta is excluded: its own turn as a root must record the diff.
    # The walk reads dependency *identities*, so this pass resolves each
    # declared name the same way before deciding whether it needs baselining:
    # a dependency met only through a unique Provides alias is otherwise
    # skipped here and reported unreadable by the walk.
    from ..depth import SnapshotMetadata

    resolve = SnapshotMetadata(new_meta).aur_name
    missing_deps, prefill_capped = _missing_direct_dependencies(
        new_meta, pending, set(to_process), MAX_DEPTH_NODES, resolve=resolve)
    if missing_deps:
        _log(
            f"Prefilling {len(missing_deps)} missing AUR "
            f"dependenc{'y' if len(missing_deps) == 1 else 'ies'} "
            "so this cycle's walks can read them"
        )
        prefetched = 0
        for dep_name, fetched in _iter_prefetched(
                missing_deps, _fetch_one, _fetch_workers()):
            status, _fact = _analyse_and_store(dep_name, fetched, 0)
            if status == "ok":
                prefetched += 1
            else:
                log.warning(
                    "dependency prefill for %s did not complete (%s); the "
                    "dependent may report deps_not_scanned", dep_name, status)
        _log(f"Prefilled {prefetched}/{len(missing_deps)} dependencies")
    if prefill_capped:
        _log(
            f"Dependency prefill stopped at its bound "
            f"({MAX_DEPTH_NODES} fetches / {_MAX_PREFILL_CANDIDATES} "
            "candidates); more may remain for a later cycle"
        )



def _scan_records(detail: dict, statuses: dict[str, str]) -> list[dict]:
    """The compact all-scan rows for one cycle, one per attempted package."""
    records = []
    for package in sorted(statuses):
        status = statuses[package]
        record = {"package": package, "status": status}
        data = detail.get(package) if status == "ok" else None
        if data:
            rules = []
            seen = set()
            for finding in data.get("findings") or ():
                rule_id = str(finding.get("rule_id", ""))
                if not rule_id or rule_id in seen:
                    continue
                seen.add(rule_id)
                row = {
                    "id": rule_id,
                    "severity": str(finding.get("severity", "")),
                }
                if (finding.get("anergic")
                        or (finding.get("evidence") or {}).get("anergic")):
                    row["weight"] = 0
                    row["anergic"] = True
                rules.append(row)
            record.update({
                "score": int(data.get("score", 0) or 0),
                "risk": str(data.get("risk", "") or ""),
                "old_version": str(data.get("old_version", "") or ""),
                "new_version": str(data.get("new_version", "") or ""),
                "maintainer": str(data.get("maintainer", "") or ""),
                "rules": rules,
                "coverage_gaps": list(data.get("coverage_gaps") or ()),
                "has_diff": bool(data.get("diff") or data.get("diff_sha256")),
            })
            if data.get("dependency_analysis"):
                record["dependency_analysis"] = data["dependency_analysis"]
        records.append(record)
    return records


def _scan_summary(records: list[dict], statuses: dict[str, str]) -> dict:
    """Cycle workload counts derived beside the records, never guessed."""
    counts = {
        "attempted": len(records),
        "succeeded": 0,
        "fetch_failed": 0,
        "not_vetted": 0,
        "vanished": 0,
        "reserved": 0,
        "with_diff": 0,
    }
    key = {"ok": "succeeded"}
    for status in statuses.values():
        name = key.get(status, status)
        if name in counts:
            counts[name] += 1
    counts["with_diff"] = sum(1 for record in records if record.get("has_diff"))
    return counts


def _finish_cycle(
    *, result, scores, over_threshold, ioc_hits, refusals, detail, partial,
    pending, pending_all, processed, backfill_day_end, now, new_meta, old_meta,
    added, changed, removed, popular, _run_corpus_sweep,
    _report_expired_campaigns, _record_cycle_feed, _persist_metadata,
    clear_resume_state, _set_since_cursor, _log, record_alerts,
    _NON_ALERTING_CLUSTER_RULES, _IMPERSONATION_GATED_RULES, _FLAGGED_SCORE,
    _FLAGGED_REPORT_LIMIT, batch_start, export_path, sign_key, time,
) -> None:
    """Scores, partial/backfill exits, sweep, alerts and the closing report."""
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
    result.refusals = sorted(refusals)
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
            # Caught up: join the live delta path.  The origin sentinel is
            # kept, not cleared, so the --since re-passed next cycle is not
            # mistaken for a new replay (see the guard above the day walk).
            _persist_metadata(new_meta)
            _set_since_cursor(None)
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
    cluster_findings = _run_corpus_sweep(
        new_meta, old_meta, processed, scores, popular, detail)
    _report_expired_campaigns(_log)
    _record_cycle_feed(new_meta, old_meta, added, changed, removed)
    _persist_metadata(new_meta)
    clear_resume_state()
    result.cluster_findings = cluster_findings
    result.processed = len(processed)
    # A context rule describes the corpus for prioritisation and must not
    # alert.  H057/H060/H061 are weight 0; feeding them to record_alerts
    # turned a routine sweep into hundreds of "new alert(s)" - 226 H061
    # centrality hubs in one cycle.  What this cycle analysed, worst first:
    # the individual packages a watcher would otherwise have to go looking
    # for in `trustsight list`.  Both lists were computed above the
    # partial-cycle return, so this path only reads them.
    alerting = [
        finding for finding in cluster_findings
        if finding["rule_id"] not in _NON_ALERTING_CLUSTER_RULES
        and not (finding["rule_id"] in _IMPERSONATION_GATED_RULES
                 and not finding.get("params", {}).get("impersonated"))
    ]
    refractory: list[dict] = []
    pairs: list[tuple] = []
    for finding in alerting:
        campaign_id = (finding.get("params") or {}).get("campaign_id", "")
        for member in finding["params"]["members"]:
            pairs.append((member, finding["rule_id"], campaign_id)
                         if campaign_id else (member, finding["rule_id"]))
    try:
        import inspect

        accepts_audit = "audit" in inspect.signature(record_alerts).parameters
    except (TypeError, ValueError):
        accepts_audit = False
    if accepts_audit:
        result.new_alerts = record_alerts(pairs, audit=refractory)
    else:  # a caller/test double with the pre-audit signature
        result.new_alerts = record_alerts(pairs)
    result.refractory = refractory
    if cluster_findings:
        _log(f"Corpus sweep: {len(cluster_findings)} cluster finding(s), "
             f"{len(alerting)} alerting")
        for finding in alerting:
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
