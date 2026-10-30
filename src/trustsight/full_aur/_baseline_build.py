"""Baseline-build implementation, using the facade for patchable globals."""

import json
import time
from typing import Callable, Optional

from ._pipeline_helpers import CycleResult


def _pipeline():
    from . import pipeline
    return pipeline


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
    CycleResult = p.CycleResult
    MAX_DEPTH_NODES = p.MAX_DEPTH_NODES
    TemporalContext = p.TemporalContext
    TokenizerUnavailable = p.TokenizerUnavailable
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
    _is_routine_bump = p._is_routine_bump
    _iter_prefetched = p._iter_prefetched
    _logger = p._logger
    _max_per_cycle = p._max_per_cycle
    _meta_snapshot_path = p._meta_snapshot_path
    _missing_direct_dependencies = p._missing_direct_dependencies
    _notify_diff = p._notify_diff
    _persist_metadata = p._persist_metadata
    _pkg_or_base = p._pkg_or_base
    _popular_candidates = p._popular_candidates
    _recipe_digest = p._recipe_digest
    _record_cycle_feed = p._record_cycle_feed
    _report_expired_campaigns = p._report_expired_campaigns
    _run_corpus_sweep = p._run_corpus_sweep
    _set_since_cursor = p._set_since_cursor
    _since_cursor = p._since_cursor
    analyze_package_text = p.analyze_package_text
    source_repos_from_pkgbuild = p.source_repos_from_pkgbuild
    clear_correlation_feeds = p.clear_correlation_feeds
    clear_resume_state = p.clear_resume_state
    diff_metadata = p.diff_metadata
    fetch_metadata = p.fetch_metadata
    fetch_pkgbuild_with_tree = p.fetch_pkgbuild_with_tree
    get_metadata = p.get_metadata
    get_pkgbuild_snapshot = p.get_pkgbuild_snapshot
    get_previous_pkgbuild_snapshot = p.get_previous_pkgbuild_snapshot
    is_reserved_name = p.is_reserved_name
    load_metadata = p.load_metadata
    load_resume_state = p.load_resume_state
    log = p.log
    record_alerts = p.record_alerts
    record_upstream_dep_additions = p.record_upstream_dep_additions
    risk_level = p.risk_level
    save_package_profile = p.save_package_profile
    save_pkgbuild_snapshot = p.save_pkgbuild_snapshot
    save_resume_state = p.save_resume_state
    set_metadata = p.set_metadata
    write_batch = p.write_batch

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

    # Cap the work per invocation so even a bootstrap advances in bounded,
    # resumable chunks.  The remainder is picked up on the next run.
    cap = _max_per_cycle()
    pending_all = [n for n in to_process if n not in processed]
    pending = pending_all[:cap] if cap else pending_all
    partial = bool(cap) and len(pending_all) > cap
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

    def _fetch_one(name):
        meta = new_meta.get(name)
        if meta is None:
            return (None, None, None, False, None, None, None, True)
        return fetch_pkgbuild_with_tree(_pkg_or_base(meta))

    def _analyse_and_store(name, fetched, analyse_depth):
        """Analyse one fetched package and persist its result.

        Returns ``(status, fact)``.  This is the shared half of the root
        path and the dependency prefill: it owns the tokenizer refusal, the
        snapshot/profile write and G004's baseline handling, but emits no
        alert.  A prefill must persist the dependency without entering the
        cycle's score/detail maps.
        """
        meta = new_meta.get(name)
        if meta is None:
            log.warning("metadata for %s vanished; skipping", name)
            return "vanished", None
        if is_reserved_name(name):
            log.warning("skipping reserved package name %r", name)
            return "reserved", None
        (new_pkgbuild, tree_manifest, trailer_finding, snapshot_refused,
         install_text, install_name, manifest_texts,
         manifest_complete) = fetched
        if new_pkgbuild is None:
            log.debug("could not fetch PKGBUILD for %s (base: %s)", name, _pkg_or_base(meta))
            return "fetch_failed", None

        old_snapshot = get_pkgbuild_snapshot(name)
        old_pkgbuild = old_snapshot["pkgbuild_text"] if old_snapshot else None
        prev_last_modified: Optional[int] = (
            old_snapshot["last_modified"] if old_snapshot else None
        )
        # G004 state: this cycle's committed remote dependencies, and the
        # set the last recorded cycle saw.  No prior set (first observation,
        # a baseline import, or a pre-migration row) is a baseline, not an
        # empty history: every dependency would look "added" otherwise.
        manifest_pairs: set[tuple[str, str]] = set()
        manifest_deps_json: Optional[str] = None
        manifest_incomplete = False
        prior_deps: Optional[set[tuple[str, str]]] = None
        if manifest_texts is not None:
            from ..analysis.manifests import tree_remote_dependency_pairs
            manifest_pairs, incomplete = tree_remote_dependency_pairs(
                manifest_texts)
            manifest_incomplete = incomplete or not manifest_complete
            if not manifest_incomplete:
                manifest_deps_json = json.dumps(
                    sorted([list(pair) for pair in manifest_pairs]))
        raw_prior = old_snapshot.get("manifest_deps") if old_snapshot else None
        if raw_prior:
            try:
                decoded = json.loads(raw_prior)
                if isinstance(decoded, list):
                    prior_deps = {
                        (str(pair[0]), str(pair[1]))
                        for pair in decoded
                        if isinstance(pair, (list, tuple)) and len(pair) == 2
                    }
            except (ValueError, TypeError):
                prior_deps = None
        manifest_state_json = None
        manifest_deltas = ()
        workflow_deltas = ()
        if manifest_texts is not None and not manifest_incomplete:
            from ..analysis.manifest_state import (
                build_manifest_state,
                manifest_state_delta,
            )

            manifest_state_json = build_manifest_state(
                manifest_texts, tree_manifest)
            if manifest_state_json and old_snapshot:
                manifest_deltas, workflow_deltas = manifest_state_delta(
                    old_snapshot.get("manifest_state"), manifest_state_json)
        try:
            with write_batch():
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
                    depth=analyse_depth,
                    # The corpus builder is a writer by definition: it exists to
                    # accumulate the observations the read-only default consumes.
                    record=True,
                    popular_candidates=popular,
                    package_popularity=int((new_meta.get(name) or {}).get("NumVotes", 0) or 0),
                    install_text=install_text,
                    install_name=install_name,
                    old_install_text=(old_snapshot.get("install_text")
                                      if old_snapshot else None),
                    upstream_manifest_incomplete=manifest_incomplete,
                    manifest_deltas=manifest_deltas,
                    workflow_deltas=workflow_deltas,
                )
                save_pkgbuild_snapshot(
                    package_name=name,
                    pkgbuild_text=new_pkgbuild,
                    version=fact.new_version or meta.get("Version", ""),
                    last_modified=meta.get("LastModified", 0),
                    install_text=install_text,
                    manifest_deps=manifest_deps_json,
                    manifest_state=manifest_state_json,
                )
                if manifest_deps_json is not None and prior_deps is not None:
                    record_upstream_dep_additions(
                        name, sorted(manifest_pairs - prior_deps))
                save_package_profile(
                    package_name=name,
                    last_score=fact.final_score,
                    # score_breakdown is a list of ScoreEntry, not a dict: asking it
                    # for "risk_label" raised AttributeError on the first package of
                    # every bootstrap.  The label is derived from the score.
                    last_risk=risk_level(fact.final_score),
                )
        except TokenizerUnavailable as exc:
            # The sandboxed tokenizer could not answer (A6).  The package is
            # not analysed and nothing is persisted, so it cannot enter the
            # corpus as if it had been vetted; the cycle continues.
            log.warning("tokenizer unavailable for %s: %s; not vetted", name, exc)
            return "not_vetted", None
        return "ok", fact

    def _store(name, fetched) -> str:
        """Analyse and persist one fetched package.  Returns a status string:
        ``ok``, ``vanished``, ``reserved`` or ``fetch_failed``."""
        status, fact = _analyse_and_store(name, fetched, depth)
        if status != "ok":
            return status
        meta = new_meta.get(name) or {}
        old_snapshot = get_pkgbuild_snapshot(name)
        scores[name] = fact.final_score
        if fact.ioc_matches:
            # A known-bad match pages at maximum priority whatever the score:
            # the IOC tier is reported outside the heuristic score, so a clean-
            # looking package on the list would never cross the alerting bar.
            for m in fact.ioc_matches:
                ioc_hits[name].append(f"{m.type}:{m.value}")
        # Federated upstream indicators use the same maximum-priority lane.
        for entry in fact.score_breakdown:
            if entry.rule_id in ("U007", "U008"):
                repo = (entry.params or {}).get("upstream_repo", "")
                ioc_hits[name].append(f"upstream_repo:{repo}")
        # What a notification needs to say *where* a finding fired, not only
        # that a rule did.  Each entry names the rule, the file and line of
        # the evidence, its severity/weight and the rendered reason, so a
        # reader can point at the exact line in the PKGBUILD.  A rule with no
        # location (corpus, novelty, provenance) carries file="" and line=None
        # rather than a guessed one.
        #
        # Every entry rides, weight or not: a zero-weight finding is still a
        # finding (a declared practice, a coverage gap, a boundary warning),
        # and dropping it here is how the feed ended up unable to explain the
        # signals the score deliberately excludes.
        from ..registry import uid_of

        findings = [
            {
                "rule_id": e.rule_id,
                # The permanent identity behind the display id, so a feed
                # reader can join an alert back to its rule however the
                # display id is later renamed.
                "rule_uid": uid_of(e.rule_id),
                "severity": e.severity,
                "weight": e.weight,
                "file": e.file or "",
                "line": e.line,
                "reason": e.reason,
            }
            for e in fact.score_breakdown
        ]
        # A parser refusal means part of the change was not read.  It is
        # alert-worthy regardless of score (the weight is capped so it cannot
        # cross the bar alone), so it is tracked as its own tier.
        if any(f["rule_id"] in ("X026", "X027") for f in findings):
            refusals.add(name)
        from ..analysis.payload_signals import payload_urls

        try:
            payload_targets = payload_urls(fact.score_breakdown)
        except Exception:
            # URL extraction is an auxiliary join feed; a malformed finding
            # must not abort the cycle or the package's stored result.
            payload_targets = []

        new_pkgbuild = fetched[0] or ""
        previous_snapshot = get_previous_pkgbuild_snapshot(name) or {}
        old_pkgbuild = previous_snapshot.get("pkgbuild_text") or ""
        detail[name] = {
            "score": fact.final_score,
            "old_version": old_snapshot["version"] if old_snapshot else "",
            "new_version": fact.new_version or meta.get("Version", ""),
            "last_modified": meta.get("LastModified"),
            # Who owns the package now, and who owned it in the previous
            # snapshot.  The alert document needs both sides for an ownership
            # rule, and a campaign needs them per member; keeping them out of
            # `detail` meant every consumer had to re-fetch the AUR metadata.
            "maintainer": meta.get("Maintainer") or "",
            "previous_maintainer": (
                ((old_meta or {}).get(name) or {}).get("Maintainer") or ""),
            # The exact bytes the analysis read.  The feed otherwise has to
            # serve the current AUR file, which may be several commits past
            # the analysed change.  The diff is bounded and inert; when it is
            # too large the digest still names the analysed revision.
            "pkgbuild_sha256": _recipe_digest(new_pkgbuild),
            "previous_pkgbuild_sha256": _recipe_digest(old_pkgbuild or ""),
            "rules": [f["rule_id"] for f in findings],
            "payload_urls": payload_targets,
            "findings": findings,
            # H058 stands down only when every member of a maintainer's batch
            # is a routine version/checksum bump.  Computed here, where both
            # recipe texts are in hand.
            "routine_only": _is_routine_bump(old_pkgbuild or "", new_pkgbuild),
            # The sweep joins on this; compute it while the recipe is in hand
            # instead of re-reading the snapshot and re-parsing it per package.
            "source_repos": sorted(source_repos_from_pkgbuild(new_pkgbuild)),
            **_notify_diff(old_pkgbuild or "", new_pkgbuild),
        }
        return "ok"

    # A direct AUR dependency missing from the corpus makes the root's walk
    # fail closed as deps_not_scanned.  The watcher analyses only changed
    # packages, so an unchanged dependency that predates the corpus would
    # otherwise stay unread indefinitely.  Baseline those dependencies here,
    # before the roots, with depth 0 so this cannot recurse.  Anything in the
    # current delta is excluded: its own turn as a root must record the diff.
    missing_deps, prefill_capped = _missing_direct_dependencies(
        new_meta, pending, set(to_process), MAX_DEPTH_NODES)
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

    fetch_failures = 0
    not_vetted = 0
    stopped = False
    progress = _corpus_progress(len(pending), json_output)
    try:
        done = 0
        for name, fetched in _iter_prefetched(process_order, _fetch_one, _fetch_workers()):
            if should_stop is not None and should_stop():
                stopped = True
                break
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
    if stopped:
        partial = True
        result.stopped = True
        _log("Stop requested; progress saved for the next cycle")

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
    result.new_alerts = record_alerts([
        (member, finding["rule_id"])
        for finding in alerting
        for member in finding["params"]["members"]
    ])
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
