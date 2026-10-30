"""Bootstrap and incremental corpus pipeline (facade)."""

import json  # noqa: F401
import time
from typing import Callable, Optional


from ..analysis.base import _ensure_init  # noqa: F401
from ..config import load_config
from ..db import (  # noqa: F401
    brand_new_packages_since,
    activate_campaign,
    active_campaigns,
    record_cycle_events,
    checkpoint_wal,
    clear_correlation_feeds,
    get_metadata,
    record_alerts,
    get_pkgbuild_snapshot,
    get_previous_pkgbuild_snapshot,
    record_upstream_dep_additions,
    is_reserved_name,
    save_package_profile,
    save_pkgbuild_snapshot,
    set_metadata,
    write_batch,
)
from ..schema import TemporalContext  # noqa: F401
from ..scoring import risk_level  # noqa: F401
from ..tokenizer import TokenizerUnavailable  # noqa: F401
from ..depth import MAX_DEPTH_NODES  # noqa: F401
from ..safe_text import clean
from .corpus import run_corpus_sweep, source_repos_from_pkgbuild
from .analyze import analyze_package_text  # noqa: F401
from .fetch import (  # noqa: F401
    clear_resume_state,
    fetch_pkgbuild_with_tree,
    load_resume_state,
    save_resume_state,
)
from .metadata import (  # noqa: F401
    clear_current_dump,
    diff_metadata,
    fetch_metadata,
    load_metadata,
    metadata_unchanged,
    release_memory,
    save_metadata,
)

from ._pipeline_helpers import (  # noqa: F401
    log,
    _FLAGGED_SCORE,
    _OVER_BENIGN_P95,
    _SINCE_DAY_SECONDS,
    _SINCE_CURSOR_KEY,
    _SINCE_ORIGIN_KEY,
    _FLAGGED_REPORT_LIMIT,
    _NON_ALERTING_CLUSTER_RULES,
    _IMPERSONATION_GATED_RULES,
    _CAMPAIGN_RULES,
    _MAX_NOTIFY_DIFF_BYTES,
    _recipe_digest,
    _notify_diff,
    _is_routine_bump,
    _since_cursor,
    _set_since_cursor,
    _meta_snapshot_path,
    _pkg_or_base,
    _profile_score,
    _H029_POPULARITY_CANDIDATE_LIMIT,
    _popular_candidates,
    _impersonates,
    _campaign_identity,
    _report_reactivation_pressure,
    _report_expired_campaigns,
    _neighborhood_elevation,
    _correlation_records,
    _contacts_enabled,
    _record_contacts_and_g010,
    _apply_cluster_weights,
    CycleResult,
)
from ._pipeline_limits import (  # noqa: F401
    _fetch_workers,
    _max_per_cycle,
    _META_DEPENDENCY_FIELDS,
    _MAX_PREFILL_CANDIDATES,
    _needs_dependency_prefill,
    _MAX_ORDER_CANDIDATES,
    _dependencies_first,
    _missing_direct_dependencies,
    _iter_prefetched,
    _corpus_progress,
)

def _persist_metadata(metadata: dict) -> None:
    """Write the snapshot and its slim index unless the dump was unchanged.

    A 304 already left that snapshot on disk; rewriting 78 MB of identical
    JSON every quiet cycle is pure CPU and I/O.
    """
    if metadata_unchanged():
        log.info("AUR metadata unchanged; keeping the stored snapshot")
        return
    save_metadata(metadata, _meta_snapshot_path())


def _run_corpus_sweep(
    new_meta: dict,
    old_meta: Optional[dict],
    processed: set[str],
    scores: dict[str, int],
    popular: Optional[list[tuple[str, int]]] = None,
    detail: Optional[dict] = None,
) -> list[dict]:
    """Run the Class D detectors and attach their additive weight.

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

    # The shared, once-per-cycle history read: the temporal engine's
    # rate/baseline instances all consume this one snapshot.
    from .temporal_engine import read_cycle_history

    history = read_cycle_history(processed)
    routine_only = {
        name for name, entry in (detail or {}).items()
        if entry.get("routine_only")
    }
    findings = run_corpus_sweep(
        new_meta,
        old_meta,
        source_repos=source_repos,
        prior_history=history["prior_history"],
        maintainer_history=history["maintainer_history"],
        routine_only=routine_only,
        now=int(time.time()),
    )

    # the G-series cross-package correlation, over the
    # cycle's records (collective input, so it runs here and not per package).
    from ..analysis.correlation import (
        correlate,
        first_seen_adoption_burst,
        package_creation_burst,
    )

    records = _correlation_records(new_meta, old_meta, processed, popular,
                                   source_repos, detail)
    config = load_config()
    findings.extend(correlate(records, config))
    # G008 reads the maintainer-event timeline to tell a first-seen account
    # from an established one; it runs before campaign activation so a burst
    # primes campaign state like any other G-series cluster.
    findings.extend(first_seen_adoption_burst(records, config))
    # G011 spans cycles: the observed placeholder burst was spread over
    # several cycles, so this reads the recorded window rather than the
    # current cycle's processed set.
    g011 = (config.get("thresholds", {}) or {}).get("g011", {}) or {}
    try:
        creation_window_days = max(0, int(g011.get("window_days", 7)))
    except (TypeError, ValueError, OverflowError):
        creation_window_days = 7
    creation_since = int(time.time()) - creation_window_days * 86400
    findings.extend(package_creation_burst(
        brand_new_packages_since(creation_since), config))
    # The Contact Ledger records every first-contact this cycle introduced
    # (weight 0, warm-only), then G010 joins the first-seen hosts across the
    # window.  Nothing here scores: contact_ledger is state, not a rule.
    findings.extend(_record_contacts_and_g010(records, config))

    refused = _activate_campaigns(findings, config, log=log)
    if refused:
        # Campaign mode is temporary memory; refusing to remember a campaign
        # because every slot holds a live TTL must be visible, not silent.
        log.warning(
            "campaign cap reached; %d campaign(s) not activated this cycle: %s",
            len(refused), clean(", ".join(sorted(refused))),
        )
    findings.extend(_neighborhood_elevation(records))

    _apply_cluster_weights(findings, new_meta, popular, scores)
    return findings

def _record_cycle_feed(*args, **kwargs):
    from ._pipeline_helpers import _record_cycle_feed as _impl
    return _impl(*args, record_events=record_cycle_events, **kwargs)


def _activate_campaigns(*args, **kwargs):
    from ._pipeline_helpers import _activate_campaigns as _impl
    return _impl(*args, activate=activate_campaign,
                 active=active_campaigns, **kwargs)


def _logger(json_output: bool):
    """The cycle's progress log, rendered inert.

    This is a terminal render path like any other: a cluster finding's
    ``match`` carries the gained host, maintainer or dependency name, all of
    which the input controls.  ``clean`` strips escape sequences, control
    bytes and bidi overrides before the message reaches stderr (A10).  The
    JSON lane is sanitised too, because a consumer may render the string
    later; escaping the document keeps it valid either way.
    """
    if json_output:
        import json as _json

        def _log(msg):
            print(_json.dumps({"msg": clean(msg)}))
    else:
        def _log(msg):
            log.info(clean(msg))
    return _log

def run_baseline_build(
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
            should_stop=should_stop,
        )
    finally:
        # A cycle can write thousands of rows; leave the WAL small
        # instead of waiting for the next manual vacuum.
        checkpoint_wal()
        # Drop the parsed dump before trimming: the next fetch replaces it,
        # and holding it across the sleep pinned ~360 MB between cycles.
        clear_current_dump()
        release_memory()


from ._baseline_build import _run_baseline_build  # noqa: E402,F401


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

from ._pipeline_watch import run_watch  # noqa: E402,F401
