"""Bootstrap and incremental corpus pipeline."""

import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

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


def _logger(json_output: bool):
    if json_output:
        import json as _json

        def _log(msg):
            print(_json.dumps({"msg": msg}))
    else:
        def _log(msg):
            log.info(msg)
    return _log


def run_baseline_build(
    resume: bool = False,
    export_path: Optional[str] = None,
    sign_key: Optional[str] = None,
    json_output: bool = False,
) -> CycleResult:
    """Bootstrap or update the full-AUR corpus.

    Fetches the metadata snapshot, diffs against the stored copy (or
    treats every package as new for a fresh bootstrap), downloads
    PKGBUILDs, analyses each package, stores results, and optionally
    exports a signed baseline artifact.

    Returns what the cycle did so ``run_watch`` can report on it; the
    single-shot CLI path ignores the value.
    """
    _ensure_init()
    result = CycleResult()
    _log = _logger(json_output)

    _log("Fetching AUR metadata snapshot …")
    new_meta = fetch_metadata()
    meta_count = len(new_meta)
    _log(f"Fetched {meta_count} package entries")

    old_meta = load_metadata(_meta_snapshot_path())

    if old_meta is None:
        added = sorted(new_meta)
        changed: list[str] = []
        removed: list[str] = []
        result.bootstrap = True
        _log("No prior snapshot found; processing all packages")
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
        return result

    resume_state = load_resume_state() if resume else None
    processed: set[str] = set(resume_state.get("processed", [])) if resume_state else set()
    scores: dict[str, int] = {}

    _log(f"Processing {len(to_process)} packages ({len(processed)} previously done)")
    batch_start = time.time()

    for i, name in enumerate(to_process):
        if name in processed:
            continue

        meta = new_meta.get(name)
        if meta is None:
            log.warning("metadata for %s vanished; skipping", name)
            continue

        pkgbase = _pkg_or_base(meta)

        old_snapshot = get_pkgbuild_snapshot(name)
        old_pkgbuild = old_snapshot["pkgbuild_text"] if old_snapshot else None
        prev_last_modified: Optional[int] = (
            old_snapshot["last_modified"] if old_snapshot else None
        )

        new_pkgbuild, tree_manifest = fetch_pkgbuild_with_tree(pkgbase)
        if new_pkgbuild is None:
            log.warning("could not fetch PKGBUILD for %s (base: %s)", name, pkgbase)
            save_resume_state({"processed": sorted(processed | {name})})
            continue

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

        if is_reserved_name(name):
            _logger().warning("skipping reserved package name %r", name)
            continue

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
        processed.add(name)

        if (i + 1) % 1000 == 0:
            elapsed = time.time() - batch_start
            rate = (i + 1) / elapsed if elapsed > 0 else 0
            _log(f"Processed {i + 1}/{len(to_process)} packages ({rate:.1f}/s)")
            save_resume_state({"processed": sorted(processed)})

    save_resume_state({"processed": sorted(processed)})
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
    default = int(limits.get("watch_interval", 3600))
    floor = int(limits.get("watch_min_interval", 60))
    return max(floor, int(requested) if requested else default)


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
    try:
        while True:
            result = run_baseline_build(json_output=json_output)
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



