"""Per-package work inside one corpus cycle: fetch, analyse, record.

Extracted from :mod:`._baseline_build` so the cycle body reads as
plan -> analyse -> record.  Every helper resolves its collaborators from the
``pipeline`` facade at call time, because that facade is where the tests and
the watcher patch them.
"""

import json
from dataclasses import dataclass, field
from typing import Optional


def _pipeline():
    from . import pipeline
    return pipeline


@dataclass
class _CycleState:
    """Everything one corpus cycle accumulates and hands between helpers."""

    new_meta: dict
    old_meta: Optional[dict]
    depth: Optional[int]
    popular: list
    scores: dict[str, int]
    detail: dict[str, dict]
    ioc_hits: dict[str, list[str]]
    refusals: set[str]
    # The manifest delta a notification should carry, kept per package:
    # computed while analysing and read by _store afterwards.
    manifests_by_name: dict[str, list[dict]] = field(default_factory=dict)
    manifests_truncated_by_name: dict[str, bool] = field(default_factory=dict)
    upstream_budget: object | None = None


#: Manifests one notification describes, and dependency names per side.  A
#: source tree can carry hundreds of manifests and the notification is bounded:
#: the feed shows the first slice and the counts, never the whole tree.
MAX_NOTIFY_MANIFESTS = 20
MAX_NOTIFY_MANIFEST_NAMES = 12


def _manifests_summary(deltas) -> list[dict]:
    """The manifest deltas a reader can act on, bounded for the payload.

    The alert already carries the recipe diff, which never contains a manifest
    that lives inside the declared source archive.  This is the one place the
    feed can learn that ``Cargo.toml`` in the archive gained a dependency,
    so it travels with the alert instead of being re-derived by the receiver.
    """
    out = []
    for delta in list(deltas or ())[:MAX_NOTIFY_MANIFESTS]:
        added = [str(name) for name in getattr(delta, "added", ()) or ()]
        removed = [str(name) for name in getattr(delta, "removed", ()) or ()]
        out.append({
            "path": str(getattr(delta, "path", "") or ""),
            "format": str(getattr(delta, "format", "") or ""),
            "status": str(getattr(delta, "status", "") or ""),
            "added": sorted(added)[:MAX_NOTIFY_MANIFEST_NAMES],
            "removed": sorted(removed)[:MAX_NOTIFY_MANIFEST_NAMES],
            "added_total": len(added),
            "removed_total": len(removed),
        })
    return out


def _dependency_analysis(fact) -> dict | None:
    """The bounded dependency-walk summary a scan record can carry.

    The feed does not need every analysed dependency (the corpus already
    stores each one under its own name); it needs to say how deep the walk
    went, what it saw, and which dependencies independently cleared the
    review threshold.  The list is capped so one hostile closure cannot
    inflate a signed scan document.
    """
    reports = list(getattr(fact, "dependencies", ()) or ())
    requested = getattr(fact, "depth", None)
    if requested in (None, 0) and not reports:
        return None

    def row(report) -> dict:
        return {
            "name": str(getattr(report, "name", "") or ""),
            "depth": int(getattr(report, "depth", 0) or 0),
            "score": int(getattr(report, "score", 0) or 0),
            "risk": str(getattr(report, "risk", "") or ""),
            "finding_count": int(getattr(report, "finding_count", 0) or 0),
            "via": str(getattr(report, "via", "") or ""),
            "parent": str(getattr(report, "parent", "") or ""),
            "failed": bool(getattr(report, "failed", False)),
        }

    flagged = [report for report in reports
               if getattr(report, "flagged", False)]
    failed = [report for report in reports
              if getattr(report, "failed", False)]
    return {
        "requested_depth": int(requested) if requested is not None else 0,
        "examined": len(reports),
        "maximum_depth_reached": max(
            (int(getattr(report, "depth", 0) or 0) for report in reports),
            default=0,
        ),
        "truncated": bool(getattr(fact, "depth_truncated", False)),
        "note": str(getattr(fact, "depth_note", "") or "")[:300],
        "flagged_count": len(flagged),
        "failed_count": len(failed),
        "flagged": [row(report) for report in flagged[:25]],
        "failed": [row(report) for report in failed[:25]],
    }


def _fetch_one(state: "_CycleState", name: str):
    """Fetch one package's PKGBUILD and snapshot tree by name."""
    p = _pipeline()
    new_meta = state.new_meta
    _pkg_or_base = p._pkg_or_base
    fetch_pkgbuild_with_tree = p.fetch_pkgbuild_with_tree
    meta = new_meta.get(name)
    if meta is None:
        return (None, None, None, False, None, None, None, True)
    return fetch_pkgbuild_with_tree(_pkg_or_base(meta))


def _analyse_and_store(state: "_CycleState", name, fetched, analyse_depth):
    """Analyse one fetched package and persist its result.

    Returns ``(status, fact)``.  This is the shared half of the root
    path and the dependency prefill: it owns the tokenizer refusal, the
    snapshot/profile write and G004's baseline handling, but emits no
    alert.  A prefill must persist the dependency without entering the
    cycle's score/detail maps.
    """
    p = _pipeline()
    log = p.log
    new_meta = state.new_meta
    popular = state.popular
    manifests_by_name = state.manifests_by_name
    manifests_truncated_by_name = state.manifests_truncated_by_name
    analyze_package_text = p.analyze_package_text
    is_reserved_name = p.is_reserved_name
    _pkg_or_base = p._pkg_or_base
    TokenizerUnavailable = p.TokenizerUnavailable
    TemporalContext = p.TemporalContext
    get_pkgbuild_snapshot = p.get_pkgbuild_snapshot
    save_pkgbuild_snapshot = p.save_pkgbuild_snapshot
    save_package_profile = p.save_package_profile
    record_upstream_dep_additions = p.record_upstream_dep_additions
    risk_level = p.risk_level

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

    # The opt-in upstream lane: the AUR snapshot only carries files
    # committed beside the recipe, so the U-series would never see a
    # manifest inside the declared source archive.  Off unless
    # [upstream_scan] enabled; a refusal is logged and never fails the
    # cycle, and the default local path does not call this.
    upstream_texts: list[tuple[str, str]] = []
    upstream_findings: list[dict] = []
    upstream_notes: list[str] = []
    verified_upstream_hashes: frozenset[str] = frozenset()
    if manifest_texts is not None:
        try:
            from ..upstream_collect import collect_upstream_manifest_texts
            if state.upstream_budget is None:
                from ..config import load_config
                from ..upstream_collect import UpstreamBudget

                state.upstream_budget = UpstreamBudget.from_config(load_config())

            (upstream_texts, upstream_notes, upstream_findings,
             verified_upstream_hashes) = collect_upstream_manifest_texts(
                new_pkgbuild, budget=state.upstream_budget)
            if upstream_texts:
                manifest_texts = list(manifest_texts) + upstream_texts
            for note in upstream_notes:
                log.info("%s: upstream scan boundary %s", name, note)
            from ..upstream_collect import persist_upstream_observation

            persist_upstream_observation(
                name, new_pkgbuild, upstream_texts, upstream_findings,
                upstream_notes, verified_upstream_hashes)
        except Exception as exc:  # noqa: BLE001 - never fail the cycle
            log.warning("%s: upstream scan failed: %s", name, exc)

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
            upstream_manifest_texts=tuple(
                text for _path, text in upstream_texts),
            manifest_deltas=manifest_deltas,
            workflow_deltas=workflow_deltas,
            upstream_findings=upstream_findings,
            verified_upstream_hashes=verified_upstream_hashes,
            upstream_scan_notes=upstream_notes,
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
    manifests_by_name[name] = _manifests_summary(manifest_deltas)
    manifests_truncated_by_name[name] = (
        len(list(manifest_deltas or ())) > MAX_NOTIFY_MANIFESTS)
    return "ok", fact


def _store(state: "_CycleState", name, fetched) -> str:
    """Analyse and persist one fetched package.  Returns a status string:
    ``ok``, ``vanished``, ``reserved`` or ``fetch_failed``."""
    p = _pipeline()
    depth = state.depth
    new_meta = state.new_meta
    old_meta = state.old_meta
    scores = state.scores
    ioc_hits = state.ioc_hits
    refusals = state.refusals
    detail = state.detail
    manifests_by_name = state.manifests_by_name
    manifests_truncated_by_name = state.manifests_truncated_by_name
    get_pkgbuild_snapshot = p.get_pkgbuild_snapshot
    get_previous_pkgbuild_snapshot = p.get_previous_pkgbuild_snapshot
    _is_routine_bump = p._is_routine_bump
    _notify_diff = p._notify_diff
    _recipe_digest = p._recipe_digest
    source_repos_from_pkgbuild = p.source_repos_from_pkgbuild

    status, fact = _analyse_and_store(state, name, fetched, depth)
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
    # A recipe that did not change has no retained previous revision:
    # ``save_pkgbuild_snapshot`` only shifts the current row into the
    # previous columns on a real text change.  Passing "" as the old
    # side then rendered "no previous recipe" as a full-addition diff,
    # which is how an ownership-only adoption (H044) appeared as a
    # wholly green PKGBUILD.  A notification may only show a diff when a
    # previous recipe was actually observed.
    notify_diff = (
        _notify_diff(old_pkgbuild, new_pkgbuild)
        if previous_snapshot and old_pkgbuild else {}
    )
    detail[name] = {
        "score": fact.final_score,
        "risk": getattr(fact, "risk", ""),
        "coverage_gaps": list(getattr(fact, "coverage_gaps", ()) or ()),
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
        "dependency_analysis": _dependency_analysis(fact),
        # T010 joins recipe dependency additions against nodes whose
        # creation/adoption is visible in this metadata cycle.
        "dependency_changes": getattr(fact, "dependency_changes", {}),
        "payload_urls": payload_targets,
        "findings": findings,
        # A manifest changed inside the source archive is invisible in the
        # recipe diff; carry its dependency delta so the feed can show it
        # in its own view instead of leaving the reader with a rule id.
        "manifests": manifests_by_name.get(name, []),
        "manifests_truncated": manifests_truncated_by_name.get(name, False),
        # H058 stands down only when every member of a maintainer's batch
        # is a routine version/checksum bump.  Computed here, where both
        # recipe texts are in hand.
        "routine_only": _is_routine_bump(old_pkgbuild or "", new_pkgbuild),
        # The sweep joins on this; compute it while the recipe is in hand
        # instead of re-reading the snapshot and re-parsing it per package.
        "source_repos": sorted(source_repos_from_pkgbuild(new_pkgbuild)),
        **notify_diff,
    }
    return "ok"
