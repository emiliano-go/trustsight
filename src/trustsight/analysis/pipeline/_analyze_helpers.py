"""Extracted analysis helpers for the package fact builder."""

import json
from ...config import (
    drifted_shipped_rules,
)
from ...db import (
    get_last_analysis,
)
from ...diffdoc import parse_diff_lines
from ...differ import (
    map_diff_lines,
    truncate_diff,
)
from ...findings import stamp
from ...sandbox.git_client import GitOpError, GitSandboxUnavailable
from ...override import (
    acknowledged_url_rows,
    suppress_acknowledged_url_findings,
)
from ...rules import (
    apply_rules,
    bound_tokenizer_lines,
    clamp_diff_lines,
    clamp_text,
    get_raw_diff_lines_indexed,
)
from ...coverage import (
    cut_hunk_details,
    gaps_from,
    note_stage_failure,
    stage_failures,
    oversized_lines,
    unresolved_assignment_rows,
)
from ...scoring import calculate_score
from ...schema import (
    with_changes,
    DiffSummary,
    PackageFact,
    fact_to_dict,
)
from ...tokenizer import split_lines, tokenize_and_resolve_indexed
from ..dependencies import name_shadow_findings
from ..ioc_match import ioc_baseline_matches
from ..placeholder import placeholder_finding
from ..structural import (
    recipe_checksum_parity_finding,
)
from ..structural_rules import apply_structural_rules
from ..version import (
    compare_installed_to_aur,
    is_vcs_package,
)
from ._common import log
from ._tree import _has_noextract, _parent_commit, _scriptlet_files_unread


def _present_before_findings(diff_text: str, config: dict) -> list[dict]:
    """What the rules see in companion content that did not move.

    These are not findings about this update.  They are emitted at weight 0
    so a reviewed trap, ``.install`` file or ``Documentation=`` URL stays
    visible on a later review instead of silently disappearing when the
    companion is diffed against the recorded baseline.
    """
    if not diff_text.strip():
        return []
    resolved, _unresolved, resolved_indices = tokenize_and_resolve_indexed(
        diff_text)
    raw_lines, raw_indices = get_raw_diff_lines_indexed(diff_text)
    findings = apply_rules(
        resolved, raw_lines,
        include_experimental=config.get("rules", {}).get("experimental", False),
        line_map=map_diff_lines(diff_text),
        resolved_indices=resolved_indices,
        raw_indices=raw_indices,
    )
    for finding in findings:
        finding["weight_override"] = 0
        params = finding.setdefault("params", {})
        params["present_before"] = True
        finding["name"] = (
            f"{finding.get('name', finding['rule_id'])} "
            "(present before, unchanged)"
        )
    return findings


def _campaign_corroboration(
    score: int, breakdown, pkg_name: str, added_urls
) -> tuple[int, list]:
    """Attach a weight-0, attributed G007 entry when a run stands in a
    campaign's scope.

    Trained immunity, **unscored**: while a campaign is primed, a run whose
    package is a campaign member, that newly gained a host in the campaign's
    scope, that fired a campaign signal, or that fetched a campaign URL is
    *reported* as corroborated - one ``G007`` ``INFO`` finding carrying
    ``campaign_id``, weight 0.

    It stays weight 0 because the points this used to add measured scope
    *breadth* (``len(scope)``), not corroboration, and the calibration corpus
    carries no active campaign state, so the added points were never measured
    against the benign false-positive rate.  The attributed report keeps the
    context visible without turning association into a score.

    Impersonated targets are deliberately **not** matched: a campaign targets
    ``yay``, and reviewing ``yay`` is not corroboration of anything.
    """
    from ...db import active_campaigns

    campaigns = active_campaigns()
    if not campaigns:
        return score, breakdown

    from urllib.parse import urlsplit

    from ..payload_signals import canonical_payload_url, payload_urls

    hosts = set()
    source_targets = set()
    for url in added_urls or ():
        try:
            parts = urlsplit(str(url))
            host = parts.hostname
        except (ValueError, TypeError):
            host = None
        if host:
            hosts.add(host)
        canonical = canonical_payload_url(str(url))
        if canonical:
            source_targets.add(canonical)

    fired = {str(getattr(entry, "rule_id", "")) for entry in breakdown or ()}
    try:
        payload_targets = set(payload_urls(breakdown))
    except Exception:
        # Corroboration is report-only; a malformed finding must not break
        # the analysis that produced it.
        payload_targets = set()
    targets = source_targets | payload_targets

    for campaign in campaigns:
        scope = campaign.get("scope", {}) or {}
        if not isinstance(scope, dict):
            continue
        names = {str(n) for n in scope.get("package_names", ()) or ()}
        scoped_hosts = {str(h) for h in scope.get("hosts", ()) or ()}
        scoped_signals = {str(s) for s in scope.get("signals", ()) or ()}
        scoped_urls = {str(u) for u in scope.get("urls", ()) or ()}
        if (pkg_name not in names
                and not (hosts & scoped_hosts)
                and not (fired & scoped_signals)
                and not (targets & scoped_urls)):
            continue
        from ...schema import ScoreEntry

        enriched = list(breakdown)
        enriched.append(ScoreEntry(
            rule_id="G007", severity="INFO", weight=0,
            reason=("stands in active campaign "
                    f"{campaign['campaign_id']} (corroboration, weight 0)"),
            evidence={"campaign_id": campaign["campaign_id"]},
        ))
        return score, enriched
    return score, breakdown


def _assemble_diff(project, old_commit: str, head_commit: str, config: dict,
                   pkg_name: str, parent_baseline: bool, diff_text: str,
                   diff_summary, generated_truncated: bool):
    """Assemble the bounded diff and its truncation/partial-hunk metadata."""
    # A local source=() companion file is build input the recipe copies into
    # $srcdir and can execute; its committed content is scanned with the same
    # rules as the PKGBUILD, or a curl|bash simply moves one file over and the
    # filename filter above drops it.  Appended before the byte cap, so an
    # oversized companion truncates the combined diff and fails closed.
    #
    # A parent baseline is not a prior review: it is the single AUR commit
    # before HEAD, used because this run has no recorded baseline.  Skipping
    # an unchanged companion there would let a payload committed before the
    # parent stay invisible on a first review (#57), so read companions whole.
    companion_baseline = "" if parent_baseline else old_commit
    present_before = ""
    if companion_baseline:
        companion, companion_truncated, present_before = (
            project.companion_hunks_with_present_before(
                head_commit, baseline_oid=companion_baseline)
        )
    else:
        companion, companion_truncated = project.companion_hunks(
            head_commit, baseline_oid=companion_baseline)
    if companion:
        diff_text = (f"{diff_text.rstrip(chr(10))}\n{companion}"
                     if diff_text.strip() else companion)

    max_bytes = config.get("diff", {}).get("max_diff_bytes", 5_242_880)
    diff_text, combined_truncated = truncate_diff(diff_text, max_bytes)
    diff_truncated = combined_truncated or generated_truncated
    if diff_truncated:
        log.warning("diff for %s exceeds %d bytes; truncating", pkg_name, max_bytes)
    diff_text, scan_truncated = clamp_diff_lines(diff_text, pkg_name)
    long_lines = oversized_lines(diff_text.split("\n"))
    diff_text = bound_tokenizer_lines(diff_text)
    cut_hunks = parse_diff_lines(split_lines(diff_text)).cut_hunks()
    return (diff_text, diff_summary, diff_truncated, scan_truncated,
            companion_truncated, present_before, long_lines, cut_hunks,
            cut_hunk_details(cut_hunks))


def _resolve_comparison_base(project, package_id: int, head_commit: str,
                             old_commit: str, full_recipe: bool):
    """Choose the base revision a run compares against."""
    last = None
    comparison_base = ""
    parent_baseline = False
    if full_recipe:
        return None, "none", False, "", False
    if old_commit:
        return None, "", False, old_commit, False
    last = get_last_analysis(package_id)
    if last is not None:
        comparison_base = "recorded"
        stored_commit = last.get("new_commit")
        if stored_commit:
            old_commit = stored_commit
        elif head_commit:
            try:
                for c in project.walk(head_commit):
                    if not c.parents:
                        old_commit = str(c.id)
                        break
            except (GitSandboxUnavailable, GitOpError):
                note_stage_failure("history-walk")
            if not old_commit:
                old_commit = head_commit
        return last, comparison_base, False, old_commit, False
    # No recorded baseline.  A read-only run never writes one; the previous
    # commit in the AUR repository is the honest one-commit base.
    comparison_base = "parent"
    parent_baseline = True
    old_commit = _parent_commit(project, head_commit)
    return last, comparison_base, parent_baseline, old_commit, not old_commit


def _make_fresh_analysis(
    pkg_name: str, version: str, commit: str, package_id: int, project, config: dict,
    installed_version: str = "", head_pkgbuild: str = "", record: bool = False,
    resolved_depth: int = 0,
) -> PackageFact:
    """A first analysis: no prior commit to diff against.

    "No diff" is not "nothing to report", and this path kept confusing the
    two. Twice now a field has been computed here and then left off the
    fact, so the same package read differently depending on whether it had
    been analysed before:

    * ``version_comparison`` was unset, so a first ``inspect`` of a VCS
      package rendered the very arrow the incremental path had been fixed
      to suppress - ``1:1.93.1.r7967.caea422f-2 -> 1.93.1.r7966.7ccbff5e``,
      an update pointing at an older commit.
    * ``triggered_rules`` were found, written to the database, and then
      dropped: the fact carried an empty ``score_breakdown`` and a
      hardcoded score of 0. A first-seen package shipping a committed ELF
      binary - H066, the Atomic Arch delivery pattern - reported **Low,
      score 0, no findings**, with the finding sitting in the database the
      whole time. First-seen is the case with the least prior evidence, so
      it is the last one that should be reported clean without looking.

    Everything knowable without a diff is therefore decided here: the
    findings and the score that follows from them, the maintainer, and the
    IOC matches against the recipe as it stands.
    """
    # Resolve through the facade: callers and tests patch these symbols on
    # ``trustsight.analysis.pipeline._analyze``.
    from . import _analyze as _facade

    _recent_update = _facade._recent_update
    _package_is_new = _facade._package_is_new
    build_novelty_context = _facade.build_novelty_context
    insert_analysis = _facade.insert_analysis
    update_package_version = _facade.update_package_version
    get_maintainer_from_commit = _facade.get_maintainer_from_commit

    novelty = build_novelty_context([], package_id, record=record)
    triggered_rules: list[dict] = []
    recent = _recent_update(project, commit)
    if recent:
        triggered_rules.append(recent)
    new_pkg = _package_is_new(project, commit, pkg_name)
    if new_pkg:
        triggered_rules.append(new_pkg)
    parity = recipe_checksum_parity_finding(head_pkgbuild)
    if parity:
        triggered_rules.append(parity)
    placeholder = placeholder_finding(head_pkgbuild)
    if placeholder:
        triggered_rules.append(placeholder)
    triggered_rules.extend(name_shadow_findings(head_pkgbuild, pkg_name))
    triggered_rules.extend(
        apply_structural_rules("", current_text=head_pkgbuild, package_name=pkg_name)
    )
    tree_manifest: list = []
    tree_complete = True
    if commit:
        from ..delivery import scan_tree_manifest
        tree_manifest, tree_complete = project.tree_files(commit)
        if tree_manifest:
            triggered_rules.extend(scan_tree_manifest(tree_manifest, [], pkg_name))
    from ..upstream_release import upstream_release_findings

    def _upstream_add(rid, name, severity, category, match,
                      weight_override=None, **params):
        finding = {
            "rule_id": rid, "name": name, "severity": severity,
            "category": category, "match": match, "params": params,
        }
        if weight_override is not None:
            finding["weight_override"] = weight_override
        triggered_rules.append(stamp(finding))

    upstream_release_findings(
        "", None, _upstream_add, config, pkg_name, current_text=head_pkgbuild,
    )
    url_acks: dict = {}
    triggered_rules = suppress_acknowledged_url_findings(
        triggered_rules, pkg_name, url_acks)
    unresolved_assignments = unresolved_assignment_rows(
        clamp_text(head_pkgbuild) or "", file="PKGBUILD")
    # This path used to declare tree_analyzed=True unconditionally, which
    # was false whenever there was no commit to read a tree from: a first
    # analysis of an empty repository examined nothing and reported a bare
    # "Low".  It is the same coverage accounting as every other producer.
    gaps = gaps_from(
        # There is no diff on this path, so the recipe itself is what
        # names the scriptlet.
        tree_analyzed=(bool(tree_manifest) and tree_complete
                       and not _scriptlet_files_unread(
                           head_pkgbuild, tree_manifest)),
        ruleset_drifted=bool(drifted_shipped_rules()),
        degraded_stages=stage_failures(),
        unresolved_assignments=bool(unresolved_assignments),
        noextract_present=_has_noextract(head_pkgbuild or ""),
    )
    # The same scorer the incremental path uses, on the findings this path
    # actually made.  Novelty is empty and stays empty - "first seen" means
    # the novelty tier has nothing to say, not that the rules did not fire -
    # and the band downgrade for a coverage gap is decided inside
    # `calculate_score`, so it is not applied a second time here.
    # M-series predicates over the completed finding set
    # (after the ownership resolver), before scoring.
    from ..meta import alert_volume_finding, m_series_findings
    from ...scoring import declared_claims, prebuilt_declared

    prebuilt = prebuilt_declared(head_pkgbuild)
    triggered_rules.extend(m_series_findings(
        triggered_rules, config, claims=declared_claims(prebuilt=prebuilt)))
    _volume = alert_volume_finding(triggered_rules, config)
    if _volume:
        triggered_rules.append(_volume)
    score, breakdown, risk = calculate_score(
        triggered_rules, {}, novelty, config, coverage_gaps=gaps,
        prebuilt=prebuilt,
    )
    fact = PackageFact(
        package_name=pkg_name,
        old_version=installed_version,
        new_version=version,
        version_comparison=compare_installed_to_aur(
            installed_version, version,
            is_vcs=is_vcs_package(pkg_name, head_pkgbuild),
        ),
        new_commit=commit,
        current_maintainer=get_maintainer_from_commit(project, commit) or "" if commit else "",
        diff_summary=DiffSummary(),
        novelty_context=novelty,
        acknowledged_urls=acknowledged_url_rows(url_acks),
        first_seen=True,
        comparison_base="none",
        temporal_source="git_commit",
        tree_analyzed=(bool(tree_manifest) and tree_complete
                       and not _scriptlet_files_unread(
                           head_pkgbuild, tree_manifest)),
        coverage_gaps=gaps,
        unresolved_assignments=unresolved_assignments,
        ioc_matches=ioc_baseline_matches("", pkg_name, current_text=head_pkgbuild),
        score_breakdown=breakdown,
        risk=risk,
        final_score=score,
        depth=resolved_depth,
    )
    with_changes(fact)
    if record:
        insert_analysis(
            package_id=package_id,
            old_version=installed_version,
            new_version=version,
            old_commit="",
            new_commit=commit,
            # The stored score is the reported one. It was hardcoded to 0 while
            # the rules that fired went into the same row, so the history said
            # "clean" about an analysis that had found something.
            final_score=score,
            raw_diff="",
            fact_json=json.dumps(fact_to_dict(fact)),
            triggered_rules=triggered_rules,
        )
        update_package_version(pkg_name, version)
    return fact
