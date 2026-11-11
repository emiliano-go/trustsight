"""Extracted from inspect.py: _render."""

from ...config import load_config
from ...contacts import contact_panel, panel_lines
from ...coverage import GAP_REASONS
from ...scoring import verdict_label
from ...safe_text import clean
from ..display import (
    DEPTH_TRUNCATED_NOTE,
    dependency_lines_plain,
    finding_where,
    no_aur_change_note,
    version_transition,
)

__all__ = ['_explain_lines', '_failed_history_result', '_finding_line', '_inspect_plain', '_inspect_rich', '_layers_and_boundaries_line', '_render_history_panel_plain', '_render_history_panel_rich', '_status_text']

def _layers_and_boundaries_line(fact) -> str | None:
    """The assurance-layer profile and boundary count, for ``--verbose``.

     / W1: the same projection the JSON ``layers``
    and ``boundaries`` fields carry, rendered as one terminal line so the
    terminal is the same surface as the JSON (B11).
    """
    from ...boundaries import boundaries_from_fact
    from ...layers import layer_profile, parse_overrides
    from ...reporting import finding_rows

    profile = layer_profile(
        fact, finding_rows(fact),
        overrides=parse_overrides(load_config()))
    active = [
        f"{layer} {entry['status']}"
        for layer, entry in profile.items() if entry["status"] != "passed"
    ]
    forbidding = sum(1 for b in boundaries_from_fact(fact) if b.forbids_clean)
    parts = []
    if active:
        parts.append("Layers: " + ", ".join(active))
    if forbidding:
        parts.append(f"{forbidding} boundary(ies) forbid a clean verdict")
    return "; ".join(parts) or None

def _inspect_payload(fact, *, verbose=False, show_score=False, show_risk=False):
    from ...contacts import contact_panel, panel_lines
    from ...schema import fact_to_dict
    from ...reporting import render_cap
    from ...review_policy import review_policy

    policy = review_policy()
    return {
        "fact": fact_to_dict(fact),
        "layers_line": _layers_and_boundaries_line(fact) or "",
        "contact_lines": panel_lines(contact_panel(fact)),
        "status_text": _status_text(fact),
        "verbose": verbose,
        "show_score": show_score,
        "show_risk": show_risk,
        "render_cap_value": render_cap(),
        "policy_threshold": policy.threshold,
    }


def _emit_render(op: str, payload: dict) -> None:
    import sys
    from ...sandbox import render_client
    from .. import display

    text = render_client.render(op, payload)
    con = display._console
    stream = getattr(con, "file", None) if con is not None else None
    target = stream if stream is not None else sys.stdout
    target.write(text)
    target.flush()


def _inspect_rich(fact, verbose=False, show_score=False, show_risk=False):
    _emit_render("inspect_panel", _inspect_payload(
        fact, verbose=verbose, show_score=show_score, show_risk=show_risk))


def _status_text(fact) -> str:
    note = no_aur_change_note(fact)
    if note:
        return note
    # A run that did not read the whole change is not entitled to a
    # clean-looking status, whatever the score says (fail_closed only
    # downgrades the *band*; the status line spoke for itself).
    if getattr(fact, "coverage_gaps", None):
        return ("Inconclusive: part of the change was not analysed. "
                "Do not treat this package as clean.")
    if fact.first_seen:
        return "First analysis. No prior history for this package."
    # The triviality call must be the shared one: weight-0 findings that
    # carry no score (the W series, H043/H065) still make the update
    # non-trivial, and the JSON body and `review` both say so.  A local
    # re-derivation that looked only at weight and severity printed the
    # reassuring sentence directly above the finding it contradicted.
    from ...reporting import is_trivial
    if not is_trivial(fact):
        return "The update is not trivial. Review it."
    return "Only pkgver and sha256sums changed. Review the diff before building."

def _inspect_plain(fact, verbose=False, show_score=False, show_risk=False):
    print(f"TrustSight Inspect: {clean(fact.package_name)}")
    print(f"  Version: {clean(version_transition(fact))}")
    print(f"  Status: {clean(_status_text(fact))}")
    carried = set(getattr(fact, "carried_coverage_gaps", ()))
    for gap in fact.coverage_gaps:
        reason = GAP_REASONS.get(gap, gap)
        # Same provenance marker as the Rich panel above (#19).
        if gap in carried:
            reason += " (unchanged since the previous review)"
        print(f"  [Not fully vetted: {clean(reason)}.]")
    if fact.first_seen:
        print("  [First analysis] No prior history; novelty carries no weight yet.")
    if fact.comparison_base == "parent":
        print("  [Compared] The parent commit only; no recorded baseline, "
              "so earlier history was not examined.")
    if fact.maintainer_changed:
        print(f"  Maintainer changed: {clean(fact.previous_maintainer)} -> {clean(fact.current_maintainer)}")
    elif fact.current_maintainer:
        print(f"  Maintainer: {clean(fact.current_maintainer)}")
    if fact.diff_summary.lines_added or fact.diff_summary.lines_removed:
        print(f"  Lines: +{fact.diff_summary.lines_added} -{fact.diff_summary.lines_removed}")
    cs = fact.source_changes.checksum_behavior
    if cs and cs != "unchanged":
        print(f"  Checksum: {clean(cs)}")
    # B7: what moved, whether or not a rule matched.  The Rich render has
    # this section and the plain one did not, so a terminal without Rich
    # could not tell "nothing fired and nothing changed" from "nothing
    # fired and a great deal changed".
    if fact.changes:
        print("  What changed:")
        for entry in fact.changes:
            print(f"    {clean(entry)}")
    # the boundary of analysis, named (see the Rich render).
    unresolved = list(getattr(fact, "unresolved_assignments", ()) or ())
    if unresolved:
        print("  Unresolved constructs:")
        for row in unresolved[:5]:
            where = f" ({clean(row.get('file', ''))})" if row.get("file") else ""
            print(f"    {clean(row.get('name', ''))}: "
                  f"{clean(row.get('line', ''))}{where}")
    if fact.diff_summary.file_changes:
        print("  Files changed:")
        for fc in fact.diff_summary.file_changes:
            status = fc.get("status", "")
            path = fc.get("path", "")
            prefix = {"added": "+", "removed": "-", "modified": "~"}.get(status, " ")
            print(f"    {prefix} {clean(path)}")
    if fact.source_changes.added_urls:
        print("  Source URLs added:")
        for url in fact.source_changes.added_urls:
            print(f"    {clean(url)} ({fact.source_buckets.get(url, 'unknown')})")
    # The reconstructed command text - the deobfuscated `curl` a rule
    # matched on. The Rich panel has always shown it and this renderer
    # showed none of it, so the evidence behind a finding was visible only
    # if Rich happened to be installed.
    if fact.execution_changes.resolved_commands:
        print("  Resolved commands:")
        for cmd in fact.execution_changes.resolved_commands[:20]:
            print(f"    {clean(cmd.strip())}")
        extra = len(fact.execution_changes.resolved_commands) - 20
        if extra > 0:
            print(f"    ... {extra} more")
    if fact.execution_changes.resolved_recipe:
        print("  Resolved recipe values:")
        for value in fact.execution_changes.resolved_recipe[:20]:
            print(f"    {clean(value.strip())}")
        extra = len(fact.execution_changes.resolved_recipe) - 20
        if extra > 0:
            print(f"    ... {extra} more")
    if fact.score_breakdown:
        print("  Rules Triggered:")
        from ...reporting import render_cap

        cap = render_cap()
        shown = fact.score_breakdown if cap <= 0 else fact.score_breakdown[:cap]
        for e in shown:
            segs = [f"    [{clean(e.rule_id)}]"]
            if show_score:
                segs.append(f"{e.weight:+d}")
            if show_risk:
                segs.append(f"{clean(e.severity):<8}")
            # Same location prefix as the Rich render (#18).
            where = finding_where(e.file, e.line)
            segs.append(f"{where}  {clean(e.reason)}" if where else clean(e.reason))
            print(" ".join(segs))
        grouped = len(fact.score_breakdown) - len(shown)
        if grouped > 0:
            print(f"    ... and {grouped} more finding(s) (see --json)")
    if verbose:
        coverage = getattr(fact, "resolution_coverage", {}) or {}
        if coverage:
            fired = coverage.get("resolved_target_rules_fired") or []
            print(
                "  Resolution: "
                f"{coverage.get('resolved_lines', 0)} resolved, "
                f"{coverage.get('unresolved_lines', 0)} unresolved line(s); "
                "resolved-target R rules fired: "
                + (", ".join(fired) if fired else "(none)")
            )
        layer_line = _layers_and_boundaries_line(fact)
        if layer_line:
            print("  " + layer_line)
    # The Contact Ledger panel: weight 0, warm-only (see the Rich render).
    for line in panel_lines(contact_panel(fact)):
        print(line)
    if fact.ioc_matches:
        print("  IOC baseline matches:")
        for m in fact.ioc_matches:
            expired = " [EXPIRED]" if m.expired else ""
            line = f" line {m.line}" if m.line is not None else ""
            print(f"    [{clean(m.source)}] {clean(m.type)}={clean(m.value)}{line} ({clean(m.surface)}){expired}")
    for line in dependency_lines_plain(getattr(fact, "dependencies", ()),
                                       show_score=show_score,
                                       show_risk=show_risk):
        print(line)
    if getattr(fact, "depth_truncated", False):
        print(f"  [{DEPTH_TRUNCATED_NOTE}]")

    if fact.suppressed_rules:
        print("  Suppressed by override (did not affect the score):")
        for r in fact.suppressed_rules:
            scope = r.get("override_package") or "ALL packages"
            corroborated = (" (indicator corroborated)"
                            if r.get("indicator_corroborated") else "")
            print(f"    {clean(r['rule_id'])} ({clean(scope)}) "
                  f"{clean(r.get('override_reason', ''))}{corroborated}")
    if getattr(fact, "overrides_expired", None):
        print("  Overrides expired (no longer suppressing):")
        for rid in fact.overrides_expired:
            print(f"    {clean(str(rid))}")
    if getattr(fact, "acknowledged_urls", None):
        print("  Acknowledged source URLs (did not affect the score):")
        for r in fact.acknowledged_urls:
            print(f"    {clean(r.get('url', ''))} {clean(r.get('reason', ''))}")
    if show_score:
        print(f"  Score: {fact.final_score}/100 ({verdict_label(fact)})")
    elif show_risk:
        print(f"  Risk: {verdict_label(fact)}")

def _render_history_panel_rich(row: dict, show_score: bool, show_risk: bool, verbose: bool):
    _emit_render("inspect_history_panel", {
        "row": row, "show_score": show_score, "show_risk": show_risk,
        "verbose": verbose,
    })


def _render_history_panel_plain(row: dict, show_score: bool, show_risk: bool):
    """Render one history result as plain text."""
    commit_id = row.get("commit", "")[:8]
    commit_msg = row.get("commit_message", "")
    print(f"\n--- {clean(commit_id)}  {clean(commit_msg)} ---")

    findings = row.get("findings", [])
    if row.get("failed"):
        print(f"  Not analysed: {clean(row.get('error', ''))}")
    elif findings:
        for f in findings:
            print(f"  {clean(_finding_line(f))}")
    elif row.get("coverage_gaps"):
        print("  No findings (incomplete: part of the change was not analysed)")
    else:
        print("  No findings")

    for gap in row.get("coverage_gaps", []):
        print(f"  Not vetted: {clean(GAP_REASONS.get(gap, gap))}")

    changes = row.get("changes", [])
    if changes:
        print(f"  Changed: {clean(changes[0])}")
        for entry in changes[1:]:
            print(f"    {clean(entry)}")

    if show_score and not row.get("failed"):
        label = row.get("risk_label") or row.get("risk", "")
        print(f"  Score: {row.get('score', 0)}/100 ({label})")
    elif show_risk and not row.get("failed"):
        label = row.get("risk_label") or row.get("risk", "")
        print(f"  Risk: {label}")

def _failed_history_result(commit, reason: str) -> dict:
    """A history row for a commit that could not be analysed.

    The row carries ``failed: True`` so both renderers show it and the JSON
    output records it, rather than the commit vanishing and the older
    commits reading as a complete history.
    """
    return {
        "failed": True,
        "error": reason,
        "commit": str(commit.id),
        "commit_time": commit.commit_time,
        "commit_message": commit.message.strip().split("\n")[0],
        "findings": [],
        "changes": [],
        "coverage_gaps": [],
    }

def _finding_line(finding: dict) -> str:
    """Format a finding dict as a one-line string for history panels."""
    parts = []
    if finding.get("file") and finding.get("line") is not None:
        parts.append(f"{finding['file']}:{finding['line']}")
    rule_id = finding.get("rule_id", "?")
    reason = finding.get("reason", "")
    parts.append(f"{rule_id}  {reason}")
    # Cleaned here so every caller is covered, including the plain renderer.
    return clean(" ".join(parts))

def _explain_lines(fact, project) -> list[str]:
    """What the parser believed: the recipe and diff documents.

    ``--explain`` renders the typed core's own view (the RecipeDoc of the
    analysed PKGBUILD and the DiffDoc summary of the analysed diff) so
    triage and rule authoring work from what the parser saw, not from a
    re-read of the raw text.
    """
    from ...diffdoc import parse_diff_lines
    from ...fetcher import get_pkgbuild_at_commit
    from ...recipedoc import parse_recipe
    from ...tokenizer import split_lines

    lines = ["Parser view:"]
    text = get_pkgbuild_at_commit(project, fact.new_commit) if fact.new_commit else ""
    if text:
        recipe = parse_recipe(text)
        scalars = ", ".join(
            f"{k}={v}" for k, v in sorted(recipe.scalars.items())
            if k in ("pkgname", "pkgver", "pkgrel", "epoch", "url", "install")
        )
        lines.append(f"  scalars: {scalars or '(none resolved)'}")
        for name in sorted(recipe.arrays):
            entries = recipe.arrays[name]
            lines.append(
                f"  array {name}: {len(entries)} "
                f"entr{'y' if len(entries) == 1 else 'ies'}"
            )
        lines.append(f"  functions: {', '.join(recipe.functions) or '(none)'}")
        if recipe.unresolved:
            lines.append(f"  unresolved ({len(recipe.unresolved)}):")
            lines.extend(f"    {u}" for u in recipe.unresolved[:5])
    else:
        lines.append("  (no PKGBUILD at the analysed commit)")
    if fact.old_commit and fact.new_commit:
        diff_text, _summary, _trunc = project.diff_bounded(
            fact.old_commit, fact.new_commit
        )
        doc = parse_diff_lines(split_lines(diff_text))
        n_hunks = sum(len(f.hunks) for f in doc.files)
        lines.append(f"  diff: {len(doc.files)} file(s), {n_hunks} hunk(s)")
        for f in doc.files:
            lines.append(f"    {f.path} ({f.status}, {len(f.hunks)} hunk(s))")
        cuts = doc.cut_hunks()
        if cuts:
            lines.append(f"  cut hunks: {cuts}")
    # This renderer is a terminal boundary too: recipe values, unresolved
    # assignments and diff paths are all package-controlled.
    return [clean(line) for line in lines]
