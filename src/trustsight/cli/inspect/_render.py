"""Extracted from inspect.py: _render."""

from ...config import load_config
from ...contacts import contact_panel, panel_lines
from ...coverage import GAP_REASONS
from ...scoring import (
    DECLARED_CAVEAT,
    DECLARED_DEFAULT,
    verdict_label,
    verdict_level,
)
from ...safe_text import clean, safe_markup
from ...unicode import describe_fatal_codepoints
from ..display import (
    DEPTH_TRUNCATED_NOTE,
    dependency_cards_rich,
    dependency_lines_plain,
    RISK_COLORS,
    _severity_text,
    _weight_text,
    console,
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

def _inspect_rich(fact, verbose=False, show_score=False, show_risk=False):
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text

    con = console()
    risk = verdict_level(fact)
    label = verdict_label(fact)
    border = RISK_COLORS.get(risk, "white") if (show_score or show_risk) else "blue"

    rows: list[tuple[str, object]] = []
    # The transition carries pkgver values from the recipe, so it is cleaned
    # like every other package-derived cell: a plain str cell is markup-
    # parsed by Rich and can carry ESC.
    rows.append(("Version", Text(clean(version_transition(fact)))))

    # B2: the gap is shown whether or not a band is.  It used to ride the
    # band label alone, and the default output withholds the band, so
    # `inspect` with no flags said nothing at all about a partial read -
    # the one light that must never be suppressible.
    carried = set(getattr(fact, "carried_coverage_gaps", ()))
    for gap in fact.coverage_gaps:
        reason = GAP_REASONS.get(gap, gap)
        # #19: a gap the previous review already carried says so, instead of
        # reading as a shortfall this diff introduced.
        if gap in carried:
            reason += " (unchanged since the previous review)"
        rows.append(("Not vetted", f"[yellow]{safe_markup(reason)}[/]"))

    # No first-seen row here: the Status row at the foot of the panel is
    # unconditional and `_status_text` returns the same sentence, so this
    # printed it twice.  It also closed its markup with `[]` rather than
    # `[/]`, which Rich renders literally - the report showed
    # "First analysis.[] No prior history for this package."
    if fact.diff_summary.lines_added or fact.diff_summary.lines_removed:
        rows.append(("Lines", f"[green]+{fact.diff_summary.lines_added}[/] [red]-{fact.diff_summary.lines_removed}[/]"))
    if fact.maintainer_changed:
        rows.append(("Maintainer", f"[yellow]{safe_markup(fact.previous_maintainer or '?')} -> {safe_markup(fact.current_maintainer or '?')}[/]"))
    elif fact.current_maintainer:
        rows.append(("Maintainer", Text(clean(fact.current_maintainer))))
    cs = fact.source_changes.checksum_behavior
    if cs and cs != "unchanged":
        rows.append(("Checksum", f"[yellow]{safe_markup(cs)}[/]"))

    inside = Table.grid(padding=(0, 2))
    inside.add_column(style="dim", justify="right", no_wrap=True)
    inside.add_column()
    for row_label, row_value in rows:
        inside.add_row(row_label, row_value)

    if fact.changes:
        inside.add_row("", "")
        inside.add_row("[underline]What changed[/]", "")
        for entry in fact.changes:
            inside.add_row("", Text("  " + clean(entry)))

    # the boundary of analysis, named. An assignment the
    # tokenizer refused is "not seen" to every rule, and the reader must
    # see where that boundary sits rather than only a generic gap.
    unresolved = list(getattr(fact, "unresolved_assignments", ()) or ())
    if unresolved:
        inside.add_row("", "")
        inside.add_row("[underline]Unresolved constructs[/]", "")
        for row in unresolved[:5]:
            where = f" ({clean(row.get('file', ''))})" if row.get("file") else ""
            inside.add_row("", Text(
                f"  {clean(row.get('name', ''))}: {clean(row.get('line', ''))}{where}"))

    declared = [e for e in fact.score_breakdown if e.rule_id.startswith("P")
                and e.rule_id[1:].isdigit()]
    # B10: the default set is the practices a reader would find surprising
    # by their *absence*.  Listing every one of them on every package
    # buries the risk findings, which is the opposite of the point.
    hidden = 0
    if not verbose:
        shown = [e for e in declared if e.rule_id in DECLARED_DEFAULT]
        hidden = len(declared) - len(shown)
        declared = shown
    if declared:
        inside.add_row("", "")
        inside.add_row("[underline]Declared verification[/]", "")
        for entry in declared:
            prefix = f"PKGBUILD:{entry.line}  " if entry.line is not None else ""
            inside.add_row("", Text(f"  {prefix}{clean(entry.reason)}"))
        if hidden:
            inside.add_row("", Text(
                f"  {hidden} more declared practice(s); --verbose to list them",
                style="dim"))
        inside.add_row("", Text("  " + DECLARED_CAVEAT, style="dim"))

    if fact.diff_summary.file_changes:
        inside.add_row("", "")
        inside.add_row("[underline]Files changed[/]", "")
        for fc in fact.diff_summary.file_changes:
            status = fc.get("status", "")
            path = fc.get("path", "")
            prefix = {"added": "[green]+[/]", "removed": "[red]-[/]", "modified": "[yellow]~[/]"}.get(status, " ")
            inside.add_row("", f"  {prefix} {safe_markup(path)}")

    if fact.source_changes.added_urls:
        inside.add_row("", "")
        inside.add_row("[underline]Source URLs added[/]", "")
        for url in fact.source_changes.added_urls:
            bucket = fact.source_buckets.get(url, "unknown")
            style = "red" if bucket in ("homograph_attack", "unknown") else "dim"
            inside.add_row("", Text(f"  [{bucket}] ", style=style) + Text(clean(url)))

    if fact.execution_changes.resolved_commands:
        inside.add_row("", "")
        inside.add_row("[underline]Resolved commands[/]", "")
        for cmd in fact.execution_changes.resolved_commands[:20]:
            inside.add_row("", Text("  " + clean(cmd.strip())))
        extra = len(fact.execution_changes.resolved_commands) - 20
        if extra > 0:
            inside.add_row("", f"  [dim]... {extra} more[/]")

    if fact.score_breakdown:
        inside.add_row("", "")
        inside.add_row("[underline]Rules Triggered[/]", "")
        from ...reporting import render_cap

        _cap = render_cap()
        _shown = fact.score_breakdown if _cap <= 0 else fact.score_breakdown[:_cap]
        for entry in _shown:
            # Declared practices have their own group above; repeating them
            # here would undo the point of showing a default subset.
            if entry.rule_id.startswith("P") and entry.rule_id[1:].isdigit():
                continue
            rid = entry.rule_id or ""
            segs = [Text(clean(rid) + " ", style="cyan")]
            if show_score:
                segs.append(str(_weight_text(entry.weight)) + " ")
            if show_risk:
                segs.append(str(_severity_text(entry.severity)) + " ")
            # Where the finding is, flag or no flag: naming the rule without
            # the location sent the reader to --json to find it (#18).
            where = finding_where(entry.file, entry.line)
            if where:
                segs.append(Text(where + "  "))
            segs.append(Text(clean(entry.reason)))
            inside.add_row("", Text.assemble(*segs))

        _grouped = len(fact.score_breakdown) - len(_shown)
        if _grouped > 0:
            inside.add_row(
                "", f"  [dim]... and {_grouped} more finding(s) (see --json)[/]")

        if show_risk:
            for entry in fact.score_breakdown:
                if entry.severity == "FATAL":
                    found = describe_fatal_codepoints(entry.reason)
                    if found:
                        inside.add_row("", "")
                        inside.add_row("[red]Deceptive codepoints[/]", "")
                        for offset, name in found:
                            inside.add_row("", f"  offset {offset}: [red]{name}[/]")

    if fact.ioc_matches:
        inside.add_row("", "")
        inside.add_row("[underline]IOC baseline matches[/]", "")
        for m in fact.ioc_matches:
            expired = " [EXPIRED]" if m.expired else ""
            line = f" line {m.line}" if m.line is not None else ""
            text = f"  [{clean(m.source)}] {clean(m.type)}={clean(m.value)}{line} ({clean(m.surface)}){expired}"
            inside.add_row("", Text(text))

    if getattr(fact, "dependencies", None):
        inside.add_row("", "")
        inside.add_row("[underline]Dependencies[/]", "")
        for card in dependency_cards_rich(fact.dependencies, show_score=show_score,
                                   show_risk=show_risk):
            inside.add_row("", card)
        if getattr(fact, "depth_truncated", False):
            inside.add_row("", Text(DEPTH_TRUNCATED_NOTE, style="yellow"))

    if fact.suppressed_rules:
        inside.add_row("", "")
        inside.add_row("[yellow]Suppressed by override[/]", "")
        for r in fact.suppressed_rules:
            scope = r.get("override_package") or "ALL packages"
            corroborated = ("  (indicator corroborated)"
                            if r.get("indicator_corroborated") else "")
            inside.add_row("", Text(
                f"  {clean(r['rule_id'])}  ({clean(scope)})  "
                f"{clean(r.get('override_reason', ''))}{corroborated}"))

    if getattr(fact, "overrides_expired", None):
        inside.add_row("", "")
        inside.add_row("[yellow]Overrides expired[/]", "")
        for rid in fact.overrides_expired:
            inside.add_row("", Text(f"  {clean(str(rid))}  no longer suppressing"))

    if getattr(fact, "acknowledged_urls", None):
        inside.add_row("", "")
        inside.add_row("[yellow]Acknowledged source URLs[/]", "")
        for r in fact.acknowledged_urls:
            inside.add_row("", Text(
                f"  {clean(r.get('url', ''))}  {clean(r.get('reason', ''))}"))

    if show_score:
        inside.add_row("", "")
        total = sum(e.weight for e in fact.score_breakdown) if fact.score_breakdown else 0
        inside.add_row("[bold]Score[/]", f"{fact.final_score}/100  ({label})")
        inside.add_row("", f"[dim]sum: {total:+d}, clamped to {fact.final_score}/100[/]")
    elif show_risk:
        inside.add_row("", "")
        inside.add_row("[bold]Risk[/]", Text(clean(label)))

    inside.add_row("", "")
    inside.add_row("[bold]Status[/]", _status_text(fact))
    if fact.comparison_base == "parent":
        inside.add_row(
            "[bold]Compared[/]",
            "The parent commit only; no recorded baseline, so earlier "
            "history was not examined.",
        )

    con.print()
    con.print(Panel(inside, title=Text(f"TrustSight Inspect: {clean(fact.package_name)}"), border_style=border))
    # Printed after the panel rather than as a table row: a long row would
    # widen the grid's value column past the terminal and push every other
    # cell off-width.
    if verbose:
        layer_line = _layers_and_boundaries_line(fact)
        if layer_line:
            con.print("  " + layer_line, style="dim")
    # The Contact Ledger panel: weight 0, warm-only.  Shown on every run so a
    # cold replay's standing note is visible rather than silently absent.
    # Wrapped in Text() so a package-derived value is printed, not parsed as
    # Rich markup (panel_lines cleans control characters but keeps brackets).
    for line in panel_lines(contact_panel(fact)):
        con.print(Text(line), style="dim")

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
    """Render one history result as a Rich panel with commit info."""
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text

    con = console()
    risk = row.get("risk", "")
    label = row.get("risk_label") or risk
    border = RISK_COLORS.get(risk, "blue") if (show_score or show_risk) else "blue"

    table = Table(show_header=False, box=None, padding=(0, 1))
    table.add_column(no_wrap=True)
    table.add_column()

    commit_id = row.get("commit", "")[:8]
    commit_msg = row.get("commit_message", "")
    # The AUR commit subject is package-controlled; Rich's Text strips BEL,
    # BS, VT, FF and CR but not ESC, so it is cleaned like every other field.
    table.add_row("Commit", Text(clean(f"{commit_id}  {commit_msg}"), style="dim"))

    findings = row.get("findings", [])
    if row.get("failed"):
        table.add_row("Status", Text(
            clean(f"not analysed: {row.get('error', '')}"), style="red"))
    elif findings:
        for f in findings:
            table.add_row("", Text(clean(_finding_line(f))))
    elif row.get("coverage_gaps"):
        # An empty finding list on an incomplete run is "nothing was found
        # in the part that was read", not "nothing is there".
        table.add_row("Status", Text(
            "No findings (incomplete: part of the change was not analysed)",
            style="yellow",
        ))
    else:
        table.add_row("Status", "No findings")

    for gap in row.get("coverage_gaps", []):
        table.add_row("Not vetted", Text(
            clean(GAP_REASONS.get(gap, gap)), style="yellow"))

    changes = row.get("changes", [])
    if changes:
        table.add_row("Changed", Text(clean(changes[0])))
        for entry in changes[1:]:
            table.add_row("", Text(clean(entry)))

    if show_score and not row.get("failed"):
        table.add_row("Score", f"{row.get('score', 0)}/100 ({label})")
    elif show_risk and not row.get("failed"):
        table.add_row("Risk", clean(label))

    panel = Panel(table, title=Text(clean(row.get("package", ""))), border_style=border)
    con.print(panel)

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
