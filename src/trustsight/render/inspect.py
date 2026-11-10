"""The inspect panel and history panel, rendered inside the sandbox."""

from __future__ import annotations

from ..coverage import GAP_REASONS
from ..safe_text import clean, safe_markup
from ..scoring import (
    DECLARED_CAVEAT,
    DECLARED_DEFAULT,
    verdict_label,
    verdict_level,
)
from ..unicode import describe_fatal_codepoints
from ..verdict import version_transition
from .display import (
    RISK_COLORS,
    console,
    dependency_cards,
    fact_view,
    severity_text,
    weight_text,
)

DEPTH_TRUNCATED_NOTE = "dependency walk cut short; part of the closure was not analysed"


def _finding_line(finding: dict) -> str:
    file = clean(finding.get("file", "") or "")
    line = finding.get("line")
    where = f"{file} line {line}" if file and line is not None else file
    desc = clean(finding.get("description", ""))
    return f"{where}  {desc}" if where else desc


def render_panel(*, fact: dict, layers_line: str = "", contact_lines=None,
                 status_text: str = "", verbose=False, show_score=False,
                 show_risk=False, render_cap_value=50,
                 policy_threshold=20) -> None:
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text

    fact = fact_view(fact)
    con = console()
    risk = verdict_level(fact)
    label = verdict_label(fact)
    border = RISK_COLORS.get(risk, "white") if (show_score or show_risk) else "blue"

    rows: list[tuple[str, object]] = []
    rows.append(("Version", Text(clean(version_transition(fact)))))

    carried = set(getattr(fact, "carried_coverage_gaps", ()))
    for gap in fact.coverage_gaps:
        reason = GAP_REASONS.get(gap, gap)
        if gap in carried:
            reason += " (unchanged since the previous review)"
        rows.append(("Not vetted", f"[yellow]{safe_markup(reason)}[/]"))

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
            prefix = {"added": "[green]+[/]", "removed": "[red]-[/]",
                      "modified": "[yellow]~[/]"}.get(status, " ")
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

    if fact.execution_changes.resolved_recipe:
        inside.add_row("", "")
        inside.add_row("[underline]Resolved recipe values[/]", "")
        for value in fact.execution_changes.resolved_recipe[:20]:
            inside.add_row("", Text("  " + clean(value.strip())))
        extra = len(fact.execution_changes.resolved_recipe) - 20
        if extra > 0:
            inside.add_row("", f"  [dim]... {extra} more[/]")

    if fact.score_breakdown:
        inside.add_row("", "")
        inside.add_row("[underline]Rules Triggered[/]", "")
        _cap = render_cap_value
        _shown = fact.score_breakdown if _cap <= 0 else fact.score_breakdown[:_cap]
        for entry in _shown:
            if entry.rule_id.startswith("P") and entry.rule_id[1:].isdigit():
                continue
            rid = entry.rule_id or ""
            segs = [Text(clean(rid) + " ", style="cyan")]
            if show_score:
                segs.append(str(weight_text(entry.weight)) + " ")
            if show_risk:
                segs.append(str(severity_text(entry.severity)) + " ")
            where = _finding_where(entry.file, entry.line)
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
        for card in dependency_cards(
                fact.dependencies, show_score=show_score,
                show_risk=show_risk, policy_threshold=policy_threshold):
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
    inside.add_row("[bold]Status[/]", status_text)
    if fact.comparison_base == "parent":
        inside.add_row(
            "[bold]Compared[/]",
            "The parent commit only; no recorded baseline, so earlier "
            "history was not examined.",
        )

    con.print()
    con.print(Panel(inside, title=Text(f"TrustSight Inspect: {clean(fact.package_name)}"), border_style=border))
    if verbose and layers_line:
        con.print("  " + layers_line, style="dim")
    for line in contact_lines or ():
        con.print(Text(line), style="dim")


def _finding_where(file: str, line: int | None) -> str:
    file_part = clean(file or "")
    if file_part and line is not None:
        return f"{file_part} line {line}"
    return file_part


def render_history_panel(*, row: dict, show_score: bool, show_risk: bool,
                         verbose: bool = False) -> None:
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
    table.add_row("Commit", Text(clean(f"{commit_id}  {commit_msg}"), style="dim"))

    findings = row.get("findings", [])
    if row.get("failed"):
        table.add_row("Status", Text(
            clean(f"not analysed: {row.get('error', '')}"), style="red"))
    elif findings:
        for f in findings:
            table.add_row("", Text(clean(_finding_line(f))))
    elif row.get("coverage_gaps"):
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
