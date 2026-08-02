import json

import typer

from ..analysis import analyze_package
from ..config import ensure_default_configs, load_config
from ..db import (
    get_package as _get_pkg,
    init_db,
    maybe_auto_import_seed,
)
from ..scoring import risk_level
from ..unicode import describe_fatal_codepoints, strip_ansi
from .display import (
    HAS_RICH,
    RISK_COLORS,
    _fact_to_dict,
    _print_colored,
    _severity_text,
    _weight_text,
    console,
    display_version,
)


def _inspect_rich(fact, verbose=False, show_score=False, show_risk=False):
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text

    con = console()
    risk = risk_level(fact.final_score)
    border = RISK_COLORS.get(risk, "white") if (show_score or show_risk) else "blue"

    rows: list[tuple[str, str]] = []
    rows.append(("Version", f"{display_version(fact.old_version)} -> {display_version(fact.new_version)}"))

    if fact.first_seen:
        rows.append(("Status", "[yellow]First analysis.[] No prior history for this package."))
    if fact.diff_summary.lines_added or fact.diff_summary.lines_removed:
        rows.append(("Lines", f"[green]+{fact.diff_summary.lines_added}[/] [red]-{fact.diff_summary.lines_removed}[/]"))
    if fact.maintainer_changed:
        rows.append(("Maintainer", f"[yellow]{fact.previous_maintainer or '?'} -> {fact.current_maintainer or '?'}[/]"))
    elif fact.current_maintainer:
        rows.append(("Maintainer", str(fact.current_maintainer)))
    cs = fact.source_changes.checksum_behavior
    if cs and cs != "unchanged":
        rows.append(("Checksum", f"[yellow]{cs}[/]"))

    inside = Table.grid(padding=(0, 2))
    inside.add_column(style="dim", justify="right", no_wrap=True)
    inside.add_column()
    for label, value in rows:
        inside.add_row(label, value)

    if fact.diff_summary.file_changes:
        inside.add_row("", "")
        inside.add_row("[underline]Files changed[/]", "")
        for fc in fact.diff_summary.file_changes:
            status = fc.get("status", "")
            path = fc.get("path", "")
            prefix = {"added": "[green]+[/]", "removed": "[red]-[/]", "modified": "[yellow]~[/]"}.get(status, " ")
            inside.add_row("", f"  {prefix} {path}")

    if fact.source_changes.added_urls:
        inside.add_row("", "")
        inside.add_row("[underline]Source URLs added[/]", "")
        for url in fact.source_changes.added_urls:
            bucket = fact.source_buckets.get(url, "unknown")
            style = "red" if bucket in ("homograph_attack", "unknown") else "dim"
            inside.add_row("", Text(f"  [{bucket}] ", style=style) + Text(strip_ansi(url)))

    if fact.execution_changes.resolved_commands:
        inside.add_row("", "")
        inside.add_row("[underline]Resolved commands[/]", "")
        for cmd in fact.execution_changes.resolved_commands[:20]:
            inside.add_row("", "  " + strip_ansi(cmd.strip()))
        extra = len(fact.execution_changes.resolved_commands) - 20
        if extra > 0:
            inside.add_row("", f"  [dim]... {extra} more[/]")

    if fact.score_breakdown:
        inside.add_row("", "")
        inside.add_row("[underline]Rules Triggered[/]", "")
        for entry in fact.score_breakdown:
            rid = entry.rule_id or ""
            segs = [f"[cyan]{rid}[/] "]
            if show_score:
                segs.append(str(_weight_text(entry.weight)) + " ")
            if show_risk:
                segs.append(str(_severity_text(entry.severity)) + " ")
            segs.append(Text(strip_ansi(entry.reason)))
            inside.add_row("", Text.assemble(*segs))

        if show_risk:
            for entry in fact.score_breakdown:
                if entry.severity == "FATAL":
                    found = describe_fatal_codepoints(entry.reason)
                    if found:
                        inside.add_row("", "")
                        inside.add_row("[red]Deceptive codepoints[/]", "")
                        for offset, name in found:
                            inside.add_row("", f"  offset {offset}: [red]{name}[/]")

    if fact.suppressed_rules:
        inside.add_row("", "")
        inside.add_row("[yellow]Suppressed by override[/]", "")
        for r in fact.suppressed_rules:
            inside.add_row("", f"  {r['rule_id']}  {r.get('override_reason', '')}")

    if show_score:
        inside.add_row("", "")
        total = sum(e.weight for e in fact.score_breakdown) if fact.score_breakdown else 0
        inside.add_row("[bold]Score[/]", f"{fact.final_score}/100  ({risk})")
        inside.add_row("", f"[dim]sum: {total:+d}, clamped to {fact.final_score}/100[/]")
    elif show_risk:
        inside.add_row("", "")
        inside.add_row("[bold]Risk[/]", f"({risk})")

    inside.add_row("", "")
    inside.add_row("[bold]Status[/]", _status_text(fact))

    con.print()
    con.print(Panel(inside, title=f"TrustSight Inspect: {fact.package_name}", border_style=border))


def _status_text(fact) -> str:
    if fact.first_seen:
        return "First analysis. No prior history for this package."
    if not fact.diff_summary.files_changed:
        return "Only pkgver and sha256sums changed. Review the diff before building."
    for e in fact.score_breakdown:
        if e.weight > 0 or e.severity in ("FATAL", "CRITICAL"):
            if e.rule_id != "C002":
                return "The update is not trivial. Review it."
    return "Only pkgver and sha256sums changed. Review the diff before building."


def _inspect_plain(fact, verbose=False, show_score=False, show_risk=False):
    print(f"TrustSight Inspect: {fact.package_name}")
    print(f"  Version: {display_version(fact.old_version)} -> {display_version(fact.new_version)}")
    print(f"  Status: {_status_text(fact)}")
    if fact.first_seen:
        print("  [First analysis] No prior history; novelty carries no weight yet.")
    if fact.maintainer_changed:
        print(f"  Maintainer changed: {fact.previous_maintainer} -> {fact.current_maintainer}")
    cs = fact.source_changes.checksum_behavior
    if cs and cs != "unchanged":
        print(f"  Checksum: {cs}")
    if fact.diff_summary.file_changes:
        print("  Files changed:")
        for fc in fact.diff_summary.file_changes:
            status = fc.get("status", "")
            path = fc.get("path", "")
            prefix = {"added": "+", "removed": "-", "modified": "~"}.get(status, " ")
            print(f"    {prefix} {path}")
    if fact.source_changes.added_urls:
        print("  Source URLs added:")
        for url in fact.source_changes.added_urls:
            print(f"    {strip_ansi(url)} ({fact.source_buckets.get(url, 'unknown')})")
    if fact.score_breakdown:
        print("  Rules Triggered:")
        for e in fact.score_breakdown:
            segs = [f"    [{e.rule_id}]"]
            if show_score:
                segs.append(f"{e.weight:+d}")
            if show_risk:
                segs.append(f"{e.severity:<8}")
            segs.append(e.reason)
            print(" ".join(segs))
    if fact.suppressed_rules:
        print("  Suppressed by override (did not affect the score):")
        for r in fact.suppressed_rules:
            print(f"    {r['rule_id']} {r.get('override_reason', '')}")
    if show_score:
        print(f"  Score: {fact.final_score}/100 ({risk_level(fact.final_score)})")
    elif show_risk:
        print(f"  Risk: {risk_level(fact.final_score)}")


def register_commands(app: typer.Typer):
    @app.command()
    def inspect(
        package: str = typer.Argument(..., help="Package name"),
        verbose: bool = typer.Option(False, "--verbose", help="Show triggered rules and score breakdown"),
        score: bool = typer.Option(False, "--score", help="Show aggregate trust score"),
        risk: bool = typer.Option(False, "--risk", help="Show risk level"),
        json_output: bool = typer.Option(False, "--json", help="Output JSON"),
    ):
        """Show a detailed analysis of a single package."""
        _show_score = score
        _show_risk = risk
        ensure_default_configs()
        init_db()
        if load_config().get("seed", {}).get("auto_import", True):
            maybe_auto_import_seed(quiet=json_output)

        from ..discovery import get_aur_package_info
        info = get_aur_package_info([package])
        if package not in info:
            from ..db import get_package as _get_pkg
            local = _get_pkg(package)
            if local is None:
                msg = f"Package '{package}' not found in the AUR."
                if json_output:
                    typer.echo(json.dumps({"error": msg}))
                else:
                    _print_colored(msg, "red")
                raise typer.Exit(code=1)

        fact = analyze_package(package)
        if json_output:
            data = _fact_to_dict(fact)
            if verbose:
                data["score_breakdown"] = [
                    {
                        "rule_id": e.rule_id,
                        "severity": e.severity,
                        "weight": e.weight,
                        "template": e.template,
                        "evidence": e.evidence,
                    }
                    for e in fact.score_breakdown
                ]
            typer.echo(json.dumps(data, indent=2))
            return

        if HAS_RICH:
            _inspect_rich(fact, verbose, _show_score, _show_risk)
        else:
            _inspect_plain(fact, verbose, _show_score, _show_risk)
