import json
import logging

import typer

from ..config import ensure_default_configs
from ..db import init_db
from ..override import (
    FATAL_RULES,
    OVERRIDES_PATH,
    add_override,
    list_overrides,
    remove_override,
)
from ..safe_text import clean
from .display import (
    _print_colored,
    console,
    use_rich,
)

log = logging.getLogger(__name__)

override_app = typer.Typer(
    help="Suppress a rule that misfires on your packages",
    no_args_is_help=True, add_completion=False,
)


# --- override subcommands ---

@override_app.command("list")
def override_list(
    json_output: bool = typer.Option(False, "--json", help="Output JSON"),
):
    """List all rule overrides."""
    ensure_default_configs()
    overrides = list_overrides()
    if not overrides:
        msg = (
            f"No overrides configured. File: {OVERRIDES_PATH}\n"
            f"Add one with: trustsight override add R010 --reason \"...\""
        )
        if json_output:
            typer.echo(json.dumps({"overrides": []}))
        elif use_rich():
            console().print(msg)
        else:
            print(msg)
        return

    if json_output:
        data = [
            {"rule_id": o.rule_id, "package": o.package, "reason": o.reason, "created_at": o.created_at}
            for o in overrides
        ]
        typer.echo(json.dumps(data, indent=2))
        return

    if use_rich():
        from rich.box import SIMPLE_HEAD
        from rich.table import Table
        table = Table(title=f"Rule overrides ({OVERRIDES_PATH})", box=SIMPLE_HEAD)
        table.add_column("Rule", style="cyan")
        table.add_column("Scope")
        table.add_column("Reason", overflow="fold")
        table.add_column("Added", style="dim")
        from rich.text import Text
        for o in overrides:
            # `Text`, not a bare string: Rich reads markup in a plain str,
            # so a `[green]` in the value recolours the row and an
            # unbalanced tag aborts the render of everything after it.
            table.add_row(Text(clean(o.rule_id)),
                          Text(clean(o.package or "all packages")),
                          Text(clean(o.reason)), Text(clean(o.created_at)))
        console().print(table)
        console().print(
            f"[dim]{', '.join(sorted(FATAL_RULES))} cannot be overridden; a FATAL "
            f"finding is never suppressed.[/]"
        )
    else:
        for o in overrides:
            print(f"{clean(o.rule_id):<8} {clean(o.package or 'all'):<20} "
                  f"{clean(o.reason)}")


@override_app.command("add")
def override_add(
    rule_id: str = typer.Argument(..., help="Rule to suppress, e.g. R010"),
    reason: str = typer.Option(..., "--reason", help="Why this rule is being suppressed (required)"),
    package: str | None = typer.Option(None, "--package", help="Limit to one package"),
    json_output: bool = typer.Option(False, "--json", help="Output JSON"),
):
    """Add a rule override to suppress a finding."""
    ensure_default_configs()
    try:
        ov = add_override(rule_id, reason, package)
    except ValueError as exc:
        msg = str(exc)
        if json_output:
            typer.echo(json.dumps({"error": msg}))
        else:
            _print_colored(msg, "red", stderr=True)
        raise typer.Exit(code=2)
    scope = ov.package or "all packages"
    msg = f"Override added: {ov.rule_id} for {scope}"
    if json_output:
        typer.echo(json.dumps({
            "status": "ok",
            "rule_id": ov.rule_id,
            "package": ov.package,
            "reason": ov.reason,
        }))
    else:
        _print_colored(msg, "green")


@override_app.command("wizard")
def override_wizard(
    package: str = typer.Argument(..., help="Package to configure overrides for"),
):
    """Interactive wizard to suppress rules that misfire on a package."""
    ensure_default_configs()
    init_db()

    from ..analysis import analyze_package
    from ..override import get_active_overrides

    con = console()

    try:
        with con.status(f"Analyzing {package}...", spinner="dots"):
            fact = analyze_package(package)
    except Exception as exc:
        msg = f"Could not analyze '{package}': {exc}"
        _print_colored(msg, "red", stderr=True)
        raise typer.Exit(code=2)

    existing = get_active_overrides(package=package)
    existing_ids = {o.rule_id for o in existing}

    non_fatal = [e for e in fact.score_breakdown if e.rule_id not in FATAL_RULES]
    already_suppressed = [e for e in non_fatal if e.rule_id in existing_ids]
    available = [e for e in non_fatal if e.rule_id not in existing_ids]

    if not non_fatal:
        con.print(f"[yellow]No suppressible rules triggered for '{package}'.[/] "
                  f"(FATAL rules cannot be overridden.)")
        return

    if available:
        from rich.box import SIMPLE_HEAD
        from rich.table import Table

        con.print(f"\n[bold]Triggered rules for [cyan]{package}[/][/]\n")
        table = Table(box=SIMPLE_HEAD)
        table.add_column("#", style="dim", justify="right")
        table.add_column("Rule", style="cyan")
        table.add_column("Severity")
        table.add_column("Reason", overflow="fold")
        from rich.text import Text
        for i, e in enumerate(available, 1):
            # `e.reason` carries package-controlled text: a tree member
            # name, a quoted diff fragment. The weaker `unicode` helper
            # used here before leaves C1 control bytes, BEL and newlines
            # behind, and \x9b2J is the 8-bit spelling of "clear screen".
            table.add_row(Text(str(i)), Text(clean(e.rule_id)),
                          Text(clean(e.severity)), Text(clean(e.reason)))
        con.print(table)

        if already_suppressed:
            con.print(f"\n[dim](Already suppressed: {', '.join(e.rule_id for e in already_suppressed)})[/]")

        con.print()
        added = []
        while True:
            try:
                pick = typer.prompt(
                    "Enter rule ID or # to suppress (or q to quit)",
                    default="q",
                    show_default=False,
                )
            except EOFError:
                # stdin is not interactive (piped/CI): stop cleanly.
                con.print("[yellow]Input closed; no more overrides added.[/]")
                break
            if pick.lower() in ("q", "quit", ""):
                break

            matched = None
            if pick.isdigit():
                idx = int(pick) - 1
                if 0 <= idx < len(available):
                    matched = available[idx]
            else:
                pick_upper = pick.upper()
                for e in available:
                    if e.rule_id == pick_upper:
                        matched = e
                        break

            if matched is None:
                con.print(f"[red]No rule matches '{pick}'.[/] Try again or enter q to quit.")
                continue

            reason = None
            try:
                reason = typer.prompt(f"Reason for suppressing {matched.rule_id}")
            except EOFError:
                con.print("[yellow]Input closed; override not added.[/]")
                break
            if not reason or not reason.strip():
                con.print("[red]Reason cannot be empty.[/]")
                continue

            add_override(matched.rule_id, reason, package=package)
            added.append(matched.rule_id)
            available = [e for e in available if e.rule_id != matched.rule_id]
            con.print(f"[green]Override added: {matched.rule_id} for {package}[/]")

            if not available:
                con.print("[dim]All suppressible rules have been handled.[/]")
                break

        if added:
            con.print(f"\n[bold green]Done.[/] Added {len(added)} override(s) for '{package}':")
            for rid in added:
                con.print(f"  [green]\u2713[/] {rid}")
        else:
            con.print("[yellow]No overrides were added.[/]")
    else:
        con.print(f"[yellow]All triggered rules for '{package}' are already suppressed.[/]")
        if already_suppressed:
            con.print(f"  Existing: {', '.join(e.rule_id for e in already_suppressed)}")


@override_app.command("rm")
def override_rm(
    rule_id: str = typer.Argument(..., help="Rule to stop suppressing"),
    package: str | None = typer.Option(None, "--package", help="Scope the removal to one package"),
    json_output: bool = typer.Option(False, "--json", help="Output JSON"),
):
    """Remove a rule override."""
    ensure_default_configs()
    if remove_override(rule_id.upper(), package):
        msg = f"Override removed: {rule_id.upper()}"
        if json_output:
            typer.echo(json.dumps({"status": "ok", "rule_id": rule_id.upper()}))
        else:
            _print_colored(msg, "green")
    else:
        msg = f"No matching override for {rule_id.upper()}"
        if json_output:
            typer.echo(json.dumps({"error": msg}))
        else:
            _print_colored(msg, "yellow")
        raise typer.Exit(code=2)


def register_commands(app: typer.Typer):
    """Register the ``override`` subcommand group on *app*."""
    app.add_typer(override_app, name="override")
