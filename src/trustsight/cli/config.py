import json
import logging
from pathlib import Path

import typer

from ..config import (
    CONFIG_DIR,
    drifted_shipped_rules,
    ensure_default_configs,
    load_config,
    missing_shipped_rules,
    outdated_shipped_rules,
    set_config,
    sync_rules,
)
from .display import (
    _print_colored,
    _weight_text,
    console,
    use_rich,
)

log = logging.getLogger(__name__)

config_app = typer.Typer(
    help="Manage configuration (subcommands: show, set, sync-rules)",
    no_args_is_help=True, add_completion=False,
)


# --- config subcommands ---

@config_app.command("show")
def config_show(
    json_output: bool = typer.Option(False, "--json", help="Output JSON"),
):
    """Display current configuration."""
    ensure_default_configs()
    cfg = load_config()
    rows = [
        ("config file", str(CONFIG_DIR / "config.toml")),
        ("seed.auto_import", str(cfg.get("seed", {}).get("auto_import", True))),
        ("rules.experimental", str(cfg.get("rules", {}).get("experimental", False))),
    ]

    if json_output:
        data = dict(rows)
        data["scoring_weights"] = {}
        for group in (
            "severity_weights", "source_bucket_weights",
            "novelty_weights",
        ):
            data["scoring_weights"][group] = (cfg.get(group) or {}).copy()
        typer.echo(json.dumps(data, indent=2))
        return

    if use_rich():
        from rich.box import SIMPLE_HEAD
        from rich.table import Table
        from rich.text import Text

        table = Table(title="TrustSight configuration", box=SIMPLE_HEAD)
        table.add_column("Key", style="cyan")
        table.add_column("Value", overflow="fold")
        for k, v in rows:
            table.add_row(k, v)
        console().print(table)

        weights = Table(title="Scoring weights", box=SIMPLE_HEAD)
        weights.add_column("Group", style="dim")
        weights.add_column("Key", style="cyan")
        weights.add_column("Weight", justify="right")
        for group in (
            "severity_weights", "source_bucket_weights",
            "novelty_weights",
        ):
            for key, value in (cfg.get(group) or {}).items():
                try:
                    weight_int = int(value)
                except (TypeError, ValueError):
                    weights.add_row(group, key, Text(str(value), style="dim"))
                else:
                    weights.add_row(group, key, _weight_text(weight_int))
        console().print(weights)
    else:
        for k, v in rows:
            print(f"  {k}: {v}")


@config_app.command("set")
def config_set(
    key: str = typer.Argument(..., help="Config key (seed.auto_import, rules.experimental)"),
    value: str = typer.Argument(..., help="Config value"),
    json_output: bool = typer.Option(False, "--json", help="Output JSON"),
):
    """Set a configuration value."""
    try:
        set_config(key, value)
    except ValueError as exc:
        if json_output:
            typer.echo(json.dumps({"error": str(exc)}))
        else:
            _print_colored(str(exc), "red")
        raise typer.Exit(code=2)
    msg = f"Set {key} in {CONFIG_DIR / 'config.toml'}"
    if json_output:
        typer.echo(json.dumps({"status": "ok", "key": key}))
    else:
        _print_colored(msg, "green")


@config_app.command("sync-rules")
def config_sync_rules(
    update: bool = typer.Option(False, "--update",
                                help="Also replace rules whose pattern is a superseded shipped one "
                                     "(rules you have edited are never touched)"),
    full: bool = typer.Option(False, "--full",
                              help="Fully overwrite all rules with shipped defaults "
                                   "(overrides user customisations)"),
    json_output: bool = typer.Option(False, "--json", help="Output JSON"),
):
    """Sync shipped rules to the user config.

    Without flags, starts an interactive wizard that shows what changed
    and lets you choose how to sync.
    """
    ensure_default_configs()
    target = CONFIG_DIR / "rules.toml"

    missing = missing_shipped_rules()
    outdated = outdated_shipped_rules()
    drift = drifted_shipped_rules()
    nothing_to_do = not missing and not outdated and not drift

    if json_output:
        added, updated = sync_rules(update_outdated=update)
        typer.echo(json.dumps({
            "target": str(target),
            "added": added,
            "updated": updated,
            "drift": [
                {"rule_id": r, "field": f, "on_disk": a, "shipped": s}
                for r, f, a, s in drift
            ],
        }, indent=2))
        return

    if nothing_to_do:
        if use_rich():
            console().print("[green]rules.toml is already up to date.[/green]")
        else:
            print("rules.toml is already up to date.")
        return

    # --- non-interactive flags ---
    if update or full:
        if full:
            # Full overwrite: rewrite every rule block with the shipped version.
            from ..config import _rule_blocks, _replace_rule_block, DEFAULT_RULES
            blocks = _rule_blocks(DEFAULT_RULES)
            text = Path(target).read_text().rstrip() + "\n"
            for rid, block in blocks.items():
                text = _replace_rule_block(text, rid, block) if rid in _current_rules(text) else text + "\n" + block
            Path(target).write_text(text)
            _print_sync_result("Full sync complete", [], [])
        else:
            added, updated = sync_rules(update_outdated=True)
            _print_sync_result("Sync complete", added, updated)
        return

    # --- interactive wizard ---
    _print_sync_wizard(target, missing, outdated, drift)


def _current_rules(text: str) -> set[str]:
    """Rule ids present in a rules.toml text."""
    import re
    return {m.group(1) for m in re.finditer(r'^id\s*=\s*["\']([^"\']+)["\']', text, re.MULTILINE)}


def _print_sync_result(title: str, added: list[str], updated: list[str], drift: list[tuple] | None = None):
    """Show sync results.  If drift is None, re-checks after sync."""
    if drift is None:
        from ..config import drifted_shipped_rules
        drift = drifted_shipped_rules()
    lines = []
    if updated:
        lines.append(f"Updated {len(updated)} superseded rule(s): {', '.join(updated)}")
    if added:
        lines.append(f"Added {len(added)} rule(s): {', '.join(added)}")
    if drift:
        lines.append(f"{len(drift)} drifted field(s) still differ (edit rules.toml manually).")
    body = "\n".join(lines) if lines else "Nothing to do."
    if use_rich():
        from rich.panel import Panel as RichPanel
        console().print(RichPanel(body, title=title, border_style="green"))
    else:
        print(f"{title}: {body}")


def _print_sync_wizard(target: Path, missing: list[str], outdated: list[str], drift: list[tuple]):
    """Interactive wizard: show changes, let user choose how to sync."""
    if use_rich():
        from rich.panel import Panel as RichPanel
        from rich.table import Table as RichTable

        # Summary
        parts = []
        if missing:
            parts.append(f"[bold]{len(missing)}[/bold] new rule(s)")
        if outdated:
            parts.append(f"[bold]{len(outdated)}[/bold] outdated pattern(s)")
        if drift:
            parts.append(f"[bold]{len(drift)}[/bold] drifted field(s)")
        console().print(RichPanel(
            f"Your rules.toml is out of date: {', '.join(parts)}.",
            title=str(target), border_style="yellow",
        ))

        # Detail table
        table = RichTable(show_header=True, header_style="bold")
        table.add_column("Rule", style="cyan", width=8)
        table.add_column("Type", width=12)
        table.add_column("Detail")

        for rid in missing:
            table.add_row(rid, "new", "Not in rules.toml; will be added")
        for rid in outdated:
            table.add_row(rid, "outdated", "Pattern is a superseded shipped version")
        for rid, field, on_disk, shipped in drift:
            table.add_row(rid, "drifted", f"{field}: {on_disk!r} (shipped: {shipped!r})")

        console().print(table)
    else:
        print(f"rules.toml is out of date: {len(missing)} new, {len(outdated)} outdated, {len(drift)} drifted.")

    # Wizard prompt
    if use_rich():
        console().print()
        console().print("[bold]How would you like to sync?[/bold]")
        console().print("  [cyan]1[/cyan]  Full update    (overwrite all rules with shipped defaults)")
        console().print("  [cyan]2[/cyan]  Safe update    (add missing + update superseded patterns only)")
        console().print("  [cyan]3[/cyan]  Skip           (don't change anything)")
        console().print()
    else:
        print("1) Full update  - overwrite all rules with shipped defaults")
        print("2) Safe update  - add missing + update superseded patterns only")
        print("3) Skip         - don't change anything")

    choice = typer.prompt("Choice", type=int, default=3)

    if choice == 1:
        from ..config import _rule_blocks, _replace_rule_block, DEFAULT_RULES
        blocks = _rule_blocks(DEFAULT_RULES)
        text = target.read_text().rstrip() + "\n"
        existing = _current_rules(text)
        for rid, block in blocks.items():
            if rid in existing:
                text = _replace_rule_block(text, rid, block)
            else:
                text += "\n" + block
        target.write_text(text)
        if use_rich():
            console().print("[green]Full sync complete.[/green]")
        else:
            print("Full sync complete.")
    elif choice == 2:
        added, updated = sync_rules(update_outdated=True)
        _print_sync_result("Safe sync complete", added, updated)
    else:
        if use_rich():
            console().print("[yellow]Skipped.[/yellow]")
        else:
            print("Skipped.")


def register_commands(app: typer.Typer):
    """Register the ``config`` subcommand group on *app*."""
    app.add_typer(config_app, name="config")
