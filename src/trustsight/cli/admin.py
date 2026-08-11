import json
import logging
import sqlite3
from datetime import datetime
from pathlib import Path

import typer

from ..config import (
    CONFIG_DIR,
    ensure_default_configs,
    drifted_shipped_rules,
    load_config,
    load_rules,
    missing_shipped_rules,
    outdated_shipped_rules,
    set_config,
    sync_rules,
)
from ..db import (
    count_observations,
    dependency_table_populated,
    effective_observation_count,
    get_all_packages,
    get_db_path,
    init_db,
    seed_observation_count,
    import_seed,
)
from ..lint import SEVERITY_ERROR, lint_rules
from ..override import FATAL_RULES, OVERRIDES_PATH, add_override, list_overrides, remove_override
from ..unicode import strip_ansi
from .display import (
    HAS_RICH,
    SIMPLE_HEAD,
    _fmt_bytes,
    _print_colored,
    _weight_text,
    console,
)

log = logging.getLogger(__name__)

config_app = typer.Typer(
    help="Manage configuration (aliases: show, set, sync-rules)",
    no_args_is_help=True, add_completion=False,
)
override_app = typer.Typer(
    help="Suppress a rule that misfires on your packages",
    no_args_is_help=True, add_completion=False,
)
db_app = typer.Typer(
    help="Database maintenance (check, vacuum, backup)",
    no_args_is_help=True, add_completion=False,
)
baseline_app = typer.Typer(
    help="Build or import a full-AUR baseline corpus",
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

    if HAS_RICH:
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
    json_output: bool = typer.Option(False, "--json", help="Output JSON"),
):
    """Sync shipped rules to the user config."""
    ensure_default_configs()
    added, updated = sync_rules(update_outdated=update)
    target = CONFIG_DIR / "rules.toml"

    drift = drifted_shipped_rules()

    if json_output:
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

    lines = []
    if updated:
        lines.append(f"Updated {len(updated)} superseded rule(s): {', '.join(updated)}")
    if added:
        lines.append(f"Added {len(added)} rule(s): {', '.join(added)}")
    if not added and not updated:
        pending = outdated_shipped_rules()
        if pending:
            lines.append(
                f"{len(pending)} rule(s) use a superseded pattern: "
                f"{', '.join(pending)}. Re-run with --update to replace them "
                f"(only rules you have not edited are touched)."
            )
        elif not drift:
            lines.append("rules.toml is already up to date.")
    if drift:
        lines.append(
            f"\n{len(drift)} rule field(s) differ from the shipped definition. "
            f"A 'match_target' still set to raw_line means that rule does not "
            f"see payloads assembled from shell variables:"
        )
        for rid, field, actual, shipped_value in drift:
            lines.append(f"  {rid}.{field}: {actual!r} on disk, {shipped_value!r} shipped")
        lines.append("Edit rules.toml to adopt these, keeping any pattern you rely on.")
    body = "\n".join(lines)
    if HAS_RICH:
        from rich.panel import Panel as RichPanel
        console().print(RichPanel(body, title=str(target), border_style="cyan"))
    else:
        print(body)


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
        else:
            console().print(msg) if HAS_RICH else print(msg)
        return

    if json_output:
        data = [
            {"rule_id": o.rule_id, "package": o.package, "reason": o.reason, "created_at": o.created_at}
            for o in overrides
        ]
        typer.echo(json.dumps(data, indent=2))
        return

    if HAS_RICH:
        from rich.table import Table
        table = Table(title=f"Rule overrides ({OVERRIDES_PATH})", box=SIMPLE_HEAD)
        table.add_column("Rule", style="cyan")
        table.add_column("Scope")
        table.add_column("Reason", overflow="fold")
        table.add_column("Added", style="dim")
        for o in overrides:
            table.add_row(o.rule_id, o.package or "all packages",
                          strip_ansi(o.reason), o.created_at)
        console().print(table)
        console().print(
            f"[dim]{', '.join(sorted(FATAL_RULES))} cannot be overridden; a FATAL "
            f"finding is never suppressed.[/]"
        )
    else:
        for o in overrides:
            print(f"{o.rule_id:<8} {o.package or 'all':<20} {strip_ansi(o.reason)}")


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
        from rich.table import Table

        con.print(f"\n[bold]Triggered rules for [cyan]{package}[/][/]\n")
        table = Table(box=SIMPLE_HEAD)
        table.add_column("#", style="dim", justify="right")
        table.add_column("Rule", style="cyan")
        table.add_column("Severity")
        table.add_column("Reason", overflow="fold")
        for i, e in enumerate(available, 1):
            table.add_row(str(i), e.rule_id, e.severity, strip_ansi(e.reason))
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


# --- db subcommands ---

@db_app.command("check")
def db_check(
    json_output: bool = typer.Option(False, "--json", help="Output JSON"),
):
    """Run integrity check on the database."""
    ensure_default_configs()
    from ..db import get_connection
    try:
        init_db()
    except sqlite3.DatabaseError:
        # A corrupt database is exactly what this command must diagnose;
        # crashing on the schema init would defeat the point.
        pass

    errors = []
    try:
        with get_connection() as conn:
            rows = conn.execute("PRAGMA integrity_check").fetchall()
            for r in rows:
                if r[0] != "ok":
                    errors.append(r[0])
    except sqlite3.DatabaseError as exc:
        errors.append(str(exc))

    if json_output:
        typer.echo(json.dumps({
            "status": "ok" if not errors else "corrupt",
            "errors": errors,
        }, indent=2))
        return

    if not errors:
        _print_colored("Database integrity check passed.", "green")
    else:
        for err in errors:
            _print_colored(err, "red", stderr=True)
        raise typer.Exit(code=2)


@db_app.command("vacuum")
def db_vacuum(
    force: bool = typer.Option(False, "--force", help="Skip confirmation prompt"),
    json_output: bool = typer.Option(False, "--json", help="Output JSON"),
):
    """Reclaim disk space by rebuilding the database file."""
    ensure_default_configs()
    init_db()
    from ..db import get_connection

    if not force and not json_output:
        typer.confirm("Vacuum the database? This may take a while.", abort=True)

    with get_connection() as conn:
        before = get_db_path().stat().st_size
        conn.execute("VACUUM")
        after = get_db_path().stat().st_size

    if json_output:
        typer.echo(json.dumps({
            "status": "ok",
            "bytes_before": before,
            "bytes_after": after,
            "bytes_reclaimed": before - after,
        }, indent=2))
        return

    reclaimed = before - after
    _print_colored(
        f"Database vacuumed: {_fmt_bytes(before)} -> {_fmt_bytes(after)} "
        f"({_fmt_bytes(reclaimed)} reclaimed)", "green",
    )


@db_app.command("backup")
def db_backup(
    output: str | None = typer.Option(None, "--output", "-o", help="Output path (default: auto-named)"),
    json_output: bool = typer.Option(False, "--json", help="Output JSON"),
):
    """Create a safe online backup of the database."""
    ensure_default_configs()
    init_db()
    from ..db import get_connection

    db_path = get_db_path()
    if not output:
        ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        output = str(db_path) + f".{ts}.bak"

    out_path = Path(output)
    if out_path.exists() and db_path != out_path and out_path.samefile(db_path):
        msg = f"backup path must differ from the live database: {output}"
        if json_output:
            typer.echo(json.dumps({"error": msg}))
        else:
            _print_colored(msg, "red", stderr=True)
        raise typer.Exit(code=2)
    if not out_path.parent.exists():
        msg = f"backup directory does not exist: {out_path.parent}"
        if json_output:
            typer.echo(json.dumps({"error": msg}))
        else:
            _print_colored(msg, "red", stderr=True)
        raise typer.Exit(code=2)

    try:
        with get_connection() as conn:
            backup_conn = sqlite3.connect(output)
            try:
                conn.backup(backup_conn, pages=0)
            finally:
                backup_conn.close()
    except sqlite3.Error as exc:
        msg = f"backup failed: {exc}"
        if json_output:
            typer.echo(json.dumps({"error": msg}))
        else:
            _print_colored(msg, "red", stderr=True)
        raise typer.Exit(code=2)

    size = Path(output).stat().st_size
    if json_output:
        typer.echo(json.dumps({
            "status": "ok",
            "path": output,
            "bytes": size,
        }, indent=2))
        return

    _print_colored(f"Database backed up to {output} ({_fmt_bytes(size)})", "green")


# --- baseline subcommands ---

@baseline_app.command("build")
def baseline_build(
    resume: bool = typer.Option(False, "--resume", help="Continue an interrupted bootstrap (now implied: cycles resume automatically)"),
    bootstrap: bool = typer.Option(False, "--bootstrap", help="Allow a from-scratch bootstrap of the whole AUR when no snapshot exists (capped per cycle, resumes)"),
    export: str | None = typer.Option(None, "--export", help="Path to write the baseline artifact"),
    sign: str | None = typer.Option(None, "--sign", help="Path to ed25519 private key for signing"),
    json_output: bool = typer.Option(False, "--json", help="Output JSON"),
):
    """Bootstrap or update the full-AUR baseline corpus."""
    from .. import release
    from ..full_aur.pipeline import run_baseline_build
    ensure_default_configs()
    init_db()
    if release.offline():
        msg = "baseline build needs the AUR network channel; TRUSTSIGHT_OFFLINE is set."
        if json_output:
            typer.echo(json.dumps({"error": msg}))
        else:
            _print_colored(msg, "red", stderr=True)
        raise typer.Exit(code=2)
    result = run_baseline_build(resume=resume, export_path=export, sign_key=sign, json_output=json_output, bootstrap=bootstrap)
    if result.refused:
        raise typer.Exit(code=2)


@baseline_app.command("import")
def baseline_import(
    path: str = typer.Argument(..., help="Path to the baseline artifact (.tar.zst)"),
    allow_unsigned: bool = typer.Option(False, "--allow-unsigned", help="Allow unsigned artifacts (local builds only)"),
    json_output: bool = typer.Option(False, "--json", help="Output JSON"),
):
    """Import a signed baseline corpus artifact."""
    ensure_default_configs()
    init_db()
    _import_baseline_wrapped(path, json_output, allow_unsigned)


def _import_baseline_wrapped(path: str, json_output: bool, allow_unsigned: bool) -> None:
    """Import a corpus baseline, turning failure into a structured exit 2.

    Errors (missing file, malformed artifact, bad signature, missing
    cryptography) are reported like every other failure path: as JSON when
    ``--json`` is set, otherwise as a single colored line.
    """
    from ..full_aur.export import import_baseline
    try:
        import_baseline(path, json_output=json_output, allow_unsigned=allow_unsigned)
    except Exception as exc:
        msg = str(exc) or exc.__class__.__name__
        if json_output:
            typer.echo(json.dumps({"error": msg}))
        else:
            _print_colored(msg, "red", stderr=True)
        raise typer.Exit(code=2)


# --- seed-db ---

def register_commands(app: typer.Typer):
    app.add_typer(config_app, name="config")
    app.add_typer(override_app, name="override")
    app.add_typer(db_app, name="db")
    app.add_typer(baseline_app, name="baseline")

    @app.command()
    def seed_db(
        do_import: bool = typer.Option(False, "--import", help="Import the seed (default action)"),
        file: str | None = typer.Option(None, "--file", help="Seed .db or .db.gz to import (default: bundled)"),
        force: bool = typer.Option(False, "--force", help="Re-import even if already seeded"),
        json_output: bool = typer.Option(False, "--json", help="Output JSON"),
    ):
        """Import or inspect the novelty seed database."""
        ensure_default_configs()
        init_db()

        if file:
            seed = Path(file)
        else:
            bundled = Path(__file__).parent.parent / "data" / "seed.db.gz"
            if not bundled.exists():
                msg = (
                    "No bundled seed ships in this build. The seed lives on "
                    "the release channel; fetch the verified baseline with:\n"
                    "  trustsight seed fetch\n"
                    "or pass an existing seed with --file."
                )
                if json_output:
                    typer.echo(json.dumps({"error": msg}))
                else:
                    _print_colored(msg, "red", stderr=True)
                raise typer.Exit(code=2)
            seed = bundled

        already = seed_observation_count()
        if already and not force:
            msg = (
                f"A seed is already imported ({already} observations). "
                f"Use --force to re-import."
            )
            if json_output:
                typer.echo(json.dumps({"status": "already_imported", "observations": already}))
            else:
                console().print(msg) if HAS_RICH else print(msg)
            return

        try:
            if HAS_RICH and not json_output:
                with console().status(f"Importing seed from {seed.name}...", spinner="dots"):
                    stats = import_seed(seed)
            else:
                if not json_output:
                    print(f"Importing seed from {seed}...")
                stats = import_seed(seed)
        except (OSError, ValueError, sqlite3.DatabaseError) as exc:
            msg = f"Failed to import seed from {seed}: {exc}"
            if json_output:
                typer.echo(json.dumps({"error": msg}))
            else:
                _print_colored(msg, "red", stderr=True)
            raise typer.Exit(code=2)

        if json_output:
            stats["effective_observations"] = effective_observation_count()
            typer.echo(json.dumps(stats, indent=2))
            return

        if HAS_RICH:
            from rich.table import Table
            table = Table(title="Novelty seed imported", box=SIMPLE_HEAD)
            table.add_column("Item", style="dim")
            table.add_column("Count", justify="right")
            table.add_row("Source URLs added", f"{stats['urls_added']:,}")
            table.add_row("Source URLs total", f"{stats['urls_total']:,}")
            table.add_row("Maintainers", f"{stats['maintainers']:,}")
            table.add_row("Bootstrap observations", f"{stats['observations']:,}")
            table.add_row("Effective observations", f"{effective_observation_count():,}")
            console().print(table)
            console().print(
                "[dim]Maturity now reflects a warm database, so Medium verdicts are "
                "no longer downgraded to INCONCLUSIVE.[/]"
            )
        else:
            print(f"Imported seed from {seed}")
            print(f"  source URLs added : {stats['urls_added']}")
            print(f"  maintainers       : {stats['maintainers']}")
            print(f"  observations      : {stats['observations']}")

    @app.command("lint-rules")
    def lint_rules_cmd(
        file: str | None = typer.Option(None, "--file", help="Lint a specific rules TOML file instead of the user config"),
        json_output: bool = typer.Option(False, "--json", help="Output JSON"),
    ):
        """Lint rules for common mistakes."""
        if file:
            import tomllib

            path = Path(file)
            if not path.exists():
                _print_colored(f"Rules file not found: {path}", "red", stderr=True)
                raise typer.Exit(code=2)
            with open(path, "rb") as fh:
                rules = tomllib.load(fh).get("rules", [])
            source = path
        else:
            ensure_default_configs()
            rules = load_rules()
            source = CONFIG_DIR / "rules.toml"

        findings = lint_rules(rules)
        missing = [] if file else missing_shipped_rules()
        outdated = [] if file else outdated_shipped_rules()

        errors = [f for f in findings if f.level == SEVERITY_ERROR]
        warnings = [f for f in findings if f.level != SEVERITY_ERROR]

        if json_output:
            data = {
                "source": str(source),
                "total_rules": len(rules),
                "errors": len(errors),
                "warnings": len(warnings),
                "findings": [
                    {"rule_id": f.rule_id, "level": f.level, "check": f.check, "message": f.message}
                    for f in findings
                ],
            }
            if missing:
                data["missing_shipped_rules"] = missing
            if outdated:
                data["outdated_shipped_rules"] = outdated
            typer.echo(json.dumps(data, indent=2))
            return

        if HAS_RICH:
            from rich.table import Table
            from rich.text import Text

            con = console()
            if not findings:
                con.print(f"[green]\u2713[/] {len(rules)} rules, no issues.")
            else:
                table = Table(title=f"Rule Lint: {source}")
                table.add_column("Rule", style="cyan")
                table.add_column("Level")
                table.add_column("Check", style="dim")
                table.add_column("Message")
                for f in findings:
                    style = "red" if f.level == SEVERITY_ERROR else "yellow"
                    table.add_row(f.rule_id, Text(f.level, style=style), f.check, f.message)
                con.print(table)
                con.print(
                    f"\n{len(rules)} rules checked: "
                    f"[red]{len(errors)} error(s)[/], [yellow]{len(warnings)} warning(s)[/]"
                )
        else:
            for f in findings:
                print(f"{f.level.upper():<8} {f.rule_id:<8} {f.check:<20} {f.message}")
            print(f"\n{len(rules)} rules checked: {len(errors)} error(s), {len(warnings)} warning(s)")

        if missing:
            msg = (
                f"{len(missing)} shipped rule(s) are missing from this file: "
                f"{', '.join(missing)}.\n"
                f"rules.toml is only written when absent, so an existing install "
                f"never receives newly shipped rules.\n"
                f"Run 'trustsight config sync-rules' to append them "
                f"(additive; your edits are preserved)."
            )
            if HAS_RICH:
                console().print(f"\n[yellow]{msg}[/]")
            else:
                print(f"\n{msg}")

        if outdated:
            msg = (
                f"{len(outdated)} rule(s) use a superseded pattern: {', '.join(outdated)}.\n"
                f"These were corrected upstream. Run 'trustsight config sync-rules --update'."
            )
            if HAS_RICH:
                console().print(f"\n[red]{msg}[/]")
            else:
                print(f"\n{msg}")

        if errors:
            raise typer.Exit(code=2)

    @app.command("status")
    def status_cmd(
        json_output: bool = typer.Option(False, "--json", help="Output JSON"),
    ):
        """Show database and system health statistics."""
        ensure_default_configs()
        init_db()

        all_pkgs = get_all_packages()
        total_analyses = count_observations()
        effective_obs = effective_observation_count()
        seed_obs = seed_observation_count()
        deps_loaded = dependency_table_populated()

        if json_output:
            typer.echo(json.dumps({
                "packages_tracked": len(all_pkgs),
                "total_analyses": total_analyses,
                "effective_observations": effective_obs,
                "seed_observations": seed_obs,
                "dependency_corpus_loaded": deps_loaded,
            }, indent=2))
            return

        if HAS_RICH:
            from rich.table import Table
            from rich.text import Text

            con = console()
            table = Table(title="TrustSight Status")
            table.add_column("Metric", style="dim")
            table.add_column("Value", justify="right")
            table.add_row("Packages tracked", str(len(all_pkgs)))
            table.add_row("Total analyses", f"{total_analyses:,}")
            table.add_row("Effective observations", f"{effective_obs:,}")
            table.add_row("Seed observations", f"{seed_obs:,}")
            table.add_row(
                "Dependency corpus",
                Text("Loaded", style="green") if deps_loaded else Text("Not loaded", style="yellow"),
            )
            con.print(table)
        else:
            print(f"Packages tracked      : {len(all_pkgs)}")
            print(f"Total analyses        : {total_analyses}")
            print(f"Effective observations: {effective_obs}")
            print(f"Seed observations     : {seed_obs}")
            print(f"Dependency corpus     : {'Loaded' if deps_loaded else 'Not loaded'}")

    @app.command("full-aur")
    def full_aur_cmd(
        resume: bool = typer.Option(False, "--resume", help="Continue an interrupted bootstrap (now implied: cycles resume automatically)"),
        bootstrap: bool = typer.Option(False, "--bootstrap", help="Allow a from-scratch bootstrap of the whole AUR when no snapshot exists (capped per cycle, resumes)"),
        export: str | None = typer.Option(None, "--export", help="Path to write the baseline artifact (.tar.zst)"),
        sign: str | None = typer.Option(None, "--sign", help="Path to ed25519 private key for signing"),
        watch: bool = typer.Option(False, "--watch", help="Keep running cycles on an interval until interrupted"),
        interval: int | None = typer.Option(None, "--interval", help="Seconds between --watch cycles (default 3600, floor 60)"),
        cycles: int = typer.Option(0, "--cycles", help="Stop --watch after this many cycles (0 = until interrupted)"),
        json_output: bool = typer.Option(False, "--json", help="Output JSON"),
    ):
        """Bootstrap or update the full-AUR baseline corpus.

        Without a prior snapshot a full bootstrap fetches every PKGBUILD in
        the AUR, so it must be asked for with --bootstrap. Every cycle is
        capped (limits.corpus_max_per_cycle) and resumes automatically, so a
        large amount of work advances in gentle chunks. With --watch the
        cycle repeats on an interval.
        """
        from .. import release
        from ..full_aur.pipeline import run_baseline_build, run_watch
        ensure_default_configs()
        init_db()
        if release.offline():
            msg = "full-aur needs the AUR network channel; TRUSTSIGHT_OFFLINE is set."
            if json_output:
                typer.echo(json.dumps({"error": msg}))
            else:
                _print_colored(msg, "red", stderr=True)
            raise typer.Exit(code=2)
        if watch:
            if export or sign or bootstrap or resume:
                typer.secho(
                    "--export/--sign describe a single artifact, and "
                    "--bootstrap/--resume a single cycle; run them "
                    "without --watch.",
                    fg=typer.colors.RED,
                )
                raise typer.Exit(2)
            if cycles < 0:
                msg = "--cycles must be 0 (until interrupted) or a positive count"
                if json_output:
                    typer.echo(json.dumps({"error": msg}))
                else:
                    _print_colored(msg, "red", stderr=True)
                raise typer.Exit(code=2)
            run_watch(interval=interval, cycles=cycles, json_output=json_output)
            return
        result = run_baseline_build(
            resume=resume, export_path=export, sign_key=sign,
            json_output=json_output, bootstrap=bootstrap,
        )
        if result.refused:
            raise typer.Exit(code=2)

    @app.command("import-baseline")
    def import_baseline_cmd(
        path: str = typer.Argument(..., help="Path to the baseline artifact (.tar.zst)"),
        allow_unsigned: bool = typer.Option(False, "--allow-unsigned", help="Allow unsigned artifacts (local builds only)"),
        json_output: bool = typer.Option(False, "--json", help="Output JSON"),
    ):
        """Import a signed baseline corpus artifact."""
        ensure_default_configs()
        init_db()
        _import_baseline_wrapped(path, json_output, allow_unsigned)
