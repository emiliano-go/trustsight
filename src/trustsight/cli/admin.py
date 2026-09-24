import json
import logging
import sqlite3
from pathlib import Path

import typer

from ..config import (
    CONFIG_DIR,
    drifted_shipped_rules,
    ensure_default_configs,
    load_rules,
    missing_shipped_rules,
    outdated_shipped_rules,
)
from ..db import (
    count_observations,
    dependency_table_populated,
    effective_observation_count,
    get_all_packages,
    init_db,
    seed_observation_count,
    import_seed,
)
from ..lint import SEVERITY_ERROR, lint_rules
from ..safe_text import clean
from .display import (
    _print_colored,
    console,
    use_rich,
)

log = logging.getLogger(__name__)


# --- seed-db ---

def _stale_rules_note(stale_patterns, missing, plain: bool = False) -> str:
    """What a stale rules.toml costs, said plainly.

    Not "your config is out of date": the consequence is that rules match
    less than the shipped definitions do, so a quiet report is quiet for a
    reason the reader cannot see from the report.
    """
    parts = []
    if stale_patterns:
        shown = ", ".join(stale_patterns[:8])
        more = f" (+{len(stale_patterns) - 8} more)" if len(stale_patterns) > 8 else ""
        parts.append(
            f"{len(stale_patterns)} rule(s) match on an older pattern than this "
            f"build ships: {shown}{more}. Those rules detect less here than "
            f"their documentation describes."
        )
    if missing:
        parts.append(
            f"{len(missing)} shipped rule(s) are absent from your rules.toml: "
            f"{', '.join(missing[:8])}."
        )
    parts.append("Run `trustsight config sync-rules --update` to reconcile "
                 "(rules you have edited yourself are left alone).")
    body = " ".join(parts)
    return body if plain else f"\n[yellow]{body}[/]"


def _dependency_corpus_note(plain: bool = False) -> str:
    """What a missing dependency corpus costs, said plainly.

    The D-series rules compare a name against every dependency name observed
    across the AUR.  Without the corpus they stay silent, so a quiet report
    is quiet for a reason the report does not show.
    """
    body = (
        "The dependency corpus is not loaded, so the D-series rules (novel "
        "dependency, typosquat, dependency count) stay silent and a quiet "
        "report is quiet for a reason the report does not show. Run "
        "`trustsight seed fetch` for the published corpus, or build it from "
        "the AUR mirror yourself (about 2.5 GB, rebuild monthly); see "
        "https://docs.trustsight.org/explanation/seed-provenance/."
    )
    return body if plain else f"\n[yellow]{body}[/]"


def register_commands(app: typer.Typer):
    """Register the subcommand groups and maintenance commands on *app*."""
    from .baseline import register_commands as _register_baseline
    from .config import register_commands as _register_config
    from .db import register_commands as _register_db
    from .override import register_commands as _register_override

    _register_config(app)
    _register_override(app)
    _register_db(app)
    _register_baseline(app)

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
            elif use_rich():
                console().print(msg)
            else:
                print(msg)
            return

        try:
            if use_rich() and not json_output:
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

        if use_rich():
            from rich.box import SIMPLE_HEAD
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

        if use_rich():
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
                    table.add_row(Text(clean(f.rule_id)),
                                  Text(f.level, style=style),
                                  Text(clean(f.check)), Text(clean(f.message)))
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
            if use_rich():
                console().print(f"\n[yellow]{msg}[/]")
            else:
                print(f"\n{msg}")

        if outdated:
            msg = (
                f"{len(outdated)} rule(s) use a superseded pattern: {', '.join(outdated)}.\n"
                f"These were corrected upstream. Run 'trustsight config sync-rules --update'."
            )
            if use_rich():
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
        # `rules.toml` is written once, at install time, and only ever gains
        # rules.  A shipped *pattern* fix therefore never reaches an existing
        # install, and the only place that said so was `config sync-rules` -
        # a command nobody runs unprompted.  A stale file means this build
        # detects less than its own documentation claims, which the reader
        # has no way to discover from a quiet report.
        drift = drifted_shipped_rules()
        stale_patterns = sorted({r for r, field, _a, _s in drift if field == "pattern"})
        missing = missing_shipped_rules()

        if json_output:
            typer.echo(json.dumps({
                "packages_tracked": len(all_pkgs),
                "total_analyses": total_analyses,
                "effective_observations": effective_obs,
                "seed_observations": seed_obs,
                "dependency_corpus_loaded": deps_loaded,
                "stale_rule_patterns": stale_patterns,
                "missing_shipped_rules": missing,
            }, indent=2))
            return

        if use_rich():
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
            table.add_row(
                "Rule patterns",
                Text("Up to date", style="green") if not stale_patterns
                else Text(f"{len(stale_patterns)} stale", style="yellow"),
            )
            con.print(table)
            if not deps_loaded:
                con.print(_dependency_corpus_note())
            if stale_patterns or missing:
                con.print(_stale_rules_note(stale_patterns, missing))
        else:
            print(f"Packages tracked      : {len(all_pkgs)}")
            print(f"Total analyses        : {total_analyses}")
            print(f"Effective observations: {effective_obs}")
            print(f"Seed observations     : {seed_obs}")
            print(f"Dependency corpus     : {'Loaded' if deps_loaded else 'Not loaded'}")
            print("Rule patterns         : "
                  + ("Up to date" if not stale_patterns
                     else f"{len(stale_patterns)} stale"))
            if not deps_loaded:
                print(_dependency_corpus_note(plain=True))
            if stale_patterns or missing:
                print(_stale_rules_note(stale_patterns, missing, plain=True))

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
