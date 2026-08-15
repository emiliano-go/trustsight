import json
import logging
import sys

import typer

from ..config import CONFIG_DIR, ensure_default_configs, load_config
from ..coverage import GAP_REASONS
from ..safe_text import clean, safe_markup
from ..db import (
    get_db_path,
    init_db,
    maybe_auto_import_seed,
)
# The pipeline itself lives in ``trustsight.review`` so the public API can
# run it without importing typer.  These names are bound here under their
# historical spellings because that is what the CLI, and the tests that
# patch the CLI, address them by.
from ..review import (  # noqa: F401
    analyze_outdated_batch as _analyze_outdated_batch,
    default_workers as _default_workers,
    discover_packages as _discover_engine,
    get_installed_packages as _get_installed_packages,
    prefetch as _prefetch,
    prefetch_deadline as _prefetch_deadline,
    verdict_for as _verdict_for,
    is_trivial_update as _is_trivial_update,
)
from .display import (
    DEPTH_TRUNCATED_NOTE,
    HAS_RICH,
    dependency_cards_rich,
    dependency_lines_plain,
    RISK_COLORS,
    _print_colored,
    console,
    display_version,
)

log = logging.getLogger(__name__)


def _discover_packages(repos, include_foreign, all_repos_flag, all_packages, _warn, json_output=False):
    """Engine discovery plus the download progress bar it cannot draw."""
    on_download = None
    progress_state = {}

    if HAS_RICH:
        from rich.progress import BarColumn, DownloadColumn, Progress, TextColumn, TimeElapsedColumn, TransferSpeedColumn

        def on_download(pos, total):
            progress = progress_state.get("progress")
            if progress is None:
                con = console()
                columns = [
                    TextColumn("[progress.description]{task.description}"),
                    BarColumn(),
                    DownloadColumn(),
                    TransferSpeedColumn(),
                    TimeElapsedColumn(),
                ]
                progress = Progress(*columns, console=con, transient=False)
                progress.start()
                progress_state["progress"] = progress
                progress_state["task"] = progress.add_task(
                    "Downloading AUR metadata...", total=None)
            progress.update(progress_state["task"], total=total, completed=pos, refresh=True)

    try:
        discovered = _discover_engine(
            repos=repos,
            include_foreign=include_foreign,
            all_repos=all_repos_flag,
            all_packages=all_packages,
            on_warn=_warn,
            on_download=on_download,
            on_notice=None if json_output else lambda msg: _print_colored(msg, "green"),
        )
    finally:
        progress = progress_state.get("progress")
        if progress is not None:
            progress.stop()

    if json_output and discovered[0] is None:
        typer.echo(json.dumps({
            "status": "metadata_downloaded",
            "message": "AUR metadata snapshot downloaded; run again to review changes.",
        }))
    return discovered


def _version_cell(result: dict) -> str:
    """Version text for one review row, honest about comparability."""
    from ..analysis.version import COMPARISON_INCONCLUSIVE

    old = display_version(result.get("old_version"))
    new = display_version(result.get("new_version"))
    if result.get("version_comparison") == COMPARISON_INCONCLUSIVE:
        return f"{old} installed / AUR pkgver {new} (not comparable)"
    return f"{old}  \u2192  {new}"





def _run_analysis_loop(outdated_pkgs, limit, verbose, quiet, json_output, total_installed=0, all_packages=False, show_score=False, show_risk=False, depth=None):
    limited = outdated_pkgs[:limit] if limit else outdated_pkgs

    has_progress = HAS_RICH and not json_output and not quiet

    if has_progress:
        from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
        con = console()
        progress_columns = [
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
        ]
        with Progress(*progress_columns, console=con, transient=False) as progress:
            task = progress.add_task("Connecting to AUR...", total=len(limited))
            progress.refresh()

            def on_progress(_current, total, description):
                if not has_progress:
                    return
                if _current < 0:
                    progress.update(task, total=None, description=description, refresh=True)
                elif total:
                    progress.update(task, total=total, completed=_current, description=description, refresh=True)
                else:
                    progress.update(task, description=description, refresh=True)

            results = _analyze_outdated_batch(limited, on_progress, verbose, depth=depth)
            progress.update(task, visible=False)
    elif json_output:
        def on_progress(_current, total, description):
            import json as _json
            print(_json.dumps({"event": "progress", "current": _current, "total": total, "phase": description}), file=sys.stderr)
        results = _analyze_outdated_batch(limited, on_progress, verbose, depth=depth)
    else:
        results = _analyze_outdated_batch(limited, None, verbose, depth=depth)

    if json_output:
        from ..config import config_fingerprint
        from ..reporting import report_body

        fingerprint = config_fingerprint()
        json_results = []
        for r in results:
            row = dict(r)
            row.setdefault("config_fingerprint", fingerprint)
            # One body for every JSON surface: this path, `inspect --json`
            # and the API's `to_dict()` all render through `report_body`, so
            # a key cannot exist on one and be missing from another.
            jr = report_body(
                row,
                include_score=show_score or show_risk,
                verbose=verbose,
            )
            if verbose:
                jr["triggered_rules"] = r.get("triggered_rules", [])
            json_results.append(jr)
        typer.echo(json.dumps(json_results, indent=2))
        return

    if not results:
        if all_packages:
            _print_colored("No AUR packages found to review.", "green")
        else:
            _print_colored("No outdated packages found.", "green")
        return

    if HAS_RICH and not json_output:
        _render_results_rich(results, total_installed, all_packages, show_score, show_risk, verbose)
    else:
        _render_results_plain(results, total_installed, all_packages, show_score, show_risk, verbose)


def _render_results_plain(results, total_installed, all_packages, show_score, show_risk, verbose):
    """The review render for a terminal without Rich.

    Extracted from ``_run_analysis_loop`` so it can be exercised: a renderer
    that cannot be called without a CLI invocation cannot be gated, and an
    ungateable path is where the dropped field will be.  See
    ``docs/contributing/security-review.md``.
    """
    for r in results:
        if r.get("failed"):
            typer.echo(f"{clean(r['package'])} {_version_cell(r)}")
            if r.get("aur_note"):
                typer.echo(f"  {clean(r['aur_note'])}")
            typer.echo(f"  {clean(r['verdict'])}")
            typer.echo()
            continue

        typer.echo(f"{clean(r['package'])} {_version_cell(r)}")

        findings = r.get("findings", [])
        file_changes = r.get("file_changes", [])
        is_trivial = r.get("is_trivial", False)

        if r.get("first_seen"):
            typer.echo("  First analysis. No prior history for this package.")
        elif is_trivial:
            typer.echo("  Only pkgver and sha256sums changed. Review the diff before building.")
        else:
            typer.echo("  The update is not trivial. Review it.")
            for f in findings:
                file_part = f.get("file", "")
                line = f.get("line")
                desc = f.get("description", "")
                if line is not None:
                    typer.echo(f"  {clean(file_part)} line {line}   {clean(desc)}")
                else:
                    typer.echo(f"  {clean(file_part)}           {clean(desc)}")
            if file_changes:
                for fc in file_changes:
                    status = fc.get("status", "")
                    path = fc.get("path", "")
                    prefix = {"added": "+", "removed": "-", "modified": "~"}.get(status, " ")
                    typer.echo(f"  {prefix} {clean(path)}")

        if show_score and not r.get("failed"):
            risk = r.get("risk_label") or r.get("risk", "")
            score_val = r.get("score", 0)
            typer.echo(f"  Score: {score_val}/100 ({risk})")
        elif show_risk and not r.get("failed"):
            label = r.get("risk_label") or r.get("risk", "")
            typer.echo(f"  Risk: ({label})")

        for entry in r.get("changes", []):
            typer.echo(f"  ~ {clean(entry)}")
        for line in dependency_lines_plain(r.get("dependencies", []),
                                           show_score=show_score):
            typer.echo(line)
        if r.get("depth_truncated"):
            typer.echo(f"  [{DEPTH_TRUNCATED_NOTE}]")

        # B5, same omission as the Rich render above: visible on screen, not
        # only in the JSON body.
        for entry in r.get("suppressed_rules", []):
            typer.echo(
                f"  [Suppressed: {clean(entry.get('rule_id', ''))} "
                f"{clean(entry.get('override_reason', ''))}]"
            )
        for m in r.get("ioc_matches", []):
            expired = " [EXPIRED]" if m.expired else ""
            line = f" line {m.line}" if m.line is not None else ""
            typer.echo(
                f"  [IOC] [{clean(m.source)}] {clean(m.type)}={clean(m.value)}"
                f"{line} ({clean(m.surface)}){expired}"
            )
        for gap in r.get("coverage_gaps", []):
            typer.echo(f"  [Not fully vetted: {GAP_REASONS.get(gap, gap)}.]")

        typer.echo()

    flagged = sum(1 for r in results if (r["score"] or 0) > 20)
    failed = sum(1 for r in results if r.get("failed"))
    reviewed = len(results) - failed
    if all_packages and total_installed:
        caption = f"{reviewed} package(s) reviewed out of {total_installed} installed"
    else:
        caption = f"{reviewed} package(s) needing update and reviewed"
        if total_installed:
            caption += f" out of {total_installed} installed"
    if show_score and flagged:
        caption += f", {flagged} above the 20-point UNFLAGGED threshold"
    if failed:
        caption += f", {failed} could NOT be vetted"
    typer.echo(caption)


def _render_results_rich(results, total_installed, all_packages, show_score, show_risk, verbose):
    from rich.panel import Panel
    from rich.text import Text

    con = console()
    for r in results:
        if verbose and not r.get("failed") and r.get("_verbose_fact"):
            from .inspect import _inspect_rich as _render_inspect
            _render_inspect(r["_verbose_fact"], show_score=show_score, show_risk=show_risk)
            continue

        from rich.table import Table
        table = Table(show_header=False, box=None, padding=(0, 1))
        table.add_column(no_wrap=True)
        table.add_column()

        table.add_row("Version", Text(_version_cell(r)))

        if r.get("failed"):
            table.add_row("Status", Text(clean(r["verdict"])))
            panel = Panel(table, title=Text(clean(r["package"])), border_style="red")
            con.print(panel)
            continue

        if r.get("aur_note"):
            table.add_row("Status", Text(clean(r["aur_note"])))
        elif r.get("first_seen"):
            table.add_row("Status", "First analysis. No prior history for this package.")
        elif r.get("is_trivial"):
            table.add_row("Status", "Only pkgver and sha256sums changed. Review the diff before building.")
        else:
            table.add_row("Status", "The update is not trivial. Review it.")
            for f in r.get("findings", []):
                file_part = f.get("file", "")
                line = f.get("line")
                rule_id = f.get("rule_id", "")
                desc = f.get("description", "")
                suffix = f" [{clean(rule_id)}]" if rule_id else ""
                if line is not None:
                    table.add_row("", Text(f"{clean(file_part)} line {line}{suffix}  {clean(desc)}"))
                else:
                    table.add_row("", Text(f"{clean(file_part)}{suffix}  {clean(desc)}"))

        file_changes = r.get("file_changes", [])
        if file_changes:
            table.add_row("", "")
            table.add_row("Files changed", "")
            for fc in file_changes:
                status = fc.get("status", "")
                path = fc.get("path", "")
                prefix = {"added": "[green]+[/]", "removed": "[red]-[/]", "modified": "[yellow]~[/]"}.get(status, " ")
                table.add_row("", f"  {prefix} {safe_markup(path)}")

        changes = r.get("changes", [])
        if changes:
            table.add_row("Changed", Text(clean(changes[0])))
            for entry in changes[1:]:
                table.add_row("", Text(clean(entry)))

        # Dependency mini-cards: each is its own analysis, so it gets its
        # own card nested in this one rather than a line in this package's
        # finding list.
        deps = r.get("dependencies", [])
        if deps:
            table.add_row("", "")
            table.add_row("Dependencies", "")
            for card in dependency_cards_rich(deps, show_score=show_score):
                table.add_row("", card)
            if r.get("depth_truncated"):
                table.add_row("", Text(DEPTH_TRUNCATED_NOTE, style="yellow"))

        # B5: a suppression a reader cannot see is one they cannot audit.
        # This render carried it in the JSON body and nowhere on screen, so
        # a rule switched off by an override looked, to anyone reading the
        # terminal, exactly like one that never matched.
        suppressed = r.get("suppressed_rules", [])
        if suppressed:
            table.add_row("Suppressed", "")
            for entry in suppressed:
                rule_id = entry.get("rule_id", "")
                reason = entry.get("override_reason", "")
                table.add_row("", Text(f"  {clean(rule_id)}  {clean(reason)}"))

        ioc_matches = r.get("ioc_matches", [])
        if ioc_matches:
            table.add_row("IOC matches", "")
            for m in ioc_matches:
                expired = " [EXPIRED]" if m.expired else ""
                line = f" line {m.line}" if m.line is not None else ""
                table.add_row("", Text(
                    f"  [{clean(m.source)}] {clean(m.type)}={clean(m.value)}"
                    f"{line} ({clean(m.surface)}){expired}"
                ))

        for gap in r.get("coverage_gaps", []):
            table.add_row("Not vetted", GAP_REASONS.get(gap, gap))

        risk = r.get("risk", "")
        label = r.get("risk_label") or risk
        score_val = r.get("score", 0)
        border = RISK_COLORS.get(risk, "blue") if (show_score or show_risk) else "blue"

        if show_score and not r.get("failed"):
            table.add_row("Score", f"{score_val}/100 ({label})")
        elif show_risk and not r.get("failed"):
            table.add_row("Risk", f"({label})")

        panel = Panel(table, title=Text(clean(r["package"])), border_style=border)
        con.print(panel)

    flagged = sum(1 for r in results if (r["score"] or 0) > 20)
    failed = sum(1 for r in results if r.get("failed"))
    reviewed = len(results) - failed
    if all_packages and total_installed:
        caption = f"{reviewed} package(s) reviewed out of {total_installed} installed"
    else:
        caption = f"{reviewed} package(s) needing update and reviewed"
        if total_installed:
            caption += f" out of {total_installed} installed"
    if show_score and flagged:
        caption += f", {flagged} above the 20-point UNFLAGGED threshold"
    if failed:
        caption += f", {failed} could NOT be vetted"
    con.print(caption)


def register_commands(app: typer.Typer):
    @app.command()
    def review(
        limit: int = typer.Option(0, "--limit", help="Max packages to review (0 = unlimited)"),
        verbose: bool = typer.Option(False, "--verbose", help="Show triggered rules per package"),
        quiet: bool = typer.Option(False, "--quiet", help="Suppress progress output"),
        score: bool = typer.Option(False, "--score", help="Show aggregate trust score"),
        risk: bool = typer.Option(False, "--risk", help="Show risk level"),
        repo: list[str] | None = typer.Option(None, "--repo", help="Scan packages from a specific local repository (can be repeated)"),
        foreign: bool = typer.Option(False, "--foreign", help="Include foreign packages (pacman -Qm)"),
        all_repos: bool = typer.Option(False, "--all-repos", help="Auto-detect all local repos from pacman.conf (excludes official repos)"),
        all_packages: bool = typer.Option(False, "--all", help="Review all installed AUR packages, not just outdated ones"),
        json_output: bool = typer.Option(False, "--json", help="Output JSON"),
        depth: int = typer.Option(
            None, "--depth",
            help="AUR dependency levels to analyse: 0 off, 1 default, n levels, "
                 "-1 every level (bounded).",
        ),
    ):
        """Review AUR packages for suspicious updates."""
        has_progress = HAS_RICH and not json_output and not quiet
        init_progress = None
        if has_progress:
            from rich.progress import Progress, SpinnerColumn, TextColumn
            init_progress = Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console(), transient=True,
            )
            init_progress.start()
            init_task = init_progress.add_task("Loading config...", total=None)

        def _step(msg: str):
            if init_progress is not None:
                init_progress.update(init_task, description=msg)

        try:
            _step("Loading config...")
            ensure_default_configs()
            config = load_config()
            _step("Initializing database...")
            init_db()
            seed_imported = False
            if config.get("seed", {}).get("auto_import", True):
                seed_stats = maybe_auto_import_seed(
                    quiet=json_output or quiet, allow_release_fetch=True
                )
                if seed_stats is not None:
                    seed_imported = True

            if not json_output and not quiet and seed_imported:
                if init_progress is not None:
                    init_progress.stop()
                    init_progress = None
                print()
                _print_colored("Welcome to TrustSight!", "bold cyan")
                print(f"  Config:    {CONFIG_DIR}")
                print(f"  Database:  {get_db_path()}")
                print()
                print("  Next steps:")
                print("    1. Run 'trustsight review'         Scan your AUR packages")
                print("    2. Run 'trustsight inspect <pkg>'  Deep-dive on a specific package")
                print()

            _step("Discovering packages...")
            effective_limit = limit

            if limit < 0:
                msg = "--limit must be 0 (unlimited) or a positive count"
                if json_output:
                    typer.echo(json.dumps({"error": msg}))
                else:
                    _print_colored(msg, "red", stderr=True)
                raise typer.Exit(code=2)

            user_specified = not (repo is None and not foreign and not all_repos)
            if user_specified:
                repos = repo or []
                include_foreign = foreign
                all_repos_flag = all_repos
            else:
                discovery_cfg = config.get("discovery", {})
                repos = discovery_cfg.get("default_repos", [])
                include_foreign = discovery_cfg.get("include_foreign", False)
                all_repos_flag = discovery_cfg.get("all_repos", False)
                if not repos and not all_repos_flag and not include_foreign:
                    include_foreign = True

            def _warn(msg: str):
                if json_output:
                    # Keep stdout a pure JSON document; diagnostics go to stderr.
                    print(f"Warning: {msg}", file=sys.stderr)
                    return
                if not HAS_RICH:
                    print(f"Warning: {msg}")
                    return
                con = console()
                con.print(f"[yellow]Warning:[/] {msg}")

            if all_repos_flag:
                from ..discovery import get_local_repos_from_pacman_conf
                try:
                    get_local_repos_from_pacman_conf()
                except RuntimeError as exc:
                    if repos:
                        _warn(str(exc) + "; falling back to explicit repos.")
                    else:
                        if json_output:
                            typer.echo(json.dumps({"error": str(exc)}))
                        elif not HAS_RICH:
                            print(f"Error: {exc}")
                        else:
                            console().print(f"[red]Error:[/] {exc}")
                        raise typer.Exit(code=2)

            try:
                changed_installed, total_installed = _discover_packages(
                    repos=repos,
                    include_foreign=include_foreign,
                    all_repos_flag=all_repos_flag,
                    all_packages=all_packages,
                    _warn=_warn,
                    json_output=json_output,
                )
            except RuntimeError as exc:
                if json_output:
                    typer.echo(json.dumps({"error": str(exc)}))
                else:
                    _print_colored(str(exc), "red", stderr=True)
                raise typer.Exit(code=2)

            if changed_installed is None:
                if json_output:
                    typer.echo(json.dumps({"error": "package discovery failed"}))
                    raise typer.Exit(code=2)
                return
            if not changed_installed:
                if json_output:
                    typer.echo(json.dumps([]))
                elif all_packages:
                    _print_colored("No AUR packages found to review.", "green")
                else:
                    _print_colored("No outdated packages found.", "green")
                return

            if init_progress is not None:
                init_progress.stop()
                init_progress = None

            _run_analysis_loop(changed_installed, effective_limit, verbose, quiet, json_output, total_installed, all_packages, score, show_risk=risk, depth=depth)
        finally:
            if init_progress is not None:
                init_progress.stop()
