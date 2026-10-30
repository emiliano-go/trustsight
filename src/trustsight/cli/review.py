import json
import logging
import sys
from contextlib import contextmanager

import typer

from ..config import CONFIG_DIR, ensure_default_configs, load_config
from ..safe_text import clean
from ..db import (
    get_db_path,
    init_db,
    maybe_auto_import_seed,
)
from ._review_render import (
    _DEPS_HINT as _DEPS_HINT,
    _deps_hint as _deps_hint,
    _finding_line as _finding_line,
    _render_results_plain as _render_results_plain,
    _render_results_rich as _render_results_rich,
    _summary_caption as _summary_caption,
    _version_cell as _version_cell,
)
from .display import (
    HAS_RICH,
    _print_colored,
    console,
    err_console,
    use_rich,
    use_rich_progress,
)
# The pipeline itself lives in ``trustsight.review`` so the public API can
# run it without importing typer.  These names are bound here under their
# historical spellings because that is what the CLI, and the tests that
# patch the CLI, address them by.
#
# Importing them here costs `trustsight.analysis` - the rule engine, the
# tokenizer and every compiled pattern - and `app.py` imports this module to
# register its commands, so `--version` and `--help` paid for the whole
# analyser before printing a line.  The three names this module calls are
# forwarding wrappers, which keeps them patchable by the tests that replace
# them wholesale; the rest resolve through `__getattr__`, which keeps the
# historical surface without loading anything until something asks.


@contextmanager
def _suppress_logging():
    """Suppress logging output while a Rich live display is active.

    Python's default logging handler prints directly to stderr, which
    bypasses Rich's live display and produces interleaved garbage.
    """
    handler = logging.root.handlers[0] if logging.root.handlers else None
    if handler is not None:
        old_level = handler.level
        handler.setLevel(logging.CRITICAL)
        try:
            yield
        finally:
            handler.setLevel(old_level)
    else:
        yield


def _analyze_outdated_batch(*args, **kwargs):
    from ..review import analyze_outdated_batch

    return analyze_outdated_batch(*args, **kwargs)


def _discover_engine(*args, **kwargs):
    from ..review import discover_packages

    return discover_packages(*args, **kwargs)


def _dependency_entries(*args, **kwargs):
    from ..review import dependency_entries

    return dependency_entries(*args, **kwargs)


#: Re-exported under their historical spellings; nothing in this module
#: calls them.  A bare global lookup does not consult `__getattr__`, so if
#: one of these ever gains a call site here it needs a wrapper like those
#: above rather than a plain reference.
_LAZY_REVIEW_NAMES = {
    "_default_workers": "default_workers",
    "_get_installed_packages": "get_installed_packages",
    "_prefetch": "prefetch",
    "_prefetch_deadline": "prefetch_deadline",
    "_verdict_for": "verdict_for",
    "_is_trivial_update": "is_trivial_update",
}


def __getattr__(name: str):
    if name not in _LAZY_REVIEW_NAMES:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    from .. import review as _review

    value = getattr(_review, _LAZY_REVIEW_NAMES[name])
    globals()[name] = value
    return value

log = logging.getLogger(__name__)


def _discover_packages(repos, include_foreign, all_repos_flag, all_packages, _warn, json_output=False,
                       force_refresh=False):
    """Engine discovery plus the download progress bar it cannot draw."""
    on_download = None
    progress_state = {}

    if use_rich_progress() and not json_output:
        from rich.progress import BarColumn, DownloadColumn, Progress, TextColumn, TimeElapsedColumn, TransferSpeedColumn

        def on_download(pos, total):
            progress = progress_state.get("progress")
            if progress is None:
                con = err_console()
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
        with _suppress_logging():
            discovered = _discover_engine(
                repos=repos,
                include_foreign=include_foreign,
                all_repos=all_repos_flag,
                all_packages=all_packages,
                on_warn=_warn,
                on_download=on_download,
                on_notice=None if json_output else lambda msg: _print_colored(msg, "green"),
                force_refresh=force_refresh,
            )
    finally:
        progress = progress_state.get("progress")
        if progress is not None:
            progress.stop()

    return discovered



# Risk levels ordered worst-first for --sort risk.
_RISK_SORT_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Inconclusive": 3, "Low": 4}


def _sort_key(sort_by: str | None, result: dict):
    """Return a sort key tuple for *result* given a --sort value."""
    if sort_by == "score":
        # Ascending: worst (highest score) last so it appears at the top
        # when the list is printed top-to-bottom.  Failed packages score 0
        # but should sink to the bottom.
        failed = 1 if result.get("failed") else 0
        return (failed, -(result.get("score") or 0))
    if sort_by == "risk":
        failed = 1 if result.get("failed") else 0
        risk = result.get("risk", "Low") or "Low"
        return (failed, _RISK_SORT_ORDER.get(risk, 5))
    if sort_by == "name":
        return (0, (result.get("package") or "").lower())
    return (0, 0)


def _run_analysis_loop(outdated_pkgs, limit, verbose, quiet, json_output, total_installed=0, all_packages=False, show_score=False, show_risk=False, depth=None, required_by=None, deps_only=False, sort_by=None, record=False):
    limited = outdated_pkgs[:limit] if limit else outdated_pkgs
    # How many needed reviewing, as opposed to how many were reviewed. The
    # caption used to report the second number under the first one's name:
    # `--limit 5` against 40 outdated packages printed "5 package(s) needing
    # update and reviewed", which is not what the tool found and not what it
    # did. The 35 it skipped went unmentioned.
    outdated_total = len(outdated_pkgs)

    has_progress = use_rich_progress() and not json_output and not quiet

    if has_progress:
        from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
        con = err_console()
        progress_columns = [
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
        ]
        with Progress(*progress_columns, console=con, transient=False) as progress, _suppress_logging():
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

            results = _analyze_outdated_batch(limited, on_progress, verbose, depth=depth, record=record)
            progress.update(task, visible=False)
    elif json_output:
        def on_progress(_current, total, description):
            import json as _json
            print(_json.dumps({"event": "progress", "current": _current, "total": total, "phase": description}), file=sys.stderr)
        results = _analyze_outdated_batch(limited, on_progress, verbose, depth=depth, record=record)
    else:
        results = _analyze_outdated_batch(limited, None, verbose, depth=depth, record=record)

    # `--deps` reverses the question the report answers: not "what does
    # this package pull in" but "who pulls this one in". The edge list is
    # attached to the row so every surface carries it - the JSON body
    # included, since a field on the terminal and not in the JSON is the
    # difference in information B11 forbids.
    for result in results:
        result["required_by"] = list((required_by or {}).get(result.get("package"), ()))

    # Sort results when --sort is given.  Applied before rendering so both
    # JSON and terminal surfaces present the same order.
    if sort_by and results:
        results.sort(key=lambda r: _sort_key(sort_by, r))

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
            json_results.append(jr)
        typer.echo(json.dumps(json_results, indent=2))
        return

    if not results:
        if all_packages:
            _print_colored("No AUR packages found to review.", "green")
        else:
            _print_colored("No outdated packages found.", "green")
        return

    if use_rich() and not json_output:
        _render_results_rich(results, total_installed, all_packages, show_score, show_risk, verbose, outdated_total, deps_only)
    else:
        _render_results_plain(results, total_installed, all_packages, show_score, show_risk, verbose, outdated_total, deps_only)


def register_commands(app: typer.Typer):
    """Register the ``review`` subcommand on *app*."""
    @app.command()
    def review(
        limit: int = typer.Option(
            None, "--limit",
            help="Max packages to review (0 = unlimited; default from "
                 "[limits] default_review_limit)"),
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
        deps_only: bool = typer.Option(
            False, "--deps",
            help="Review the AUR dependencies of the discovered packages "
                 "instead of the packages themselves. Honours --depth, and "
                 "each dependency reports which packages require it.",
        ),
        sort_by: str = typer.Option(
            None, "--sort",
            help="Sort results: score (worst first), risk, or name. "
                 "Default: discovery order.",
        ),
        refresh: bool = typer.Option(
            False, "--refresh",
            help="Force refresh the AUR metadata snapshot regardless of TTL.",
        ),
        record: bool = typer.Option(
            False, "--record",
            help="Persist observations and analysis history (default: read-only).",
        ),
    ):
        """Review AUR packages for suspicious updates."""
        has_progress = use_rich_progress() and not json_output and not quiet
        init_progress = None
        if has_progress:
            from rich.progress import Progress, SpinnerColumn, TextColumn
            init_progress = Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=err_console(), transient=True,
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
            # Stop the spinner before discovery starts: the download
            # progress bar inside _discover_packages draws its own
            # Progress, and two concurrent Rich live displays fight
            # over the terminal, producing interleaved output.
            if init_progress is not None:
                init_progress.stop()
                init_progress = None
            # The configured default applies only when the flag is absent.
            # `--limit 0` is an explicit request for all of them and must
            # not be overridden by a config value, which is why the option
            # defaults to None rather than to 0.
            if limit is None:
                try:
                    limit = int(config.get("limits", {}).get("default_review_limit", 0))
                except (TypeError, ValueError):
                    limit = 0
            effective_limit = limit

            if limit < 0:
                msg = "--limit must be 0 (unlimited) or a positive count"
                if json_output:
                    typer.echo(json.dumps({"error": msg}))
                else:
                    _print_colored(msg, "red", stderr=True)
                raise typer.Exit(code=2)

            _VALID_SORT = ("score", "risk", "name")
            if sort_by is not None and sort_by not in _VALID_SORT:
                msg = f"--sort must be one of: {', '.join(_VALID_SORT)} (got '{sort_by}')"
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
                from rich.text import Text
                con = console()
                # Text, not markup interpolation: msg carries --repo values
                # and paths, and Rich reads a bare str as markup, so a
                # bracketed substring would be eaten or abort the render.
                con.print(Text(f"Warning: {clean(msg)}", style="yellow"))

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
                            from rich.text import Text
                            # Same markup hazard as _warn above: str(exc)
                            # carries user-supplied paths and repo names.
                            console().print(Text(f"Error: {clean(exc)}", style="red"))
                        raise typer.Exit(code=2)

            try:
                changed_installed, total_installed = _discover_packages(
                    repos=repos,
                    include_foreign=include_foreign,
                    all_repos_flag=all_repos_flag,
                    all_packages=all_packages,
                    _warn=_warn,
                    json_output=json_output,
                    force_refresh=refresh,
                )
            except RuntimeError as exc:
                if json_output:
                    typer.echo(json.dumps({"error": str(exc)}))
                else:
                    _print_colored(str(exc), "red", stderr=True)
                raise typer.Exit(code=2)

            if changed_installed is None:
                if json_output:
                    # A first metadata download has no baseline to compare, not
                    # a discovery failure. Keep the review JSON list shape in
                    # sync with ReviewResult(metadata_bootstrapped=True).
                    typer.echo(json.dumps([]))
                    return
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

            required_by = {}
            if deps_only:
                changed_installed, required_by, closure_note = _dependency_entries(
                    changed_installed, depth, config, _warn,
                )
                if closure_note and not json_output:
                    _print_colored(closure_note, "yellow")
                if not changed_installed:
                    if json_output:
                        typer.echo(json.dumps([]))
                    else:
                        _print_colored(
                            "No AUR dependencies found for the discovered packages.",
                            "green",
                        )
                    return
                # The dependencies are the subject now, so their own closure
                # is not walked again underneath them: `--deps --depth 2`
                # means two levels of dependencies to review, not two levels
                # below each of them.
                depth = 0

            # Warn once if the user's rules.toml has drifted from the
            # shipped set.  A per-package "Not vetted" note is already
            # attached to every finding; a single header saves the user
            # from scrolling past fifteen identical lines.
            if not json_output:
                from ..config import drifted_shipped_rules, sync_rules
                drifted = drifted_shipped_rules()
                if drifted:
                    _print_colored(
                        "Your rules.toml differs from the shipped rule set.",
                        "yellow",
                    )
                    if sys.stdin.isatty() and typer.confirm("Sync rules now?", default=False):
                        added, updated = sync_rules(update_outdated=True)
                        remaining = drifted_shipped_rules()
                        parts = []
                        if added:
                            parts.append(f"added {len(added)} rule(s)")
                        if updated:
                            parts.append(f"updated {len(updated)} rule(s)")
                        if parts:
                            _print_colored(
                                f"Rules synced: {', '.join(parts)}.",
                                "green",
                            )
                        if remaining:
                            # A pattern the user edited is never overwritten,
                            # so these cannot be repaired automatically.  Say
                            # so, rather than the misleading "already up to
                            # date" the un-repairable case used to print.
                            ids = sorted({rid for rid, *_ in remaining})
                            _print_colored(
                                f"{len(ids)} rule(s) still differ and are not "
                                f"auto-repairable (edited by you or superseded): "
                                f"{', '.join(ids)}. Their detection is unaffected.",
                                "yellow",
                            )
                        elif not parts:
                            _print_colored("Rules are already up to date.", "green")

            _run_analysis_loop(changed_installed, effective_limit, verbose, quiet, json_output, total_installed, all_packages, score, show_risk=risk, depth=depth, required_by=required_by, deps_only=deps_only, sort_by=sort_by, record=record)
        finally:
            if init_progress is not None:
                init_progress.stop()
