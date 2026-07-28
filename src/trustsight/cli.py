import json
import logging
import sqlite3
import socket
import sys
import time
from pathlib import Path
from typing import Optional

import typer

from .analysis import analyze_package
from .discovery import discover_packages
from .config import (
    CONFIG_DIR,
    ensure_default_configs,
    load_config,
    load_rules,
    drifted_shipped_rules,
    missing_shipped_rules,
    outdated_shipped_rules,
    set_config,
    sync_rules,
)
from .db import (
    count_observations,
    dependency_table_populated,
    effective_observation_count,
    get_all_packages,
    get_history,
    get_db_path,
    get_last_analysis,
    get_package_id,
    get_triggered_rules,
    import_seed,
    init_db,
    maybe_auto_import_seed,
    read_aur_cache,
    seed_observation_count,
)
from .lint import SEVERITY_ERROR, lint_rules
from .override import FATAL_RULES, OVERRIDES_PATH, add_override, list_overrides, remove_override
from .scoring import risk_level
from .unicode import describe_fatal_codepoints, strip_ansi

RISK_COLORS = {
    "Low": "green",
    "Medium": "yellow",
    "High": "red",
    "Critical": "bold red",
    "Inconclusive": "dim",
    # Not a risk level: a package whose analysis failed outright.  It must
    # not be mistaken for a clean result.
    "Error": "bold white on red",
}

SEVERITY_COLORS = {
    "FATAL": "bold white on red",
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "cyan",
    "INFO": "dim",
}

TIER_OF = {
    "SOURCE_BUCKET": ("B", "Priors / context"),
    "NOVELTY": ("C", "History / novelty"),
    "PINNING": ("D", "Verification"),
    "VERIFICATION": ("D", "Verification"),
}
TIER_ORDER = ["A", "B", "C", "D"]
TIER_NAMES = {
    "A": "Structural (rules)",
    "B": "Priors / context",
    "C": "History / novelty",
    "D": "Verification (subtractive)",
}

try:
    from rich.box import SIMPLE_HEAD
    from rich.console import Console
    from rich.panel import Panel
    from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
    from rich.rule import Rule
    from rich.table import Table
    from rich.text import Text

    HAS_RICH = True
except ImportError:
    HAS_RICH = False

log = logging.getLogger(__name__)
_console = None


def console() -> "Console":
    """Return the global rich Console instance."""
    if not HAS_RICH:
        raise RuntimeError("rich is not available")
    global _console
    if _console is None:
        _console = Console()
    return _console


def _tier_of(entry) -> str:
    """tier label for a score entry"""
    return TIER_OF.get(entry.rule_id, ("A", ""))[0]


def _severity_text(severity: str) -> "Text":
    """colored text for a severity label"""
    return Text(severity, style=SEVERITY_COLORS.get(severity, "white"))


def _weight_text(weight: int) -> "Text":
    """colored text for a numeric weight"""
    if weight > 0:
        return Text(f"+{weight}", style="red")
    if weight < 0:
        return Text(str(weight), style="green")
    return Text("0", style="dim")


def _score_text(score: int, risk: str | None = None) -> "Text":
    """colored text for a score with risk color"""
    risk = risk or risk_level(score)
    return Text(f"{score}/100", style=RISK_COLORS.get(risk, "white"))


def _fact_to_dict(fact):
    """analysis fact as a json-serializable dict"""
    data = {
        "package": fact.package_name,
        "old_version": fact.old_version,
        "new_version": fact.new_version,
        "score": fact.final_score,
        "risk": risk_level(fact.final_score),
        "first_seen": fact.first_seen,
        "maintainer_changed": fact.maintainer_changed,
        "checksum_behavior": fact.source_changes.checksum_behavior if hasattr(fact.source_changes, "checksum_behavior") else None,
        "score_breakdown": [
            {
                "rule_id": e.rule_id,
                "severity": e.severity,
                "weight": e.weight,
                "reason": e.reason,
            }
            for e in fact.score_breakdown
        ],
        "suppressed_rules": fact.suppressed_rules,
    }
    if fact.maintainer_changed:
        data["previous_maintainer"] = fact.previous_maintainer
        data["current_maintainer"] = fact.current_maintainer
    if fact.source_changes.added_urls:
        data["added_urls"] = [
            {"url": url, "bucket": fact.source_buckets.get(url, "unknown")}
            for url in fact.source_changes.added_urls
        ]
    if fact.execution_changes.resolved_commands:
        data["resolved_commands"] = fact.execution_changes.resolved_commands[:50]
    return data


app = typer.Typer(
    name="trustsight",
    help="TrustSight - AUR Package Update Vetting Tool",
    no_args_is_help=True,
    add_completion=True,
    epilog="New? Start with 'trustsight review', then 'trustsight inspect <pkg>'.",
)
config_app = typer.Typer(
    help="Manage configuration (aliases: show, set, sync-rules)",
    no_args_is_help=True,
    add_completion=False,
)
override_app = typer.Typer(
    help="Suppress a rule that misfires on your packages",
    no_args_is_help=True,
    add_completion=False,
)
db_app = typer.Typer(
    help="Database maintenance (check, vacuum, backup)",
    no_args_is_help=True,
    add_completion=False,
)
baseline_app = typer.Typer(
    help="Build or import a full-AUR baseline corpus",
    no_args_is_help=True,
    add_completion=False,
)
app.add_typer(config_app, name="config")
app.add_typer(override_app, name="override")
app.add_typer(db_app, name="db")
app.add_typer(baseline_app, name="baseline")


def _version_callback(value: bool):
    """print version and exit when --version is passed"""
    if value:
        # Imported here so that resolving the version, which costs an
        # importlib.metadata import, only happens when it is asked for.
        from . import __version__

        typer.echo(f"trustsight {__version__}")
        raise typer.Exit()


@app.callback()
def _main(
    version: bool = typer.Option(
        False, "-v", "--version",
        callback=_version_callback,
        help="Show program's version number and exit",
    ),
):
    """trustsight cli entry point"""
    pass


# --- review ---

@app.command()
def review(
    limit: int = typer.Option(0, "--limit", help="Max packages to review (0 = unlimited)"),
    verbose: bool = typer.Option(False, "--verbose", help="Show triggered rules per package"),
    quiet: bool = typer.Option(False, "--quiet", help="Suppress progress output"),
    repo: Optional[list[str]] = typer.Option(
        None, "--repo", help="Scan packages from a specific local repository (can be repeated)"
    ),
    foreign: bool = typer.Option(False, "--foreign", help="Include foreign packages (pacman -Qm)"),
    all_repos: bool = typer.Option(
        False, "--all-repos",
        help="Auto-detect all local repos from pacman.conf (excludes official repos)",
    ),
    all_packages: bool = typer.Option(
        False, "--all", help="Review all installed AUR packages, not just outdated ones",
    ),
    json_output: bool = typer.Option(False, "--json", help="Output JSON"),
):
    """Review AUR packages for suspicious updates."""
    ensure_default_configs()
    config = load_config()
    init_db()
    seed_imported = False
    if config.get("seed", {}).get("auto_import", True):
        seed_stats = maybe_auto_import_seed(quiet=json_output or quiet)
        if seed_stats is not None:
            seed_imported = True

    if not json_output and not quiet and seed_imported:
        print()
        _print_colored("Welcome to TrustSight!", "bold cyan")
        print(f"  Config:    {CONFIG_DIR}")
        print(f"  Database:  {get_db_path()}")
        print()
        print("  Next steps:")
        print("    1. Run 'trustsight review'         Scan your AUR packages")
        print("    2. Run 'trustsight inspect <pkg>'  Deep-dive on a specific package")
        print()

    effective_limit = limit if limit > 0 else config.get("limits", {}).get("default_review_limit", 0)

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
        """print a warning message"""
        if not HAS_RICH:
            print(f"Warning: {msg}")
            return
        con = console()
        con.print(f"[yellow]Warning:[/] {msg}")

    if all_repos_flag:
        from .discovery import get_local_repos_from_pacman_conf
        try:
            get_local_repos_from_pacman_conf()
        except RuntimeError as exc:
            if repos:
                _warn(str(exc) + "; falling back to explicit repos.")
            else:
                if not HAS_RICH:
                    print(f"Error: {exc}")
                else:
                    console().print(f"[red]Error:[/] {exc}")
                sys.exit(1)

    outdated_pkgs = discover_packages(
        repos=repos,
        include_foreign=include_foreign,
        all_repos=all_repos_flag,
        all_packages=all_packages,
        _warn_func=_warn if repos else None,
    )

    total_installed = 0
    if include_foreign:
        from .discovery import get_installed_foreign
        total_installed = len(get_installed_foreign())

    if not outdated_pkgs:
        if all_packages:
            _print_colored("No AUR packages found to review.", "green")
        else:
            _print_colored("No outdated packages found.", "green")
        return

    _run_analysis_loop(outdated_pkgs, effective_limit, verbose, quiet, json_output, total_installed, all_packages)


def _run_analysis_loop(
    outdated_pkgs: list[dict], limit: int, verbose: bool, quiet: bool, json_output: bool,
    total_installed: int = 0, all_packages: bool = False,
) -> None:
    """run the full analysis loop with optional progress display"""
    limited = outdated_pkgs[:limit] if limit else outdated_pkgs

    has_progress = HAS_RICH and not json_output and not quiet

    if has_progress:
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

            def on_progress(_current, total, description):
                """update the progress bar with the current task"""
                if not has_progress:
                    return
                if _current < 0:
                    # Phase transition: set indeterminate without resetting elapsed time
                    progress.update(task, total=None, description=description)
                elif total:
                    progress.update(
                        task, total=total, completed=_current,
                        description=description,
                    )
                else:
                    progress.update(task, description=description)

            results = _analyze_outdated_batch(limited, on_progress, verbose)
            progress.update(task, visible=False)
    elif json_output:
        def on_progress(_current, total, description):
            """emit progress as JSON-lines to stderr"""
            import json as _json
            print(_json.dumps({"event": "progress", "current": _current, "total": total, "phase": description}), file=sys.stderr)
        results = _analyze_outdated_batch(limited, on_progress, verbose)
    else:
        results = _analyze_outdated_batch(limited, None, verbose)

    if json_output:
        typer.echo(json.dumps(results, indent=2))
        return

    if not results:
        if all_packages:
            _print_colored("No AUR packages found to review.", "green")
        else:
            _print_colored("No outdated packages found.", "green")
        return

    flagged = sum(1 for r in results if (r["score"] or 0) > 20)
    failed = sum(1 for r in results if r.get("failed"))
    reviewed = len(results) - failed
    if all_packages and total_installed:
        caption = f"{reviewed} package(s) reviewed out of {total_installed} installed"
    else:
        caption = f"{reviewed} package(s) needing update and reviewed"
        if total_installed:
            caption += f" out of {total_installed} installed"
    caption += f", {flagged} above the 20-point CLEAN threshold"
    if failed:
        caption += f", {failed} could NOT be vetted"

    if has_progress:
        table = Table(
            title="TrustSight Review",
            caption=caption,
            caption_justify="right",
        )
        table.add_column("Package", style="cyan", no_wrap=True)
        table.add_column("Score", justify="right")
        table.add_column("Risk")
        table.add_column("Verdict", overflow="fold")
        if verbose:
            table.add_column("Triggered Rules", overflow="fold")
        for r in results:
            verdict = Text(strip_ansi(r["verdict"]))
            if r.get("first_seen"):
                verdict = Text.assemble(("first analysis: ", "yellow"), verdict)
            score_cell = (
                Text("n/a", style="bold red") if r.get("failed")
                else _score_text(r["score"], r["risk"])
            )
            row = [
                r["package"],
                score_cell,
                Text(r["risk"], style=RISK_COLORS.get(r["risk"], "white")),
                verdict,
            ]
            if verbose:
                analysis_t = r.get("analysis_time", 0)
                llm_t = r.get("llm_time", 0)
                if r.get("failed"):
                    row.append(Text("n/a", style="dim"))
                    row.append(Text("n/a", style="dim"))
                else:
                    row.append(Text(f"{analysis_t:.1f}s", style="dim" if analysis_t < 1 else "white"))
                    row.append(Text(f"{llm_t:.1f}s", style="dim" if llm_t < 1 else "white"))
                rules_text = (
                    ", ".join(f"{rule['rule_id']}" for rule in r.get("triggered_rules", []))
                    if r.get("triggered_rules") else "[dim]none[/]"
                )
                row.append(Text(strip_ansi(rules_text)))
            table.add_row(*row)
        con.print(table)
    else:
        if verbose:
            print(f"{'Package':<20} {'Score':<7} {'Anal':>5} {'LLM':>5} Verdict  Rules")
        else:
            print(f"{'Package':<20} {'Score':<7} Verdict")
        print("-" * (100 if verbose else 80))
        for r in results:
            verdict = r["verdict"]
            if r.get("first_seen"):
                verdict = f"[First analysis] {verdict}"
            score = "n/a" if r.get("failed") else str(r["score"])
            if verbose and not r.get("failed"):
                analysis_t = r.get("analysis_time", 0)
                llm_t = r.get("llm_time", 0)
                timing = f"{analysis_t:>4.1f}s {llm_t:>4.1f}s"
                line = f"{r['package']:<20} {score:<7} {timing} {verdict}"
            elif verbose:
                line = f"{r['package']:<20} {score:<7}  n/a   n/a  {verdict}"
            else:
                line = f"{r['package']:<20} {score:<7} {verdict}"
            if verbose:
                rules_str = (
                    ", ".join(rule["rule_id"] for rule in r.get("triggered_rules", []))
                    if r.get("triggered_rules") else "none"
                )
                line += f"  {rules_str}"
            print(line)
        print(caption)


def _default_workers() -> int:
    """How many packages to fetch or ask about concurrently."""
    try:
        configured = int(load_config().get("limits", {}).get("workers", 0))
    except (TypeError, ValueError):
        configured = 0
    return configured if configured > 0 else 8


def _prefetch(pkgs: list[dict], progress_callback=None) -> dict[str, int]:
    """Clone or update every package's repo concurrently.

    Fetching is the slowest step of an analysis and is pure network wait,
    so running the batch serially left the link idle most of the time.
    Each package has its own directory and no database is touched here, so
    the work is independent.

    Returns ``{name: upstream_mtime}`` for the packages that succeeded.
    That is handed back to :func:`analyze_package`, whose own
    ``clone_or_fetch`` compares it against the clone's last-fetch marker,
    finds the clone current, and skips fetching the same repository twice.
    """
    assert len(pkgs) == len({e["name"] for e in pkgs}), "_prefetch requires unique package names"
    from concurrent.futures import ThreadPoolExecutor, TimeoutError as _FutureTimeout, as_completed

    from .fetcher import clone_or_fetch, last_fetch_time

    def fetch(entry: dict) -> tuple[str, int | None]:
        name = entry["name"]
        socket.setdefaulttimeout(30)
        repo = clone_or_fetch(name, entry.get("last_modified"))
        # Prefer the AUR's own timestamp; when the RPC did not supply one,
        # fall back to when this clone was fetched, which by definition is
        # not older than the clone.  Never the HEAD commit's date: that is
        # chosen upstream and must not decide whether we fetch.
        hint = entry.get("last_modified")
        if hint is None:
            hint = last_fetch_time(repo)
        return name, hint

    hints: dict[str, int] = {}
    total = len(pkgs)
    workers = max(1, min(_default_workers(), total))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(fetch, entry): entry["name"] for entry in pkgs}
        try:
            for done, future in enumerate(as_completed(futures, timeout=120), start=1):
                name = futures[future]
                if progress_callback:
                    progress_callback(done, total, f"Fetching {name}")
                try:
                    fetched, commit_time = future.result()
                except Exception:  # noqa: BLE001 — analysis retries and reports
                    log.warning("fetch of %s failed; will retry during analysis",
                                name, exc_info=True)
                    continue
                if commit_time is not None:
                    hints[fetched] = commit_time
        except _FutureTimeout:
            log.warning("prefetch timed out after 120s; remaining packages will fetch during analysis")
            for f in futures:
                f.cancel()
    return hints


def _verdict_for(fact) -> str:
    from .verdict import fallback_verdict
    return fallback_verdict(fact)


def _verdicts_for(facts: list, progress_callback=None) -> list[str]:
    if not facts:
        return []
    verdicts = [_verdict_for(f) for f in facts]
    if progress_callback:
        progress_callback(len(verdicts), len(verdicts), "Writing verdicts")
    return verdicts


def _analyze_outdated_batch(
    pkgs: list[dict], progress_callback=None, verbose: bool = False
) -> list[dict]:
    """analyze a batch of outdated package entries"""
    from concurrent.futures import ThreadPoolExecutor, as_completed

    hints = _prefetch(pkgs, progress_callback)

    # Phase transition: signal the progress bar to reset
    if progress_callback:
        progress_callback(-1, 0, "Reviewing packages...")

    def _pipeline_one(entry):
        name = entry["name"]
        try:
            fact = analyze_package(
                name,
                installed_version=entry.get("current_version"),
                upstream_mtime=hints.get(name),
            )
        except Exception as exc:  # noqa: BLE001 — one package must not end the run
            log.warning("analysis of %s failed unexpectedly", name, exc_info=True)
            return ("fail", entry, None, None, exc)
        verdict = _verdict_for(fact)
        return ("ok", entry, fact, verdict, None)

    total = len(pkgs)
    analysed_by_idx: dict[int, tuple] = {}
    failures: list[dict] = []

    with ThreadPoolExecutor(max_workers=_default_workers()) as pool:
        futures = {pool.submit(_pipeline_one, entry): i for i, entry in enumerate(pkgs)}
        done_count = 0
        for future in as_completed(futures):
            idx = futures[future]
            result = future.result()
            status = result[0]
            entry = result[1]
            done_count += 1
            if progress_callback:
                phase = f"Reviewing {entry['name']}" if status == "ok" else f"Failed {entry['name']}"
                if verbose and status == "ok":
                    phase += "  [dim]analysed[/]"
                progress_callback(done_count, total, phase)

            if status == "fail":
                _, _, _, _, exc = result
                failures.append({
                    "package": entry["name"],
                    "old_version": entry.get("current_version", ""),
                    "new_version": entry.get("latest_version", ""),
                    "score": None,
                    "verdict": f"Analysis failed ({type(exc).__name__}): "
                               f"this package was NOT vetted.",
                    "risk": "Error",
                    "first_seen": False,
                    "failed": True,
                })
            else:
                _, _, fact, verdict, _ = result
                analysed_by_idx[idx] = (entry, fact, verdict)

    # Rebuild results in original order
    results = []
    for idx in range(total):
        item = analysed_by_idx.get(idx)
        if item is None:
            continue
        entry, fact, verdict = item
        if fact.diff_truncated:
            verdict = (
                "Diff exceeded the size cap and was truncated; only part of "
                f"this change was vetted. {verdict}"
            )
        res = {
            "package": entry["name"],
            "old_version": entry.get("current_version", ""),
            "new_version": entry.get("latest_version", ""),
            "score": fact.final_score,
            "verdict": verdict,
            "risk": risk_level(fact.final_score),
            "first_seen": fact.first_seen,
            "diff_truncated": fact.diff_truncated,
        }
        if verbose:
            fired = [
                {"rule_id": e.rule_id, "severity": e.severity}
                for e in fact.score_breakdown
                if e.weight > 0 or e.severity == "FATAL"
            ]
            res["triggered_rules"] = fired
            res["suppressed_rules"] = fact.suppressed_rules
        results.append(res)
    results.extend(failures)
    return results


# --- inspect ---

@app.command()
def inspect(
    package: str = typer.Argument(..., help="Package name"),
    verbose: bool = typer.Option(False, "--verbose", help="Show triggered rules and score breakdown"),
    json_output: bool = typer.Option(False, "--json", help="Output JSON"),
):
    """Show a detailed analysis of a single package."""
    ensure_default_configs()
    init_db()
    if load_config().get("seed", {}).get("auto_import", True):
        maybe_auto_import_seed(quiet=json_output)

    fact = analyze_package(package)
    if json_output:
        data = _fact_to_dict(fact)
        if verbose:
            data["score_breakdown"] = [
                {"rule_id": e.rule_id, "severity": e.severity, "weight": e.weight}
                for e in fact.score_breakdown
            ]
        typer.echo(json.dumps(data, indent=2))
        return

    if HAS_RICH:
        _inspect_rich(fact, verbose)
    else:
        _inspect_plain(fact, verbose)


def _inspect_rich(fact, verbose=False):
    """rich-formatted inspection output"""
    con = console()
    risk = risk_level(fact.final_score)

    header = Text()
    header.append(fact.package_name, style="bold cyan")
    header.append("  ")
    header.append_text(_score_text(fact.final_score, risk))
    header.append(f"  ({risk})", style=RISK_COLORS.get(risk, "white"))
    con.print()
    con.print(Panel(header, title="TrustSight Inspect",
                    border_style=RISK_COLORS.get(risk, "white")))

    if fact.first_seen:
        con.print(
            "[yellow]First analysis.[/] No prior history for this package, so "
            "novelty signals carry no weight yet."
        )

    meta = Table.grid(padding=(0, 2))
    meta.add_column(style="dim", justify="right")
    meta.add_column()
    meta.add_row("Version", f"{fact.old_version or '?'} -> {fact.new_version or '?'}")
    if fact.diff_summary.files_changed:
        meta.add_row("Files", ", ".join(fact.diff_summary.files_changed))
    if fact.diff_summary.lines_added or fact.diff_summary.lines_removed:
        meta.add_row("Lines", f"[green]+{fact.diff_summary.lines_added}[/] "
                              f"[red]-{fact.diff_summary.lines_removed}[/]")
    if fact.maintainer_changed:
        meta.add_row("Maintainer",
                     f"[yellow]{fact.previous_maintainer or '?'} -> "
                     f"{fact.current_maintainer or '?'}[/]")
    elif fact.current_maintainer:
        meta.add_row("Maintainer", fact.current_maintainer)
    cs = fact.source_changes.checksum_behavior
    if cs and cs != "unchanged":
        meta.add_row("Checksum", f"[yellow]{cs}[/]")
    con.print(meta)

    if fact.source_changes.added_urls:
        con.print(Rule("Source URLs added", style="dim"))
        urls = Table(box=SIMPLE_HEAD, show_edge=False, pad_edge=False)
        urls.add_column("Bucket", style="dim")
        urls.add_column("URL", overflow="fold")
        for url in fact.source_changes.added_urls:
            bucket = fact.source_buckets.get(url, "unknown")
            style = "red" if bucket in ("homograph_attack", "unknown") else "dim"
            urls.add_row(Text(bucket, style=style), Text(strip_ansi(url)))
        con.print(urls)

    if fact.execution_changes.resolved_commands:
        con.print(Rule("Resolved commands", style="dim"))
        for cmd in fact.execution_changes.resolved_commands[:20]:
            con.print(Text("  " + strip_ansi(cmd.strip()), style="white"))
        extra = len(fact.execution_changes.resolved_commands) - 20
        if extra > 0:
            con.print(f"  [dim]... {extra} more[/]")

    if fact.score_breakdown:
        con.print(Rule("Score breakdown by evidence tier", style="dim"))
        grouped = {}
        for entry in fact.score_breakdown:
            grouped.setdefault(_tier_of(entry), []).append(entry)
        for tier in TIER_ORDER:
            entries = grouped.get(tier)
            if not entries:
                continue
            table = Table(
                box=SIMPLE_HEAD, show_edge=False, pad_edge=False,
                title=f"Tier {tier}  {TIER_NAMES[tier]}",
                title_justify="left", title_style="bold",
            )
            table.add_column("Weight", justify="right", width=7)
            table.add_column("Severity", width=9)
            table.add_column("Rule", style="cyan", width=14)
            table.add_column("Evidence", overflow="fold")
            for e in entries:
                table.add_row(
                    _weight_text(e.weight), _severity_text(e.severity),
                    e.rule_id, Text(strip_ansi(e.reason))
                )
            con.print(table)

        total = sum(e.weight for e in fact.score_breakdown)
        con.print(f"  [dim]sum of contributions: {total:+d}, "
                  f"clamped to {fact.final_score}/100[/]")

    fatal = [e for e in fact.score_breakdown if e.severity == "FATAL"]
    for entry in fatal:
        found = describe_fatal_codepoints(entry.reason)
        if found:
            con.print(Rule("Deceptive codepoints", style="red"))
            cp = Table(box=SIMPLE_HEAD, show_edge=False)
            cp.add_column("Offset", justify="right", style="dim")
            cp.add_column("Codepoint", style="red")
            for offset, name in found:
                cp.add_row(str(offset), name)
            con.print(cp)

    if fact.suppressed_rules:
        con.print(Rule("Suppressed by override", style="yellow"))
        sup = Table(box=SIMPLE_HEAD, show_edge=False)
        sup.add_column("Rule", style="cyan")
        sup.add_column("Severity")
        sup.add_column("Reason", overflow="fold")
        for r in fact.suppressed_rules:
            sup.add_row(r["rule_id"], _severity_text(r.get("severity", "")),
                        r.get("override_reason", ""))
        con.print(sup)
        con.print("  [yellow]These findings did not contribute to the score.[/]")

    from .verdict import fallback_verdict as _fb
    verdict = _fb(fact)
    con.print(Rule("Verdict", style="dim"))
    con.print(Panel(Text(verdict),
                    border_style=RISK_COLORS.get(risk, "white")))


def _inspect_plain(fact, verbose=False):
    """plain-text inspection output"""
    if fact.first_seen:
        print("[First analysis] No prior history; novelty carries no weight yet.")
    print(f"TrustSight Inspect: {fact.package_name}")
    print(f"  Version: {fact.old_version or '?'} -> {fact.new_version or '?'}")
    print(f"  Score: {fact.final_score}/100 ({risk_level(fact.final_score)})")
    if fact.maintainer_changed:
        print(f"  Maintainer changed: {fact.previous_maintainer} -> {fact.current_maintainer}")
    cs = fact.source_changes.checksum_behavior
    if cs and cs != "unchanged":
        print(f"  Checksum: {cs}")
    if fact.source_changes.added_urls:
        print("  Source URLs added:")
        for url in fact.source_changes.added_urls:
            print(f"    {strip_ansi(url)} ({fact.source_buckets.get(url, 'unknown')})")
    if fact.score_breakdown:
        print("  Score breakdown:")
        for e in fact.score_breakdown:
            print(f"    [{_tier_of(e)}] {e.weight:+d} {e.severity:<8} {e.rule_id:<14} {e.reason}")
    if fact.suppressed_rules:
        print("  Suppressed by override (did not affect the score):")
        for r in fact.suppressed_rules:
            print(f"    {r['rule_id']} {r.get('override_reason', '')}")
    from .verdict import fallback_verdict as _fb
    verdict = _fb(fact)
    print(f"  Verdict: {verdict}")


# --- history ---

@app.command()
def history(
    package: str = typer.Argument(..., help="Package name"),
    limit: int = typer.Option(20, "--limit", help="Max history entries"),
    score_breakdown: bool = typer.Option(
        False, "--score-breakdown", help="Show score breakdown"
    ),
    json_output: bool = typer.Option(False, "--json", help="Output JSON"),
):
    """Show analysis history for a package."""
    ensure_default_configs()
    init_db()

    pkg_id = get_package_id(package)
    if pkg_id is None:
        print(f"Package '{package}' has not been analysed yet. "
              f"Run 'trustsight inspect {package}' first.")
        return

    history_records = get_history(pkg_id, limit=limit)

    if not history_records:
        print(f"No analysis history for '{package}'.")
        return

    if json_output:
        data = []
        for h in history_records:
            item = {
                "timestamp": h.get("timestamp", ""),
                "old_version": h.get("old_version", ""),
                "new_version": h.get("new_version", ""),
                "score": h.get("final_score", 0),
                "risk": risk_level(h.get("final_score", 0)),
            }
            if score_breakdown:
                rules = get_triggered_rules(h["id"])
                if rules:
                    item["triggered_rules"] = rules
            data.append(item)
        typer.echo(json.dumps(data, indent=2))
        return

    if HAS_RICH:
        con = console()
        table = Table(title=f"History: {package}")
        table.add_column("Date", style="dim")
        table.add_column("Old", justify="right")
        table.add_column("-> New", justify="right")
        table.add_column("Score", justify="right")
        table.add_column("Risk")

        for h in history_records:
            ts = h.get("timestamp", "")[:10] if h.get("timestamp") else ""
            score = h.get("final_score", 0)
            risk = risk_level(score)
            score_text = Text(f"{score}/100", style=RISK_COLORS.get(risk, "white"))
            table.add_row(
                ts,
                h.get("old_version", "") or "",
                h.get("new_version", "") or "",
                score_text,
                risk,
            )

        con.print(table)

        if score_breakdown and history_records:
            rules = get_triggered_rules(history_records[0]["id"])
            if rules:
                bd = Table(title="Latest run: rules that fired", box=SIMPLE_HEAD)
                bd.add_column("Rule", style="cyan")
                bd.add_column("Severity")
                for r in rules:
                    bd.add_row(r["rule_id"], _severity_text(r["severity"]))
                con.print(bd)
            else:
                con.print("[dim]No rules fired on the latest run.[/]")
    else:
        for h in history_records:
            print(
                f"{h.get('timestamp','')[:10]:<12} "
                f"{str(h.get('old_version','')):<12} -> "
                f"{str(h.get('new_version','')):<12} "
                f"Score: {h.get('final_score',0)}"
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
            "novelty_weights", "verification_evidence", "pinning_weights",
        ):
            data["scoring_weights"][group] = (cfg.get(group) or {}).copy()
        typer.echo(json.dumps(data, indent=2))
        return

    if HAS_RICH:
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
            "novelty_weights", "verification_evidence", "pinning_weights",
        ):
            for key, value in (cfg.get(group) or {}).items():
                weights.add_row(group, key, _weight_text(int(value)))
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
    set_config(key, value)
    msg = f"Set {key} in {CONFIG_DIR / 'config.toml'}"
    if json_output:
        typer.echo(json.dumps({"status": "ok", "key": key}))
    else:
        _print_colored(msg, "green")





@config_app.command("sync-rules")
def config_sync_rules(
    update: bool = typer.Option(
        False, "--update",
        help="Also replace rules whose pattern is a superseded shipped one "
             "(rules you have edited are never touched)",
    ),
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
        # Not auto-corrected: a rule whose pattern the user has broadened
        # would lose that work if the shipped block replaced it.
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
        console().print(Panel(body, title=str(target), border_style="cyan"))
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
    package: Optional[str] = typer.Option(None, "--package", help="Limit to one package"),
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
        raise typer.Exit(code=1)
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


@override_app.command("rm")
def override_rm(
    rule_id: str = typer.Argument(..., help="Rule to stop suppressing"),
    package: Optional[str] = typer.Option(None, "--package", help="Scope the removal to one package"),
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
        raise typer.Exit(code=1)


# --- seed-db ---

@app.command()
def seed_db(
    do_import: bool = typer.Option(
        False, "--import", help="Import the seed (default action)"
    ),
    file: Optional[str] = typer.Option(
        None, "--file", help="Seed .db or .db.gz to import (default: bundled)"
    ),
    force: bool = typer.Option(False, "--force", help="Re-import even if already seeded"),
    json_output: bool = typer.Option(False, "--json", help="Output JSON"),
):
    """Import or inspect the novelty seed database."""
    ensure_default_configs()
    init_db()

    if file:
        seed = Path(file)
    else:
        bundled = Path(__file__).parent / "data" / "seed.db.gz"
        if not bundled.exists():
            msg = (
                "No bundled seed found. Build one with:\n"
                "  python scripts/generate_seed.py --out src/trustsight/data/seed.db\n"
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
    except FileNotFoundError:
        msg = f"Seed file not found: {seed}"
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


# --- lint-rules ---

@app.command("lint-rules")
def lint_rules_cmd(
    file: Optional[str] = typer.Option(
        None, "--file", help="Lint a specific rules TOML file instead of the user config"
    ),
    json_output: bool = typer.Option(False, "--json", help="Output JSON"),
):
    """Lint rules for common mistakes."""
    if file:
        from ._toml import tomllib

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
        con = console()
        if not findings:
            con.print(f"[green]✓[/] {len(rules)} rules, no issues.")
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
        raise typer.Exit(code=1)


# --- db subcommands ---


@db_app.command("check")
def db_check(
    json_output: bool = typer.Option(False, "--json", help="Output JSON"),
):
    """Run integrity check on the database."""
    ensure_default_configs()
    init_db()
    from .db import get_connection

    errors = []
    with get_connection() as conn:
        rows = conn.execute("PRAGMA integrity_check").fetchall()
        for r in rows:
            if r[0] != "ok":
                errors.append(r[0])

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
        raise typer.Exit(code=1)


@db_app.command("vacuum")
def db_vacuum(
    force: bool = typer.Option(False, "--force", help="Skip confirmation prompt"),
    json_output: bool = typer.Option(False, "--json", help="Output JSON"),
):
    """Reclaim disk space by rebuilding the database file."""
    ensure_default_configs()
    init_db()
    from .db import get_connection

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
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output path (default: auto-named)"),
    json_output: bool = typer.Option(False, "--json", help="Output JSON"),
):
    """Create a safe online backup of the database."""
    ensure_default_configs()
    init_db()
    from datetime import datetime
    from .db import get_connection

    db_path = get_db_path()
    if not output:
        ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        output = str(db_path) + f".{ts}.bak"

    with get_connection() as conn:
        backup_conn = sqlite3.connect(output)
        try:
            conn.backup(backup_conn, pages=0)
        finally:
            backup_conn.close()

    size = Path(output).stat().st_size

    if json_output:
        typer.echo(json.dumps({
            "status": "ok",
            "path": output,
            "bytes": size,
        }, indent=2))
        return

    _print_colored(f"Database backed up to {output} ({_fmt_bytes(size)})", "green")


def _fmt_bytes(n: int) -> str:
    """Format a byte count as a human-readable string."""
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f}{unit}"
        n /= 1024
    return f"{n:.1f}TB"


# --- list ---


@app.command("list")
def list_cmd(
    limit: int = typer.Option(0, "--limit", help="Max packages to show (0 = unlimited)"),
    json_output: bool = typer.Option(False, "--json", help="Output JSON"),
):
    """List all packages tracked in the database with their latest score."""
    ensure_default_configs()
    init_db()

    all_pkgs = get_all_packages()
    if limit:
        all_pkgs = all_pkgs[:limit]

    if not all_pkgs:
        if json_output:
            typer.echo(json.dumps([]))
        else:
            _print_colored("No packages tracked yet. Run 'trustsight review' first.", "yellow")
        return

    rows = []
    for pkg in all_pkgs:
        last = get_last_analysis(pkg["id"])
        rows.append({
            "name": pkg["name"],
            "version": pkg["current_version"] or "?",
            "last_checked": pkg["last_checked"] or "",
            "score": last["final_score"] if last else None,
            "risk": risk_level(last["final_score"]) if last else "—",
            "maintainer": pkg["current_maintainer"] or "",
        })

    if json_output:
        typer.echo(json.dumps(rows, indent=2))
        return

    if HAS_RICH:
        con = console()
        table = Table(title=f"Tracked packages ({len(rows)} total)")
        table.add_column("Package", style="cyan", no_wrap=True)
        table.add_column("Version")
        table.add_column("Maintainer", overflow="fold")
        table.add_column("Last Checked")
        table.add_column("Score", justify="right")
        table.add_column("Risk")
        for r in rows:
            score = r["score"]
            score_cell = Text("n/a", style="dim") if score is None else _score_text(score, r["risk"])
            table.add_row(
                r["name"],
                r["version"],
                r["maintainer"] or "[dim]—[/]",
                r["last_checked"][:10] if r["last_checked"] else "[dim]—[/]",
                score_cell,
                Text(r["risk"], style=RISK_COLORS.get(r["risk"], "white")),
            )
        con.print(table)
    else:
        print(f"{'Package':<20} {'Version':<15} {'Score':<8} {'Risk':<12} Last Checked")
        print("-" * 75)
        for r in rows:
            score = "n/a" if r["score"] is None else str(r["score"])
            checked = r["last_checked"][:10] if r["last_checked"] else "—"
            print(f"{r['name']:<20} {r['version']:<15} {score:<8} {r['risk']:<12} {checked}")


# --- status ---


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


# --- helpers ---


def _print_colored(msg: str, color: str = "", stderr: bool = False):
    """print a message with optional rich color"""
    if HAS_RICH:
        style = f"[{color}]" if color else ""
        console().print(f"{style}{msg}[/]")
    else:
        kwargs = {"file": sys.stderr} if stderr else {}
        print(msg, **kwargs)


# --- entry point ---

# --- baseline subcommands ---


@baseline_app.command("build")
def baseline_build(
    resume: bool = typer.Option(False, "--resume", help="Continue an interrupted bootstrap"),
    export: Optional[str] = typer.Option(None, "--export", help="Path to write the baseline artifact"),
    sign: Optional[str] = typer.Option(None, "--sign", help="Path to ed25519 private key for signing"),
    json_output: bool = typer.Option(False, "--json", help="Output JSON"),
):
    """Bootstrap or update the full-AUR baseline corpus.

    Fetches the AUR metadata snapshot, downloads PKGBUILDs for every
    package, analyses them, and optionally emits a signed baseline artifact.
    Run once to build the corpus; everyone else imports the artifact.
    """
    from .full_aur.pipeline import run_baseline_build
    ensure_default_configs()
    init_db()
    run_baseline_build(
        resume=resume,
        export_path=export,
        sign_key=sign,
        json_output=json_output,
    )


@baseline_app.command("import")
def baseline_import(
    path: str = typer.Argument(..., help="Path to the baseline artifact (.tar.zst)"),
    allow_unsigned: bool = typer.Option(False, "--allow-unsigned", help="Allow unsigned artifacts (local builds only)"),
    json_output: bool = typer.Option(False, "--json", help="Output JSON"),
):
    """Import a signed baseline corpus artifact.

    Verifies the signature, then merges profiles, priors, and the metadata
    snapshot into the local database. After import the database is warm:
    no cold-start floor, real stable_for_n values, populated priors.
    """
    from .full_aur.export import import_baseline
    ensure_default_configs()
    init_db()
    import_baseline(path, json_output=json_output, allow_unsigned=allow_unsigned)


# --- watch ---


@app.command("watch")
def watch(
    interval: str = typer.Option("6h", "--interval", help="Poll interval (e.g. 6h, 30m, 1d)"),
    threshold: int = typer.Option(30, "--threshold", "--alert-threshold", help="Minimum score to trigger an alert"),
    alert_hook: Optional[str] = typer.Option(None, "--alert-hook", help="Command to run on alert (receives JSON on stdin)"),
    json_output: bool = typer.Option(False, "--json", help="Output JSON"),
):
    """Daemon mode: poll the AUR metadata and analyse new updates.

    Repeatedly fetches the AUR metadata snapshot, diffs it against the
    stored copy, downloads PKGBUILDs for changed packages, analyses them,
    and optionally fires alert hooks for findings above threshold.
    """
    from .full_aur.pipeline import run_watch
    ensure_default_configs()
    init_db()
    run_watch(
        interval=interval,
        threshold=threshold,
        alert_hook=alert_hook,
        json_output=json_output,
    )

if __name__ == "__main__":
    try:
        app()
    except KeyboardInterrupt:
        print("\nInterrupted.")
        sys.exit(130)
