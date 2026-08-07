import json
import logging
import sys
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as _FutureTimeout, as_completed

import typer

from ..analysis import analyze_package
from ..config import CONFIG_DIR, ensure_default_configs, load_config
from ..coverage import GAP_REASONS, describe as describe_coverage
from ..safe_text import clean, safe_markup
from ..db import (
    get_db_path,
    init_db,
    maybe_auto_import_seed,
)
from ..fetcher import clone_or_fetch, last_fetch_time
from ..scoring import risk_level, verdict_label, verdict_level
from .display import (
    HAS_RICH,
    RISK_COLORS,
    _print_colored,
    console,
    display_version,
    no_aur_change_note,
    _score_text,
)

log = logging.getLogger(__name__)


def _discover_packages(repos, include_foreign, all_repos_flag, all_packages, _warn):
    try:
        from ..full_aur.metadata import fetch_metadata, load_metadata, save_metadata
        from ..discovery import _vercmp

        meta_path = CONFIG_DIR / "full-aur-meta.json"
        meta = load_metadata(path=meta_path)
        if meta is None:
            if HAS_RICH:
                con = console()
                from rich.progress import BarColumn, DownloadColumn, Progress, TextColumn, TimeElapsedColumn, TransferSpeedColumn
                columns = [
                    TextColumn("[progress.description]{task.description}"),
                    BarColumn(),
                    DownloadColumn(),
                    TransferSpeedColumn(),
                    TimeElapsedColumn(),
                ]
                with Progress(*columns, console=con, transient=False) as progress:
                    task = progress.add_task("Downloading AUR metadata...", total=None)
                    progress.refresh()

                    def _on_progress(pos, total):
                        progress.update(task, total=total, completed=pos, refresh=True)
                    meta = fetch_metadata(on_progress=_on_progress)
            else:
                meta = fetch_metadata()
            save_metadata(meta, path=meta_path)
            _print_colored("Downloaded AUR metadata snapshot. Run again to review changes.", "green")
            return None, 0

        installed = _get_installed_packages(repos, include_foreign, all_repos_flag, all_packages, _warn_func=_warn)
        total_installed = len(installed)

        outdated = []
        show_unmatched = load_config().get("discovery", {}).get("show_unmatched", True)
        for pkg in installed:
            name = pkg["name"]
            aur = meta.get(name)
            latest_ver = aur.get("Version", "") if aur else ""
            if all_packages and aur is None and not show_unmatched:
                continue
            if all_packages:
                pkg["latest_version"] = latest_ver or pkg["current_version"]
                if aur and isinstance(aur.get("LastModified"), int):
                    pkg["last_modified"] = aur["LastModified"]
                outdated.append(pkg)
            elif latest_ver and _vercmp(pkg["current_version"], latest_ver) < 0:
                pkg["latest_version"] = latest_ver
                if isinstance(aur.get("LastModified"), int):
                    pkg["last_modified"] = aur["LastModified"]
                outdated.append(pkg)

        return outdated, total_installed
    except Exception:
        log.warning("metadata-dump discovery failed, falling back to AUR RPC", exc_info=True)
        from ..discovery import discover_packages as dp
        pkgs = dp(
            repos=repos,
            include_foreign=include_foreign,
            all_repos=all_repos_flag,
            all_packages=all_packages,
            _warn_func=_warn if repos else None,
        )
        total = 0
        if include_foreign:
            from ..discovery import get_installed_foreign
            total = len(get_installed_foreign())
        return pkgs, total


def _get_installed_packages(repos, include_foreign, all_repos, all_packages, _warn_func=None):
    from ..discovery import get_installed_foreign, get_installed_from_repo
    from ..discovery import get_local_repos_from_pacman_conf, _repo_exists

    sources: set[tuple[str, str]] = set()

    if all_repos:
        for repo in get_local_repos_from_pacman_conf():
            sources.update(get_installed_from_repo(repo))

    if repos:
        for repo in repos:
            pkgs = get_installed_from_repo(repo)
            if not pkgs and _warn_func:
                if _repo_exists(repo):
                    _warn_func(f"repo '{repo}' exists but no packages from it are installed.")
                else:
                    _warn_func(f"repo '{repo}' does not exist.")
            sources.update(pkgs)

    if include_foreign or (not repos and not all_repos):
        sources.update(get_installed_foreign())

    return [{"name": name, "current_version": ver} for name, ver in sources]


def _default_workers() -> int:
    try:
        configured = int(load_config().get("limits", {}).get("workers", 0))
    except (TypeError, ValueError):
        configured = 0
    return configured if configured > 0 else 8


def _prefetch_deadline() -> int:
    try:
        configured = int(load_config().get("limits", {}).get("prefetch_timeout", 0))
    except (TypeError, ValueError):
        configured = 0
    return configured if configured > 0 else 120


def _prefetch(pkgs: list[dict], progress_callback=None) -> dict[str, int]:
    from ..fetcher import clone_or_fetch, last_fetch_time

    def fetch(entry: dict) -> tuple[str, int | None]:
        name = entry["name"]
        repo = clone_or_fetch(name, entry.get("last_modified"))
        hint = entry.get("last_modified")
        if hint is None:
            hint = last_fetch_time(repo)
        return name, hint

    hints: dict[str, int] = {}
    total = len(pkgs)
    deadline = _prefetch_deadline()
    workers = max(1, min(_default_workers(), total))
    # Not a `with` block: the context manager exit calls shutdown(wait=True),
    # which blocks on the fetches still running when the deadline fires - the
    # progress bar then sits frozen on the last package it painted for as long
    # as those fetches take.  Abandon them instead; analysis re-fetches what
    # the deadline cut off.
    pool = ThreadPoolExecutor(max_workers=workers)
    try:
        futures = {pool.submit(fetch, entry): entry["name"] for entry in pkgs}
        try:
            for done, future in enumerate(as_completed(futures, timeout=deadline), start=1):
                name = futures[future]
                if progress_callback:
                    progress_callback(done, total, f"Fetching {name}")
                try:
                    fetched, commit_time = future.result()
                except Exception:
                    log.warning("fetch of %s failed; will retry during analysis", name, exc_info=True)
                    continue
                if commit_time is not None:
                    hints[fetched] = commit_time
        except _FutureTimeout:
            log.warning(
                "prefetch timed out after %ss; remaining packages will fetch during analysis",
                deadline,
            )
            if progress_callback:
                progress_callback(-1, 0, "Prefetch timed out; continuing...")
    finally:
        pool.shutdown(wait=False, cancel_futures=True)
    return hints


def _version_cell(result: dict) -> str:
    """Version text for one review row, honest about comparability."""
    from ..analysis.version import COMPARISON_INCONCLUSIVE

    old = display_version(result.get("old_version"))
    new = display_version(result.get("new_version"))
    if result.get("version_comparison") == COMPARISON_INCONCLUSIVE:
        return f"{old} installed / AUR pkgver {new} (not comparable)"
    return f"{old}  \u2192  {new}"


def _verdict_for(fact) -> str:
    from ..verdict import fallback_verdict
    return fallback_verdict(fact)


def _verdicts_for(facts: list, progress_callback=None) -> list[str]:
    if not facts:
        return []
    verdicts = [_verdict_for(f) for f in facts]
    if progress_callback:
        progress_callback(len(verdicts), len(verdicts), "Writing verdicts")
    return verdicts


def _is_trivial_update(fact, findings: list[dict]) -> bool:
    if not fact.diff_summary.files_changed:
        return True
    for f in findings:
        if f.get("rule_id") not in ("C002",):
            return False
    return True


def _analyze_outdated_batch(pkgs: list[dict], progress_callback=None, verbose: bool = False) -> list[dict]:
    from concurrent.futures import ThreadPoolExecutor, as_completed

    hints = _prefetch(pkgs, progress_callback)

    if progress_callback:
        progress_callback(-1, 0, "Reviewing packages...")

    def _pipeline_one(entry):
        name = entry["name"]
        try:
            fact = analyze_package(name, installed_version=entry.get("current_version"), upstream_mtime=hints.get(name))
        except Exception as exc:
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
                    "verdict": f"Analysis failed ({type(exc).__name__}): this package was NOT vetted.",
                    "risk": "Error",
                    "first_seen": False,
                    "failed": True,
                })
            else:
                _, _, fact, verdict, _ = result
                analysed_by_idx[idx] = (entry, fact, verdict)

    from ..verdict import _render as _render_verdict

    results = []
    for idx in range(total):
        item = analysed_by_idx.get(idx)
        if item is None:
            continue
        entry, fact, verdict = item

        findings = []
        for e in fact.score_breakdown:
            if e.weight > 0 or e.severity in ("FATAL", "CRITICAL"):
                desc = _render_verdict(e, fact)
                findings.append({
                    "rule_id": e.rule_id,
                    "file": e.file,
                    "line": e.line,
                    "description": desc,
                    "template": e.template,
                    "evidence": e.evidence,
                    "severity": e.severity,
                    "weight": e.weight,
                })

        file_changes = fact.diff_summary.file_changes
        is_trivial = _is_trivial_update(fact, findings)

        # Coverage first: what the run could not see qualifies everything
        # the verdict goes on to say about what it did see.
        coverage_note = describe_coverage(fact.coverage_gaps)
        if coverage_note:
            verdict = f"{coverage_note} {verdict}"
        res = {
            "package": entry["name"],
            "old_version": entry.get("current_version", ""),
            "new_version": entry.get("latest_version", ""),
            "score": fact.final_score,
            "verdict": verdict,
            "risk": verdict_level(fact),
            # The label a person sees: same band, qualified when the run
            # did not read the whole change (coverage.qualified_band).
            "risk_label": verdict_label(fact),
            "first_seen": fact.first_seen,
            "diff_truncated": fact.diff_truncated,
            "changes": fact.changes,
            "coverage_gaps": fact.coverage_gaps,
            # A VCS package's AUR pkgver is a placeholder its build replaces,
            # so the two versions are not comparable and must not render as
            # an update arrow (plan §13).
            "version_comparison": fact.version_comparison,
            "aur_note": no_aur_change_note(fact),
            "findings": findings,
            "file_changes": file_changes,
            "is_trivial": is_trivial,
        }
        if verbose:
            fired = [
                {"rule_id": e.rule_id, "severity": e.severity}
                for e in fact.score_breakdown
                if e.weight > 0 or e.severity == "FATAL"
            ]
            res["triggered_rules"] = fired
            res["suppressed_rules"] = fact.suppressed_rules
            res["_verbose_fact"] = fact
        results.append(res)
    results.extend(failures)
    return results


def _run_analysis_loop(outdated_pkgs, limit, verbose, quiet, json_output, total_installed=0, all_packages=False, show_score=False, show_risk=False):
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

            results = _analyze_outdated_batch(limited, on_progress, verbose)
            progress.update(task, visible=False)
    elif json_output:
        def on_progress(_current, total, description):
            import json as _json
            print(_json.dumps({"event": "progress", "current": _current, "total": total, "phase": description}), file=sys.stderr)
        results = _analyze_outdated_batch(limited, on_progress, verbose)
    else:
        results = _analyze_outdated_batch(limited, None, verbose)

    if json_output:
        from ..config import config_fingerprint

        fingerprint = config_fingerprint()
        json_results = []
        for r in results:
            jr = {
                "package": r["package"],
                "old_version": r["old_version"],
                "new_version": r["new_version"],
                "findings": [
                    {"rule_id": f["rule_id"], "file": f["file"], "line": f["line"], "description": f["description"]}
                    for f in r.get("findings", [])
                ],
                "file_changes": r.get("file_changes", []),
                "verdict": r["verdict"],
                "first_seen": r.get("first_seen", False),
                "is_trivial": r.get("is_trivial", False),
                # Always present, with or without --score: a consumer
                # gating on the score must be able to see that the score
                # describes an incomplete analysis.
                # B7: what moved, whether or not a rule matched.  A
                # consumer reading only `findings` is unaffected.
                "changes": r.get("changes", []),
                "coverage_gaps": r.get("coverage_gaps", []),
                "config_fingerprint": fingerprint,
            }
            if show_score or show_risk:
                jr["score"] = r.get("score")
                jr["risk"] = r.get("risk")
                jr["risk_label"] = r.get("risk_label")
            if verbose:
                jr["triggered_rules"] = r.get("triggered_rules", [])
                jr["suppressed_rules"] = r.get("suppressed_rules", [])
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
                seed_stats = maybe_auto_import_seed(quiet=json_output or quiet)
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
                        if not HAS_RICH:
                            print(f"Error: {exc}")
                        else:
                            console().print(f"[red]Error:[/] {exc}")
                        raise typer.Exit(code=2)

            changed_installed, total_installed = _discover_packages(
                repos=repos,
                include_foreign=include_foreign,
                all_repos_flag=all_repos_flag,
                all_packages=all_packages,
                _warn=_warn,
            )

            if changed_installed is None:
                return
            if not changed_installed:
                if all_packages:
                    _print_colored("No AUR packages found to review.", "green")
                else:
                    _print_colored("No outdated packages found.", "green")
                return

            if init_progress is not None:
                init_progress.stop()
                init_progress = None

            _run_analysis_loop(changed_installed, effective_limit, verbose, quiet, json_output, total_installed, all_packages, score, show_risk=risk)
        finally:
            if init_progress is not None:
                init_progress.stop()
