import json
import logging
import sys
from contextlib import contextmanager

import typer

from ..config import CONFIG_DIR, ensure_default_configs, load_config
from ..coverage import GAP_REASONS
from ..safe_text import clean, safe_markup
from ..db import (
    get_db_path,
    init_db,
    maybe_auto_import_seed,
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


def _version_cell(result: dict) -> str:
    """Version text for one review row, honest about comparability."""
    from ..analysis.version import COMPARISON_INCONCLUSIVE

    old = display_version(result.get("old_version"))
    new = display_version(result.get("new_version"))
    if result.get("version_comparison") == COMPARISON_INCONCLUSIVE:
        from ..schema import PackageFact
        from ..verdict import inconclusive_reason

        # No "AUR pkgver": the AUR side is its declared version when one can
        # be read, and no bare pkgver phrase survives anyway.  The review
        # row and the inspect version line must name the same cause, or the
        # same comparison disagrees with itself between the two surfaces.
        reason = inconclusive_reason(PackageFact(
            old_version=result.get("old_version"),
            new_version=result.get("new_version"),
            coverage_gaps=result.get("coverage_gaps") or [],
        ))
        return f"{old} installed / {new} declared in the AUR (not comparable: {reason})"
    return f"{old}  \u2192  {new}"




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


def _run_analysis_loop(outdated_pkgs, limit, verbose, quiet, json_output, total_installed=0, all_packages=False, show_score=False, show_risk=False, depth=None, required_by=None, deps_only=False, sort_by=None):
    limited = outdated_pkgs[:limit] if limit else outdated_pkgs
    # How many needed reviewing, as opposed to how many were reviewed. The
    # caption used to report the second number under the first one's name:
    # `--limit 5` against 40 outdated packages printed "5 package(s) needing
    # update and reviewed", which is not what the tool found and not what it
    # did. The 35 it skipped went unmentioned.
    outdated_total = len(outdated_pkgs)

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

            results = _analyze_outdated_batch(limited, on_progress, verbose, depth=depth)
            progress.update(task, visible=False)
    elif json_output:
        def on_progress(_current, total, description):
            import json as _json
            print(_json.dumps({"event": "progress", "current": _current, "total": total, "phase": description}), file=sys.stderr)
        results = _analyze_outdated_batch(limited, on_progress, verbose, depth=depth)
    else:
        results = _analyze_outdated_batch(limited, None, verbose, depth=depth)

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

    if HAS_RICH and not json_output:
        _render_results_rich(results, total_installed, all_packages, show_score, show_risk, verbose, outdated_total, deps_only)
    else:
        _render_results_plain(results, total_installed, all_packages, show_score, show_risk, verbose, outdated_total, deps_only)


def _summary_caption(reviewed, failed, flagged, total_installed, all_packages,
                     outdated_total, show_score, deps_only=False) -> str:
    """The one-line summary, counting what was found separately from what
    was read.

    These used to be the same number. `--limit 5` against 40 outdated
    packages printed "5 package(s) needing update and reviewed": the count
    of packages *needing an update* was silently replaced by the count of
    packages the limit allowed through, and the 35 skipped were never
    mentioned. A review that stops early is a coverage gap, and this tool's
    rule for a coverage gap is that it is stated rather than absorbed.
    """
    if deps_only:
        # The subject is not "packages needing an update" here, and saying
        # so would misreport both what was reviewed and what it was
        # reviewed out of.
        caption = f"{reviewed} AUR dependenc{'y' if reviewed == 1 else 'ies'} reviewed"
        if total_installed:
            caption += f" for {total_installed} installed package(s)"
    elif all_packages and total_installed:
        caption = f"{reviewed} package(s) reviewed out of {total_installed} installed"
    else:
        caption = f"{reviewed} package(s) needing update and reviewed"
        if total_installed:
            caption += f" out of {total_installed} installed"
    skipped = max(0, outdated_total - (reviewed + failed))
    if skipped:
        caption += (
            f"; {skipped} more needed review and were NOT read "
            f"(--limit); pass --limit 0 for all of them"
        )
    if show_score and flagged:
        from ..review_policy import review_policy

        policy = review_policy()
        caption += f", {flagged} above the {policy.threshold}-point {policy.name} review threshold"
    if failed:
        caption += f", {failed} could NOT be vetted"
    return caption


def _finding_line(finding: dict) -> str:
    """One finding as `file line N  description`, for either renderer.

    The rule id is not added here: the description already carries it, and
    the two renderers previously disagreed about that - the Rich one
    printed it twice and the plain one once. A finding with no file (an
    aggregate such as `SOURCE_BUCKET`) used to open with a stray space
    where the filename would have been.
    """
    file_part = clean(finding.get("file", "") or "")
    line = finding.get("line")
    desc = clean(finding.get("description", ""))
    where = f"{file_part} line {line}" if file_part and line is not None else file_part
    return f"{where}  {desc}" if where else desc


#: Shown once under an ordinary review, and only when there is something for
#: it to point at. A dependency was analysed and summarised in a card, but
#: the card is a summary: `--deps` reviews each one as a package in its own
#: right and says which packages require it. Suppressed under `--deps`
#: itself (already there), under `--json` (a document, not a conversation),
#: and when nothing reported a dependency (advice about an empty set).
_DEPS_HINT = (
    "Tip: those dependencies are summarised, not reviewed. "
    "`trustsight review --deps` reviews each as a package in its own right "
    "and names what requires it; add `--depth n` for deeper levels."
)


def _deps_hint(results, deps_only: bool) -> str:
    """The `--deps` recommendation, or "" when it would be noise."""
    if deps_only:
        return ""
    if not any(r.get("dependencies") for r in results):
        return ""
    return _DEPS_HINT


def _render_results_plain(results, total_installed, all_packages, show_score, show_risk, verbose, outdated_total=0, deps_only=False):
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

        # `--verbose` means the full report, on both renderers. The Rich
        # path has always handed off to the inspect panel here; this one
        # did not, so asking for more detail without Rich installed
        # silently returned the same summary - the drop this function's
        # docstring exists to prevent.
        if verbose and r.get("_verbose_fact"):
            from .inspect import _inspect_plain

            _inspect_plain(r["_verbose_fact"], verbose=verbose,
                           show_score=show_score, show_risk=show_risk)
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
                typer.echo(f"  {_finding_line(f)}")
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
            typer.echo(f"  Risk: {label}")

        for entry in r.get("changes", []):
            typer.echo(f"  ~ {clean(entry)}")
        required_by_names = r.get("required_by") or []
        if required_by_names:
            typer.echo(f"  Required by: {clean(', '.join(required_by_names))}")
        for line in dependency_lines_plain(r.get("dependencies", []),
                                           show_score=show_score,
                                           show_risk=show_risk):
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

    from ..review_policy import review_policy
    policy = review_policy()
    flagged = sum(1 for r in results if policy.flagged(r["score"] or 0))
    failed = sum(1 for r in results if r.get("failed"))
    reviewed = len(results) - failed
    caption = _summary_caption(
        reviewed, failed, flagged, total_installed, all_packages,
        outdated_total, show_score, deps_only,
    )
    typer.echo(caption)
    hint = _deps_hint(results, deps_only)
    if hint:
        typer.echo(hint)


def _render_results_rich(results, total_installed, all_packages, show_score, show_risk, verbose, outdated_total=0, deps_only=False):
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
                # The description already ends with `[R001]` - `verdict._render`
                # puts it there, and the JSON body and the plain renderer both
                # carry it that way. Adding a second copy in front printed
                # every finding as
                #   `PKGBUILD line 4 [R001]  Remote Script Execution: ... [R001]`
                # and made this renderer disagree with the plain one about the
                # same finding.
                table.add_row("", Text(clean(_finding_line(f))))

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

        # `--deps`: the subject of this panel is a dependency, so the
        # relationship worth naming is the reverse one. A dependency nobody
        # in the reviewed set requires is not what was asked for; one that
        # three packages require is the reason to read it first.
        required_by_names = r.get("required_by") or []
        for position, name in enumerate(required_by_names):
            table.add_row("Required by" if position == 0 else "", Text(clean(name)))

        # Dependency mini-cards: each is its own analysis, so it gets its
        # own card nested in this one rather than a line in this package's
        # finding list.
        deps = r.get("dependencies", [])
        if deps:
            table.add_row("", "")
            table.add_row("Dependencies", "")
            for card in dependency_cards_rich(deps, show_score=show_score,
                                       show_risk=show_risk):
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
            table.add_row("Risk", clean(label))

        panel = Panel(table, title=Text(clean(r["package"])), border_style=border)
        con.print(panel)

    from ..review_policy import review_policy
    policy = review_policy()
    flagged = sum(1 for r in results if policy.flagged(r["score"] or 0))
    failed = sum(1 for r in results if r.get("failed"))
    reviewed = len(results) - failed
    caption = _summary_caption(
        reviewed, failed, flagged, total_installed, all_packages,
        outdated_total, show_score, deps_only,
    )
    con.print(caption)
    hint = _deps_hint(results, deps_only)
    if hint:
        con.print(f"[dim]{hint}[/]")


def register_commands(app: typer.Typer):
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
                        if added or updated:
                            parts = []
                            if added:
                                parts.append(f"added {len(added)} rule(s)")
                            if updated:
                                parts.append(f"updated {len(updated)} rule(s)")
                            _print_colored(
                                f"Rules synced: {', '.join(parts)}.",
                                "green",
                            )
                        else:
                            _print_colored("Rules are already up to date.", "green")

            _run_analysis_loop(changed_installed, effective_limit, verbose, quiet, json_output, total_installed, all_packages, score, show_risk=risk, depth=depth, required_by=required_by, deps_only=deps_only, sort_by=sort_by)
        finally:
            if init_progress is not None:
                init_progress.stop()
