import json
import sys

import typer

from ..config import ensure_default_configs, load_config
from ..coverage import GAP_REASONS, HISTORY_TRUNCATED
from ..db import (
    init_db,
    maybe_auto_import_seed,
)
from ..fetcher import MAX_HISTORY_DIFFS
from ..scoring import (
    DECLARED_CAVEAT,
    DECLARED_DEFAULT,
    verdict_label,
    verdict_level,
)
from ..safe_text import clean, safe_markup
from ..unicode import describe_fatal_codepoints
from .display import (
    DEPTH_TRUNCATED_NOTE,
    HAS_RICH,
    dependency_cards_rich,
    dependency_lines_plain,
    RISK_COLORS,
    _print_colored,
    _severity_text,
    _weight_text,
    console,
    no_aur_change_note,
    version_transition,
)

# Imported on call rather than at module scope: `app.py` imports this module
# to register `inspect`, and `trustsight.analysis` is the rule engine, so at
# module scope every invocation - `--version` included - loaded the analyser
# before doing anything.  The wrapper keeps the name patchable, which is how
# the tests replace it.
def analyze_package(*args, **kwargs):
    from ..analysis import analyze_package as _analyze_package

    return _analyze_package(*args, **kwargs)




def _inspect_rich(fact, verbose=False, show_score=False, show_risk=False):
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text

    con = console()
    risk = verdict_level(fact)
    label = verdict_label(fact)
    border = RISK_COLORS.get(risk, "white") if (show_score or show_risk) else "blue"

    rows: list[tuple[str, str]] = []
    rows.append(("Version", version_transition(fact)))

    # B2: the gap is shown whether or not a band is.  It used to ride the
    # band label alone, and the default output withholds the band, so
    # `inspect` with no flags said nothing at all about a partial read -
    # the one light that must never be suppressible.
    for gap in fact.coverage_gaps:
        rows.append(("Not vetted", f"[yellow]{safe_markup(GAP_REASONS.get(gap, gap))}[/]"))

    # No first-seen row here: the Status row at the foot of the panel is
    # unconditional and `_status_text` returns the same sentence, so this
    # printed it twice.  It also closed its markup with `[]` rather than
    # `[/]`, which Rich renders literally - the report showed
    # "First analysis.[] No prior history for this package."
    if fact.diff_summary.lines_added or fact.diff_summary.lines_removed:
        rows.append(("Lines", f"[green]+{fact.diff_summary.lines_added}[/] [red]-{fact.diff_summary.lines_removed}[/]"))
    if fact.maintainer_changed:
        rows.append(("Maintainer", f"[yellow]{safe_markup(fact.previous_maintainer or '?')} -> {safe_markup(fact.current_maintainer or '?')}[/]"))
    elif fact.current_maintainer:
        rows.append(("Maintainer", Text(clean(fact.current_maintainer))))
    cs = fact.source_changes.checksum_behavior
    if cs and cs != "unchanged":
        rows.append(("Checksum", f"[yellow]{safe_markup(cs)}[/]"))

    inside = Table.grid(padding=(0, 2))
    inside.add_column(style="dim", justify="right", no_wrap=True)
    inside.add_column()
    for row_label, row_value in rows:
        inside.add_row(row_label, row_value)

    if fact.changes:
        inside.add_row("", "")
        inside.add_row("[underline]What changed[/]", "")
        for entry in fact.changes:
            inside.add_row("", Text("  " + clean(entry)))

    declared = [e for e in fact.score_breakdown if e.rule_id.startswith("P")
                and e.rule_id[1:].isdigit()]
    # B10: the default set is the practices a reader would find surprising
    # by their *absence*.  Listing every one of them on every package
    # buries the risk findings, which is the opposite of the point.
    hidden = 0
    if not verbose:
        shown = [e for e in declared if e.rule_id in DECLARED_DEFAULT]
        hidden = len(declared) - len(shown)
        declared = shown
    if declared:
        inside.add_row("", "")
        inside.add_row("[underline]Declared verification[/]", "")
        for entry in declared:
            prefix = f"PKGBUILD:{entry.line}  " if entry.line is not None else ""
            inside.add_row("", Text(f"  {prefix}{clean(entry.reason)}"))
        if hidden:
            inside.add_row("", Text(
                f"  {hidden} more declared practice(s); --verbose to list them",
                style="dim"))
        inside.add_row("", Text("  " + DECLARED_CAVEAT, style="dim"))

    if fact.diff_summary.file_changes:
        inside.add_row("", "")
        inside.add_row("[underline]Files changed[/]", "")
        for fc in fact.diff_summary.file_changes:
            status = fc.get("status", "")
            path = fc.get("path", "")
            prefix = {"added": "[green]+[/]", "removed": "[red]-[/]", "modified": "[yellow]~[/]"}.get(status, " ")
            inside.add_row("", f"  {prefix} {safe_markup(path)}")

    if fact.source_changes.added_urls:
        inside.add_row("", "")
        inside.add_row("[underline]Source URLs added[/]", "")
        for url in fact.source_changes.added_urls:
            bucket = fact.source_buckets.get(url, "unknown")
            style = "red" if bucket in ("homograph_attack", "unknown") else "dim"
            inside.add_row("", Text(f"  [{bucket}] ", style=style) + Text(clean(url)))

    if fact.execution_changes.resolved_commands:
        inside.add_row("", "")
        inside.add_row("[underline]Resolved commands[/]", "")
        for cmd in fact.execution_changes.resolved_commands[:20]:
            inside.add_row("", Text("  " + clean(cmd.strip())))
        extra = len(fact.execution_changes.resolved_commands) - 20
        if extra > 0:
            inside.add_row("", f"  [dim]... {extra} more[/]")

    if fact.score_breakdown:
        inside.add_row("", "")
        inside.add_row("[underline]Rules Triggered[/]", "")
        for entry in fact.score_breakdown:
            # Declared practices have their own group above; repeating them
            # here would undo the point of showing a default subset.
            if entry.rule_id.startswith("P") and entry.rule_id[1:].isdigit():
                continue
            rid = entry.rule_id or ""
            segs = [Text(clean(rid) + " ", style="cyan")]
            if show_score:
                segs.append(str(_weight_text(entry.weight)) + " ")
            if show_risk:
                segs.append(str(_severity_text(entry.severity)) + " ")
            segs.append(Text(clean(entry.reason)))
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

    if fact.ioc_matches:
        inside.add_row("", "")
        inside.add_row("[underline]IOC baseline matches[/]", "")
        for m in fact.ioc_matches:
            expired = " [EXPIRED]" if m.expired else ""
            line = f" line {m.line}" if m.line is not None else ""
            text = f"  [{clean(m.source)}] {clean(m.type)}={clean(m.value)}{line} ({clean(m.surface)}){expired}"
            inside.add_row("", Text(text))

    if getattr(fact, "dependencies", None):
        inside.add_row("", "")
        inside.add_row("[underline]Dependencies[/]", "")
        for card in dependency_cards_rich(fact.dependencies, show_score=show_score,
                                   show_risk=show_risk):
            inside.add_row("", card)
        if getattr(fact, "depth_truncated", False):
            inside.add_row("", Text(DEPTH_TRUNCATED_NOTE, style="yellow"))

    if fact.suppressed_rules:
        inside.add_row("", "")
        inside.add_row("[yellow]Suppressed by override[/]", "")
        for r in fact.suppressed_rules:
            inside.add_row("", Text(f"  {clean(r['rule_id'])}  {clean(r.get('override_reason', ''))}"))

    if show_score:
        inside.add_row("", "")
        total = sum(e.weight for e in fact.score_breakdown) if fact.score_breakdown else 0
        inside.add_row("[bold]Score[/]", f"{fact.final_score}/100  ({label})")
        inside.add_row("", f"[dim]sum: {total:+d}, clamped to {fact.final_score}/100[/]")
    elif show_risk:
        inside.add_row("", "")
        inside.add_row("[bold]Risk[/]", Text(clean(label)))

    inside.add_row("", "")
    inside.add_row("[bold]Status[/]", _status_text(fact))

    con.print()
    con.print(Panel(inside, title=Text(f"TrustSight Inspect: {clean(fact.package_name)}"), border_style=border))


def _status_text(fact) -> str:
    note = no_aur_change_note(fact)
    if note:
        return note
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
    print(f"TrustSight Inspect: {clean(fact.package_name)}")
    print(f"  Version: {clean(version_transition(fact))}")
    print(f"  Status: {clean(_status_text(fact))}")
    for gap in fact.coverage_gaps:
        print(f"  [Not fully vetted: {clean(GAP_REASONS.get(gap, gap))}.]")
    if fact.first_seen:
        print("  [First analysis] No prior history; novelty carries no weight yet.")
    if fact.maintainer_changed:
        print(f"  Maintainer changed: {clean(fact.previous_maintainer)} -> {clean(fact.current_maintainer)}")
    elif fact.current_maintainer:
        print(f"  Maintainer: {clean(fact.current_maintainer)}")
    if fact.diff_summary.lines_added or fact.diff_summary.lines_removed:
        print(f"  Lines: +{fact.diff_summary.lines_added} -{fact.diff_summary.lines_removed}")
    cs = fact.source_changes.checksum_behavior
    if cs and cs != "unchanged":
        print(f"  Checksum: {clean(cs)}")
    # B7: what moved, whether or not a rule matched.  The Rich render has
    # this section and the plain one did not, so a terminal without Rich
    # could not tell "nothing fired and nothing changed" from "nothing
    # fired and a great deal changed".
    if fact.changes:
        print("  What changed:")
        for entry in fact.changes:
            print(f"    {clean(entry)}")
    if fact.diff_summary.file_changes:
        print("  Files changed:")
        for fc in fact.diff_summary.file_changes:
            status = fc.get("status", "")
            path = fc.get("path", "")
            prefix = {"added": "+", "removed": "-", "modified": "~"}.get(status, " ")
            print(f"    {prefix} {clean(path)}")
    if fact.source_changes.added_urls:
        print("  Source URLs added:")
        for url in fact.source_changes.added_urls:
            print(f"    {clean(url)} ({fact.source_buckets.get(url, 'unknown')})")
    # The reconstructed command text - the deobfuscated `curl` a rule
    # matched on. The Rich panel has always shown it and this renderer
    # showed none of it, so the evidence behind a finding was visible only
    # if Rich happened to be installed.
    if fact.execution_changes.resolved_commands:
        print("  Resolved commands:")
        for cmd in fact.execution_changes.resolved_commands[:20]:
            print(f"    {clean(cmd.strip())}")
        extra = len(fact.execution_changes.resolved_commands) - 20
        if extra > 0:
            print(f"    ... {extra} more")
    if fact.score_breakdown:
        print("  Rules Triggered:")
        for e in fact.score_breakdown:
            segs = [f"    [{clean(e.rule_id)}]"]
            if show_score:
                segs.append(f"{e.weight:+d}")
            if show_risk:
                segs.append(f"{clean(e.severity):<8}")
            segs.append(clean(e.reason))
            print(" ".join(segs))
    if fact.ioc_matches:
        print("  IOC baseline matches:")
        for m in fact.ioc_matches:
            expired = " [EXPIRED]" if m.expired else ""
            line = f" line {m.line}" if m.line is not None else ""
            print(f"    [{clean(m.source)}] {clean(m.type)}={clean(m.value)}{line} ({clean(m.surface)}){expired}")
    for line in dependency_lines_plain(getattr(fact, "dependencies", ()),
                                       show_score=show_score,
                                       show_risk=show_risk):
        print(line)
    if getattr(fact, "depth_truncated", False):
        print(f"  [{DEPTH_TRUNCATED_NOTE}]")

    if fact.suppressed_rules:
        print("  Suppressed by override (did not affect the score):")
        for r in fact.suppressed_rules:
            print(f"    {clean(r['rule_id'])} {clean(r.get('override_reason', ''))}")
    if show_score:
        print(f"  Score: {fact.final_score}/100 ({verdict_label(fact)})")
    elif show_risk:
        print(f"  Risk: {verdict_label(fact)}")


def _render_history_panel_rich(row: dict, show_score: bool, show_risk: bool, verbose: bool):
    """Render one history result as a Rich panel with commit info."""
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text

    con = console()
    risk = row.get("risk", "")
    label = row.get("risk_label") or risk
    border = RISK_COLORS.get(risk, "blue") if (show_score or show_risk) else "blue"

    table = Table(show_header=False, box=None, padding=(0, 1))
    table.add_column(no_wrap=True)
    table.add_column()

    commit_id = row.get("commit", "")[:8]
    commit_msg = row.get("commit_message", "")
    table.add_row("Commit", Text(f"{commit_id}  {commit_msg}", style="dim"))

    findings = row.get("findings", [])
    if findings:
        for f in findings:
            table.add_row("", Text(clean(_finding_line(f))))
    else:
        table.add_row("Status", "No findings")

    for gap in row.get("coverage_gaps", []):
        table.add_row("Not vetted", Text(
            clean(GAP_REASONS.get(gap, gap)), style="yellow"))

    changes = row.get("changes", [])
    if changes:
        table.add_row("Changed", Text(clean(changes[0])))
        for entry in changes[1:]:
            table.add_row("", Text(clean(entry)))

    if show_score and not row.get("failed"):
        table.add_row("Score", f"{row.get('score', 0)}/100 ({label})")
    elif show_risk and not row.get("failed"):
        table.add_row("Risk", clean(label))

    panel = Panel(table, title=Text(clean(row.get("package", ""))), border_style=border)
    con.print(panel)


def _render_history_panel_plain(row: dict, show_score: bool, show_risk: bool):
    """Render one history result as plain text."""
    commit_id = row.get("commit", "")[:8]
    commit_msg = row.get("commit_message", "")
    print(f"\n--- {commit_id}  {commit_msg} ---")

    findings = row.get("findings", [])
    if findings:
        for f in findings:
            print(f"  {_finding_line(f)}")
    else:
        print("  No findings")

    for gap in row.get("coverage_gaps", []):
        print(f"  Not vetted: {GAP_REASONS.get(gap, gap)}")

    changes = row.get("changes", [])
    if changes:
        print(f"  Changed: {changes[0]}")
        for entry in changes[1:]:
            print(f"    {entry}")

    if show_score and not row.get("failed"):
        label = row.get("risk_label") or row.get("risk", "")
        print(f"  Score: {row.get('score', 0)}/100 ({label})")
    elif show_risk and not row.get("failed"):
        label = row.get("risk_label") or row.get("risk", "")
        print(f"  Risk: {label}")


def _finding_line(finding: dict) -> str:
    """Format a finding dict as a one-line string for history panels."""
    parts = []
    if finding.get("file") and finding.get("line") is not None:
        parts.append(f"{finding['file']}:{finding['line']}")
    rule_id = finding.get("rule_id", "?")
    reason = finding.get("reason", "")
    parts.append(f"{rule_id}  {reason}")
    return " ".join(parts)


def _inspect_one(fact, *, show_score, show_risk, verbose, json_output):
    """Render a single PackageFact to the appropriate surface."""
    if json_output:
        from ..reporting import evaluate_fact, report_body
        return report_body(
            evaluate_fact(fact),
            include_score=show_score or show_risk,
            verbose=verbose,
        )
    if HAS_RICH:
        _inspect_rich(fact, verbose, show_score, show_risk)
    else:
        _inspect_plain(fact, verbose, show_score, show_risk)
    return None


def register_commands(app: typer.Typer):
    @app.command()
    def inspect(
        package: str = typer.Argument(..., help="Package name"),
        verbose: bool = typer.Option(False, "--verbose", help="Show triggered rules and score breakdown"),
        score: bool = typer.Option(False, "--score", help="Show aggregate trust score"),
        risk: bool = typer.Option(False, "--risk", help="Show risk level"),
        json_output: bool = typer.Option(False, "--json", help="Output JSON"),
        depth: int = typer.Option(
            None, "--depth",
            help="AUR dependency levels to analyse: 0 off, 1 default, n levels, "
                 "-1 every level (bounded).",
        ),
        allow_uninstalled: bool = typer.Option(
            False, "--allow-uninstalled",
            help="Analyse a package not in the local pacman set",
        ),
        last: int = typer.Option(
            None, "--last",
            help="Analyse the N most recent content-bearing commits as N separate results",
        ),
        record: bool = typer.Option(
            False, "--record",
            help="Write observations to the database (default: read-only for uninstalled packages)",
        ),
    ):
        """Show a detailed analysis of a single package."""
        _show_score = score
        _show_risk = risk
        ensure_default_configs()
        init_db()
        if load_config().get("seed", {}).get("auto_import", True):
            maybe_auto_import_seed(quiet=json_output, allow_release_fetch=True)

        # --record without --allow-uninstalled is a no-op: installed
        # packages already record observations on every analysis.
        if record and not allow_uninstalled:
            msg = "--record is only meaningful with --allow-uninstalled"
            if json_output:
                typer.echo(json.dumps({"error": msg}))
            else:
                _print_colored(msg, "red")
            raise typer.Exit(code=2)

        # --last validation
        if last is not None and last < 1:
            msg = f"--last must be >= 1 (got {last})"
            if json_output:
                typer.echo(json.dumps({"error": msg}))
            else:
                _print_colored(msg, "red", stderr=True)
            raise typer.Exit(code=2)
        if last is not None and last > MAX_HISTORY_DIFFS:
            msg = f"--last cannot exceed {MAX_HISTORY_DIFFS} (got {last})"
            if json_output:
                typer.echo(json.dumps({"error": msg}))
            else:
                _print_colored(msg, "red", stderr=True)
            raise typer.Exit(code=2)

        # --last with --depth is refused in v1: N × MAX_DEPTH_NODES is
        # the A14 product-composition shape.
        if last is not None and depth is not None and depth != 0:
            msg = "--last and --depth > 0 are not combined in this version"
            if json_output:
                typer.echo(json.dumps({"error": msg}))
            else:
                _print_colored(msg, "red", stderr=True)
            raise typer.Exit(code=2)

        # Check local installation status for the --allow-uninstalled gate.
        from ..db import get_package as _get_pkg
        local = _get_pkg(package)
        if local is None and not allow_uninstalled:
            msg = (
                f"Package '{package}' is not installed and "
                "--allow-uninstalled was not passed."
            )
            if json_output:
                typer.echo(json.dumps({"error": msg}))
            else:
                _print_colored(msg, "red")
            raise typer.Exit(code=2)

        # Resolve the package name against the AUR.
        from ..discovery import get_aur_package_info
        info = get_aur_package_info([package])
        if package not in info and local is None:
            msg = f"Package '{package}' not found in the AUR."
            if json_output:
                typer.echo(json.dumps({"error": msg}))
            else:
                _print_colored(msg, "red")
            raise typer.Exit(code=2)

        # --last path: walk history and analyse N content-bearing diffs.
        if last is not None:
            _inspect_history(
                package=package,
                n_results=last,
                allow_uninstalled=allow_uninstalled,
                record=record,
                show_score=_show_score,
                show_risk=_show_risk,
                verbose=verbose,
                json_output=json_output,
            )
            return

        # Single-result path (current behaviour).
        try:
            fact = analyze_package(package, depth=depth)
        except Exception as exc:
            msg = f"Analysis of '{package}' failed: {exc}"
            if json_output:
                typer.echo(json.dumps({"error": msg}))
            else:
                _print_colored(msg, "red", stderr=True)
            raise typer.Exit(code=2)
        _inspect_one(
            fact,
            show_score=_show_score,
            show_risk=_show_risk,
            verbose=verbose,
            json_output=json_output,
        )


def _inspect_history(
    *,
    package: str,
    n_results: int,
    allow_uninstalled: bool,
    record: bool,
    show_score: bool,
    show_risk: bool,
    verbose: bool,
    json_output: bool,
):
    """Walk history and analyse the N most recent content-bearing diffs."""
    import time

    from ..differ import MAX_DIFF_BYTES, generate_diff_bounded
    from ..coverage import HISTORY_TRUNCATED
    from ..fetcher import (
        MAX_HISTORY_COMMITS,
        MAX_RUN_DIFF_BYTES,
        clone_or_fetch,
        get_head_commit,
        walk_bounded,
    )
    from ..full_aur.analyze import TemporalContext, analyze_package_text
    from ..reporting import evaluate_fact, report_body

    # Resolve the upstream metadata.
    from ..discovery import get_aur_package_info
    info = get_aur_package_info([package])
    pkg_info = info.get(package, {})
    upstream_mtime = pkg_info.get("LastModified")

    # Clone or fetch the repository.
    try:
        repo = clone_or_fetch(package, upstream_mtime)
    except Exception as exc:
        msg = f"Could not fetch '{package}' from AUR: {exc}"
        if json_output:
            typer.echo(json.dumps({"error": msg}))
        else:
            _print_colored(msg, "red", stderr=True)
        raise typer.Exit(code=2)

    head = get_head_commit(repo)
    if not head:
        msg = f"Package '{package}' has no commits."
        if json_output:
            typer.echo(json.dumps({"error": msg}))
        else:
            _print_colored(msg, "red")
        raise typer.Exit(code=2)

    # Walk the history.
    run_diff_bytes = 0
    results: list[dict] = []
    history_truncated = False
    commits_seen = 0

    for commit in walk_bounded(repo, head, limit=MAX_HISTORY_COMMITS):
        commits_seen += 1
        if len(results) >= n_results:
            break

        # Get parent commit.
        parent = commit.parents[0] if commit.parents else None
        if parent is None:
            continue

        # Read PKGBUILD content from each commit.
        try:
            new_tree = commit.tree
            old_tree = parent.tree
            # Check if PKGBUILD exists in new commit
            if "PKGBUILD" not in new_tree:
                continue
            new_pkgbuild = new_tree["PKGBUILD"].data.decode("utf-8", errors="replace")
            # Read old PKGBUILD (empty if not present)
            if "PKGBUILD" in old_tree:
                old_pkgbuild = old_tree["PKGBUILD"].data.decode("utf-8", errors="replace")
            else:
                old_pkgbuild = None
        except Exception:
            continue

        # Skip if PKGBUILD didn't change.
        if old_pkgbuild == new_pkgbuild:
            continue

        # Charge the run budget.
        diff_bytes = len(new_pkgbuild.encode("utf-8", errors="replace"))
        run_diff_bytes += diff_bytes
        if run_diff_bytes > MAX_RUN_DIFF_BYTES:
            history_truncated = True
            break

        # Build temporal context.
        temporal = TemporalContext(
            last_modified=commit.commit_time,
            source="git_commit",
        )

        # Analyse the diff.
        try:
            fact = analyze_package_text(
                pkg_name=package,
                old_pkgbuild=old_pkgbuild,
                new_pkgbuild=new_pkgbuild,
                maintainer=pkg_info.get("Maintainer", ""),
                temporal=temporal,
            )
        except Exception as _exc:
            import traceback as _tb
            print(f"ANALYSIS FAILED: {_exc}", file=sys.stderr, flush=True)
            _tb.print_exc(file=sys.stderr)
            continue

        # Attach commit metadata.
        fact_dict = report_body(
            evaluate_fact(fact),
            include_score=show_score or show_risk,
            verbose=verbose,
        )
        fact_dict["commit"] = str(commit.id)
        fact_dict["commit_time"] = commit.commit_time
        fact_dict["commit_message"] = commit.message.strip().split("\n")[0]

        results.append(fact_dict)

    # Check if we got fewer results than requested.
    if len(results) < n_results and not history_truncated:
        history_truncated = True

    # Attach run-level coverage gap to the newest result.
    if history_truncated and results:
        results[0].setdefault("coverage_gaps", [])
        if HISTORY_TRUNCATED not in results[0]["coverage_gaps"]:
            results[0]["coverage_gaps"].insert(0, HISTORY_TRUNCATED)

    # Exit 2 when zero results could be produced (per spec §6 exit code).
    if not results:
        msg = f"No content-bearing diffs found for '{package}' (walked {commits_seen} commits)."
        if json_output:
            typer.echo(json.dumps({"error": msg}))
        else:
            _print_colored(msg, "red")
        raise typer.Exit(code=2)

    if json_output:
        typer.echo(json.dumps(results, indent=2))
    else:
        for r in results:
            if HAS_RICH:
                _render_history_panel_rich(r, show_score, show_risk, verbose)
            else:
                _render_history_panel_plain(r, show_score, show_risk)
        if history_truncated:
            _print_colored(
                f"History walk stopped after {len(results)} result(s) "
                f"({commits_seen} commits examined).",
                "yellow",
            )
