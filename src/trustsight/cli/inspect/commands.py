"""Extracted from inspect.py: commands."""

import json
import sys
import typer
from ...config import ensure_default_configs, load_config
from ...coverage import HISTORY_TRUNCATED
from ...db import (
    init_db,
    maybe_auto_import_seed,
)
from ...fetcher import MAX_HISTORY_DIFFS
from ..completion import installed_packages
from ..display import (
    _print_colored,
    use_rich,
)
from ._render import _explain_lines, _failed_history_result, _inspect_plain, _inspect_rich, _render_history_panel_plain, _render_history_panel_rich

__all__ = ['_inspect_history', '_inspect_one', 'analyze_package', 'register_commands']

def analyze_package(*args, **kwargs):
    """Thin wrapper that defers the analysis import until first call."""
    from ...analysis import analyze_package as _analyze_package

    return _analyze_package(*args, **kwargs)

def _inspect_one(fact, *, show_score, show_risk, verbose, json_output):
    """Render a single PackageFact to the appropriate surface."""
    if json_output:
        from ...reporting import evaluate_fact, report_body
        return report_body(
            evaluate_fact(fact),
            include_score=show_score or show_risk,
            verbose=verbose,
        )
    if use_rich():
        _inspect_rich(fact, verbose, show_score, show_risk)
    else:
        _inspect_plain(fact, verbose, show_score, show_risk)
    return None

def register_commands(app: typer.Typer):
    """Register the ``inspect`` and ``history`` subcommands on *app*."""
    @app.command()
    def inspect(
        package: str = typer.Argument(..., help="Package name", autocompletion=installed_packages),
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
            help="Persist observations and analysis history (default: read-only)",
        ),
        full_recipe: bool = typer.Option(
            False, "--full-recipe",
            help="Analyse the whole recipe as if newly added, not only the last change",
        ),
        explain: bool = typer.Option(
            False, "--explain",
            help="Show what the parser believed: the recipe and diff documents",
        ),
        fp_template: bool = typer.Option(
            False, "--fp-template",
            help="Print a Markdown false-positive issue body instead of the report",
        ),
    ):
        """Show a detailed analysis of a single package."""
        _show_score = score
        _show_risk = risk
        ensure_default_configs()
        init_db()
        if load_config().get("seed", {}).get("auto_import", True):
            maybe_auto_import_seed(quiet=json_output, allow_release_fetch=True)

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

        if last is not None and full_recipe:
            msg = "--last and --full-recipe are not combined"
            if json_output:
                typer.echo(json.dumps({"error": msg}))
            else:
                _print_colored(msg, "red", stderr=True)
            raise typer.Exit(code=2)

        # The gate is the local pacman set, not trustsight's database: a
        # package trustsight has not recorded yet (no `--record`) is still
        # installed, and `get_package` returned "not tracked" while the
        # message claimed "not installed".  The database is for history only.
        from ...discovery import get_all_installed, get_aur_package_info
        try:
            local = get_all_installed().get(package)
        except Exception:
            local = None
        if local is None and not allow_uninstalled:
            msg = (
                f"Package '{package}' is not installed locally; "
                "pass --allow-uninstalled."
            )
            if json_output:
                typer.echo(json.dumps({"error": msg}))
            else:
                _print_colored(msg, "red")
            raise typer.Exit(code=2)

        # Resolve the package name against the AUR.
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
            fact = analyze_package(package, depth=depth, record=record, full_recipe=full_recipe)
        except Exception as exc:
            msg = f"Analysis of '{package}' failed: {exc}"
            if json_output:
                typer.echo(json.dumps({"error": msg}))
            else:
                _print_colored(msg, "red", stderr=True)
            raise typer.Exit(code=2)
        if fp_template:
            from ... import __version__
            from ...fp_issue import issue_body, issue_url
            from ...reporting import evaluate_fact, report_body

            report = report_body(
                evaluate_fact(fact), include_score=True, verbose=verbose)
            package_name = report.get("package") or package
            rule_ids = [
                finding["rule_id"]
                for finding in report.get("findings", ())
                if finding.get("rule_id")
            ]
            typer.echo(issue_body(
                package=package_name,
                report=report,
                version=__version__,
                command=f"trustsight inspect {package} --fp-template",
            ))
            typer.echo(f"\nFile at: {issue_url(package_name, rule_ids)}")
            return
        body = _inspect_one(
            fact,
            show_score=_show_score,
            show_risk=_show_risk,
            verbose=verbose,
            json_output=json_output,
        )
        if explain:
            from ...fetcher import clone_or_fetch
            project = clone_or_fetch(package)
            try:
                lines = _explain_lines(fact, project)
            finally:
                project.close()
            if json_output:
                if body is not None:
                    body["explain"] = lines
            else:
                typer.echo("\n".join(lines))
        if body is not None:
            typer.echo(json.dumps(body, indent=2))

    @app.command()
    def report(
        package: str = typer.Argument(..., help="Package name"),
        output_format: str = typer.Option(
            "sarif", "--format", help="Report format (sarif)"),
        diff_path: str = typer.Option(
            None, "--diff",
            help="Analysed diff text; lets removed-line findings anchor to "
                 "the pre-image",
        ),
        depth: int = typer.Option(
            None, "--depth", help="AUR dependency levels to analyse",
        ),
    ):
        """Emit a machine-readable report document (SARIF 2.1.0)."""
        if output_format != "sarif":
            _print_colored(
                f"unknown report format '{output_format}' (supported: sarif)",
                "red", stderr=True,
            )
            raise typer.Exit(code=2)
        from ...reporting import evaluate_fact, report_to_sarif

        ensure_default_configs()
        init_db()
        try:
            fact = analyze_package(package, depth=depth, record=False)
        except Exception as exc:
            _print_colored(
                f"Analysis of '{package}' failed: {exc}", "red", stderr=True)
            raise typer.Exit(code=2)
        diffs = None
        if diff_path:
            from pathlib import Path

            from ...api import MAX_API_TEXT_BYTES
            from ...bounded_io import read_file_capped

            try:
                raw = read_file_capped(
                    Path(diff_path), MAX_API_TEXT_BYTES, what="diff")
                diffs = {package: raw.decode("utf-8", errors="replace")}
            except Exception as exc:
                _print_colored(f"could not read {diff_path}: {exc}",
                               "red", stderr=True)
                raise typer.Exit(code=2)
        typer.echo(json.dumps(
            report_to_sarif([evaluate_fact(fact)], diffs), indent=2))

    @app.command("verify-build")
    def verify_build_cmd(
        package: str = typer.Argument(..., help="Package name"),
        json_output: bool = typer.Option(False, "--json", help="Output JSON"),
    ):
        """Run the optional L9 build lane.

        Off by default.  With ``[verify] enabled = false`` or no sandbox
        container, this reports ``l9_unavailable`` - a weight-0 boundary,
        never a clean or malicious verdict.  The lane never runs package
        code in the static core.
        """
        from ...api import TrustSight
        from ...config import ensure_default_configs
        from ...db import init_db

        ensure_default_configs()
        init_db()
        # review L1-L8 first, then offer the L9 lane. The static
        # result is passed only so a divergence between the two can be named;
        # it never changes the static verdict.
        try:
            fact = analyze_package(package)
            static_clean = not any(
                e.severity in ("FATAL", "CRITICAL", "HIGH")
                for e in fact.score_breakdown)
        except Exception:
            static_clean = None
        result = TrustSight().verify_build(package, static_clean=static_clean)
        if json_output:
            typer.echo(json.dumps(result, indent=2))
            return
        if result["status"] == "l9_unavailable":
            typer.echo(f"L9 build lane unavailable for {package}: "
                       f"{result['reason']}")
            return
        for finding in result["findings"]:
            typer.echo(f"{finding['rule_id']}: {finding['match']}")
        if result.get("l9_divergence"):
            typer.echo("L9 divergence: the artifact and the static analysis "
                       "disagree; both profiles stand.")

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

    from ...differ import MAX_HISTORY_COMMITS
    from ...fetcher import (
        MAX_RUN_DIFF_BYTES,
        clone_or_fetch,
        get_head_commit,
    )
    from ...full_aur.analyze import TemporalContext, analyze_package_text
    from ...reporting import evaluate_fact, report_body

    # Resolve the upstream metadata.
    from ...discovery import get_aur_package_info
    info = get_aur_package_info([package])
    pkg_info = info.get(package, {})
    upstream_mtime = pkg_info.get("LastModified")

    # Clone or fetch the repository.
    try:
        project = clone_or_fetch(package, upstream_mtime)
    except Exception as exc:
        msg = f"Could not fetch '{package}' from AUR: {exc}"
        if json_output:
            typer.echo(json.dumps({"error": msg}))
        else:
            _print_colored(msg, "red", stderr=True)
        raise typer.Exit(code=2)

    head = get_head_commit(project)
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

    for commit in project.walk(head, MAX_HISTORY_COMMITS):
        commits_seen += 1
        if len(results) >= n_results:
            break

        # Get parent commit id.
        parent = commit.parents[0] if commit.parents else None
        if parent is None:
            continue

        # Read PKGBUILD content from each commit.
        try:
            # An absent PKGBUILD reads as empty text, which is also how an
            # empty one reads; neither carries content to analyse.
            new_pkgbuild = project.file_at(commit.id, "PKGBUILD")
            if not new_pkgbuild:
                continue
            old_pkgbuild = project.file_at(parent, "PKGBUILD")
        except Exception as exc:
            # A commit whose tree could not be read is not "nothing to see":
            # dropping it shortens the history silently and reads as clean.
            results.append(_failed_history_result(commit, f"tree unreadable: {exc}"))
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

        # The commit's tree is in hand, so hand it to the analysis: without
        # it every history result reported ``tree_not_analyzed`` and read as
        # Inconclusive even for a trivial bump.
        try:
            tree_files, _tree_complete = project.tree_files(str(commit.id))
        except Exception:
            tree_files = []
        try:
            fact = analyze_package_text(
                pkg_name=package,
                old_pkgbuild=old_pkgbuild,
                new_pkgbuild=new_pkgbuild,
                maintainer=pkg_info.get("Maintainer", ""),
                temporal=temporal,
                tree_manifest=tree_files or None,
                record=record,
            )
        except Exception as _exc:
            import traceback as _tb
            _tb.print_exc(file=sys.stderr)
            # Emitted as its own result, not dropped: a crash must not read
            # as a clean older commit, and it must not be mislabelled as a
            # truncated walk (the result count stays whole).
            results.append(_failed_history_result(commit, f"analysis failed: {_exc}"))
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

    # Exit 2 when zero results could be produced (exit code).
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
            if use_rich():
                _render_history_panel_rich(r, show_score, show_risk, verbose)
            else:
                _render_history_panel_plain(r, show_score, show_risk)
        if history_truncated:
            _print_colored(
                f"History walk stopped after {len(results)} result(s) "
                f"({commits_seen} commits examined).",
                "yellow",
            )
