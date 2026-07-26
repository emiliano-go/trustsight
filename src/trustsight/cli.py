import json
import sys
from pathlib import Path
from typing import Optional

import typer

from . import __version__
from .analysis import analyze_package
from .discovery import discover_packages
from .config import (
    CONFIG_DIR,
    ensure_default_configs,
    load_config,
    load_rules,
    missing_shipped_rules,
    outdated_shipped_rules,
    set_config,
    sync_rules,
)
from .db import (
    effective_observation_count,
    get_history,
    get_package_id,
    get_triggered_rules,
    import_seed,
    init_db,
    maybe_auto_import_seed,
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

_console = None


def console() -> "Console":
    global _console
    if _console is None:
        _console = Console()
    return _console


def _tier_of(entry) -> str:
    return TIER_OF.get(entry.rule_id, ("A", ""))[0]


def _severity_text(severity: str) -> "Text":
    return Text(severity, style=SEVERITY_COLORS.get(severity, "white"))


def _weight_text(weight: int) -> "Text":
    if weight > 0:
        return Text(f"+{weight}", style="red")
    if weight < 0:
        return Text(str(weight), style="green")
    return Text("0", style="dim")


def _score_text(score: int, risk: str | None = None) -> "Text":
    risk = risk or risk_level(score)
    return Text(f"{score}/100", style=RISK_COLORS.get(risk, "white"))


def _fact_to_dict(fact):
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
    add_completion=False,
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
app.add_typer(config_app, name="config")
app.add_typer(override_app, name="override")


def _version_callback(value: bool):
    if value:
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
    pass


# --- review ---

@app.command()
def review(
    limit: int = typer.Option(20, "--limit", help="Max packages to review"),
    verbose: bool = typer.Option(False, "--verbose", help="Show triggered rules per package"),
    repo: Optional[list[str]] = typer.Option(
        None, "--repo", help="Scan packages from a specific local repository (can be repeated)"
    ),
    foreign: bool = typer.Option(False, "--foreign", help="Include foreign packages (pacman -Qm)"),
    all_repos: bool = typer.Option(
        False, "--all-repos",
        help="Auto-detect all local repos from pacman.conf (excludes official repos)",
    ),
    json_output: bool = typer.Option(False, "--json", help="Output JSON"),
):
    ensure_default_configs()
    config = load_config()
    init_db()
    if config.get("seed", {}).get("auto_import", True):
        maybe_auto_import_seed()
    effective_limit = limit or config.get("limits", {}).get("default_review_limit", 20)

    user_specified = not (repo is None and not foreign and not all_repos)
    if user_specified:
        repos = repo or []
        include_foreign = foreign
        all_flag = all_repos
    else:
        discovery_cfg = config.get("discovery", {})
        repos = discovery_cfg.get("default_repos", [])
        include_foreign = discovery_cfg.get("include_foreign", False)
        all_flag = discovery_cfg.get("all_repos", False)
        if not repos and not all_flag and not include_foreign:
            include_foreign = True

    def _warn(msg: str):
        con = console()
        con.print(f"[yellow]Warning:[/] {msg}")

    if all_flag:
        from .discovery import get_local_repos_from_pacman_conf
        try:
            get_local_repos_from_pacman_conf()
        except RuntimeError as exc:
            if repos:
                _warn(str(exc) + "; falling back to explicit repos.")
            else:
                console().print(f"[red]Error:[/] {exc}")
                sys.exit(1)

    outdated_pkgs = discover_packages(
        repos=repos,
        include_foreign=include_foreign,
        all_repos=all_flag,
        _warn_func=_warn if repos else None,
    )

    if not outdated_pkgs:
        _print_green("No outdated packages found.")
        return

    _run_analysis_loop(outdated_pkgs, effective_limit, verbose, json_output)


def _run_analysis_loop(
    outdated_pkgs: list[dict], limit: int, verbose: bool, json_output: bool
) -> None:
    from .llm import fallback_verdict, generate_verdict

    limited = outdated_pkgs[:limit] if limit else outdated_pkgs

    if HAS_RICH and not json_output:
        con = console()
        progress_columns = [
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
        ]
        with Progress(*progress_columns, console=con, transient=False) as progress:
            task = progress.add_task("Fetching AUR packages...", total=None)

            def on_progress(_current, total, name):
                if total:
                    progress.update(
                        task, total=total, completed=_current,
                        description=f"Analyzing {name}"
                    )
                else:
                    progress.update(task, description=name)

            results = _analyze_outdated_batch(limited, on_progress, verbose)
            progress.update(task, visible=False)

        if json_output:
            typer.echo(json.dumps(results, indent=2))
            return

        if not results:
            con.print("[yellow]No outdated AUR packages found.[/]")
            return

        flagged = sum(1 for r in results if r["score"] > 20)
        table = Table(
            title="TrustSight Review",
            caption=f"{len(results)} package(s) reviewed, {flagged} above the "
                    f"20-point CLEAN threshold",
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
            row = [
                r["package"],
                _score_text(r["score"], r["risk"]),
                Text(r["risk"], style=RISK_COLORS.get(r["risk"], "white")),
                verdict,
            ]
            if verbose:
                rules_text = (
                    ", ".join(f"{rule['rule_id']}" for rule in r.get("triggered_rules", []))
                    if r.get("triggered_rules") else "[dim]none[/]"
                )
                row.append(Text(strip_ansi(rules_text)))
            table.add_row(*row)

        con.print(table)
    else:
        results = _analyze_outdated_batch(limited, None, verbose)

        if json_output:
            typer.echo(json.dumps(results, indent=2))
            return

        if not results:
            print("No outdated AUR packages found.")
            return

        print(f"{'Package':<20} {'Risk Score':<10} Verdict", end="")
        if verbose:
            print("  Rules")
        else:
            print()
        print("-" * (80 if not verbose else 120))
        for r in results:
            verdict = r["verdict"]
            if r.get("first_seen"):
                verdict = f"[First analysis] {verdict}"
            line = f"{r['package']:<20} {r['score']:<10} {verdict}"
            if verbose:
                rules_str = (
                    ", ".join(rule["rule_id"] for rule in r.get("triggered_rules", []))
                    if r.get("triggered_rules") else "none"
                )
                line += f"  {rules_str}"
            print(line)


def _analyze_outdated_batch(
    pkgs: list[dict], progress_callback=None, verbose: bool = False
) -> list[dict]:
    from .llm import fallback_verdict, generate_verdict

    results = []
    total = len(pkgs)
    for i, entry in enumerate(pkgs):
        name = entry["name"]
        if progress_callback:
            progress_callback(i, total, name)
        fact = analyze_package(name)
        verdict = (
            generate_verdict(fact) if fact.final_score > 0
            else fallback_verdict(fact)
        )
        res = {
            "package": name,
            "old_version": entry.get("current_version", ""),
            "new_version": entry.get("latest_version", ""),
            "score": fact.final_score,
            "verdict": verdict,
            "risk": (
                "Low" if fact.final_score <= 20
                else "Medium" if fact.final_score <= 50
                else "High" if fact.final_score <= 80
                else "Critical"
            ),
            "first_seen": fact.first_seen,
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
    return results


# --- inspect ---

@app.command()
def inspect(
    package: str = typer.Argument(..., help="Package name"),
    json_output: bool = typer.Option(False, "--json", help="Output JSON"),
):
    ensure_default_configs()
    init_db()
    if load_config().get("seed", {}).get("auto_import", True):
        maybe_auto_import_seed()

    fact = analyze_package(package)
    if json_output:
        typer.echo(json.dumps(_fact_to_dict(fact), indent=2))
        return

    if HAS_RICH:
        _inspect_rich(fact)
    else:
        _inspect_plain(fact)


def _inspect_rich(fact):
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

    from .llm import fallback_verdict
    con.print(Rule("Verdict", style="dim"))
    con.print(Panel(Text(fallback_verdict(fact)),
                    border_style=RISK_COLORS.get(risk, "white")))


def _inspect_plain(fact):
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
    from .llm import fallback_verdict
    print(f"  Verdict: {fallback_verdict(fact)}")


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
    ensure_default_configs()
    init_db()

    pkg_id = get_package_id(package)
    if pkg_id is None:
        print(f"Package '{package}' not found in history.")
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
    ensure_default_configs()
    cfg = load_config()
    llm = cfg.get("llm", {})
    openai_cfg = llm.get("openai", {})
    api_key = openai_cfg.get("api_key", "")
    masked = api_key[:4] + "..." if len(api_key) > 8 else "(not set)"
    rows = [
        ("config file", str(CONFIG_DIR / "config.toml")),
        ("llm.provider", llm.get("provider", "ollama")),
        ("llm.model", llm.get("model", "gpt-4o-mini")),
        ("llm.enabled", str(llm.get("enabled", True))),
        ("llm.openai.api_key", masked),
        ("llm.openai.base_url", openai_cfg.get("base_url", "https://api.openai.com/v1")),
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
    key: str = typer.Argument(..., help="Config key (api_key or base_url)"),
    value: str = typer.Argument(..., help="Config value"),
    json_output: bool = typer.Option(False, "--json", help="Output JSON"),
):
    if key not in ("api_key", "base_url"):
        msg = f"Unknown key: {key}. Use api_key or base_url."
        if json_output:
            typer.echo(json.dumps({"error": msg}))
        else:
            _print_red(msg)
        raise typer.Exit(code=1)
    set_config(f"llm.openai.{key}", value)
    msg = f"Set llm.openai.{key} in {CONFIG_DIR / 'config.toml'}"
    if json_output:
        typer.echo(json.dumps({"status": "ok", "key": f"llm.openai.{key}"}))
    else:
        _print_green(msg)


@config_app.command("sync-rules")
def config_sync_rules(
    update: bool = typer.Option(
        False, "--update",
        help="Also replace rules whose pattern is a superseded shipped one "
             "(rules you have edited are never touched)",
    ),
    json_output: bool = typer.Option(False, "--json", help="Output JSON"),
):
    ensure_default_configs()
    added, updated = sync_rules(update_outdated=update)
    target = CONFIG_DIR / "rules.toml"

    if json_output:
        typer.echo(json.dumps({
            "target": str(target),
            "added": added,
            "updated": updated,
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
        else:
            lines.append("rules.toml is already up to date.")
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
    ensure_default_configs()
    try:
        ov = add_override(rule_id, reason, package)
    except ValueError as exc:
        msg = str(exc)
        if json_output:
            typer.echo(json.dumps({"error": msg}))
        else:
            _print_red(msg)
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
        _print_green(msg)


@override_app.command("rm")
def override_rm(
    rule_id: str = typer.Argument(..., help="Rule to stop suppressing"),
    package: Optional[str] = typer.Option(None, "--package", help="Scope the removal to one package"),
    json_output: bool = typer.Option(False, "--json", help="Output JSON"),
):
    ensure_default_configs()
    if remove_override(rule_id.upper(), package):
        msg = f"Override removed: {rule_id.upper()}"
        if json_output:
            typer.echo(json.dumps({"status": "ok", "rule_id": rule_id.upper()}))
        else:
            _print_green(msg)
    else:
        msg = f"No matching override for {rule_id.upper()}"
        if json_output:
            typer.echo(json.dumps({"error": msg}))
        else:
            _print_yellow(msg)
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
                _print_red(msg)
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
            _print_red(msg)
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
    if file:
        from ._toml import tomllib

        path = Path(file)
        if not path.exists():
            _print_red(f"Rules file not found: {path}")
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


# --- helpers ---

def _print_green(msg: str):
    if HAS_RICH:
        console().print(f"[green]{msg}[/]")
    else:
        print(msg)


def _print_red(msg: str):
    if HAS_RICH:
        console().print(f"[red]{msg}[/]")
    else:
        print(msg, file=sys.stderr)


def _print_yellow(msg: str):
    if HAS_RICH:
        console().print(f"[yellow]{msg}[/]")
    else:
        print(msg)


# --- entry point ---

if __name__ == "__main__":
    try:
        app()
    except KeyboardInterrupt:
        print("\nInterrupted.")
        sys.exit(130)
