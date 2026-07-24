import argparse
import sys

from .analysis import analyze_package, discover_updates
from .config import (
    ensure_default_configs,
    load_config,
    load_rules,
    missing_shipped_rules,
    outdated_shipped_rules,
    set_config,
    sync_rules,
    CONFIG_DIR,
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
from .override import (
    FATAL_RULES,
    OVERRIDES_PATH,
    add_override,
    list_overrides,
    remove_override,
)
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

# Which evidence tier a breakdown entry belongs to.  The tiers are the
# tool's explanation of itself, so the report groups by them rather than
# listing findings in the order they happened to fire.
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
    from rich.progress import (
        BarColumn,
        Progress,
        SpinnerColumn,
        TextColumn,
        TimeElapsedColumn,
    )
    from rich.rule import Rule
    from rich.table import Table
    from rich.text import Text

    HAS_RICH = True
except ImportError:
    HAS_RICH = False


_console = None


def console() -> "Console":
    """One Console for the process, so styling and width stay consistent."""
    global _console
    if _console is None:
        _console = Console()
    return _console


def _tier_of(entry) -> str:
    return TIER_OF.get(entry.rule_id, ("A", ""))[0]


def _severity_text(severity: str) -> "Text":
    return Text(severity, style=SEVERITY_COLORS.get(severity, "white"))


def _weight_text(weight: int) -> "Text":
    """Credits are as meaningful as penalties, so colour them apart."""
    if weight > 0:
        return Text(f"+{weight}", style="red")
    if weight < 0:
        return Text(str(weight), style="green")
    return Text("0", style="dim")


def _score_text(score: int, risk: str | None = None) -> "Text":
    risk = risk or risk_level(score)
    return Text(f"{score}/100", style=RISK_COLORS.get(risk, "white"))


def cmd_review(args):
    ensure_default_configs()
    config = load_config()
    init_db()
    if config.get("seed", {}).get("auto_import", True):
        maybe_auto_import_seed()
    limit = args.limit or config.get("limits", {}).get("default_review_limit", 20)

    if HAS_RICH:
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
                    progress.update(task, total=total, completed=_current, description=f"Analyzing {name}")
                else:
                    progress.update(task, description=name)

            results = discover_updates(limit=limit, progress_callback=on_progress)
            progress.update(task, visible=False)

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

        for r in results:
            verdict = Text(strip_ansi(r["verdict"]))
            if r.get("first_seen"):
                verdict = Text.assemble(("first analysis: ", "yellow"), verdict)
            table.add_row(
                r["package"],
                _score_text(r["score"], r["risk"]),
                Text(r["risk"], style=RISK_COLORS.get(r["risk"], "white")),
                verdict,
            )

        con.print(table)
    else:
        results = discover_updates(limit=limit)

        if not results:
            print("No outdated AUR packages found.")
            return

        print(f"{'Package':<20} {'Risk Score':<10} Verdict")
        print("-" * 80)
        for r in results:
            verdict = r["verdict"]
            if r.get("first_seen"):
                verdict = f"[First analysis] {verdict}"
            print(f"{r['package']:<20} {r['score']:<10} {verdict}")


def _inspect_rich(fact):
    con = console()
    risk = risk_level(fact.final_score)

    header = Text()
    header.append(fact.package_name, style="bold cyan")
    header.append("  ")
    header.append_text(_score_text(fact.final_score, risk))
    header.append(f"  ({risk})", style=RISK_COLORS.get(risk, "white"))
    con.print()
    con.print(Panel(header, title="TrustSight Inspect", border_style=RISK_COLORS.get(risk, "white")))

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
                table.add_row(_weight_text(e.weight), _severity_text(e.severity),
                              e.rule_id, Text(strip_ansi(e.reason)))
            con.print(table)

        total = sum(e.weight for e in fact.score_breakdown)
        con.print(f"  [dim]sum of contributions: {total:+d}, "
                  f"clamped to {fact.final_score}/100[/]")

    # A FATAL unicode finding is unreadable without saying exactly which
    # invisible characters were found and where.
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
    print(f"  Version: {fact.old_version} -> {fact.new_version}")
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


def cmd_inspect(args):
    ensure_default_configs()
    init_db()
    if load_config().get("seed", {}).get("auto_import", True):
        maybe_auto_import_seed()

    fact = analyze_package(args.package)
    if HAS_RICH:
        _inspect_rich(fact)
    else:
        _inspect_plain(fact)


def cmd_history(args):
    ensure_default_configs()
    init_db()

    pkg_id = get_package_id(args.package)
    if pkg_id is None:
        print(f"Package '{args.package}' not found in history.")
        return

    history = get_history(pkg_id, limit=args.limit or 20)

    if not history:
        print(f"No analysis history for '{args.package}'.")
        return

    if HAS_RICH:
        con = console()
        table = Table(title=f"History: {args.package}")
        table.add_column("Date", style="dim")
        table.add_column("Old", justify="right")
        table.add_column("→ New", justify="right")
        table.add_column("Score", justify="right")
        table.add_column("Risk")

        for h in history:
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

        if args.score_breakdown and history:
            rules = get_triggered_rules(history[0]["id"])
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
        for h in history:
            print(f"{h.get('timestamp','')[:10]:<12} {str(h.get('old_version','')):<12} → {str(h.get('new_version','')):<12} Score: {h.get('final_score',0)}")


def cmd_config(args):
    ensure_default_configs()
    if args.action == "show":
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
            ("llm.openai.base_url",
             openai_cfg.get("base_url", "https://api.openai.com/v1")),
            ("seed.auto_import", str(cfg.get("seed", {}).get("auto_import", True))),
            ("rules.experimental", str(cfg.get("rules", {}).get("experimental", False))),
        ]
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
            for group in ("severity_weights", "source_bucket_weights",
                          "novelty_weights", "verification_evidence",
                          "pinning_weights"):
                for key, value in (cfg.get(group) or {}).items():
                    weights.add_row(group, key, _weight_text(int(value)))
            console().print(weights)
        else:
            for k, v in rows:
                print(f"  {k}: {v}")
    elif args.action == "sync-rules":
        added, updated = sync_rules(update_outdated=args.update)
        target = CONFIG_DIR / "rules.toml"
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
    elif args.action == "set":
        if args.key in ("api_key", "base_url"):
            set_config(f"llm.openai.{args.key}", args.value)
            msg = f"Set llm.openai.{args.key} in {CONFIG_DIR / 'config.toml'}"
            console().print(f"[green]{msg}[/]") if HAS_RICH else print(msg)
        else:
            msg = f"Unknown key: {args.key}. Use api_key or base_url."
            console().print(f"[red]{msg}[/]") if HAS_RICH else print(msg, file=sys.stderr)
            sys.exit(1)


def cmd_seed_db(args):
    """Import the novelty seed so a fresh install is not cold."""
    from pathlib import Path

    ensure_default_configs()
    init_db()

    if args.file:
        seed = Path(args.file)
    else:
        bundled = Path(__file__).parent / "data" / "seed.db.gz"
        if not bundled.exists():
            msg = ("No bundled seed found. Build one with:\n"
                   "  python scripts/generate_seed.py --out src/trustsight/data/seed.db\n"
                   "or pass an existing seed with --file.")
            if HAS_RICH:
                console().print(f"[red]{msg}[/]")
            else:
                print(msg, file=sys.stderr)
            sys.exit(2)
        seed = bundled

    already = seed_observation_count()
    if already and not args.force:
        msg = (f"A seed is already imported ({already} observations). "
               f"Use --force to re-import.")
        console().print(msg) if HAS_RICH else print(msg)
        return

    try:
        if HAS_RICH:
            # The import decompresses ~12 MB and merges ~178k rows; it takes
            # several seconds, so say so rather than appear hung.
            with console().status(f"Importing seed from {seed.name}...", spinner="dots"):
                stats = import_seed(seed)
        else:
            print(f"Importing seed from {seed}...")
            stats = import_seed(seed)
    except FileNotFoundError:
        msg = f"Seed file not found: {seed}"
        console().print(f"[red]{msg}[/]") if HAS_RICH else print(msg, file=sys.stderr)
        sys.exit(2)

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


def cmd_override(args):
    """Suppress a rule that misfires on your packages, with a reason."""
    ensure_default_configs()

    if args.action == "add":
        try:
            ov = add_override(args.rule_id, args.reason, args.package)
        except ValueError as exc:
            msg = str(exc)
            console().print(f"[red]{msg}[/]") if HAS_RICH else print(msg, file=sys.stderr)
            sys.exit(1)
        scope = ov.package or "all packages"
        msg = f"Override added: {ov.rule_id} for {scope}"
        console().print(f"[green]{msg}[/]") if HAS_RICH else print(msg)
        return

    if args.action == "rm":
        if remove_override(args.rule_id.upper(), args.package):
            msg = f"Override removed: {args.rule_id.upper()}"
            console().print(f"[green]{msg}[/]") if HAS_RICH else print(msg)
        else:
            msg = f"No matching override for {args.rule_id.upper()}"
            console().print(f"[yellow]{msg}[/]") if HAS_RICH else print(msg)
            sys.exit(1)
        return

    overrides = list_overrides()
    if not overrides:
        msg = (f"No overrides configured. File: {OVERRIDES_PATH}\n"
               f"Add one with: trustsight override add R010 --reason \"...\"")
        console().print(msg) if HAS_RICH else print(msg)
        return

    if HAS_RICH:
        table = Table(title=f"Rule overrides ({OVERRIDES_PATH})", box=SIMPLE_HEAD)
        table.add_column("Rule", style="cyan")
        table.add_column("Scope")
        table.add_column("Reason", overflow="fold")
        table.add_column("Added", style="dim")
        for o in overrides:
            table.add_row(o.rule_id, o.package or "all packages", o.reason, o.created_at)
        console().print(table)
        console().print(
            f"[dim]{', '.join(sorted(FATAL_RULES))} cannot be overridden; a FATAL "
            f"finding is never suppressed.[/]"
        )
    else:
        for o in overrides:
            print(f"{o.rule_id:<8} {o.package or 'all':<20} {o.reason}")


def cmd_lint_rules(args):
    if args.file:
        import tomllib
        from pathlib import Path

        path = Path(args.file)
        if not path.exists():
            print(f"Rules file not found: {path}", file=sys.stderr)
            sys.exit(2)
        with open(path, "rb") as fh:
            rules = tomllib.load(fh).get("rules", [])
        source = path
    else:
        ensure_default_configs()
        rules = load_rules()
        source = CONFIG_DIR / "rules.toml"

    findings = lint_rules(rules)
    missing = [] if args.file else missing_shipped_rules()
    outdated = [] if args.file else outdated_shipped_rules()

    errors = [f for f in findings if f.level == SEVERITY_ERROR]
    warnings = [f for f in findings if f.level != SEVERITY_ERROR]

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
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description="TrustSight - AUR Package Update Vetting Tool")
    sub = parser.add_subparsers(dest="command")

    p_review = sub.add_parser("review", help="Scan AUR and analyze outdated packages")
    p_review.add_argument("--limit", type=int, default=0, help="Max packages to review")

    p_inspect = sub.add_parser("inspect", help="Analyze a specific package")
    p_inspect.add_argument("package", help="Package name")

    p_history = sub.add_parser("history", help="Show analysis history for a package")
    p_history.add_argument("package", help="Package name")
    p_history.add_argument("--limit", type=int, default=20, help="Max history entries")
    p_history.add_argument("--score-breakdown", action="store_true", help="Show score breakdown")

    p_lint = sub.add_parser("lint-rules", help="Check rules.toml for unreachable or over-broad rules")
    p_lint.add_argument("--file", help="Lint a specific rules TOML file instead of the user config")

    p_seed = sub.add_parser(
        "seed-db", help="Import the novelty seed database (removes cold-start INCONCLUSIVE)"
    )
    p_seed.add_argument(
        "--import", dest="do_import", action="store_true",
        help="Import the seed (default action)",
    )
    p_seed.add_argument("--file", help="Seed .db or .db.gz to import (default: bundled)")
    p_seed.add_argument("--force", action="store_true", help="Re-import even if already seeded")

    p_override = sub.add_parser(
        "override", help="Suppress a rule that misfires on your packages"
    )
    p_override_sub = p_override.add_subparsers(dest="action")
    p_override_sub.add_parser("list", help="List configured overrides")
    p_ov_add = p_override_sub.add_parser("add", help="Add an override")
    p_ov_add.add_argument("rule_id", help="Rule to suppress, e.g. R010")
    p_ov_add.add_argument("--reason", required=True,
                          help="Why this rule is being suppressed (required)")
    p_ov_add.add_argument("--package", help="Limit to one package (default: all)")
    p_ov_rm = p_override_sub.add_parser("rm", help="Remove an override")
    p_ov_rm.add_argument("rule_id", help="Rule to stop suppressing")
    p_ov_rm.add_argument("--package", help="Scope the removal to one package")

    p_config = sub.add_parser("config", help="Manage configuration")
    p_config_sub = p_config.add_subparsers(dest="action")

    p_config_sub.add_parser("show", help="Show current configuration")
    p_sync = p_config_sub.add_parser(
        "sync-rules", help="Append shipped rules missing from your rules.toml"
    )
    p_sync.add_argument(
        "--update", action="store_true",
        help="Also replace rules whose pattern is a superseded shipped one "
             "(rules you have edited are never touched)",
    )
    p_config_set = p_config_sub.add_parser("set", help="Set a configuration value")
    p_config_set.add_argument("key", choices=["api_key", "base_url"], help="Config key")
    p_config_set.add_argument("value", help="Config value")

    args = parser.parse_args()

    if args.command == "review":
        cmd_review(args)
    elif args.command == "inspect":
        cmd_inspect(args)
    elif args.command == "history":
        cmd_history(args)
    elif args.command == "override":
        if args.action is None:
            args.action = "list"
        cmd_override(args)
    elif args.command == "seed-db":
        cmd_seed_db(args)
    elif args.command == "lint-rules":
        cmd_lint_rules(args)
    elif args.command == "config":
        cmd_config(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
