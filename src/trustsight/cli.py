import argparse
import json

from .analysis import analyze_package, discover_updates
from .config import ensure_default_configs, load_config
from .db import get_history, get_package_id, get_triggered_rules, init_db
from .scoring import risk_level

RISK_COLORS = {"Low": "green", "Medium": "yellow", "High": "red", "Critical": "bold red"}

try:
    from rich.console import Console
    from rich.table import Table
    from rich.text import Text

    HAS_RICH = True
except ImportError:
    HAS_RICH = False


def cmd_review(args):
    ensure_default_configs()
    config = load_config()
    limit = args.limit or config.get("limits", {}).get("default_review_limit", 20)

    results = discover_updates(limit=limit)

    if not results:
        print("No outdated AUR packages found.")
        return

    if HAS_RICH:
        console = Console()
        table = Table(title="TrustSight Review")
        table.add_column("Package", style="cyan")
        table.add_column("Score", justify="right")
        table.add_column("Verdict")

        for r in results:
            score_text = Text(f"{r['score']}/100", style=RISK_COLORS.get(r["risk"], "white"))
            table.add_row(r["package"], score_text, r["verdict"])

        console.print(table)
    else:
        print(f"{'Package':<20} {'Score':<10} Verdict")
        print("-" * 80)
        for r in results:
            print(f"{r['package']:<20} {r['score']:<10} {r['verdict']}")


def cmd_inspect(args):
    ensure_default_configs()
    init_db()

    fact = analyze_package(args.package)

    if HAS_RICH:
        console = Console()
        console.print(f"\n[bold cyan]TrustSight Inspect: {fact.package_name}[/]")
        console.print(f"  Version: {fact.old_version} → {fact.new_version}")
        console.print(f"  Score: {fact.final_score}/100 [bold {RISK_COLORS.get(risk_level(fact.final_score), 'white')}]({risk_level(fact.final_score)})[/]")

        if fact.maintainer_changed:
            console.print(f"  [yellow]Maintainer changed: {fact.previous_maintainer} → {fact.current_maintainer}[/]")

        console.print("\n  [underline]Diff Summary[/]")
        console.print(f"  Files changed: {', '.join(fact.diff_summary.files_changed) or 'none'}")
        console.print(f"  Lines: +{fact.diff_summary.lines_added}/-{fact.diff_summary.lines_removed}")

        if fact.source_changes.added_urls:
            console.print("\n  [underline]Source URLs Added[/]")
            for url in fact.source_changes.added_urls:
                bucket = fact.source_buckets.get(url, "unknown")
                console.print(f"    {url} [dim]({bucket})[/]")

        if fact.execution_changes.resolved_commands:
            console.print("\n  [underline]Resolved Commands[/]")
            for cmd in fact.execution_changes.resolved_commands:
                console.print(f"    {cmd}")

        if fact.score_breakdown:
            console.print("\n  [underline]Score Breakdown[/]")
            for entry in fact.score_breakdown:
                sign = "+" if entry.weight >= 0 else ""
                style = RISK_COLORS.get(entry.severity.capitalize(), "white")
                console.print(f"  {sign}{entry.weight} [{style}]{entry.severity}[/]  {entry.rule_id}  {entry.reason[:80]}")

        console.print("\n  [underline]Verdict[/]")
        from .llm import fallback_verdict
        console.print(f"  {fallback_verdict(fact)}")
    else:
        print(json.dumps(type("fact_dict", (), {}).__class__.__dict__, indent=2))


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
        console = Console()
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

        console.print(table)

        if args.score_breakdown and history:
            latest = history[0]
            rules = get_triggered_rules(latest["id"])
            if rules:
                console.print("\n  [underline]Latest Score Breakdown[/]")
                for r in rules:
                    sign = "+"
                    console.print(f"  {sign}{r['severity']:<10} {r['rule_id']}")
    else:
        for h in history:
            print(f"{h.get('timestamp','')[:10]:<12} {str(h.get('old_version','')):<12} → {str(h.get('new_version','')):<12} Score: {h.get('final_score',0)}")


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

    args = parser.parse_args()

    if args.command == "review":
        cmd_review(args)
    elif args.command == "inspect":
        cmd_inspect(args)
    elif args.command == "history":
        cmd_history(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
