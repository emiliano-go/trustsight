import json

import typer

from ..config import ensure_default_configs
from ..db import get_history, get_package_id, get_triggered_rules, init_db
from ..scoring import risk_level
from .display import (
    HAS_RICH,
    RISK_COLORS,
    SIMPLE_HEAD,
    _severity_text,
    console,
    display_version,
)


def register_commands(app: typer.Typer):
    @app.command()
    def history(
        package: str = typer.Argument(..., help="Package name"),
        limit: int = typer.Option(20, "--limit", help="Max history entries"),
        score_breakdown: bool = typer.Option(False, "--score-breakdown", help="Show score breakdown"),
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
                    "old_version": display_version(h.get("old_version")),
                    "new_version": display_version(h.get("new_version")),
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
            from rich.table import Table
            from rich.text import Text

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
                table.add_row(ts, display_version(h.get("old_version")), display_version(h.get("new_version")), score_text, risk)

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
                    f"{display_version(h.get('old_version')):<12} -> "
                    f"{display_version(h.get('new_version')):<12} "
                    f"Score: {h.get('final_score',0)}"
                )
