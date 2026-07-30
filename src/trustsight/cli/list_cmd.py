import json

import typer

from ..config import ensure_default_configs
from ..db import get_all_packages, get_last_analysis, init_db
from ..scoring import risk_level
from .display import (
    HAS_RICH,
    RISK_COLORS,
    _print_colored,
    _score_text,
    console,
    display_version,
)


def register_commands(app: typer.Typer):
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
            score = last["final_score"] if last else None
            rows.append({
                "name": pkg["name"],
                "version": display_version(pkg.get("current_version")),
                "last_checked": pkg["last_checked"] or "",
                "score": score,
                "risk": risk_level(score) if last else "\u2014",
                "maintainer": pkg["current_maintainer"] or "",
            })

        if json_output:
            typer.echo(json.dumps(rows, indent=2))
            return

        if HAS_RICH:
            from rich.table import Table
            from rich.text import Text

            con = console()
            table = Table(title=f"Tracked packages ({len(rows)} total)")
            table.add_column("Package", style="cyan", no_wrap=True)
            table.add_column("Version")
            table.add_column("Maintainer", overflow="ellipsis")
            table.add_column("Last Checked")
            table.add_column("Score", justify="right")
            table.add_column("Risk")
            for r in rows:
                score = r["score"]
                version = r["version"]
                risk = r["risk"]
                if score is not None:
                    score_cell = _score_text(score, risk)
                elif version == "unresolved" or version == "\u2014":
                    score_cell = Text("\u2014", style="dim")
                else:
                    score_cell = Text("\u2014", style="dim")
                if risk == "\u2014" or risk == "Inconclusive":
                    risk_obj = Text(risk, style="yellow")
                else:
                    risk_obj = Text(risk, style=RISK_COLORS.get(risk, "white"))
                table.add_row(
                    r["name"],
                    version,
                    r["maintainer"] or "[dim]-[/]",
                    r["last_checked"][:10] if r["last_checked"] else "[dim]-[/]",
                    score_cell,
                    risk_obj,
                )
            con.print(table)
        else:
            print(f"{'Package':<20} {'Version':<15} {'Score':<8} {'Risk':<12} Last Checked")
            print("-" * 75)
            for r in rows:
                score = "\u2014" if r["score"] is None else str(r["score"])
                checked = r["last_checked"][:10] if r["last_checked"] else "-"
                print(f"{r['name']:<20} {r['version']:<15} {score:<8} {r['risk']:<12} {checked}")
