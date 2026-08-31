import json

import typer

from ..config import ensure_default_configs
from ..db import get_all_packages, get_last_analysis, init_db
from ..safe_text import clean
from ..scoring import stored_band
from .display import (
    band_colour,
    HAS_RICH,
    _print_colored,
    _score_text,
    console,
    display_version,
)


# Risk levels ordered worst-first for --sort risk.
_RISK_SORT_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Inconclusive": 3, "Low": 4, "-": 5}
_VALID_SORT = ("score", "risk", "name", "last-checked")


def _sort_key(sort_by: str | None, row: dict):
    """Return a sort key tuple for *row* given a --sort value."""
    if sort_by == "score":
        score = row.get("score")
        if score is None:
            return (1, 0)  # unanalysed packages sink
        return (0, -score)  # worst first
    if sort_by == "risk":
        risk = row.get("risk", "-") or "-"
        return (_RISK_SORT_ORDER.get(risk, 5),)
    if sort_by == "name":
        return (0, row.get("name", "").lower())
    if sort_by == "last-checked":
        ts = row.get("last_checked", "") or ""
        return (0, ts)  # oldest first; reverse for most-recent first
    return (0, 0)


def register_commands(app: typer.Typer):
    @app.command("list")
    def list_cmd(
        limit: int = typer.Option(0, "--limit", help="Max packages to show (0 = unlimited)"),
        json_output: bool = typer.Option(False, "--json", help="Output JSON"),
        sort_by: str = typer.Option(
            None, "--sort",
            help=f"Sort results: {', '.join(_VALID_SORT)}. Default: alphabetical.",
        ),
    ):
        """List all packages tracked in the database with their latest score."""
        ensure_default_configs()
        init_db()
        if limit < 0:
            msg = "--limit must be 0 (unlimited) or a positive count"
            if json_output:
                typer.echo(json.dumps({"error": msg}))
            else:
                _print_colored(msg, "red", stderr=True)
            raise typer.Exit(code=2)
        if sort_by is not None and sort_by not in _VALID_SORT:
            msg = f"--sort must be one of: {', '.join(_VALID_SORT)} (got '{sort_by}')"
            if json_output:
                typer.echo(json.dumps({"error": msg}))
            else:
                _print_colored(msg, "red", stderr=True)
            raise typer.Exit(code=2)

        all_pkgs = get_all_packages()

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
            band, _complete = stored_band(last, score) if last else ("-", False)
            rows.append({
                "name": pkg["name"],
                "version": display_version(pkg.get("current_version")),
                "last_checked": pkg["last_checked"] or "",
                "score": score,
                "risk": band,
                "verdict": band,
                "maintainer": pkg["current_maintainer"] or "",
            })

        # Apply limit after building all rows.
        if limit:
            rows = rows[:limit]

        # Sort when --sort is given.
        if sort_by and rows:
            rows.sort(key=lambda r: _sort_key(sort_by, r))

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
                else:
                    score_cell = Text("-", style="dim")
                if risk == "-" or risk == "Inconclusive":
                    risk_obj = Text(risk, style="yellow")
                else:
                    risk_obj = Text(risk, style=band_colour(risk))
                table.add_row(
                    Text(clean(r["name"])),
                    Text(version),
                    Text(clean(r["maintainer"])) if r["maintainer"] else "[dim]-[/]",
                    r["last_checked"][:10] if r["last_checked"] else "[dim]-[/]",
                    score_cell,
                    risk_obj,
                )
            con.print(table)
        else:
            print(f"{'Package':<20} {'Version':<15} {'Score':<8} {'Risk':<12} Last Checked")
            print("-" * 75)
            for r in rows:
                score = "-" if r["score"] is None else str(r["score"])
                checked = r["last_checked"][:10] if r["last_checked"] else "-"
                print(f"{clean(r['name']):<20} {r['version']:<15} {score:<8} {r['risk']:<12} {checked}")
