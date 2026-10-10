import json

import typer

from ..config import ensure_default_configs
from ..coverage import GAP_REASONS
from ..db import get_history, get_package_id, get_triggered_rules, init_db
from ..safe_text import clean
from ..scoring import stored_band
from .completion import tracked_packages
from .display import (
    band_colour,
    _print_colored,
    _severity_text,
    console,
    display_version,
    use_rich,
)


def _validate_date(date_str: str | None, label: str) -> str | None:
    """Validate and normalise a date string for SQL comparison.

    Accepts ``YYYY-MM-DD`` or full ISO datetime.  Returns the string
    unchanged if valid, or raises typer.Exit(2) with a message.
    """
    if date_str is None:
        return None
    import re
    if re.match(r"^\d{4}-\d{2}-\d{2}$", date_str):
        return date_str  # bare date, OK
    if re.match(r"^\d{4}-\d{2}-\d{2}T", date_str):
        return date_str  # full ISO, OK
    msg = f"{label} must be YYYY-MM-DD or ISO datetime (got '{date_str}')"
    _print_colored(msg, "red", stderr=True)
    raise typer.Exit(code=2)


def _stored_coverage_gaps(row: dict) -> list[str]:
    """The coverage gaps a stored analysis row carried, [] for old rows."""
    raw = row.get("fact_json")
    if not raw:
        return []
    try:
        fact = json.loads(raw)
    except (ValueError, TypeError):
        return []
    if not isinstance(fact, dict):
        return []
    return list(fact.get("coverage_gaps") or [])


def _gap_summary(gaps: list[str]) -> str:
    return "; ".join(GAP_REASONS.get(g, g) for g in gaps)


def register_commands(app: typer.Typer):
    """Register the ``history`` subcommand on *app*."""
    @app.command()
    def history(
        package: str = typer.Argument(..., help="Package name", autocompletion=tracked_packages),
        limit: int = typer.Option(20, "--limit", help="Max history entries"),
        score_breakdown: bool = typer.Option(False, "--score-breakdown", help="Show score breakdown"),
        json_output: bool = typer.Option(False, "--json", help="Output JSON"),
        from_date: str = typer.Option(None, "--from-date", help="Show entries from this date (YYYY-MM-DD) onward"),
        to_date: str = typer.Option(None, "--to-date", help="Show entries up to and including this date (YYYY-MM-DD)"),
    ):
        """Show analysis history for a package."""
        ensure_default_configs()
        init_db()
        if limit < 0:
            msg = "--limit must be 0 (all entries) or a positive count"
            if json_output:
                typer.echo(json.dumps({"error": msg}))
            else:
                _print_colored(msg, "red", stderr=True)
            raise typer.Exit(code=2)
        # 0 means "all entries", matching review/list conventions.
        effective_limit = limit or None

        from_date = _validate_date(from_date, "--from-date")
        to_date = _validate_date(to_date, "--to-date")

        pkg_id = get_package_id(package)
        if pkg_id is None:
            msg = (f"Package '{package}' has not been analysed yet. "
                   f"Run 'trustsight inspect --record {package}' first.")
            if json_output:
                typer.echo(json.dumps({"error": msg}))
            else:
                _print_colored(msg, "yellow", stderr=True)
            raise typer.Exit(code=2)

        history_records = get_history(pkg_id, limit=effective_limit, from_date=from_date, to_date=to_date)

        if not history_records:
            if json_output:
                typer.echo(json.dumps([]))
            else:
                print(f"No analysis history for '{package}'. "
                      f"Record an analysis with 'trustsight inspect --record {package}'.")
            return

        if json_output:
            data = []
            for h in history_records:
                band, complete = stored_band(h)
                item = {
                    "id": h.get("id"),
                    "timestamp": h.get("timestamp", ""),
                    "old_version": display_version(h.get("old_version")),
                    "new_version": display_version(h.get("new_version")),
                    "old_commit": h.get("old_commit") or "",
                    "new_commit": h.get("new_commit") or "",
                    "score": h.get("final_score", 0),
                    "risk": band,
                    "complete": complete,
                }
                gaps = _stored_coverage_gaps(h)
                if gaps:
                    item["coverage_gaps"] = gaps
                if score_breakdown:
                    rules = get_triggered_rules(h["id"])
                    if rules:
                        item["triggered_rules"] = rules
                data.append(item)
            typer.echo(json.dumps(data, indent=2))
            return

        if use_rich():
            from rich.box import SIMPLE_HEAD
            from rich.table import Table
            from rich.text import Text

            con = console()
            table = Table(title=Text(f"History: {clean(package)}"))
            table.add_column("ID", style="dim", justify="right")
            table.add_column("Date", style="dim")
            table.add_column("Old", justify="right")
            table.add_column("-> New", justify="right")
            table.add_column("Score", justify="right")
            table.add_column("Risk")

            for h in history_records:
                ts = h.get("timestamp", "")[:10] if h.get("timestamp") else ""
                score = h.get("final_score", 0)
                band, complete = stored_band(h)
                score_text = Text(f"{score}/100", style=band_colour(band))
                risk_text = Text(clean(band))
                if not complete:
                    risk_text.append(" (incomplete)", style="yellow")
                table.add_row(str(h.get("id", "")), ts, display_version(h.get("old_version")), display_version(h.get("new_version")), score_text, risk_text)

            con.print(table)

            if score_breakdown and history_records:
                rules = get_triggered_rules(history_records[0]["id"])
                if rules:
                    bd = Table(title="Latest run: rules that fired", box=SIMPLE_HEAD)
                    bd.add_column("Rule", style="cyan")
                    bd.add_column("Severity")
                    for r in rules:
                        bd.add_row(Text(clean(r["rule_id"])), _severity_text(r["severity"]))
                    con.print(bd)
                else:
                    con.print("[dim]No rules fired on the latest run.[/]")
        else:
            for h in history_records:
                band, complete = stored_band(h)
                gaps = _stored_coverage_gaps(h)
                incomplete = "" if complete else f"  [INCOMPLETE: {_gap_summary(gaps)}]"
                print(
                    f"{h.get('timestamp','')[:10]:<12} "
                    f"{display_version(h.get('old_version')):<12} -> "
                    f"{display_version(h.get('new_version')):<12} "
                    f"Score: {h.get('final_score',0)}/100 ({band}) "
                    f"#{h.get('id', '')}{incomplete}"
                )
