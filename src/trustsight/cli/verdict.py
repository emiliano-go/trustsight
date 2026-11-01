"""Record a human review verdict for the tender-point ledger."""

from __future__ import annotations

import json
import sqlite3

import typer

from ..safe_text import clean


def register_commands(app: typer.Typer):
    """Register the ``verdict`` command on *app*."""

    @app.command()
    def verdict(
        package: str = typer.Argument(..., help="Package the verdict is about."),
        disposition: str = typer.Option(
            ..., "--verdict",
            help="confirmed, cleared or uncertain."),
        rule: str = typer.Option(
            "", "--rule", help="Rule id the verdict applies to (optional)."),
        campaign: str = typer.Option(
            "", "--campaign", help="Campaign id (optional)."),
        note: str = typer.Option(
            "", "--note", help="Short human note (optional)."),
        json_output: bool = typer.Option(False, "--json", help="Output JSON"),
    ):
        """Record a review verdict for the tender-point ledger."""
        from ..db import init_db, record_verdict

        try:
            init_db()
            record_verdict(package, disposition, rule_id=rule,
                           campaign_id=campaign, note=note)
        except (ValueError, RuntimeError, sqlite3.Error, OSError) as exc:
            if json_output:
                typer.echo(json.dumps({"error": str(exc)}))
            else:
                typer.echo(clean(str(exc)), err=True)
            raise typer.Exit(code=2)
        if json_output:
            typer.echo(json.dumps({
                "package": package,
                "rule_id": rule,
                "verdict": disposition.lower(),
                "campaign_id": campaign,
            }, indent=2))
            return
        print(f"Recorded {disposition.lower()} for {clean(package)}"
              + (f" ({clean(rule)})" if rule else ""))
