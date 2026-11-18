"""The ``diff`` command: compare an analysis with its last stored run."""

from __future__ import annotations

import json
from typing import Optional

import typer

from ..config import ensure_default_configs
from ..db import get_history, get_package_id, get_triggered_rules, init_db
from ..safe_text import clean
from ..scoring import stored_band, verdict_label
from .display import _print_colored


def register_commands(app: typer.Typer) -> None:
    @app.command("diff")
    def diff(
        package: str = typer.Argument(..., help="Package name"),
        since_last: bool = typer.Option(
            True, "--since-last/--no-since-last",
            help="Compare with the last stored analysis (the only mode in v1).",
        ),
        json_output: bool = typer.Option(False, "--json", help="Output JSON"),
        depth: Optional[int] = typer.Option(None, "--depth", help="Dependency depth"),
    ):
        """Show what changed since the last recorded analysis."""
        ensure_default_configs()
        init_db()
        if not since_last:
            msg = "--no-since-last is not supported; diff compares the last run"
            if json_output:
                typer.echo(json.dumps({"error": msg}))
            else:
                _print_colored(msg, "red", stderr=True)
            raise typer.Exit(code=2)

        pkg_id = get_package_id(package)
        if pkg_id is None:
            msg = f"Package '{package}' has no stored analysis; run inspect --record first"
            if json_output:
                typer.echo(json.dumps({"error": msg}))
            else:
                _print_colored(msg, "red", stderr=True)
            raise typer.Exit(code=2)
        previous = get_history(pkg_id, limit=1)
        if not previous:
            msg = f"Package '{package}' has no stored analysis; run inspect --record first"
            if json_output:
                typer.echo(json.dumps({"error": msg}))
            else:
                _print_colored(msg, "red", stderr=True)
            raise typer.Exit(code=2)

        from ..analysis import analyze_package

        fact = analyze_package(package, depth=depth)
        before = previous[0]
        old_score = int(before.get("final_score", 0) or 0)
        old_band, old_complete = stored_band(before)
        old_rules = {
            row.get("rule_id") for row in (get_triggered_rules(before["id"]) or ())
            if row.get("rule_id")
        }
        new_rules = {
            entry.rule_id for entry in (fact.score_breakdown or ())
            if getattr(entry, "rule_id", "")
        }
        new_score = int(getattr(fact, "final_score", 0) or 0)
        new_band = verdict_label(fact)
        payload = {
            "package": package,
            "previous": {
                "timestamp": before.get("timestamp", ""),
                "score": old_score,
                "risk": old_band,
                "complete": old_complete,
            },
            "current": {"score": new_score, "risk": new_band},
            "delta": new_score - old_score,
            "new": sorted(new_rules - old_rules),
            "resolved": sorted(old_rules - new_rules),
        }
        if json_output:
            typer.echo(json.dumps(payload, indent=2))
            return
        print(f"package: {clean(package)}")
        print(f"previous: {old_score}/100 ({old_band}) at {before.get('timestamp', '')}")
        print(f"current:  {new_score}/100 ({new_band})")
        print(f"delta:    {payload['delta']:+d}")
        print("new:      " + (", ".join(payload["new"]) or "(none)"))
        print("resolved: " + (", ".join(payload["resolved"]) or "(none)"))
