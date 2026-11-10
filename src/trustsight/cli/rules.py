"""``trustsight rules``: the rule registry, in its one shared order.

Every rule's permanent uid, category and status, listed in the same
series-major order the reference pages and the catalog use
(:func:`trustsight.registry.sort_key`).  This is the CLI face of that
ordering: it cannot disagree with the docs because both read the registry.
"""

from __future__ import annotations

import json

import typer

from ..categories import RuleCategory
from ..registry import REGISTRY
from .display import _print_colored, emit, use_rich


def register_commands(app: typer.Typer):
    """Register the ``rules`` subcommand on *app*."""

    @app.command("rules")
    def rules(
        category: str = typer.Option(
            None, "--category", help="Only rules in this RuleCategory slug."
        ),
        json_output: bool = typer.Option(False, "--json", help="Output JSON"),
    ):
        """List every detection rule, in the one registry order."""
        if category is not None:
            try:
                wanted = RuleCategory(category)
            except ValueError:
                valid = ", ".join(c.value for c in RuleCategory)
                _print_colored(
                    f"--category must be one of: {valid} (got '{category}')",
                    "red",
                    stderr=True,
                )
                raise typer.Exit(code=2)
            listed = REGISTRY.in_category(wanted)
        else:
            listed = REGISTRY.all()

        rows = [
            {
                "id": rule.id,
                "uid": rule.uid,
                "series": rule.series,
                "category": rule.category.value,
                "status": rule.status,
                "aliases": list(rule.aliases),
            }
            for rule in listed
        ]

        if json_output:
            typer.echo(json.dumps(rows, indent=2))
            return

        if use_rich():
            from ..sandbox.render_client import render

            emit(render("rules_table", {"rows": rows}))
        else:
            print(f"{'Rule':<8} {'UID':<9} {'Category':<22} Status")
            print("-" * 60)
            for row in rows:
                print(
                    f"{row['id']:<8} {row['uid']:<9} "
                    f"{row['category']:<22} {row['status']}"
                )
