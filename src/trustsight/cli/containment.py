"""Report active container containment controls."""

from __future__ import annotations

import json

import typer

from ..containment import status

__all__ = ["register_commands"]

containment_app = typer.Typer(
    name="containment",
    help="Report the runtime containment controls this process sees.",
    no_args_is_help=True,
)


def register_commands(app: typer.Typer):
    app.add_typer(containment_app, name="containment")


@containment_app.command("status")
def status_cmd(
    as_json: bool = typer.Option(False, "--json",
                                 help="Emit one JSON object."),
):
    """Print uid, seccomp, AppArmor, root read-only and default route."""
    value = status()
    if as_json:
        typer.echo(json.dumps(value, sort_keys=True))
        return
    for key in sorted(value):
        typer.echo(f"{key}: {value[key]}")
