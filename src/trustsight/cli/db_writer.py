"""Run the narrow database writer."""
from __future__ import annotations

import typer

from ..db_writer_service import DEFAULT_SOCKET, serve
from .display import _print_colored

__all__ = ["register_commands"]

db_writer_app = typer.Typer(
    name="db-writer",
    help="Own the writable database handle and serve narrow writes.",
    no_args_is_help=True,
)


def register_commands(app: typer.Typer):
    app.add_typer(db_writer_app, name="db-writer")


@db_writer_app.callback(invoke_without_command=True)
def db_writer_cmd(
    socket_path: str = typer.Option(DEFAULT_SOCKET, "--socket"),
    db_path: str = typer.Option(..., "--db"),
    audit_log: str | None = typer.Option(None, "--audit-log"),
):
    """Serve INSERT/UPDATE writes over a Unix socket; DELETE and DDL are refused."""
    try:
        serve(socket_path, db_path, audit_log)
    except KeyboardInterrupt:
        raise typer.Exit(code=0) from None
    except Exception as exc:  # noqa: BLE001
        _print_colored(f"db-writer: {exc}", "red", stderr=True)
        raise typer.Exit(code=2) from None
