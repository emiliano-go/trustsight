"""Run the separate feed signer."""

from __future__ import annotations

import typer

from ..feed_signer_service import DEFAULT_SOCKET, serve
from .display import _print_colored

__all__ = ["register_commands"]

feed_signer_app = typer.Typer(
    name="feed-signer",
    help="Run the separate feed signer (Unix socket).",
    no_args_is_help=True,
)


def register_commands(app: typer.Typer):
    app.add_typer(feed_signer_app, name="feed-signer")


@feed_signer_app.callback(invoke_without_command=True)
def feed_signer_cmd(
    socket_path: str = typer.Option(
        DEFAULT_SOCKET, "--socket",
        help="Unix socket to listen on; mount the same path into the watcher."),
    audit_log: str | None = typer.Option(
        None, "--audit-log",
        help="Append one JSON record per signed body; refuses to sign if it cannot write."),
    audit_head: str | None = typer.Option(
        None, "--audit-head",
        help="Atomically publish the latest chain value for an external anchor."),
):
    """Sign bounded feed bodies without exposing the key to the watcher."""
    try:
        serve(socket_path, audit_log, audit_head)
    except KeyboardInterrupt:
        raise typer.Exit(code=0) from None
    except Exception as exc:  # noqa: BLE001
        _print_colored(f"feed-signer: {exc}", "red", stderr=True)
        raise typer.Exit(code=2) from None
