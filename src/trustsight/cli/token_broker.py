"""Run the local short-lived token broker."""

from __future__ import annotations

import typer

from ..token_broker_service import DEFAULT_SOCKET, serve
from .display import _print_colored

__all__ = ["register_commands"]

token_broker_app = typer.Typer(
    name="token-broker",
    help="Serve provider tokens over a local Unix socket.",
    no_args_is_help=True,
)


def register_commands(app: typer.Typer):
    app.add_typer(token_broker_app, name="token-broker")


@token_broker_app.callback(invoke_without_command=True)
def token_broker_cmd(
    socket_path: str = typer.Option(DEFAULT_SOCKET, "--socket"),
    token_dir: str = typer.Option("/run/trustsight/tokens", "--token-dir"),
):
    """Serve `<provider>.token` and optional `<provider>.expires` files."""
    try:
        serve(socket_path, token_dir)
    except KeyboardInterrupt:
        raise typer.Exit(code=0) from None
    except Exception as exc:  # noqa: BLE001
        _print_colored(f"token-broker: {exc}", "red", stderr=True)
        raise typer.Exit(code=2) from None
