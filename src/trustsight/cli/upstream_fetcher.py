"""Run the separate upstream archive fetcher."""

from __future__ import annotations

import typer

from ..upstream_fetcher_service import DEFAULT_SOCKET, serve
from .display import _print_colored

__all__ = ["register_commands"]

upstream_fetcher_app = typer.Typer(
    name="upstream-fetcher",
    help="Run the separate upstream archive fetcher (Unix socket).",
    no_args_is_help=True,
)


def register_commands(app: typer.Typer):
    app.add_typer(upstream_fetcher_app, name="upstream-fetcher")


@upstream_fetcher_app.callback(invoke_without_command=True)
def upstream_fetcher_cmd(
    socket_path: str = typer.Option(
        DEFAULT_SOCKET, "--socket",
        help="Unix socket to listen on; mount the same path into the watcher."),
):
    """Serve bounded, checksum-gated upstream reads."""
    try:
        serve(socket_path)
    except KeyboardInterrupt:
        raise typer.Exit(code=0) from None
    except Exception as exc:  # noqa: BLE001
        _print_colored(f"upstream-fetcher: {exc}", "red", stderr=True)
        raise typer.Exit(code=2) from None
