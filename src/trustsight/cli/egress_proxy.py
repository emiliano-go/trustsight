"""Run the allowlisted CONNECT egress proxy."""

from __future__ import annotations

import os

import typer

from ..egress_proxy import serve
from .display import _print_colored

__all__ = ["register_commands"]

egress_proxy_app = typer.Typer(
    name="egress-proxy",
    help="Run the allowlisted CONNECT proxy for the upstream fetcher.",
    no_args_is_help=True,
)


def register_commands(app: typer.Typer):
    app.add_typer(egress_proxy_app, name="egress-proxy")


@egress_proxy_app.callback(invoke_without_command=True)
def egress_proxy_cmd(
    listen: str = typer.Option("127.0.0.1:3128", "--listen"),
    audit_log: str | None = typer.Option(
        None, "--audit-log", help="Append one JSON record per CONNECT."),
    auth_token: str | None = typer.Option(
        os.environ.get("TRUSTSIGHT_PROXY_TOKEN") or None,
        "--auth-token", help="Require Basic proxy auth with this password."),
    alert_url: str | None = typer.Option(
        os.environ.get("TRUSTSIGHT_PROXY_ALERT_URL") or None,
        "--alert-url", help="POST refused CONNECT alerts to this URL."),
):
    """Serve CONNECT only to the forge/CDN allowlist."""
    try:
        serve(listen, audit_log, auth_token, alert_url)
    except KeyboardInterrupt:
        raise typer.Exit(code=0) from None
    except Exception as exc:  # noqa: BLE001
        _print_colored(f"egress-proxy: {exc}", "red", stderr=True)
        raise typer.Exit(code=2) from None
