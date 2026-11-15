"""Check or watch the signer audit head against an off-host anchor."""

from __future__ import annotations

import typer

from ..audit_anchor import AnchorError, check, watch
from .display import _print_colored

__all__ = ["register_commands"]

audit_anchor_app = typer.Typer(
    name="audit-anchor",
    help="Check the signer audit head against an off-host anchor.",
    no_args_is_help=True,
)


def register_commands(app: typer.Typer):
    app.add_typer(audit_anchor_app, name="audit-anchor")


@audit_anchor_app.command("check")
def check_cmd(
    head: str = typer.Option(..., "--head", help="signer head.json"),
    expected: str | None = typer.Option(None, "--expected"),
    expected_file: str | None = typer.Option(None, "--expected-file"),
):
    """Exit 0 when the head matches, 2 otherwise."""
    try:
        _print_colored(check(head, expected=expected,
                             expected_file=expected_file), "green")
    except AnchorError as exc:
        _print_colored(f"audit-anchor: {exc}", "red", stderr=True)
        raise typer.Exit(code=2) from None


@audit_anchor_app.command("watch")
def watch_cmd(
    head: str = typer.Option(..., "--head"),
    expected: str | None = typer.Option(None, "--expected"),
    expected_file: str | None = typer.Option(None, "--expected-file"),
    interval: float = typer.Option(300.0, "--interval",
                                   help="Seconds between checks."),
):
    """Poll the head; a mismatch exits non-zero."""
    try:
        watch(head, expected=expected, expected_file=expected_file,
              interval_seconds=interval)
    except KeyboardInterrupt:
        raise typer.Exit(code=0) from None
    except AnchorError as exc:
        _print_colored(f"audit-anchor: {exc}", "red", stderr=True)
        raise typer.Exit(code=2) from None
