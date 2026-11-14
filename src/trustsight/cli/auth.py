"""Manage provider tokens for the optional upstream-scan lane.

The token is never a positional or ``--token`` argument: a value on the command
line lands in the process table and the shell history.  ``login`` prompts with
hidden input by default, and ``--stdin`` / ``--file`` exist so a script or a
CI job can pass a secret without putting it on an argument list.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer

from ..credentials import (
    PROVIDERS,
    CredentialError,
    delete_token,
    normalize_provider,
    resolve_token,
    store_token,
    token_from_stdin,
)
from .display import _print_colored

__all__ = ["register_commands"]

auth_app = typer.Typer(
    name="auth",
    help="Manage provider tokens (OS keyring / secret file).",
    no_args_is_help=True,
)


def register_commands(app: typer.Typer):
    """Register the ``auth`` subcommand group on *app*."""
    app.add_typer(auth_app, name="auth")


def _read_token(stdin: bool, file: Optional[str]) -> str:
    if stdin and file:
        raise CredentialError("choose --stdin or --file, not both")
    if stdin:
        return token_from_stdin()
    if file:
        try:
            text = Path(file).expanduser().read_text(encoding="utf-8")
        except OSError as exc:
            raise CredentialError(f"could not read {file}: {exc}") from exc
        return text.strip()
    # Hidden prompt: the token is not echoed and is not in argv or history.
    return typer.prompt("Token", hide_input=True, confirmation_prompt=False).strip()


@auth_app.command("login")
def auth_login(
    provider: str = typer.Argument(..., help="github, gitlab, codeberg, bitbucket"),
    stdin: bool = typer.Option(
        False, "--stdin",
        help="Read the token from stdin (for `read -rsp` or a CI secret)."),
    file: Optional[str] = typer.Option(
        None, "--file", help="Read the token from a file (prefer --stdin)."),
):
    """Store a provider token in the OS keyring.

    Nothing is printed but a label.  With no usable keyring, the error names
    the ``0600`` token-file alternative rather than writing a plaintext file.
    """
    try:
        provider = normalize_provider(provider)
        token = _read_token(stdin, file)
        if not token:
            _print_colored("empty token; nothing stored", "red", stderr=True)
            raise typer.Exit(code=2)
        store_token(provider, token)
    except CredentialError as exc:
        _print_colored(f"trustsight auth: {exc}", "red", stderr=True)
        raise typer.Exit(code=2) from None
    _print_colored(
        f"stored {provider} token (ending {token[-4:]}) in the OS keyring",
        "green",
    )


@auth_app.command("status")
def auth_status():
    """Show which providers have a token and where it comes from (no value)."""
    any_token = False
    for provider in PROVIDERS:
        try:
            secret = resolve_token(provider)
        except CredentialError as exc:
            _print_colored(f"{provider:10} unavailable: {exc}", "yellow")
            continue
        if secret is None:
            _print_colored(f"{provider:10} no token", "yellow")
            continue
        any_token = True
        _print_colored(f"{provider:10} configured (ending {secret.label})", "green")
    if not any_token:
        _print_colored(
            "no provider tokens configured; upstream scan will run "
            "anonymously (rate limited)", "yellow")


@auth_app.command("logout")
def auth_logout(
    provider: str = typer.Argument(..., help="github, gitlab, codeberg, bitbucket"),
):
    """Remove a provider token from the OS keyring."""
    try:
        provider = normalize_provider(provider)
    except CredentialError as exc:
        _print_colored(f"trustsight auth: {exc}", "red", stderr=True)
        raise typer.Exit(code=2) from None
    if delete_token(provider):
        _print_colored(f"removed the {provider} token from the OS keyring", "green")
    else:
        _print_colored(f"no {provider} token was stored", "yellow")
