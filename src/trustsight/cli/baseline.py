import json
import logging

import typer

from ..config import ensure_default_configs
from ..db import init_db
from .display import _print_colored

log = logging.getLogger(__name__)

baseline_app = typer.Typer(
    help="Build or import a full-AUR baseline corpus",
    no_args_is_help=True, add_completion=False,
)


# --- baseline subcommands ---

@baseline_app.command("build")
def baseline_build(
    resume: bool = typer.Option(False, "--resume", help="Continue an interrupted bootstrap (now implied: cycles resume automatically)"),
    bootstrap: bool = typer.Option(False, "--bootstrap", help="Allow a from-scratch bootstrap of the whole AUR when no snapshot exists (capped per cycle, resumes)"),
    export: str | None = typer.Option(None, "--export", help="Path to write the baseline artifact"),
    sign: str | None = typer.Option(None, "--sign", help="Path to ed25519 private key for signing"),
    json_output: bool = typer.Option(False, "--json", help="Output JSON"),
):
    """Bootstrap or update the full-AUR baseline corpus."""
    from .. import release
    from ..full_aur.pipeline import run_baseline_build
    ensure_default_configs()
    init_db()
    if release.offline():
        msg = "baseline build needs the AUR network channel; TRUSTSIGHT_OFFLINE is set."
        if json_output:
            typer.echo(json.dumps({"error": msg}))
        else:
            _print_colored(msg, "red", stderr=True)
        raise typer.Exit(code=2)
    result = run_baseline_build(resume=resume, export_path=export, sign_key=sign, json_output=json_output, bootstrap=bootstrap)
    if result.refused:
        raise typer.Exit(code=2)


@baseline_app.command("import")
def baseline_import(
    path: str = typer.Argument(..., help="Path to the baseline artifact (.tar.zst)"),
    allow_unsigned: bool = typer.Option(False, "--allow-unsigned", help="Allow unsigned artifacts (local builds only)"),
    json_output: bool = typer.Option(False, "--json", help="Output JSON"),
):
    """Import a signed baseline corpus artifact."""
    ensure_default_configs()
    init_db()
    _import_baseline_wrapped(path, json_output, allow_unsigned)


def _import_baseline_wrapped(path: str, json_output: bool, allow_unsigned: bool) -> None:
    """Import a corpus baseline, turning failure into a structured exit 2.

    Errors (missing file, malformed artifact, bad signature, missing
    cryptography) are reported like every other failure path: as JSON when
    ``--json`` is set, otherwise as a single colored line.
    """
    from ..full_aur.export import import_baseline
    try:
        import_baseline(path, json_output=json_output, allow_unsigned=allow_unsigned)
    except Exception as exc:
        msg = str(exc) or exc.__class__.__name__
        if json_output:
            typer.echo(json.dumps({"error": msg}))
        else:
            _print_colored(msg, "red", stderr=True)
        raise typer.Exit(code=2)


def register_commands(app: typer.Typer):
    """Register the ``baseline`` group and the ``import-baseline`` command on *app*."""
    app.add_typer(baseline_app, name="baseline")

    @app.command("import-baseline")
    def import_baseline_cmd(
        path: str = typer.Argument(..., help="Path to the baseline artifact (.tar.zst)"),
        allow_unsigned: bool = typer.Option(False, "--allow-unsigned", help="Allow unsigned artifacts (local builds only)"),
        json_output: bool = typer.Option(False, "--json", help="Output JSON"),
    ):
        """Import a signed baseline corpus artifact."""
        ensure_default_configs()
        init_db()
        _import_baseline_wrapped(path, json_output, allow_unsigned)
