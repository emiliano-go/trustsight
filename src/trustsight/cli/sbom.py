"""The ``trustsight sbom`` command."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer

from ..config import ensure_default_configs, load_config
from ..db import init_db, maybe_auto_import_seed
from ..safe_text import clean

__all__ = ["register_commands"]


def register_commands(app: typer.Typer) -> None:
    """Register the ``sbom`` command on *app*."""

    @app.command("sbom")
    def sbom(
        package: str = typer.Argument(..., help="Package name"),
        format_name: str = typer.Option(
            "cyclonedx", "--format",
            help="SBOM format; only cyclonedx is supported.",
        ),
        out: Optional[Path] = typer.Option(
            None, "--out",
            help="Write the document to FILE instead of stdout.",
        ),
    ):
        """Export a deterministic CycloneDX 1.5 SBOM for one package."""
        if format_name.lower() != "cyclonedx":
            typer.echo(
                f"unsupported SBOM format: {clean(format_name)} "
                "(only cyclonedx)",
                err=True,
            )
            raise typer.Exit(code=2)

        ensure_default_configs()
        init_db()
        config = load_config()
        if config.get("seed", {}).get("auto_import", True):
            maybe_auto_import_seed(quiet=True, allow_release_fetch=True)

        from ..sbom import render_sbom, sbom_for_package

        try:
            bom = sbom_for_package(package)
        except Exception as exc:
            typer.echo(
                f"SBOM for '{clean(package)}' failed: {clean(str(exc))}",
                err=True,
            )
            raise typer.Exit(code=2)

        text = render_sbom(bom)
        if out is None:
            typer.echo(text, nl=False)
            return
        try:
            out.write_text(text, encoding="utf-8")
        except OSError as exc:
            typer.echo(
                f"could not write '{clean(str(out))}': {clean(str(exc))}",
                err=True,
            )
            raise typer.Exit(code=2)
