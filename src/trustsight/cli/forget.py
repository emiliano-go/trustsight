import json

import typer

from ..config import ensure_default_configs
from ..safe_text import clean
from ..db import (
    forget_package,
    forget_prune,
    get_all_packages,
    init_db,
)
from ..discovery import get_aur_package_info
from .display import _print_colored


def register_commands(app: typer.Typer):
    @app.command()
    def forget(
        packages: list[str] = typer.Argument(None, help="Package name(s) to forget"),
        prune: bool = typer.Option(False, "--prune", help="Remove packages not in the AUR"),
        dry_run: bool = typer.Option(False, "--dry-run", help="Show what would be removed without deleting"),
        yes: bool = typer.Option(False, "--yes", help="Skip confirmation prompt"),
        json_output: bool = typer.Option(False, "--json", help="Output JSON"),
    ):
        """Remove a tracked package and all its history.

        Provide one or more package names, or use --prune to remove every
        tracked package that no longer exists in the AUR.
        """
        ensure_default_configs()
        init_db()

        if not packages and not prune:
            typer.echo("Usage: trustsight forget <package>...  or  trustsight forget --prune")
            raise typer.Exit(code=2)

        if prune:
            all_pkgs = get_all_packages()
            names = [p["name"] for p in all_pkgs]
            if not names:
                if json_output:
                    typer.echo(json.dumps({"prune": "nothing_to_do"}))
                else:
                    typer.echo("No packages tracked.")
                return
            info = get_aur_package_info(names)
            aur_names = set(info.keys())
            if not aur_names and names:
                msg = ("AUR RPC returned no data; cannot determine which packages "
                       "still exist. Check your network connection and try again.")
                if json_output:
                    typer.echo(json.dumps({"error": msg}))
                else:
                    _print_colored(msg, "red")
                raise typer.Exit(code=2)
            removed = forget_prune(aur_names, dry_run=dry_run)
            if json_output:
                typer.echo(json.dumps({"prune": {n: c for n, c in removed.items()}}, indent=2))
            else:
                if not removed:
                    typer.echo("All tracked packages are still in the AUR. Nothing to prune.")
                else:
                    if dry_run:
                        typer.echo(f"Would remove {len(removed)} package(s) not in the AUR:")
                    else:
                        typer.echo(f"Removed {len(removed)} package(s) not in the AUR:")
                    for name in sorted(removed):
                        typer.echo(f"  {clean(name)}")
            return

        if not yes and not json_output:
            typer.echo(f"About to permanently remove {len(packages)} package(s):")
            for p in packages:
                typer.echo(f"  {p}")
            confirm = input("Are you sure? [y/N] ")
            if confirm.lower() not in ("y", "yes"):
                typer.echo("Aborted.")
                raise typer.Exit(code=2)

        results = {}
        for name in packages:
            try:
                counts = forget_package(name)
                results[name] = counts
            except ValueError as exc:
                results[name] = {"error": str(exc)}

        if json_output:
            typer.echo(json.dumps({"forget": results}, indent=2))
        else:
            for name, counts in results.items():
                if "error" in counts:
                    typer.echo(f"  {name}: {counts['error']}")
                elif not counts:
                    typer.echo(f"  {name}: not found")
                else:
                    tables = ", ".join(f"{k}={v}" for k, v in counts.items() if v)
                    typer.echo(f"  {name}: removed ({tables})")
