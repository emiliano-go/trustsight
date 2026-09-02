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
from .display import _print_colored


# `discovery` pulls `urllib.request`, and `app.py` imports this module to
# register `forget`, so at module scope every invocation paid for the HTTP
# stack. The wrapper keeps the name patchable.
def get_aur_package_info(*args, **kwargs):
    from ..discovery import get_aur_package_info as _get_aur_package_info

    return _get_aur_package_info(*args, **kwargs)



def register_commands(app: typer.Typer):
    """Register the ``forget`` subcommand on *app*."""
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
            if len(aur_names) < len(names):
                # A short reply would be read as "these packages vanished"
                # and their history deleted.  The RPC batches in one call, so
                # fewer names than asked for means a truncated response.
                msg = (
                    f"AUR RPC replied with {len(aur_names)} of {len(names)} "
                    "packages; refusing to prune on a partial reply. Retry."
                )
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
            if dry_run:
                typer.echo(f"Would remove {len(packages)} package(s):")
            else:
                typer.echo(f"About to permanently remove {len(packages)} package(s):")
            for p in packages:
                typer.echo(f"  {p}")
            if not dry_run:
                try:
                    confirm = input("Are you sure? [y/N] ")
                except EOFError:
                    typer.echo("Aborted.")
                    raise typer.Exit(code=2)
                if confirm.lower() not in ("y", "yes"):
                    typer.echo("Aborted.")
                    raise typer.Exit(code=2)

        results = {}
        for name in packages:
            if dry_run:
                # Show what would be removed without touching the database.
                from ..db import get_package_id, get_triggered_rules
                pkg_id = get_package_id(name)
                if pkg_id is None:
                    results[name] = {}
                else:
                    rules = get_triggered_rules(pkg_id)
                    results[name] = {"rule_count": len(rules) if rules else 0}
            else:
                try:
                    counts = forget_package(name)
                    results[name] = counts
                except ValueError as exc:
                    results[name] = {"error": str(exc)}

        if json_output:
            typer.echo(json.dumps({"forget": results, "dry_run": dry_run}, indent=2))
        else:
            for name, counts in results.items():
                if "error" in counts:
                    typer.echo(f"  {name}: {counts['error']}")
                elif not counts:
                    typer.echo(f"  {name}: not found")
                else:
                    if dry_run:
                        typer.echo(f"  {name}: would remove ({counts})")
                    else:
                        tables = ", ".join(f"{k}={v}" for k, v in counts.items() if v)
                        typer.echo(f"  {name}: removed ({tables})")
