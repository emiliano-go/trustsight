"""Watchlist release management commands.

The operator's hand-curated watchlist (``~/.config/trustsight/watchlist.json``)
is local and never published.  This group handles the *imported* watchlist: a
signed ``watchlist-*`` release carrying public package names and salted
maintainer hashes, ingested exactly like a baseline/IOC channel.
"""

from __future__ import annotations

import json
from pathlib import Path

import typer

from ..config import ensure_default_configs
from ..db import init_db
from ..safe_text import clean
from .display import (
    _print_colored,
    download_progress,
    use_rich_progress,
)

watchlist_app = typer.Typer(
    name="watchlist",
    help="Manage the imported watchlist release",
    no_args_is_help=True,
    add_completion=False,
)


@watchlist_app.command("update")
def watchlist_update(
    tag: str | None = typer.Option(
        None, "--tag", help="Exact watchlist-* release tag to pull"),
    json_output: bool = typer.Option(False, "--json", help="Output JSON"),
):
    """Pull, verify and import the newest signed watchlist release."""
    from .. import channels, release

    ensure_default_configs()
    init_db()

    if release.offline():
        msg = ("watchlist update fetches from the release channel; "
               "TRUSTSIGHT_OFFLINE is set.")
        if json_output:
            typer.echo(json.dumps({"status": "skipped", "reason": msg}))
        else:
            _print_colored(f"skipped: {msg}", "yellow")
        raise typer.Exit(code=0)

    progress = None
    if use_rich_progress() and not json_output:
        def progress(description: str):
            return download_progress(description, enabled=True)

    channel = release.active_baseline_channel()
    try:
        result = channels.pull_watchlist(
            channel=channel, tag=tag, progress=progress)
    except release.ReleaseError as exc:
        if json_output:
            typer.echo(json.dumps({"error": str(exc)}))
        else:
            _print_colored(str(exc), "red", stderr=True)
        raise typer.Exit(code=2)

    if json_output:
        typer.echo(json.dumps(result, indent=2))
        return
    note = ""
    if result.get("maintainers_skipped"):
        note = (f" ({result['maintainers_skipped']} maintainer hashes skipped: "
                "built under a different salt)")
    _print_colored(
        f"{result['tag']}: imported {result['packages_imported']} packages, "
        f"{result['maintainers_imported']} maintainer hashes"
        f"{note}", "green")


@watchlist_app.command("import")
def watchlist_import(
    path: str = typer.Argument(..., help="Path to a watchlist release JSON file"),
    source: str | None = typer.Option(
        None, "--source", help="Override the source name"),
    json_output: bool = typer.Option(False, "--json", help="Output JSON"),
):
    """Import a watchlist release document from a local file.

    The document is the same shape the signed release carries; this path does
    not verify a signature, so use it only for a file you already trust.
    """
    from ..bounded_io import read_file_capped
    from ..watchlist import MAX_WATCHLIST_BYTES, import_release

    ensure_default_configs()
    init_db()

    try:
        data = json.loads(read_file_capped(
            Path(path), MAX_WATCHLIST_BYTES, "watchlist"))
        result = import_release(data, source=source or "")
    except (OSError, ValueError) as exc:
        if json_output:
            typer.echo(json.dumps({"error": str(exc)}))
        else:
            _print_colored(str(exc), "red", stderr=True)
        raise typer.Exit(code=2)

    if json_output:
        typer.echo(json.dumps(result, indent=2))
        return
    _print_colored(
        f"{result['source']}: imported {result['packages_imported']} packages, "
        f"{result['maintainers_imported']} maintainer hashes", "green")


@watchlist_app.command("list")
def watchlist_list(
    json_output: bool = typer.Option(False, "--json", help="Output JSON"),
):
    """Show the watchlist: local entries unioned with the imported release."""
    from ..watchlist import (
        load_packages,
        load_release_maintainers,
        load_release_packages,
        load_watchlist,
    )

    ensure_default_configs()
    init_db()

    packages = load_packages()
    local_hashes = load_watchlist()
    imported_packages = load_release_packages()
    imported_hashes = load_release_maintainers()

    if json_output:
        typer.echo(json.dumps({
            "packages": packages,
            "maintainers": local_hashes,
            "imported_packages": imported_packages,
            "imported_maintainers": imported_hashes,
        }, indent=2))
        return

    if not packages and not local_hashes:
        typer.echo("The watchlist is empty.")
        return
    if packages:
        typer.echo(f"Packages ({len(packages)}):")
        for name in sorted(packages):
            origin = "imported" if name in imported_packages else "local"
            typer.echo(f"  {clean(name)}  [{origin}]")
    if local_hashes:
        typer.echo(f"Maintainer hashes ({len(local_hashes)}):")
        for value, label in sorted(local_hashes.items()):
            origin = "imported" if value in imported_hashes else "local"
            suffix = f"  ({label})" if label else ""
            typer.echo(f"  {clean(value[:16])}…  [{origin}]{clean(suffix)}")


def register_commands(app: typer.Typer):
    """Register the ``watchlist`` subcommand group on *app*."""
    app.add_typer(watchlist_app, name="watchlist")
