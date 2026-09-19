import json
import logging
import sqlite3
from datetime import datetime
from pathlib import Path

import typer

from ..config import ensure_default_configs
from ..db import get_db_path, init_db
from .display import _fmt_bytes, _print_colored

log = logging.getLogger(__name__)

db_app = typer.Typer(
    help="Database maintenance (check, vacuum, backup)",
    no_args_is_help=True, add_completion=False,
)


# --- db subcommands ---

@db_app.command("check")
def db_check(
    json_output: bool = typer.Option(False, "--json", help="Output JSON"),
):
    """Run integrity check on the database."""
    ensure_default_configs()
    from ..db import get_connection
    try:
        init_db()
    except sqlite3.DatabaseError:
        # A corrupt database is exactly what this command must diagnose;
        # crashing on the schema init would defeat the point.
        pass

    errors = []
    try:
        with get_connection() as conn:
            rows = conn.execute("PRAGMA integrity_check").fetchall()
            for r in rows:
                if r[0] != "ok":
                    errors.append(r[0])
    except sqlite3.DatabaseError as exc:
        errors.append(str(exc))

    if json_output:
        typer.echo(json.dumps({
            "status": "ok" if not errors else "corrupt",
            "errors": errors,
        }, indent=2))
        if errors:
            raise typer.Exit(code=2)
        return

    if not errors:
        _print_colored("Database integrity check passed.", "green")
    else:
        for err in errors:
            _print_colored(err, "red", stderr=True)
        raise typer.Exit(code=2)


@db_app.command("vacuum")
def db_vacuum(
    force: bool = typer.Option(False, "--force", help="Skip confirmation prompt"),
    json_output: bool = typer.Option(False, "--json", help="Output JSON"),
):
    """Reclaim disk space by rebuilding the database file."""
    ensure_default_configs()
    init_db()
    from ..db import get_connection

    if not force and not json_output:
        typer.confirm("Vacuum the database? This may take a while.", abort=True)

    with get_connection() as conn:
        before = get_db_path().stat().st_size
        conn.execute("VACUUM")
        after = get_db_path().stat().st_size

    if json_output:
        typer.echo(json.dumps({
            "status": "ok",
            "bytes_before": before,
            "bytes_after": after,
            "bytes_reclaimed": before - after,
        }, indent=2))
        return

    reclaimed = before - after
    _print_colored(
        f"Database vacuumed: {_fmt_bytes(before)} -> {_fmt_bytes(after)} "
        f"({_fmt_bytes(reclaimed)} reclaimed)", "green",
    )


@db_app.command("backup")
def db_backup(
    output: str | None = typer.Option(None, "--output", "-o", help="Output path (default: auto-named)"),
    json_output: bool = typer.Option(False, "--json", help="Output JSON"),
):
    """Create a safe online backup of the database."""
    ensure_default_configs()
    init_db()
    from ..db import get_connection

    db_path = get_db_path()
    if not output:
        ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        output = str(db_path) + f".{ts}.bak"

    out_path = Path(output)
    if out_path.exists() and db_path != out_path and out_path.samefile(db_path):
        msg = f"backup path must differ from the live database: {output}"
        if json_output:
            typer.echo(json.dumps({"error": msg}))
        else:
            _print_colored(msg, "red", stderr=True)
        raise typer.Exit(code=2)
    if not out_path.parent.exists():
        msg = f"backup directory does not exist: {out_path.parent}"
        if json_output:
            typer.echo(json.dumps({"error": msg}))
        else:
            _print_colored(msg, "red", stderr=True)
        raise typer.Exit(code=2)

    try:
        with get_connection() as conn:
            backup_conn = sqlite3.connect(output)
            try:
                conn.backup(backup_conn, pages=0)
            finally:
                backup_conn.close()
    except sqlite3.Error as exc:
        msg = f"backup failed: {exc}"
        if json_output:
            typer.echo(json.dumps({"error": msg}))
        else:
            _print_colored(msg, "red", stderr=True)
        raise typer.Exit(code=2)

    size = Path(output).stat().st_size
    if json_output:
        typer.echo(json.dumps({
            "status": "ok",
            "path": output,
            "bytes": size,
        }, indent=2))
        return

    _print_colored(f"Database backed up to {output} ({_fmt_bytes(size)})", "green")


def register_commands(app: typer.Typer):
    """Register the ``db`` subcommand group on *app*."""
    app.add_typer(db_app, name="db")
