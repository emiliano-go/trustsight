"""Commands for inspecting and managing the hashed maintainer seed."""

import json
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import typer

from ..db import (
    SEED_DIGEST_KEY,
    SEED_META_HASH_ALGORITHM_KEY,
    SEED_ORIGIN_KEY,
    SEED_VERSION_KEY,
    _ensure_salt,
    _get_salt,
    _hash_maintainer_value,
    get_connection,
    get_metadata,
    import_seed,
    init_db,
    seed_observation_count,
)
from .display import HAS_RICH, _print_colored, console

seed_app = typer.Typer(
    help="Inspect and manage the hashed maintainer seed",
    no_args_is_help=True,
    add_completion=False,
)


def register_commands(app: typer.Typer):
    """Register the ``seed`` subcommand group on *app*."""
    app.add_typer(seed_app, name="seed")


@seed_app.command("info")
def seed_info(
    json_output: bool = typer.Option(False, "--json", help="Output JSON"),
):
    """Show seed metadata and hashing configuration."""
    init_db()
    with get_connection() as conn:
        salt = _get_salt(conn)
        algo_row = conn.execute(
            "SELECT value FROM seed_meta WHERE key = ?",
            (SEED_META_HASH_ALGORITHM_KEY,),
        ).fetchone()
        algorithm = algo_row["value"] if algo_row else None
        maint_count = conn.execute(
            "SELECT COUNT(*) AS n FROM maintainers_hashed"
        ).fetchone()["n"]

    data = {
        "seeded": salt is not None,
        "salt": salt,
        "hash_algorithm": algorithm,
        "maintainers_hashed": maint_count,
        "seed_observations": seed_observation_count(),
        "seed_version": get_metadata(SEED_VERSION_KEY),
        "seed_hash": get_metadata(SEED_DIGEST_KEY),
        "seed_origin": get_metadata(SEED_ORIGIN_KEY),
    }

    if json_output:
        typer.echo(json.dumps(data, indent=2))
        return

    if HAS_RICH:
        from rich.box import SIMPLE_HEAD
        from rich.table import Table
        table = Table(title="TrustSight seed", box=SIMPLE_HEAD)
        table.add_column("Key", style="cyan")
        table.add_column("Value", overflow="fold")
        table.add_row("Seeded", "Yes" if data["seeded"] else "No")
        table.add_row("Salt", salt or "-")
        table.add_row("Hash algorithm", algorithm or "-")
        table.add_row("Hashed maintainers", f"{maint_count:,}")
        table.add_row("Seed observations", f"{data['seed_observations']:,}")
        table.add_row("Seed version", data["seed_version"] or "-")
        table.add_row("Seed hash", data["seed_hash"] or "-")
        table.add_row("Seed origin", data["seed_origin"] or "-")
        console().print(table)
    else:
        print(f"Seeded             : {'Yes' if data['seeded'] else 'No'}")
        print(f"Salt               : {salt or '-'}")
        print(f"Hash algorithm     : {algorithm or '-'}")
        print(f"Hashed maintainers : {maint_count}")
        print(f"Seed observations  : {data['seed_observations']}")
        print(f"Seed version       : {data['seed_version'] or '-'}")
        print(f"Seed hash          : {data['seed_hash'] or '-'}")
        print(f"Seed origin        : {data['seed_origin'] or '-'}")


@seed_app.command("fetch")
def seed_fetch(
    tag: str | None = typer.Option(
        None, "--tag", help="Fetch a specific release tag instead of the latest"
    ),
    key: str | None = typer.Option(
        None, "--key", help="Path to the pinned ed25519 public key (shipped key by default)"
    ),
    json_output: bool = typer.Option(False, "--json", help="Output JSON"),
):
    """Download, verify and import the signed seed release asset.

    The seed ships as ``baseline-seed.tar.gz`` in the TrustSight release
    channel together with a detached Ed25519 signature.  The download is
    verified against the pinned distribution key before anything is
    imported; a mismatch is a refusal, not a warning.
    """
    from .. import release

    if release.offline():
        msg = "The release channel is disabled (TRUSTSIGHT_OFFLINE is set)."
        if json_output:
            typer.echo(json.dumps({"error": msg}))
        else:
            _print_colored(msg, "red", stderr=True)
        raise typer.Exit(code=2)

    try:
        data = release.fetch_verified_asset(
            "baseline-seed.tar.gz",
            tag=tag,
            pubkey_path=Path(key) if key else None,
        )
    except release.ReleaseError as exc:
        msg = f"Seed fetch refused: {exc}"
        if json_output:
            typer.echo(json.dumps({"error": msg}))
        else:
            _print_colored(msg, "red", stderr=True)
        raise typer.Exit(code=2)

    tmp_dir = Path(tempfile.mkdtemp(prefix="trustsight-seed-fetch-"))
    try:
        path = tmp_dir / "baseline-seed.tar.gz"
        path.write_bytes(data)
        stats = import_seed(path)
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)

    result = {
        "status": "ok",
        "tag": tag or "latest",
        "url": release.asset_url("baseline-seed.tar.gz", tag),
        **stats,
    }
    if json_output:
        typer.echo(json.dumps(result, indent=2))
    else:
        _print_colored(
            f"Verified and imported {stats['urls_total']:,} known source URLs and "
            f"{stats['maintainers']} maintainers from the release channel.",
            "green",
        )


@seed_app.command("stats")
def seed_stats(
    json_output: bool = typer.Option(False, "--json", help="Output JSON"),
):
    """Show statistics about the hashed maintainer corpus."""
    init_db()
    with get_connection() as conn:
        total = conn.execute(
            "SELECT COUNT(*) AS n FROM maintainers_hashed"
        ).fetchone()["n"]
        with_email = conn.execute(
            "SELECT COUNT(*) AS n FROM maintainers_hashed WHERE email_hash IS NOT NULL"
        ).fetchone()["n"]
        total_packages = conn.execute(
            "SELECT COALESCE(SUM(package_count), 0) AS n FROM maintainers_hashed"
        ).fetchone()["n"]
        sources = conn.execute(
            "SELECT source, COUNT(*) AS n FROM maintainers_hashed "
            "GROUP BY source ORDER BY n DESC"
        ).fetchall()

    data = {
        "total_maintainers": total,
        "with_email_hash": with_email,
        "total_package_count": int(total_packages),
        "by_source": [{"source": r["source"], "count": r["n"]} for r in sources],
    }

    if json_output:
        typer.echo(json.dumps(data, indent=2))
        return

    if HAS_RICH:
        from rich.box import SIMPLE_HEAD
        from rich.table import Table
        table = Table(title="Hashed maintainer corpus", box=SIMPLE_HEAD)
        table.add_column("Metric", style="cyan")
        table.add_column("Value", justify="right")
        table.add_row("Total maintainers", f"{total:,}")
        table.add_row("With email hash", f"{with_email:,}")
        table.add_row("Total package count", f"{int(total_packages):,}")
        console().print(table)
        if sources:
            src_table = Table(title="By source", box=SIMPLE_HEAD)
            src_table.add_column("Source", style="dim")
            src_table.add_column("Count", justify="right")
            for r in sources:
                src_table.add_row(r["source"] or "(none)", f"{r['n']:,}")
            console().print(src_table)
    else:
        print(f"Total maintainers   : {total}")
        print(f"With email hash     : {with_email}")
        print(f"Total package count : {int(total_packages)}")
        for r in sources:
            print(f"  {r['source'] or '(none)'}: {r['n']}")


@seed_app.command("migrate")
def seed_migrate(
    from_backup: bool = typer.Option(
        False,
        "--from-backup",
        help="Migrate from maintainers_deprecated_backup (after auto-migration)",
    ),
    json_output: bool = typer.Option(False, "--json", help="Output JSON"),
):
    """Migrate plaintext maintainer data into the hashed store."""
    init_db()
    with get_connection() as conn:
        tables = {
            row["name"]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        if "maintainers_deprecated_backup" not in tables and "maintainers" not in tables:
            msg = "No plaintext maintainer backup found; nothing to migrate."
            if json_output:
                typer.echo(json.dumps({"status": "noop", "message": msg}))
            else:
                _print_colored(msg, "yellow")
            raise typer.Exit()

        salt = _ensure_salt(conn)
        source_table = (
            "maintainers_deprecated_backup"
            if from_backup and "maintainers_deprecated_backup" in tables
            else "maintainers"
        )
        rows = conn.execute(
            f"SELECT name, first_seen_package_id FROM {source_table}"
        ).fetchall()

        by_name: dict[str, list[int]] = {}
        for row in rows:
            by_name.setdefault(row["name"], []).append(row["first_seen_package_id"] or 0)

        pkg_ids = [pid for pids in by_name.values() for pid in pids if pid]
        pkg_names: dict[int, str] = {}
        if pkg_ids:
            placeholders = ",".join("?" * len(pkg_ids))
            for r in conn.execute(
                f"SELECT id, name FROM packages WHERE id IN ({placeholders})", pkg_ids
            ).fetchall():
                pkg_names[r["id"]] = r["name"]

        now = datetime.now(timezone.utc).isoformat()
        migrated = 0
        for name, pids in by_name.items():
            name_hash = _hash_maintainer_value(name, salt)
            packages = sorted({pkg_names[pid] for pid in pids if pid in pkg_names})
            conn.execute(
                """INSERT OR REPLACE INTO maintainers_hashed
                   (name_hash, email_hash, first_seen, package_count, packages, source)
                   VALUES (?, NULL, ?, ?, ?, ?)""",
                (name_hash, now, len(pids), json.dumps(packages), "migrated"),
            )
            for pid in pids:
                conn.execute(
                    """INSERT OR IGNORE INTO package_maintainers_hashed
                       (name_hash, email_hash, package_id, first_seen)
                       VALUES (?, NULL, ?, ?)""",
                    (name_hash, pid, now),
                )
            migrated += 1
        conn.commit()

    data = {"status": "ok", "migrated_maintainers": migrated, "source_table": source_table}
    if json_output:
        typer.echo(json.dumps(data, indent=2))
    else:
        _print_colored(
            f"Migrated {migrated} maintainer(s) from {source_table} into maintainers_hashed.",
            "green",
        )
