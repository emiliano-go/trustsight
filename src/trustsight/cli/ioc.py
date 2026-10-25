"""IOC Federation baseline management commands."""

from __future__ import annotations

import json
import logging
import shutil
import sys
import tempfile
from pathlib import Path

import typer

from ..safe_text import clean

from ..config import ensure_default_configs, load_config
from ..db import init_db
from .display import (
    _print_colored,
    console,
    download_progress,
    use_rich,
    use_rich_progress,
)

log = logging.getLogger(__name__)

ioc_app = typer.Typer(
    name="ioc",
    help="Manage IOC federation baselines",
    no_args_is_help=True,
    add_completion=False,
)


def _config_feeds() -> list[dict]:
    """Return configured IOC feeds from config.toml."""
    cfg = load_config()
    section = cfg.get("baselines", {}).get("ioc", {})
    feeds = section.get("feeds", [])
    if not isinstance(feeds, list):
        return []
    out = []
    for feed in feeds:
        if isinstance(feed, dict):
            out.append(feed)
    return out


def _enabled() -> bool:
    cfg = load_config()
    section = cfg.get("baselines", {}).get("ioc", {})
    return bool(section.get("enabled", True))


@ioc_app.command("sources")
def ioc_sources(
    json_output: bool = typer.Option(False, "--json", help="Output JSON"),
):
    """Show configured and imported IOC baseline sources."""
    from ..ioc_baseline import (
        all_ioc_sources,
    )

    ensure_default_configs()
    init_db()

    enabled = _enabled()
    configured = load_config().get("baselines", {}).get("ioc", {}).get("sources", [])
    if isinstance(configured, str):
        configured = [configured]
    configured = [str(s).strip() for s in configured if str(s).strip()]
    feeds = _config_feeds()
    imported = all_ioc_sources()

    if json_output:
        typer.echo(json.dumps({
            "enabled": enabled,
            "configured_sources": configured,
            "imported_sources": imported,
            "feeds": feeds,
        }, indent=2))
        return

    if use_rich():
        from rich.box import SIMPLE_HEAD
        from rich.table import Table
        table = Table(title="IOC baseline sources", box=SIMPLE_HEAD)
        table.add_column("Kind", style="dim")
        table.add_column("Name")
        table.add_column("Status")
        from rich.text import Text
        for source in configured:
            table.add_row("configured", Text(clean(source)),
                          "enabled" if enabled else "disabled")
        for source in imported:
            table.add_row("imported", Text(clean(source)), "")
        for feed in feeds:
            table.add_row(
                "feed",
                str(feed.get("name", "")),
                "enabled" if feed.get("enabled", False) else "disabled",
            )
        console().print(table)
        if not configured and not imported:
            console().print(
                "[dim]No sources configured; imported baselines are all "
                "shown unless a configured source restricts them.[/]"
            )
    else:
        print(f"IOC baseline stage: {'enabled' if enabled else 'disabled'}")
        print("Configured sources:")
        for source in configured:
            print(f"  - {source}")
        if not configured and not imported:
            print("  (none; imported baselines are all shown)")
        print("Imported sources:")
        for source in imported:
            print(f"  - {source}")


@ioc_app.command("import")
def ioc_import(
    path: str = typer.Argument(..., help="Path to baseline directory"),
    source: str | None = typer.Option(None, "--source", help="Override source name"),
    allow_unsigned: bool = typer.Option(False, "--allow-unsigned", help="Allow unsigned baselines"),
    json_output: bool = typer.Option(False, "--json", help="Output JSON"),
):
    """Import an IOC federation baseline directory."""
    from ..ioc_baseline import (
        InvalidSignatureError,
        MalformedBaselineError,
        UnsignedBaselineError,
        import_baseline,
    )

    ensure_default_configs()
    init_db()

    try:
        result = import_baseline(path, source_name=source, allow_unsigned=allow_unsigned)
    except (UnsignedBaselineError, InvalidSignatureError, MalformedBaselineError) as exc:
        msg = str(exc)
        if json_output:
            typer.echo(json.dumps({"error": msg}))
        else:
            _print_colored(msg, "red", stderr=True)
        raise typer.Exit(code=2)
    except FileNotFoundError as exc:
        msg = f"Baseline not found: {exc}"
        if json_output:
            typer.echo(json.dumps({"error": msg}))
        else:
            _print_colored(msg, "red", stderr=True)
        raise typer.Exit(code=2)

    if json_output:
        typer.echo(json.dumps(result, indent=2))
        return

    status = "verified" if result["verified"] else "imported"
    if result["verified"]:
        _print_colored(f"{status.capitalize()} {result['entries_imported']} IOCs from {result['source']}", "green")
    else:
        _print_colored(
            f"Imported {result['entries_imported']} IOCs from {result['source']} (signature not verified)",
            "yellow",
        )


def _update_feed(feed: dict, show_progress: bool = False) -> dict:
    """Update one configured feed from its channel, verifiably.

    A feed whose ``url`` names a followed release channel is fetched as the
    pair ``baseline-ioc-<prefix>-manifest.json`` / ``-iocs.jsonl`` from the
    newest ``ioc-*`` release (or a feed ``tag``); the detached signatures are
    verified against that channel's pinned key.  Any other ``http(s)`` URL is
    read as a publisher's federation directory and verified against the feed's
    own ``key``.  Either way the import is refused unless every byte is
    verified.  The work itself lives in :mod:`trustsight.channels`, shared with
    the watcher's ``--auto-pull-iocs``; this only supplies the progress bar.

    *show_progress* draws one download bar per asset on stderr; the default
    keeps direct calls (and tests) silent.
    """
    from .. import channels

    progress = None
    if show_progress:
        def progress(description: str):
            return download_progress(description, enabled=True)

    return channels.pull_ioc_feed(feed, progress=progress)


def _update_federation(
    base_url: str, pubkey_path: Path, allow_unsigned: bool = False
) -> dict:
    """Fetch and import a federated indicator set, signature-verified.

``manifest.json`` and ``iocs.jsonl`` are fetched from
    *base_url* and verified against the pinned *pubkey_path* before import
    (hashed indicators only, the curator signature inside the manifest is
    checked by ``import_baseline``).
    """
    from .. import channels, release
    from ..ioc_baseline import (
        InvalidSignatureError,
        MalformedBaselineError,
        UnsignedBaselineError,
        import_baseline,
    )

    # A federation publisher is by definition non-official: say so before any
    # byte is fetched or imported.
    print(channels.publisher_warning(base_url.rstrip("/")), file=sys.stderr)
    tmp_dir = Path(tempfile.mkdtemp(prefix="trustsight-ioc-federation-"))
    try:
        for asset, target in (("manifest.json", "manifest.json"),
                              ("iocs.jsonl", "iocs.jsonl")):
            (tmp_dir / target).write_bytes(
                release.fetch_verified_url(base_url, asset,
                                           pubkey_path=pubkey_path))
        result = import_baseline(tmp_dir, source_name=base_url.rstrip("/"),
                                 trust_manifest_key=True,
                                 allow_unsigned=allow_unsigned)
        return {"feed": base_url, "status": "ok", "url": base_url, **result}
    except (release.ReleaseError, UnsignedBaselineError, InvalidSignatureError,
            MalformedBaselineError, FileNotFoundError) as exc:
        return {"feed": base_url, "status": "error", "error": str(exc)}
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


@ioc_app.command("update")
def ioc_update(
    path: list[str] = typer.Option(None, "--path", help="Local baseline directory (repeatable)"),
    federation: str | None = typer.Option(
        None, "--federation",
        help="Base URL of a publisher's signed indicator set (manifest.json + iocs.jsonl)"),
    publisher_key: str | None = typer.Option(
        None, "--publisher-key",
        help="Path to the Ed25519 public key pinning the federation publisher"),
    allow_unsigned: bool = typer.Option(False, "--allow-unsigned", help="Allow unsigned baselines"),
    json_output: bool = typer.Option(False, "--json", help="Output JSON"),
):
    """Re-import IOC baselines from local directories, configured feeds, or a
    signed federation URL.

    Without ``--path`` the command updates every enabled feed whose url is a
    TrustSight release channel URL: the ``baseline-ioc-*`` assets are
    downloaded from the newest ``ioc-*`` release, verified against the pinned
    distribution key, and imported.  ``--federation URL`` fetches a
    publisher's ``manifest.json``/``iocs.jsonl`` from that base URL and
    verifies them against ``--publisher-key``.
    """
    from ..ioc_baseline import (
        InvalidSignatureError,
        MalformedBaselineError,
        UnsignedBaselineError,
        import_baseline,
    )

    ensure_default_configs()
    init_db()

    if federation:
        if not publisher_key:
            msg = "--federation requires --publisher-key (a pinned Ed25519 public key)"
            if json_output:
                typer.echo(json.dumps({"error": msg}))
            else:
                _print_colored(msg, "red", stderr=True)
            raise typer.Exit(code=2)
        result = _update_federation(
            federation, Path(publisher_key), allow_unsigned=allow_unsigned)
        if json_output:
            typer.echo(json.dumps({"results": [result]}, indent=2))
        elif result["status"] == "error":
            _print_colored(f"{federation}: {result['error']}", "red", stderr=True)
        else:
            _print_colored(
                f"{federation}: verified {result.get('entries_imported', 0)} "
                "IOCs", "green")
        if result["status"] == "error":
            raise typer.Exit(code=2)
        return

    paths = path or []
    if not paths:
        from .. import release as _release
        if _release.offline():
            msg = "ioc update fetches from the release channel; TRUSTSIGHT_OFFLINE is set."
            if json_output:
                typer.echo(json.dumps({"status": "skipped", "reason": msg}))
            else:
                _print_colored(f"skipped: {msg}", "yellow")
            raise typer.Exit(code=0)
        feeds = _config_feeds()
        if not feeds:
            msg = "No --path given and no feeds configured. Use 'ioc import <dir>' instead."
            if json_output:
                typer.echo(json.dumps({"error": msg, "feeds": []}))
            else:
                _print_colored(msg, "yellow")
            raise typer.Exit(code=2)
        results = [
            _update_feed(feed, show_progress=use_rich_progress() and not json_output)
            for feed in feeds
            if feed.get("enabled", True)
        ]
        if not results:
            msg = "All configured feeds are disabled. Enable one in config.toml or pass --path."
            if json_output:
                typer.echo(json.dumps({"error": msg, "feeds": feeds}))
            else:
                _print_colored(msg, "yellow")
            raise typer.Exit(code=2)
        errors = [r for r in results if r["status"] == "error"]
        if json_output:
            typer.echo(json.dumps({"results": results}, indent=2))
            if errors:
                raise typer.Exit(code=2)
            return
        for r in results:
            if r["status"] == "error":
                _print_colored(f"{r['feed'] or '(unnamed)'}: {r['error']}", "red", stderr=True)
            else:
                status = "verified" if r["verified"] else "imported"
                _print_colored(
                    f"{r['feed']}: {status} {r['entries_imported']} IOCs from {r['source']}",
                    "green" if r["verified"] else "yellow",
                )
        if errors:
            raise typer.Exit(code=2)
        return

    results = []
    for p in paths:
        try:
            result = import_baseline(p, allow_unsigned=allow_unsigned)
            results.append({"path": p, "status": "ok", **result})
        except (UnsignedBaselineError, InvalidSignatureError, MalformedBaselineError) as exc:
            results.append({"path": p, "status": "error", "error": str(exc)})
        except FileNotFoundError as exc:
            results.append({"path": p, "status": "error", "error": f"not found: {exc}"})

    errors = [r for r in results if r["status"] == "error"]
    if json_output:
        typer.echo(json.dumps({"results": results}, indent=2))
        if errors:
            raise typer.Exit(code=2)
        return

    for r in results:
        if r["status"] == "error":
            _print_colored(f"{r['path']}: {r['error']}", "red", stderr=True)
        else:
            status = "verified" if r["verified"] else "imported"
            _print_colored(
                f"{r['path']}: {status} {r['entries_imported']} IOCs from {r['source']}",
                "green" if r["verified"] else "yellow",
            )
    if errors:
        raise typer.Exit(code=2)


@ioc_app.command("list")
def ioc_list(
    source: str | None = typer.Option(None, "--source", help="Filter by source"),
    type: str | None = typer.Option(None, "--type", help="Filter by type (domain, hash, package, file_path, pkgbuild_pattern)"),
    include_expired: bool = typer.Option(False, "--include-expired", help="Include expired entries"),
    json_output: bool = typer.Option(False, "--json", help="Output JSON"),
):
    """List active IOC baseline entries."""
    from ..ioc_baseline import (
        active_iocs,
    )

    ensure_default_configs()
    init_db()

    from ..iocs import IOC_TYPES
    if type and type.lower() not in IOC_TYPES:
        msg = (f"unknown indicator type {type!r}; expected one of "
               f"{', '.join(sorted(IOC_TYPES))}")
        if json_output:
            typer.echo(json.dumps({"error": msg}))
        else:
            _print_colored(msg, "red", stderr=True)
        raise typer.Exit(code=2)

    entries = active_iocs(source=source, expired=include_expired)
    if type:
        entries = [e for e in entries if e.type == type.lower()]

    if json_output:
        typer.echo(json.dumps([
            {
                "type": e.type,
                "value": e.value,
                "source": e.source,
                "confidence": e.confidence,
                "provenance": e.provenance,
                "campaign": e.campaign,
                "added": e.added,
                "expires_at": e.expires_at,
            }
            for e in entries
        ], indent=2))
        return

    if not entries:
        print("No IOC entries match the selected criteria.")
        return

    if use_rich():
        from rich.box import SIMPLE_HEAD
        from rich.table import Table
        table = Table(title="IOC baseline entries", box=SIMPLE_HEAD)
        table.add_column("Type", style="dim")
        table.add_column("Value")
        table.add_column("Source")
        table.add_column("Confidence", style="dim")
        from rich.text import Text
        for e in entries:
            label = f"{e.type}"
            value = e.value
            if e.expires_at:
                from ..ioc_baseline import _is_expired
                if _is_expired(e.expires_at):
                    value += " [EXPIRED]"
            # Every field here comes from an imported baseline, and IOC
            # federation means third parties supply them by design. Passed
            # as bare strings, Rich reads them as markup: a value holding
            # `[/]` raises MarkupError and aborts the whole table, so one
            # hostile indicator makes `ioc list` unusable.
            table.add_row(Text(clean(label)), Text(clean(value)),
                          Text(clean(e.source)),
                          Text(clean(e.confidence or "-")))
        console().print(table)
    else:
        for e in entries:
            line = f"{e.type:<8} {e.value:<40} {e.source:<20}"
            if e.confidence:
                line += f" ({e.confidence})"
            if e.expires_at:
                from ..ioc_baseline import _is_expired
                if _is_expired(e.expires_at):
                    line += " [EXPIRED]"
            print(clean(line))


def _export_row(e) -> dict:
    """One IOC entry as an export/debug JSON object, source always present."""
    row = {"type": e.type, "value": e.value, "source": e.source}
    if e.confidence:
        row["confidence"] = e.confidence
    if e.provenance:
        row["provenance"] = e.provenance
    if e.campaign:
        row["campaign"] = e.campaign
    if e.added:
        row["added"] = e.added
    if e.expires_at:
        row["expires_at"] = e.expires_at
    return row


@ioc_app.command("export")
def ioc_export(
    output: str | None = typer.Argument(
        None, help="Output directory for manifest.json and iocs.jsonl; omit with --json to print the merged view"),
    source: str | None = typer.Option(None, "--source", help="Export only one source"),
    json_output: bool = typer.Option(False, "--json", help="Print the merged IOC view as JSON instead of writing a directory"),
):
    """Export the current merged IOC view.

    With a directory argument, writes a ``manifest.json`` + ``iocs.jsonl``
    baseline.  With ``--json`` and no directory, prints every active IOC as a
    JSON array to stdout, the debugging view from the spec.
    """
    from ..ioc_baseline import (
        active_iocs,
    )

    ensure_default_configs()
    init_db()

    entries = active_iocs(source=source, expired=True)
    rows = [_export_row(e) for e in entries]

    # `ioc export --json` is the merged view for debugging, and
    # needs no output directory.
    if output is None:
        if not json_output:
            _print_colored(
                "Provide an output directory, or use --json to print the "
                "merged view.", "red",
            )
            raise typer.Exit(code=2)
        typer.echo(json.dumps(rows, indent=2, ensure_ascii=False))
        return

    out = Path(output)
    if out.exists() and not out.is_dir():
        msg = f"output path exists and is not a directory: {output}"
        if json_output:
            typer.echo(json.dumps({"error": msg}))
        else:
            _print_colored(msg, "red", stderr=True)
        raise typer.Exit(code=2)
    out.mkdir(parents=True, exist_ok=True)
    manifest = {
        "version": 1,
        "source": source or "export",
        "created_at": _now_iso(),
        "expires_at": "",
        "signature": "",
        "public_key": "",
    }
    (out / "manifest.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    lines = [json.dumps(row, ensure_ascii=False) for row in rows]
    (out / "iocs.jsonl").write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")

    result = {"directory": str(out), "entries": len(entries), "source": source or "export"}
    if json_output:
        typer.echo(json.dumps(result, indent=2))
        return
    _print_colored(f"Exported {result['entries']} IOCs to {out}", "green")


def _now_iso() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()


def register_commands(app: typer.Typer):
    """Register the ``ioc`` subcommand group on *app*."""
    app.add_typer(ioc_app, name="ioc")
