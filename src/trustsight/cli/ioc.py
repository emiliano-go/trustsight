"""IOC Federation baseline management commands."""

from __future__ import annotations

import json
import logging
import re
import shutil
import tempfile
from pathlib import Path

import typer

from ..config import ensure_default_configs, load_config
from ..db import init_db
from ..ioc_baseline import (
    UnsignedBaselineError,
    InvalidSignatureError,
    MalformedBaselineError,
    active_iocs,
    all_ioc_sources,
    import_baseline,
)
from .display import HAS_RICH, SIMPLE_HEAD, _print_colored, console

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

    if HAS_RICH:
        from rich.table import Table
        table = Table(title="IOC baseline sources", box=SIMPLE_HEAD)
        table.add_column("Kind", style="dim")
        table.add_column("Name")
        table.add_column("Status")
        for source in configured or ["(all imported sources)"]:
            table.add_row("configured", source, "enabled" if enabled else "disabled")
        for source in imported:
            table.add_row("imported", source, "")
        for feed in feeds:
            table.add_row(
                "feed",
                str(feed.get("name", "")),
                "enabled" if feed.get("enabled", False) else "disabled",
            )
        console().print(table)
    else:
        print(f"IOC baseline stage: {'enabled' if enabled else 'disabled'}")
        print("Configured sources:")
        for source in configured or ["(all imported sources)"]:
            print(f"  - {source}")
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


_ASSET_PREFIX_RE = re.compile(r"^[a-z0-9][a-z0-9.-]*$")


def _update_feed(feed: dict) -> dict:
    """Update one configured feed from the release channel, verifiably.

    A feed whose ``url`` names the TrustSight release channel is fetched as
    the pair ``baseline-ioc-<prefix>-manifest.json`` and
    ``baseline-ioc-<prefix>-iocs.jsonl``, each with its detached signature,
    both verified against the pinned distribution key before the curator
    signature inside the manifest is checked by ``import_baseline``.  Any
    other URL is refused: there is no scheme in which an unverified remote
    baseline is imported.
    """
    from .. import release

    name = feed.get("name") or ""
    url = feed.get("url") or ""
    prefix = feed.get("asset") or name
    if not release.is_release_url(url):
        return {
            "feed": name,
            "status": "error",
            "error": (
                "unsupported feed URL; only the TrustSight release channel is "
                "implemented (use 'ioc import <dir>' for local baselines)"
            ),
        }
    if not prefix or not _ASSET_PREFIX_RE.match(prefix):
        return {
            "feed": name,
            "status": "error",
            "error": f"invalid asset prefix {prefix!r}; use [a-z0-9.-]",
        }
    manifest_asset = f"baseline-ioc-{prefix}-manifest.json"
    iocs_asset = f"baseline-ioc-{prefix}-iocs.jsonl"
    tmp_dir = Path(tempfile.mkdtemp(prefix="trustsight-ioc-fetch-"))
    try:
        (tmp_dir / "manifest.json").write_bytes(release.fetch_verified_asset(manifest_asset))
        (tmp_dir / "iocs.jsonl").write_bytes(release.fetch_verified_asset(iocs_asset))
        result = import_baseline(tmp_dir, source_name=name)
        return {"feed": name, "status": "ok", "url": release.asset_url(manifest_asset), **result}
    except (release.ReleaseError, UnsignedBaselineError, InvalidSignatureError,
            MalformedBaselineError, FileNotFoundError) as exc:
        return {"feed": name, "status": "error", "error": str(exc)}
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


@ioc_app.command("update")
def ioc_update(
    path: list[str] = typer.Option(None, "--path", help="Local baseline directory (repeatable)"),
    allow_unsigned: bool = typer.Option(False, "--allow-unsigned", help="Allow unsigned baselines"),
    json_output: bool = typer.Option(False, "--json", help="Output JSON"),
):
    """Re-import IOC baselines from local directories or configured feeds.

    Without ``--path`` the command updates every enabled feed whose url is a
    TrustSight release channel URL: the ``baseline-ioc-*`` assets are
    downloaded, verified against the pinned distribution key, and imported.
    """
    ensure_default_configs()
    init_db()

    paths = path or []
    if not paths:
        feeds = _config_feeds()
        if not feeds:
            msg = "No --path given and no feeds configured. Use 'ioc import <dir>' instead."
            if json_output:
                typer.echo(json.dumps({"error": msg, "feeds": []}))
            else:
                _print_colored(msg, "yellow")
            raise typer.Exit(code=2)
        results = [_update_feed(feed) for feed in feeds if feed.get("enabled", True)]
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
    type: str | None = typer.Option(None, "--type", help="Filter by type (domain, hash, package)"),
    include_expired: bool = typer.Option(False, "--include-expired", help="Include expired entries"),
    json_output: bool = typer.Option(False, "--json", help="Output JSON"),
):
    """List active IOC baseline entries."""
    ensure_default_configs()
    init_db()

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

    if HAS_RICH:
        from rich.table import Table
        table = Table(title="IOC baseline entries", box=SIMPLE_HEAD)
        table.add_column("Type", style="dim")
        table.add_column("Value")
        table.add_column("Source")
        table.add_column("Confidence", style="dim")
        for e in entries:
            label = f"{e.type}"
            value = e.value
            if e.expires_at:
                from ..ioc_baseline import _is_expired
                if _is_expired(e.expires_at):
                    value += " [EXPIRED]"
            table.add_row(label, value, e.source, e.confidence or "-")
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
            print(line)


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
    ensure_default_configs()
    init_db()

    entries = active_iocs(source=source, expired=True)
    rows = [_export_row(e) for e in entries]

    # Spec §2.4.2: `ioc export --json` is the merged view for debugging, and
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
    app.add_typer(ioc_app, name="ioc")
