"""``trustsight corpus`` - corpus-wide queries (plan §9).

``corpus pivot <ioc>`` inverts H056: instead of asking what one package
carries, it asks which packages reference one indicator.  That is the shape
of the question an advisory creates.

``corpus fetch`` is the opt-in pull channel for the signed corpus
baseline: it downloads ``baseline-corpus.tar.zst`` through the release
channel, verifies the detached ed25519 signature against the pinned
distribution key before the bytes are parsed, and imports the artifact.
"""

import json

import typer

from ..config import ensure_default_configs
from ..db import init_db
from ..safe_text import clean
from .display import _print_colored, console, download_progress, use_rich, use_rich_progress

#: The corpus baseline release asset.  Matches the name the release
#: workflow builds (``scripts/build_release_baselines.py --corpus``);
#: the ``.sig`` sibling carries the detached signature.
CORPUS_ASSET_NAME = "baseline-corpus.tar.zst"

corpus_app = typer.Typer(
    name="corpus",
    help="Corpus-wide queries over the full-AUR baseline",
    no_args_is_help=True,
)


@corpus_app.command("pivot")
def pivot_cmd(
    indicator: str = typer.Argument(..., help="Package name, domain, or artifact hash"),
    type_: str | None = typer.Option(
        None, "--type",
        help="Force the indicator type (package|domain|hash) when the shape is ambiguous",
    ),
    json_output: bool = typer.Option(False, "--json", help="Output JSON"),
):
    """List every corpus package that references INDICATOR.

    The match is exact - a near miss is a miss - and it reads only stored
    corpus material, never the network.  An empty result means the corpus
    holds no reference, not that the indicator is harmless.
    """
    ensure_default_configs()
    init_db()

    from ..full_aur.pivot import pivot
    from ..iocs import PIVOT_IOC_TYPES

    if type_ is not None and type_.lower() not in PIVOT_IOC_TYPES:
        _print_colored(
            f"unknown indicator type {type_!r}; expected one of "
            f"{', '.join(sorted(PIVOT_IOC_TYPES))}", "red",
        )
        raise typer.Exit(code=2)
    # PIVOT_IOC_TYPES is lowercase; accept any casing, as `ioc list` does.
    type_ = type_.lower() if type_ is not None else None

    result = pivot(indicator, type=type_)

    if result.get("error"):
        if json_output:
            typer.echo(json.dumps({"error": result["error"]}))
        else:
            _print_colored(result["error"], "red")
        raise typer.Exit(code=2)

    if json_output:
        typer.echo(json.dumps(result, indent=2))
        return

    _render_pivot(result)


def _corpus_row_counts() -> dict:
    """How much corpus the local database already holds."""
    from ..db import get_connection
    counts = {"profiles": 0, "snapshots": 0}
    with get_connection() as conn:
        counts["profiles"] = conn.execute(
            "SELECT COUNT(*) AS n FROM package_profiles"
        ).fetchone()["n"]
        counts["snapshots"] = conn.execute(
            "SELECT COUNT(*) AS n FROM pkgbuild_snapshots"
        ).fetchone()["n"]
    return counts


@corpus_app.command("fetch")
def corpus_fetch(
    tag: str | None = typer.Option(
        None, "--tag", help="Fetch a specific release tag instead of the latest"
    ),
    yes: bool = typer.Option(
        False, "--yes", help="Import without asking, even into a non-empty corpus"
    ),
    json_output: bool = typer.Option(False, "--json", help="Output JSON"),
):
    """Download, verify and import the signed corpus baseline.

    The corpus baseline ships as ``baseline-corpus.tar.zst`` in the
    TrustSight release channel with a detached ed25519 signature.  The
    signature is verified against the pinned distribution key before the
    artifact bytes are parsed; a mismatch is a refusal, not a warning,
    and there is no path that imports unverified bytes.  A version 2
    artifact also warms the novelty priors (source URLs, dependency
    names, salted maintainer hashes) as part of the import.

    Unless ``--yes`` is given, importing into an existing non-empty
    corpus asks first; declining exits 2.  With ``--json`` the plan is
    printed without prompting, like every other ``--json`` mode.
    """
    from .. import release

    ensure_default_configs()
    init_db()

    if release.offline():
        msg = "The release channel is disabled (TRUSTSIGHT_OFFLINE is set)."
        if json_output:
            typer.echo(json.dumps({"error": msg}))
        else:
            _print_colored(msg, "red", stderr=True)
        raise typer.Exit(code=2)

    existing = _corpus_row_counts()
    plan = {"asset": CORPUS_ASSET_NAME, "tag": tag or "latest", **existing}
    if json_output:
        typer.echo(json.dumps({"plan": plan}))
    elif (existing["profiles"] or existing["snapshots"]) and not yes:
        if not typer.confirm(
            f"The local corpus already holds {existing['profiles']:,} profile(s) "
            f"and {existing['snapshots']:,} snapshot(s). Merge the fetched "
            "baseline into it?"
        ):
            _print_colored("Corpus fetch cancelled; the local corpus is unchanged.", "yellow")
            raise typer.Exit(code=2)

    try:
        with download_progress(
            f"Downloading {CORPUS_ASSET_NAME}...",
            enabled=use_rich_progress() and not json_output,
        ) as on_download:
            data = release.fetch_verified_asset(
                CORPUS_ASSET_NAME, tag=tag, on_progress=on_download,
            )
    except release.ReleaseError as exc:
        msg = f"Corpus fetch refused: {exc}"
        if json_output:
            typer.echo(json.dumps({"error": msg}))
        else:
            _print_colored(msg, "red", stderr=True)
        raise typer.Exit(code=2)

    import shutil
    import tempfile
    from pathlib import Path

    from ..full_aur.export import import_baseline

    tmp_dir = Path(tempfile.mkdtemp(prefix="trustsight-corpus-fetch-"))
    try:
        artifact_path = tmp_dir / CORPUS_ASSET_NAME
        artifact_path.write_bytes(data)
        try:
            import_baseline(str(artifact_path), json_output=json_output)
        except Exception as exc:
            # fetch_verified_asset already pinned the signature, so a
            # failure here is a malformed artifact, not an unverified one;
            # still report it like every other refusal.
            msg = str(exc) or exc.__class__.__name__
            if json_output:
                typer.echo(json.dumps({"error": msg}))
            else:
                _print_colored(msg, "red", stderr=True)
            raise typer.Exit(code=2)
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)

    if not json_output:
        _print_colored(
            "Verified and imported the corpus baseline from the release channel.",
            "green",
        )


def _render_pivot(result: dict) -> None:
    """Print a pivot result.

    Split out of ``pivot_cmd`` so it can be exercised directly: a renderer
    that cannot be called without a CLI invocation cannot be covered by
    the ``terminal output is inert`` gate, and an uncoverable render path
    is where an unsanitised value hides.
    """
    listed = "shipped indicator" if result["listed"] else "not on the shipped list"
    header = f"{result['indicator']}  ({result['type']}, {listed})"
    if result["listed"]:
        header += f"  confidence={result['confidence'] or 'unspecified'}"

    if not result["sources"]:
        _print_colored(
            "No corpus data searched: run 'trustsight full-aur' or import a "
            "baseline first.", "yellow",
        )
        return

    if not result["matches"]:
        _print_colored(clean(header), "cyan")
        _print_colored(
            f"No package in {', '.join(result['sources'])} references it. "
            "A miss is uninformative.", "yellow",
        )
        return

    if use_rich():
        from rich.table import Table
        from rich.text import Text

        con = console()
        con.print(Text(clean(header), style="bold cyan"))
        table = Table(show_header=True, header_style="bold")
        table.add_column("Package")
        table.add_column("Surface")
        table.add_column("Reference")
        for match in result["matches"]:
            table.add_row(
                Text(clean(match["package"])),
                Text(clean(match["surface"])),
                Text(clean(match["detail"], limit=200)),
            )
        con.print(table)
        con.print(f"[dim]searched: {', '.join(result['sources'])}[/]")
    else:
        print(clean(header))
        for match in result["matches"]:
            print(f"{clean(match['package'])}\t{clean(match['surface'])}\t{clean(match['detail'], limit=200)}")
        print(f"searched: {', '.join(result['sources'])}")


def register_commands(app: typer.Typer):
    """Register the ``corpus`` subcommand group on *app*."""
    app.add_typer(corpus_app, name="corpus")
