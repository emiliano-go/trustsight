"""``trustsight corpus`` - corpus-wide queries (plan §9).

``corpus pivot <ioc>`` inverts R106: instead of asking what one package
carries, it asks which packages reference one indicator.  That is the shape
of the question an advisory creates.
"""

import json

import typer

from ..config import ensure_default_configs
from ..db import init_db
from ..safe_text import clean
from .display import HAS_RICH, _print_colored, console

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
    from ..iocs import IOC_TYPES

    if type_ is not None and type_ not in IOC_TYPES:
        _print_colored(
            f"unknown indicator type {type_!r}; expected one of "
            f"{', '.join(sorted(IOC_TYPES))}", "red",
        )
        raise typer.Exit(code=2)

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

    if HAS_RICH:
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
    app.add_typer(corpus_app, name="corpus")
