import sys

import typer


def _version_callback(value: bool):
    if value:
        from .. import __version__
        typer.echo(f"trustsight {__version__}")
        raise typer.Exit()


app = typer.Typer(
    name="trustsight",
    help="TrustSight - AUR Package Update Vetting Tool",
    no_args_is_help=True,
    add_completion=True,
    epilog="New? Start with 'trustsight review', then 'trustsight inspect <pkg>'.",
)


@app.callback()
def _main(
    version: bool = typer.Option(
        False, "-v", "--version",
        callback=_version_callback,
        help="Show program's version number and exit",
    ),
):
    pass


# Register all command modules
from .review import register_commands as _register_review
from .inspect import register_commands as _register_inspect
from .history import register_commands as _register_history
from .list_cmd import register_commands as _register_list
from .forget import register_commands as _register_forget
from .admin import register_commands as _register_admin
from .corpus import register_commands as _register_corpus

_register_review(app)
_register_inspect(app)
_register_history(app)
_register_list(app)
_register_forget(app)
_register_admin(app)
_register_corpus(app)
