"""The public CLI entry points.

``app`` and ``main`` keep their historical spellings.  ``run`` is the
process entry point: ``main`` raises ``typer.Exit`` by contract (the exit
code the command chose), and a console script that called it directly
would print a traceback for every deliberate failure.  ``run`` converts
that exception to the process status.
"""

from __future__ import annotations

import typer

from .app import app as app
from .app import main as main


def entrypoint() -> None:
    """Console entry point: main()'s ``typer.Exit`` becomes an exit status."""
    try:
        main()
    except typer.Exit as exc:
        raise SystemExit(exc.exit_code) from None
