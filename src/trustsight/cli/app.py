import logging
import os
import sys

import typer

from ..safe_text import clean, clean_log


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
    # Every command warns when a newer release exists, so a version behind
    # cannot silently miss a detection.  Skipped for `--help`/`-h` (help
    # must not touch the network or create config) and for `-v`/`--version`
    # (handled eagerly above).
    argv = sys.argv[1:]
    if not any(token in argv for token in ("-h", "--help", "-v", "--version")):
        from .updates import check_and_warn, check_and_warn_pending

        check_and_warn()
        check_and_warn_pending()


# Register all command modules
from .review import register_commands as _register_review
from .inspect import register_commands as _register_inspect
from .explain import register_commands as _register_explain
from .lint import register_commands as _register_lint
from .history import register_commands as _register_history
from .list_cmd import register_commands as _register_list
from .forget import register_commands as _register_forget
from .admin import register_commands as _register_admin
from .corpus import register_commands as _register_corpus
from .ioc import register_commands as _register_ioc
from .watchlist import register_commands as _register_watchlist
from .seed import register_commands as _register_seed
from .rules import register_commands as _register_rules
from .verdict import register_commands as _register_verdict

_register_review(app)
_register_inspect(app)
_register_explain(app)
_register_lint(app)
_register_history(app)
_register_list(app)
_register_forget(app)
_register_admin(app)
_register_corpus(app)
_register_ioc(app)
_register_watchlist(app)
_register_seed(app)
_register_rules(app)
_register_verdict(app)


class _StderrHandler(logging.StreamHandler):
    """Write to the *current* ``sys.stderr``, not the object at setup time.

    ``logging.basicConfig(stream=sys.stderr)`` captures the stream object.  A
    caller that swaps and then closes ``stderr`` - a CLI test runner, a
    notebook - leaves the handler holding a closed file, and the next record
    raises ``ValueError: I/O operation on closed file`` in logging's own error
    path (which prints "--- Logging error ---" and can corrupt a ``--json``
    document).  Resolving the stream on every emit keeps the handler pointed at
    a live stream.
    """

    def emit(self, record: logging.LogRecord) -> None:
        self.stream = sys.stderr
        super().emit(record)

    def format(self, record: logging.LogRecord) -> str:
        """Render the record inert, without changing the record itself.

        The log is a terminal render path like any other (A10): a message may
        carry a maintainer name, URL, path or finding field the input chose.
        The message is one line, so ``clean`` collapses newlines and a value
        cannot forge a second log line.  Exception and stack text are
        deliberately multi-line, so ``clean_log`` strips the control
        sequences while keeping the layout a reader needs.

        A copy is formatted so a later file or document handler still sees
        the bytes the analysis produced; the terminal is the boundary, not
        the shared record.
        """
        inert = logging.makeLogRecord(record.__dict__)
        inert.msg = clean(record.getMessage())
        inert.args = ()
        return clean_log(super().format(inert))

    def handleError(self, record: logging.LogRecord) -> None:
        """Never dump the raw record when formatting fails.

        ``logging.Handler.handleError`` writes the record's message and
        arguments to stderr on a formatting error, which is exactly the
        untrusted text this handler exists to clean.  The failure stays
        visible; the contents do not.
        """
        try:
            self.stream = sys.stderr
            self.stream.write(
                "trustsight: log record could not be formatted\n")
        except Exception:
            pass


def _configure_logging() -> None:
    """Send the pipeline's progress log to stderr, honouring the env knobs.

    ``TRUSTSIGHT_LOG_LEVEL`` raises or lowers the level and
    ``TRUSTSIGHT_LOG_TIMESTAMPS`` adds a timestamp and level to each line, so an
    unattended watcher's ``docker logs`` (or journal) shows *when* a cycle ran.

    A handler is added only when the root logger has none, exactly as
    ``logging.basicConfig`` does by default.  The CLI is not the only caller of
    the engine: a test harness (or an embedder) that already configured logging
    owns the root, and adding a second handler to ``sys.stderr`` would leak the
    engine's log lines into its captured output - which corrupted the ``--json``
    documents a CLI test reads back.  ``force=True`` used to do exactly that.
    """
    level = getattr(logging, os.environ.get("TRUSTSIGHT_LOG_LEVEL", "").upper(),
                    logging.INFO)
    fmt = ("%(asctime)s %(levelname)s %(message)s"
           if os.environ.get("TRUSTSIGHT_LOG_TIMESTAMPS", "").strip()
           else "%(message)s")
    root = logging.getLogger()
    if root.handlers:
        return
    handler = _StderrHandler()
    handler.setFormatter(logging.Formatter(fmt))
    root.addHandler(handler)
    root.setLevel(level)


def main() -> None:
    """Console entry point.

    Uncaught exceptions become exit code 2 (operational failure), matching the
    contract in docs/reference/exit-codes.md: 0 means the command ran, 2 means
    it could not run or complete. Deliberate exits (typer.Exit) pass through.
    """
    # The corpus pipeline reports progress through logging; without a handler
    # those messages (including its refusal to bootstrap) would be invisible.
    # Messages go to stderr so stdout stays machine-readable.
    _configure_logging()
    try:
        app()
    except typer.Exit:
        raise
    except KeyboardInterrupt:
        print("Interrupted.", file=sys.stderr)
        raise typer.Exit(code=130)
    except Exception as exc:
        print(f"trustsight: error: {clean_log(str(exc))[:2000]}", file=sys.stderr)
        raise typer.Exit(code=2)
