import importlib.util
import logging
import os
import sys
from contextlib import contextmanager

from ..coverage import GAP_REASONS
from ..safe_text import clean

# Fact-to-text helpers live in ``verdict`` so the review engine and the API
# can render a version line without importing anything CLI-shaped.  They are
# re-exported here because that is where every caller already looks for them.
from ..verdict import (  # noqa: F401
    display_version,
    no_aur_change_note,
    version_transition,
)

# Whether rich is installed, answered without executing it.  `app.py`
# imports every command module to register its commands, and each of those
# imports this one, so importing rich here put its whole package on the path
# of `--version`.  `find_spec` reads the import system's metadata and stops;
# the objects themselves are imported where they are used, which is the
# pattern the command modules already follow for `Table` and `Text`.
HAS_RICH = importlib.util.find_spec("rich") is not None

log = logging.getLogger(__name__)
_console = None


def _isatty(stream) -> bool:
    try:
        return bool(stream.isatty())
    except (AttributeError, ValueError):
        return False


def _rich_forced() -> bool:
    return bool(os.environ.get("FORCE_COLOR") or os.environ.get("TRUSTSIGHT_FORCE_RICH"))


def use_rich() -> bool:
    """Whether to render stdout with Rich.

    Rich is for a terminal.  A pipe, a redirect or a captured stream gets
    the plain renderer, so ``trustsight ... | cat`` carries text rather than
    box drawing and escape sequences.  ``NO_COLOR`` turns it off everywhere;
    ``FORCE_COLOR`` (or ``TRUSTSIGHT_FORCE_RICH``) turns it back on for a
    pipe that does want the styled form.
    """
    if not HAS_RICH:
        return False
    if _rich_forced():
        return True
    if os.environ.get("NO_COLOR"):
        return False
    return _isatty(sys.stdout)


def use_rich_progress() -> bool:
    """Whether to draw Rich progress bars, which are written to stderr."""
    if not HAS_RICH:
        return False
    if _rich_forced():
        return True
    if os.environ.get("NO_COLOR"):
        return False
    return _isatty(sys.stderr)


@contextmanager
def download_progress(description: str, *, enabled: bool = True):
    """Yield an ``on_progress(pos, total)`` callback drawing a download bar.

    The bar is written to stderr and starts on the first callback, so a
    download that refuses before its first byte draws nothing.  When
    *enabled* is false the yielded callback is a no-op, keeping ``--json``,
    pipes and ``NO_COLOR`` terminals exactly as they were.
    """
    if not enabled:
        yield lambda pos, total: None
        return
    from ..sandbox import render_client

    state: dict = {"started": False}

    def on_progress(pos: int, total: int | None) -> None:
        if not state["started"]:
            render_client.start_progress(
                "download", description, kind="download")
            state["started"] = True
        render_client.update_progress(
            "download", completed=pos, total=total)

    try:
        yield on_progress
    finally:
        if state["started"]:
            render_client.stop_progress("download")


def band_colour(label: str) -> str:
    """Colour for a possibly-qualified band such as "High (incomplete analysis)".

    The qualifier is prose appended by coverage.qualified_band; the colour
    belongs to the band itself, so it is looked up on the bare word.
    """
    return RISK_COLORS.get((label or "").split(" (")[0], "white")


RISK_COLORS = {
    "Low": "green",
    "Medium": "yellow",
    "High": "red",
    "Critical": "bold red",
    "Inconclusive": "dim",
    "Error": "bold white on red",
}

SEVERITY_COLORS = {
    "FATAL": "bold white on red",
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "cyan",
    "INFO": "dim",
}

def _fmt_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f}{unit}"
        n /= 1024
    return f"{n:.1f}TB"


def finding_where(file: str, line: "int | None") -> str:
    """A finding's location as ``PKGBUILD line 4``, or ``""`` when it has none.

    One definition, shared by the review and inspect renderers: an aggregate
    entry (no file, no line - ``SOURCE_BUCKET``, a coverage row) gets no
    location prefix, and a file with no line renders as the file alone.
    The file is package-derived text, so it is cleaned like every other
    such cell.
    """
    file_part = clean(file or "")
    if file_part and line is not None:
        return f"{file_part} line {line}"
    return file_part


def emit(text: str) -> None:
    """Write render-sandbox text where the owning console would have written."""
    con = _console
    stream = getattr(con, "file", None) if con is not None else None
    target = stream if stream is not None else sys.stdout
    target.write(text)
    target.flush()


def _print_colored(msg: str, color: str = "", stderr: bool = False):
    if HAS_RICH and use_rich():
        from ..sandbox.render_client import RenderUnavailable, render
        try:
            text = render("print_colored", {
                "msg": msg, "color": color, "stderr": stderr,
            })
        except RenderUnavailable:
            raise
        con = _console
        stream = getattr(con, "file", None) if con is not None else None
        target = stream if stream is not None else (
            sys.stderr if stderr else sys.stdout)
        target.write(text)
        target.flush()
        return
    kwargs = {"file": sys.stderr} if stderr else {}
    print(msg, **kwargs)


# ---------------------------------------------------------------------------
# Dependency mini-cards.
#
# A dependency is a full analysis with its own score and band, so it gets its
# own card - nested inside the parent's, indented by depth. Both a Rich and a
# plain form live here rather than in each command, because B11 requires the
# same information on every surface and four copies of this is four chances
# to drop a field from one of them.
# ---------------------------------------------------------------------------

#: Shown when the walk stopped early, so a short list cannot read as a
#: complete closure.
DEPTH_TRUNCATED_NOTE = "dependency walk cut short; part of the closure was not analysed"


def _dep_fields(dep):
    """``(name, depth, score, risk_label, findings, gaps, failed, error)``.

    Accepts a ``DependencyReport`` or the plain dict a JSON body carries, so
    a renderer fed either shape shows the same thing.
    """
    if isinstance(dep, dict):
        get = dep.get
    else:
        def get(key, default=None):
            return getattr(dep, key, default)
    return (
        str(get("name", "") or ""),
        int(get("depth", 0) or 0),
        int(get("score", 0) or 0),
        str(get("risk_label", "") or get("risk", "") or ""),
        int(get("finding_count", 0) or 0),
        list(get("coverage_gaps", ()) or ()),
        bool(get("failed", False)),
        str(get("error", "") or ""),
    )


def dependency_lines_plain(dependencies, *, show_score=False, show_risk=False):
    """The same information, as indented plain-text lines."""
    from ..review_policy import review_policy

    policy = review_policy()
    out = []
    for dep in dependencies:
        name, depth, score, label, findings, gaps, failed, error = _dep_fields(dep)
        indent = "  " * (depth + 1)
        if failed:
            out.append(f"{indent}[dep L{depth}] {clean(name)}: NOT vetted ({clean(error)})")
            continue
        head = f"{indent}[dep L{depth}] {clean(name)}: {findings} finding(s)"
        if show_score:
            head += f", {score}/100 ({clean(label)})"
        elif show_risk and label:
            head += f", {clean(label)}"
        if policy.flagged(score):
            head += "  <- flagged"
        out.append(head)
        for gap in gaps:
            out.append(f"{indent}  [Not fully vetted: {clean(GAP_REASONS.get(gap, gap))}.]")
    return out
