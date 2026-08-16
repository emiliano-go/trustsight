import logging
import sys

from ..coverage import GAP_REASONS
from ..safe_text import clean
from ..scoring import risk_level

# Fact-to-text helpers live in ``verdict`` so the review engine and the API
# can render a version line without importing anything CLI-shaped.  They are
# re-exported here because that is where every caller already looks for them.
from ..verdict import (  # noqa: F401
    display_version,
    no_aur_change_note,
    version_transition,
)

try:
    from rich.box import SIMPLE_HEAD
    from rich.console import Console
    from rich.panel import Panel
    from rich.progress import BarColumn, DownloadColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn, TransferSpeedColumn
    from rich.rule import Rule
    from rich.table import Table
    from rich.text import Text

    HAS_RICH = True
except ImportError:
    HAS_RICH = False

log = logging.getLogger(__name__)
_console = None

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

TIER_OF = {
    "SOURCE_BUCKET": ("B", "Priors / context"),
    "NOVELTY": ("C", "History / novelty"),
    "PINNING": ("D", "Verification"),
    "VERIFICATION": ("D", "Verification"),
}
TIER_ORDER = ["A", "B", "C", "D"]
TIER_NAMES = {
    "A": "Structural (rules)",
    "B": "Priors / context",
    "C": "History / novelty",
    "D": "Verification (subtractive)",
}





def console() -> "Console":
    if not HAS_RICH:
        raise RuntimeError("rich is not available")
    global _console
    if _console is None:
        _console = Console(force_terminal=True)
    return _console


def _tier_of(entry) -> str:
    return TIER_OF.get(entry.rule_id, ("A", ""))[0]


def _severity_text(severity: str) -> "Text":
    return Text(severity, style=SEVERITY_COLORS.get(severity, "white"))


def _weight_text(weight: int) -> "Text":
    if weight > 0:
        return Text(f"+{weight}", style="red")
    if weight < 0:
        return Text(str(weight), style="green")
    return Text("0", style="dim")


def _score_text(score: int, risk: str | None = None) -> "Text":
    risk = risk or risk_level(score)
    return Text(f"{score}/100", style=RISK_COLORS.get(risk, "white"))


def _fmt_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f}{unit}"
        n /= 1024
    return f"{n:.1f}TB"


def _print_colored(msg: str, color: str = "", stderr: bool = False):
    if HAS_RICH:
        from rich.markup import escape

        style = f"[{color}]" if color else ""
        console().print(f"{style}{escape(msg)}[/]")
    else:
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


def dependency_cards_rich(dependencies, *, show_score=False, show_risk=False):
    """A Rich renderable holding one mini-card per analysed dependency.

    The band is withheld unless it was asked for, like everywhere else. It
    used to be shown whenever it was known, so a plain `review` that
    withheld the band on the package itself printed `Risk (High)` for its
    dependency - and `--risk` changed nothing, because the flag was never
    passed down here at all.
    """
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text

    from ..scoring import FLAG_THRESHOLD

    cards = []
    for dep in dependencies:
        name, depth, score, label, findings, gaps, failed, error = _dep_fields(dep)
        inner = Table.grid(padding=(0, 1))
        inner.add_column(style="dim", justify="right", no_wrap=True)
        inner.add_column()

        if failed:
            inner.add_row("Status", Text(f"NOT vetted: {clean(error)}", style="yellow"))
        else:
            inner.add_row("Findings", Text(str(findings)))
            if show_score:
                inner.add_row("Score", Text(f"{score}/100 ({clean(label)})"))
            elif show_risk and label:
                # No parentheses: they belong to the score line, where they
                # qualify a number. Alone they read as an aside.
                inner.add_row("Risk", Text(clean(label)))
        for gap in gaps:
            inner.add_row("Not vetted", Text(clean(GAP_REASONS.get(gap, gap)), style="yellow"))

        border = "yellow" if failed else (
            "red" if score > FLAG_THRESHOLD else "blue")
        cards.append(Panel(
            inner,
            title=Text(f"L{depth}  {clean(name)}"),
            border_style=border,
            padding=(0, 1),
        ))
    return cards


def dependency_lines_plain(dependencies, *, show_score=False, show_risk=False):
    """The same information, as indented plain-text lines."""
    from ..scoring import FLAG_THRESHOLD

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
        if score > FLAG_THRESHOLD:
            head += "  <- flagged"
        out.append(head)
        for gap in gaps:
            out.append(f"{indent}  [Not fully vetted: {clean(GAP_REASONS.get(gap, gap))}.]")
    return out
