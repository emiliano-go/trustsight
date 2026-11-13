"""Shared Rich console and cell helpers for the render sandbox."""

from __future__ import annotations

import sys
from types import SimpleNamespace

from ..coverage import GAP_REASONS
from ..safe_text import clean
from ..scoring import risk_level

#: Set by the worker before any render module is imported.
_OUT = None
_COLOR = False

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


def set_output(stream=None, *, color: bool = False) -> None:
    """Point the render console at *stream* and choose its color mode."""
    global _OUT, _COLOR
    _OUT = stream
    _COLOR = bool(color)


def _stream():
    return _OUT if _OUT is not None else sys.stdout


def console():
    from rich.console import Console

    return Console(
        file=_stream(), force_terminal=_COLOR, width=140,
        color_system="standard" if _COLOR else None,
        no_color=not _COLOR,
    )


def err_console():
    from rich.console import Console

    return Console(
        file=_stream(), force_terminal=_COLOR, width=140,
        color_system="standard" if _COLOR else None,
        no_color=not _COLOR, stderr=True,
    )


def print_colored(*, msg: str, color: str = "", stderr: bool = False) -> None:
    """Render one coloured message.  Child of the old display helper."""
    from rich.markup import escape

    style = f"[{color}]" if color else ""
    target = err_console() if stderr else console()
    target.print(f"{style}{escape(msg)}[/]")


def severity_text(severity: str):
    from rich.text import Text

    return Text(severity, style=SEVERITY_COLORS.get(severity, "white"))


def weight_text(weight: int):
    from rich.text import Text

    if weight > 0:
        return Text(f"+{weight}", style="red")
    if weight < 0:
        return Text(str(weight), style="green")
    return Text("0", style="dim")


def score_text(score: int, risk: str | None = None):
    from rich.text import Text

    risk = risk or risk_level(score)
    return Text(f"{score}/100", style=RISK_COLORS.get(risk, "white"))


def dependency_cards(dependencies, *, show_score=False, show_risk=False,
                     policy_threshold=20):
    """One mini-card per analysed dependency."""
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text

    cards = []
    for dep in dependencies:
        name = str(_get(dep, "name", "") or "")
        depth = int(_get(dep, "depth", 0) or 0)
        score = int(_get(dep, "score", 0) or 0)
        label = str(_get(dep, "risk_label", "") or _get(dep, "risk", "") or "")
        findings = int(_get(dep, "finding_count", 0) or 0)
        gaps = list(_get(dep, "coverage_gaps", ()) or ())
        failed = bool(_get(dep, "failed", False))
        error = str(_get(dep, "error", "") or "")

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
                inner.add_row("Risk", Text(clean(label)))
        for gap in gaps:
            inner.add_row("Not vetted", Text(clean(GAP_REASONS.get(gap, gap)), style="yellow"))

        border = "yellow" if failed else (
            "red" if score > policy_threshold else "blue")
        cards.append(Panel(
            inner,
            title=Text(f"L{depth}  {clean(name)}"),
            border_style=border,
            padding=(0, 1),
        ))
    return cards


def _get(obj, key, default=None):
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def fact_view(data: dict) -> SimpleNamespace:
    """Rehydrate the plain payload into the attribute-access shape renderers use.

    Lists of dicts stay dicts where the renderer calls ``.get``; only the
    dataclass-shaped sections become namespaces.
    """
    def ns(value):
        return SimpleNamespace(**value) if isinstance(value, dict) else value

    fact = dict(data)
    for key in ("diff_summary", "source_changes", "execution_changes", "novelty_context"):
        fact[key] = ns(fact.get(key) or {})
    fact["score_breakdown"] = [ns(e) for e in fact.get("score_breakdown") or []]
    fact["ioc_matches"] = [ns(m) for m in fact.get("ioc_matches") or []]
    return SimpleNamespace(**fact)
