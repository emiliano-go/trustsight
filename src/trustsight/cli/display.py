import logging
import re
import sys

from ..scoring import risk_level
from ..unicode import describe_fatal_codepoints, strip_ansi

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
_PLAUSIBLE_VERSION_RE = re.compile(r"^[A-Za-z0-9._+~:-]+$")

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


def display_version(v: str | None) -> str:
    if not v:
        return "-"
    if not _PLAUSIBLE_VERSION_RE.fullmatch(v):
        return "unresolved"
    return v


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


def _fact_to_dict(fact):
    data = {
        "package": fact.package_name,
        "old_version": fact.old_version,
        "new_version": fact.new_version,
        "score": fact.final_score,
        "risk": risk_level(fact.final_score),
        "first_seen": fact.first_seen,
        "maintainer_changed": fact.maintainer_changed,
        "checksum_behavior": fact.source_changes.checksum_behavior if hasattr(fact.source_changes, "checksum_behavior") else None,
        "score_breakdown": [
            {
                "rule_id": e.rule_id,
                "severity": e.severity,
                "weight": e.weight,
                "reason": e.reason,
            }
            for e in fact.score_breakdown
        ],
        "suppressed_rules": fact.suppressed_rules,
    }
    if fact.maintainer_changed:
        data["previous_maintainer"] = fact.previous_maintainer
        data["current_maintainer"] = fact.current_maintainer
    if fact.source_changes.added_urls:
        data["added_urls"] = [
            {"url": url, "bucket": fact.source_buckets.get(url, "unknown")}
            for url in fact.source_changes.added_urls
        ]
    if fact.execution_changes.resolved_commands:
        data["resolved_commands"] = fact.execution_changes.resolved_commands[:50]
    return data


def _fmt_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f}{unit}"
        n /= 1024
    return f"{n:.1f}TB"


def _print_colored(msg: str, color: str = "", stderr: bool = False):
    if HAS_RICH:
        style = f"[{color}]" if color else ""
        console().print(f"{style}{msg}[/]")
    else:
        kwargs = {"file": sys.stderr} if stderr else {}
        print(msg, **kwargs)
