import logging
import re
import sys

from ..scoring import risk_level, verdict_label, verdict_level

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


def display_version(v: str | None) -> str:
    if not v:
        return "-"
    if not _PLAUSIBLE_VERSION_RE.fullmatch(v):
        return "unresolved"
    return v


def version_transition(fact) -> str:
    """Render the version line for *fact* without implying a false update.

    An ``old -> new`` arrow is a claim that the two are comparable and that
    the right-hand side is newer.  For a VCS package that claim is wrong in
    both halves: the installed value is a full version built from whatever
    the upstream repository held at build time, and the AUR side is the
    placeholder ``pkgver=`` line, which is routinely *behind*.  Rendering
    that as an arrow reported a downgrade as an update.
    """
    from ..analysis.version import COMPARISON_INCONCLUSIVE, COMPARISON_SAME

    old = display_version(fact.old_version)
    new = display_version(fact.new_version)
    comparison = getattr(fact, "version_comparison", "")
    if comparison == COMPARISON_INCONCLUSIVE and fact.old_version and fact.new_version:
        return f"{old} installed / AUR pkgver {new} (not comparable)"
    if comparison == COMPARISON_SAME:
        return old
    return f"{old} -> {new}"


def no_aur_change_note(fact) -> str | None:
    """The plan §13.3 line, when the AUR holds nothing new for this package.

    The user asked what changed; the honest answer when the commit has not
    moved is that nothing did, plus why the installed version still looks
    different.
    """
    from ..analysis.version import COMPARISON_INCONCLUSIVE

    if not fact.old_commit or fact.old_commit != fact.new_commit:
        return None
    note = (
        "No changes in the AUR since last review "
        f"(commit {fact.new_commit[:8]})."
    )
    if getattr(fact, "version_comparison", "") == COMPARISON_INCONCLUSIVE:
        note += (
            "  Your installed version differs because this is a VCS package "
            "rebuilt locally."
        )
    return note


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
    from ..config import config_fingerprint
    from ..ioc_baseline import IocMatch

    def _ioc_match_dict(m: IocMatch) -> dict:
        return {
            "type": m.type,
            "value": m.value,
            "source": m.source,
            "confidence": m.confidence,
            "provenance": m.provenance,
            "campaign": m.campaign,
            "added": m.added,
            "surface": m.surface,
            "line": m.line,
            "expired": m.expired,
        }

    data = {
        # B1: which instrument produced this.  Every machine-readable report
        # carries it, so two operators comparing results can tell at a glance
        # whether they are running the same rules, thresholds and overrides.
        # `review --json` and schema.fact_to_dict carried it and this one did
        # not, which made the guarantee true of some reports and not others.
        "config_fingerprint": config_fingerprint(),
        "package": fact.package_name,
        "old_version": fact.old_version,
        "new_version": fact.new_version,
        # Machine consumers need the same caveat the table shows: the two
        # versions above are not always comparable (plan §13).
        "version_comparison": getattr(fact, "version_comparison", ""),
        "score": fact.final_score,
        "risk": verdict_level(fact),
        "risk_label": verdict_label(fact),
        "coverage_gaps": list(getattr(fact, "coverage_gaps", [])),
        "first_seen": fact.first_seen,
        "maintainer_changed": fact.maintainer_changed,
        "checksum_behavior": fact.source_changes.checksum_behavior if hasattr(fact.source_changes, "checksum_behavior") else None,
        "score_breakdown": [
            {
                "rule_id": e.rule_id,
                "severity": e.severity,
                "weight": e.weight,
                "reason": e.reason,
                "template": e.template,
                "evidence": e.evidence,
                "file": e.file,
                "line": e.line,
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
    if fact.ioc_matches:
        data["ioc_matches"] = [_ioc_match_dict(m) for m in fact.ioc_matches]
    return data


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
