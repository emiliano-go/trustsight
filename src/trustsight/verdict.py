import re

from .findings import TEMPLATES
from .schema import PackageFact, ScoreEntry

_SEVERITY_ORDER = ["FATAL", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

_PLAUSIBLE_VERSION_RE = re.compile(r"^[A-Za-z0-9._+~:-]+$")

# B9, enforced structurally rather than lexically.  Every verdict ends with
# a direction to look, so the gate can assert that something is *present*
# rather than chasing an open-ended list of reassuring phrasings.  A wording
# nobody anticipated cannot slip past a check that requires a direction.
REVIEW_DIRECTION = "Review the diff before building."
FATAL_DIRECTION = "Do not build this package. Inspect the diff and report it."
DIRECTIONS = (REVIEW_DIRECTION, FATAL_DIRECTION)


def _render(entry: ScoreEntry, fact: PackageFact) -> str:
    template = entry.template or TEMPLATES.get(entry.rule_id)
    if template is None:
        return f"{entry.reason} [{entry.rule_id}]"
    params = dict(entry.evidence) if entry.evidence else dict(entry.params) if entry.params else {}
    if fact:
        for field in ("package_name", "previous_maintainer", "current_maintainer"):
            val = getattr(fact, field, None)
            if val and field not in params:
                params[field] = val
    try:
        return f"{template.format(**params)} [{entry.rule_id}]"
    except (KeyError, ValueError):
        return f"{entry.reason} [{entry.rule_id}]"


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
    from .analysis.version import COMPARISON_INCONCLUSIVE, COMPARISON_SAME

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
    from .analysis.version import COMPARISON_INCONCLUSIVE

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


def fallback_verdict(fact: PackageFact) -> str:
    if fact.first_seen:
        seen = "No prior history for this package"
        if not fact.old_version and not fact.new_version:
            return f"{seen}. Insufficient data for a verdict. {REVIEW_DIRECTION}"
        return (
            f"First analysis. {seen}. No version bump confirmed yet. "
            f"{REVIEW_DIRECTION}"
        )

    reasons = []
    if fact.diff_summary.files_changed:
        reasons.append(f"modified {', '.join(fact.diff_summary.files_changed)}")
    if fact.source_changes.added_urls:
        reasons.append(f"added {len(fact.source_changes.added_urls)} source URL(s)")
    if fact.maintainer_changed:
        reasons.append("maintainer changed")
    if not reasons:
        reasons.append("no structural changes")
    change_summary = "; ".join(reasons)

    fired = [e for e in fact.score_breakdown if e.weight > 0 or e.severity == "FATAL"]
    if not fired:
        # B9: a fact, then the standing instruction.  "No risk signals
        # fired" on its own reads as a clearance, and no output may grant
        # permission to skip review, least of all when nothing fired.
        return (
            f"Version bump. {change_summary}. No published rule matched. "
            "Review the diff before building."
        )

    fired.sort(key=lambda e: (
        _SEVERITY_ORDER.index(e.severity) if e.severity in _SEVERITY_ORDER else 99,
        -e.weight,
    ))
    worst = fired[0]
    if worst.severity == "FATAL":
        detail = _render(worst, fact)
        return (
            f"{change_summary}. {detail}. "
            f"The package is attempting to deceive the reviewer, so the score "
            f"is capped at maximum regardless of other evidence. "
            f"{FATAL_DIRECTION}"
        )

    details = [_render(e, fact) for e in fired[:5]]
    if len(fired) > 5:
        details.append(f"and {len(fired) - 5} more signal(s)")
    signals = "; ".join(details)
    return f"Version bump. {change_summary}. Signals: {signals}. {REVIEW_DIRECTION}"
