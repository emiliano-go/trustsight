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
    except (KeyError, IndexError, ValueError):
        # A malformed template (a missing key, a bare "{}" with no positional
        # argument, a bad conversion) must not escape: rules.toml templates
        # are user-written and get no load-time validation, so the reason
        # text stands in for whatever the template could not say.
        return f"{entry.reason} [{entry.rule_id}]"


def display_version(v: str | None) -> str:
    """Render a version string for display, normalizing empty or unparseable values."""
    if not v:
        return "-"
    if not _PLAUSIBLE_VERSION_RE.fullmatch(v):
        return "unresolved"
    return v


def inconclusive_reason(fact) -> str:
    """Why the two versions were not compared, in the reader's terms.

    "Not comparable" without a reason is what sent the second report on
    this line: a maintainer whose recipe declares ``epoch=1`` read the
    missing epoch on the AUR side as the cause, and reasonably so.  The
    epoch was a real defect, but it is not why the comparison was declined.

    There are exactly two causes, and they are told apart without a new
    fact field: if both sides parse as versions, the only remaining reason
    :func:`compare_installed_to_aur` refuses is that the package computes
    its version in ``pkgver()``.  Anything else means a side could not be
    read as a version at all.
    """
    from .analysis.version import parse_version

    if parse_version(fact.old_version) and parse_version(fact.new_version):
        return "pkgver() computes the version at build time"
    return "a version could not be resolved"


def version_transition(fact) -> str:
    """Render the version line for *fact* without implying a false update.

    An ``old -> new`` arrow is a claim that the two are comparable and that
    the right-hand side is newer.  For a VCS package that claim is wrong in
    both halves: the installed value is a full version built from whatever
    the upstream repository held at build time, and the AUR side is the
    ``pkgver=`` the maintainer's own last build produced, which is routinely
    *behind*.  Rendering that as an arrow reported a downgrade as an update.
    """
    from .analysis.version import COMPARISON_INCONCLUSIVE, COMPARISON_SAME

    old = display_version(fact.old_version)
    new = display_version(fact.new_version)
    comparison = getattr(fact, "version_comparison", "")
    if comparison == COMPARISON_INCONCLUSIVE and fact.old_version and fact.new_version:
        return (
            f"{old} installed / {new} declared in the AUR "
            f"(not comparable: {inconclusive_reason(fact)})"
        )
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
        from .analysis.version import parse_version

        if parse_version(fact.old_version) and parse_version(fact.new_version):
            note += (
                "  Your installed version differs because pkgver() computes "
                "the version at build time, so the AUR text records whatever "
                "the last build produced."
            )
        else:
            note += "  The two versions could not be compared."
    return note


def cached_note(fact) -> str | None:
    """The #20 status line, when the recorded analysis was served unchanged.

    Distinct from :func:`no_aur_change_note`: that one describes a fresh
    analysis of an unmoved commit, this one says the analysis itself was
    not re-run, and when the reused one was recorded.
    """
    if not getattr(fact, "cached", False):
        return None
    # The stored timestamp is SQLite's ``datetime('now')``: the date is the
    # part a reader wants, the seconds are noise.
    when = str(getattr(fact, "cached_at", "") or "").split(" ", 1)[0]
    if when:
        return f"Unchanged since last review; reusing the analysis from {when}."
    return "Unchanged since last review; reusing the recorded analysis."


def _version_prefix(fact: PackageFact) -> str:
    """Open the verdict with the version fact, never with a false claim.

    The prefix used to be the literal ``"Version bump."``, so a diff that
    changed the source but left ``pkgver`` at 1.2.3 still read as a version
    bump - contradicting C001/C002 in the same report and the change
    summary beside it.      It is derived from the fact's ``version_moved`` - any of pkgver, pkgrel
    or epoch by resolved value - so a pkgrel rebuild is not reported as
    "Version unchanged", and the sentence and C001/C002 cannot disagree.
    """
    if getattr(fact, "version_moved", False):
        return "Version bump. "
    if getattr(fact, "pkgver_changed", False):
        return "Version bump. "
    return "Version unchanged. "


def layer_sentence(fact: PackageFact) -> str:
    """Name the evidence categories the fired findings represent (Addendum 5 §3).

    A layer is the kind of evidence a finding represents, not a stage an
    attacker passed.  The sentence lists the fired categories, so the summary
    answers "which kinds of evidence produced findings" rather than implying a
    sequential attacker progression.  A ``[layers]`` override is honoured so
    every surface agrees.  Empty when nothing scored, so a clean package's
    verdict is unchanged.
    """
    from .config import load_config
    from .layers import LAYER_ORDER, layer_of, parse_overrides

    overrides = parse_overrides(load_config())
    fired = {
        layer_of(str(entry.rule_id), overrides)
        for entry in fact.score_breakdown
        if entry.weight > 0 or entry.severity == "FATAL"
    }
    fired.discard(None)
    if not fired:
        return ""
    ordered = sorted(fired, key=LAYER_ORDER.index)
    named = ", ".join(f"{layer.value} ({layer.name_text})" for layer in ordered)
    return f"Evidence categories fired: {named}. "


def fallback_verdict(fact: PackageFact) -> str:
    """Build a human-readable verdict when scoring does not produce one."""
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
        # Spec §2: a run with an open coverage gap cannot claim "no
        # structural changes" - it does not know what it did not see.  The
        # qualified phrasing is still a claim, but one bounded by what was
        # actually read.
        if fact.coverage_gaps:
            reasons.append("no structural changes in the examined portion")
        else:
            reasons.append("no structural changes")
    change_summary = "; ".join(reasons)

    fired = [e for e in fact.score_breakdown if e.weight > 0 or e.severity == "FATAL"]
    if not fired:
        # B9: a fact, then the standing instruction.  "No risk signals
        # fired" on its own reads as a clearance, and no output may grant
        # permission to skip review, least of all when nothing fired.
        return (
            f"{_version_prefix(fact)}{change_summary}. No published rule matched. "
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
            f"{_version_prefix(fact)}{change_summary}. {detail}. "
            f"The package is attempting to deceive the reviewer, so the score "
            f"is capped at maximum regardless of other evidence. "
            f"{layer_sentence(fact)}"
            f"{FATAL_DIRECTION}"
        )

    details = [_render(e, fact) for e in fired[:5]]
    if len(fired) > 5:
        details.append(f"and {len(fired) - 5} more signal(s)")
    signals = "; ".join(details)
    return (
        f"{_version_prefix(fact)}{change_summary}. Signals: {signals}. "
        f"{layer_sentence(fact)}"
        f"{REVIEW_DIRECTION}"
    )
