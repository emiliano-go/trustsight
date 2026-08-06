"""Analysis coverage: what a given run was able to look at.

A score answers "what did the evidence say".  It cannot answer "was there
evidence I never saw", and the two read identically in a report unless the
second one is stated.  Three things make a run partial:

* the diff was larger than the configured cap, so only its prefix was
  examined (padding a diff past the cap and appending the payload is a
  scoring bypass, and it is the reason this module exists);
* the repository file manifest was not available, so nothing outside the
  PKGBUILD was inspected;
* a ``source=`` entry is computed at build time, so the URL the build will
  actually fetch is not in the text being analysed.

Every one of those is recorded as a *gap*.  A gap does not add points: it
is not evidence of wrongdoing, and inventing a score for it would corrupt
the calibration.  What it does is forbid the run from presenting as clean.
:func:`fail_closed` is where that happens, and it is the single place in
the codebase allowed to turn coverage into a verdict.
"""

import re

# The gap identifiers.  These are part of the report schema and the
# security gates assert on them, so they are values, not prose.
DIFF_TRUNCATED = "diff_truncated"
LINE_TRUNCATED = "line_truncated"
TREE_NOT_ANALYZED = "tree_not_analyzed"
UNRESOLVED_SOURCE = "unresolved_source"

GAPS = (DIFF_TRUNCATED, LINE_TRUNCATED, TREE_NOT_ANALYZED, UNRESOLVED_SOURCE)

GAP_REASONS = {
    DIFF_TRUNCATED: (
        "the diff exceeded the size cap, so only its first bytes were examined"
    ),
    LINE_TRUNCATED: (
        "a line was longer than the matching limit, so its tail was not "
        "matched against any rule"
    ),
    TREE_NOT_ANALYZED: (
        "the repository file manifest was unavailable, so only the PKGBUILD "
        "was examined"
    ),
    UNRESOLVED_SOURCE: (
        "a source entry is computed at build time, so the URL that will be "
        "fetched is not in the analysed text"
    ),
}

# A source assignment, or a variable whose name says it holds a URL and
# which a source array is built from.  Both halves are declared facts: the
# array name is defined by makepkg, and the variable name is what the
# recipe itself calls it.
_SOURCE_ASSIGN_RE = re.compile(
    r"^\+?\s*(?:"
    r"source(?:_[A-Za-z0-9_]+)?"
    r"|_[A-Za-z0-9_]*(?:url|uri|src|source|mirror|tarball)[A-Za-z0-9_]*"
    r")\s*(?:\+)?=",
    re.IGNORECASE,
)

# Command substitution is the form the tokenizer cannot resolve: the value
# is whatever a program printed on the build machine.  ``${var}`` is not
# included, because the tokenizer does resolve those and R-rules already
# cover the ones it cannot.
_COMMAND_SUBSTITUTION_RE = re.compile(r"\$\(|`")


def unresolved_source_lines(diff_text: str) -> list[str]:
    """Added ``source=`` entries whose value is computed, not written.

    Returns the offending lines, stripped, so the report can quote what it
    could not resolve rather than asserting it in the abstract.
    """
    found: list[str] = []
    for line in diff_text.splitlines():
        if not line.startswith("+") or line.startswith("+++"):
            continue
        body = line[1:]
        if body.lstrip().startswith("#"):
            continue
        if not _SOURCE_ASSIGN_RE.match(body):
            continue
        if _COMMAND_SUBSTITUTION_RE.search(body):
            found.append(body.strip()[:200])
    return found


def oversized_lines(lines: list[str]) -> int:
    """How many of *lines* the rule engine will only match a prefix of.

    The clamp in :mod:`trustsight.rules` bounds matching cost, which is
    necessary, but a bound that silently drops the tail of a line is a
    skip: a payload placed past the limit is neither matched nor
    mentioned.  Counting them here turns the bound into a declared gap.
    """
    from .rules import MAX_RULE_LINE_BYTES

    return sum(1 for line in lines if len(line) > MAX_RULE_LINE_BYTES)


def gaps_from(
    diff_truncated: bool = False,
    tree_analyzed: bool = True,
    unresolved_sources: list[str] | None = None,
    long_lines: int = 0,
) -> list[str]:
    """Assemble the gap list for one analysis, in a stable order."""
    gaps: list[str] = []
    if diff_truncated:
        gaps.append(DIFF_TRUNCATED)
    if long_lines:
        gaps.append(LINE_TRUNCATED)
    if not tree_analyzed:
        gaps.append(TREE_NOT_ANALYZED)
    if unresolved_sources:
        gaps.append(UNRESOLVED_SOURCE)
    return gaps


def describe(gaps: list[str]) -> str:
    """One sentence naming every gap, for the verdict text."""
    if not gaps:
        return ""
    reasons = [GAP_REASONS[g] for g in gaps if g in GAP_REASONS]
    if not reasons:
        return ""
    if len(reasons) == 1:
        body = reasons[0]
    else:
        body = ", and ".join([", ".join(reasons[:-1]), reasons[-1]])
    return (
        f"This analysis was incomplete: {body}. "
        "The result describes what was examined, not the whole change."
    )


INCOMPLETE_SUFFIX = " (incomplete analysis)"


def qualified_band(level: str, gaps: list[str]) -> str:
    """The band as it must be *displayed* when coverage is incomplete.

    :func:`fail_closed` protects the clean and merely-elevated bands, but
    it deliberately lets a HIGH or worse keep its band, and that leaves a
    seam: pad the diff past the cap, put the payload after the cut, and
    include one cheap deliberate HIGH in the visible prefix.  The result
    reads "High", which is a confident-looking verdict, and the reviewer's
    attention lands on the decoy rather than on the fact that most of the
    change was never read.

    So the gap travels with the band wherever the band is shown.  A
    reviewer never sees a bare "High" for a run that examined part of a
    diff.  The machine-readable ``risk`` field stays a bare band, with
    ``coverage_gaps`` beside it: consumers get two fields, humans get one
    string that cannot be read without the caveat.
    """
    if not gaps or not level:
        return level
    if level == "Inconclusive":
        return level
    return level + INCOMPLETE_SUFFIX


def fail_closed(level: str, gaps: list[str], breakdown) -> str:
    """Downgrade *level* to ``Inconclusive`` when coverage is incomplete.

    A run that did not see the whole change is not entitled to say the
    change is clean.  It is still entitled to say the change is dangerous:
    a HIGH or worse finding stands on its own evidence, and hiding it
    behind "inconclusive" would lose the signal that matters most.  So the
    downgrade applies to the clean and merely-elevated bands only.
    """
    if not gaps:
        return level
    if level not in ("Low", "Medium"):
        return level
    for entry in breakdown or ():
        if entry.severity in ("HIGH", "CRITICAL", "FATAL"):
            return level
    return "Inconclusive"
