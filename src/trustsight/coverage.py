"""Analysis coverage: what a given run was able to look at.

A score answers "what did the evidence say".  It cannot answer "was there
evidence I never saw", and the two read identically in a report unless the
second one is stated.  These things make a run partial:

* the diff was larger than the configured cap, so only its prefix was
  examined (padding a diff past the cap and appending the payload is a
  scoring bypass, and it is the reason this module exists);
* the repository file manifest was not available, so nothing outside the
  PKGBUILD was inspected;
* a ``source=`` entry is computed at build time, so the URL the build will
  actually fetch is not in the text being analysed;
* a command substitution sits at the top level of the recipe, where makepkg
  executes it while *sourcing* the file for metadata, so part of the recipe
  runs before any rule reads it and its result is not in the text either;
* the snapshot archive was refused by a read bound, so the committed file
  tree was not examined and the PKGBUILD came from the text endpoint
  instead;
* a build step resolves dependencies from a package registry, so what the
  build will fetch and run is chosen at build time by a service this
  analysis never contacts.  This is the June 2026 AUR campaign's shape: the
  upstream source was untouched and only the recipe was poisoned, so a
  reader looking at source URLs and checksums saw nothing wrong.

Every one of those is recorded as a *gap*.  A gap does not add points: it
is not evidence of wrongdoing, and inventing a score for it would corrupt
the calibration.  What it does is forbid the run from presenting as clean.
:func:`fail_closed` is where that happens, and it is the single place in
the codebase allowed to turn coverage into a verdict.
"""

import re
import threading
from .tokenizer import split_lines

# The gap identifiers.  These are part of the report schema and the
# security gates assert on them, so they are values, not prose.
DIFF_TRUNCATED = "diff_truncated"
SCAN_TRUNCATED = "scan_truncated"
LINE_TRUNCATED = "line_truncated"
TREE_NOT_ANALYZED = "tree_not_analyzed"
UNRESOLVED_SOURCE = "unresolved_source"
UNRESOLVED_PARSE_TIME = "unresolved_parse_time"
SNAPSHOT_REFUSED = "snapshot_refused"
UNPINNED_BUILD_DEPS = "unpinned_build_deps"
COMPANION_TRUNCATED = "companion_truncated"
UNPINNED_SOURCE_REF = "unpinned_source_ref"
DEPS_NOT_SCANNED = "deps_not_scanned"
RULESET_DRIFTED = "ruleset_drifted"
STAGE_DEGRADED = "stage_degraded"

GAPS = (
    DIFF_TRUNCATED,
    LINE_TRUNCATED,
    TREE_NOT_ANALYZED,
    COMPANION_TRUNCATED,
    UNRESOLVED_SOURCE,
    UNRESOLVED_PARSE_TIME,
    SNAPSHOT_REFUSED,
    UNPINNED_BUILD_DEPS,
    RULESET_DRIFTED,
    DEPS_NOT_SCANNED,
    STAGE_DEGRADED,
)

GAP_REASONS = {
    DIFF_TRUNCATED: (
        "the diff exceeded the size cap, so only its first bytes were examined"
    ),
    SCAN_TRUNCATED: (
        "the diff held more lines than the matching limit, so its last lines "
        "were not matched against any rule"
    ),
    LINE_TRUNCATED: (
        "a line was longer than the matching limit, so its tail was not "
        "matched against any rule"
    ),
    TREE_NOT_ANALYZED: (
        "the repository file manifest was unavailable, so only the PKGBUILD "
        "was examined"
    ),
    COMPANION_TRUNCATED: (
        "a committed file the recipe names was larger than the companion "
        "read budget, or there were more of them than the file limit, so "
        "its content was not matched against any rule"
    ),
    UNRESOLVED_SOURCE: (
        "a source entry is computed at build time, so the URL that will be "
        "fetched is not in the analysed text"
    ),
    UNRESOLVED_PARSE_TIME: (
        "a command substitution runs when the recipe is parsed, so its "
        "result is not in the analysed text"
    ),
    SNAPSHOT_REFUSED: (
        "the snapshot archive exceeded a read bound and was refused, so the "
        "committed file tree was not examined"
    ),
    UNPINNED_BUILD_DEPS: (
        "a build step resolves dependencies from a package registry, so the "
        "code the build will fetch and execute is not in the analysed text "
        "and no checksum in this recipe covers it"
    ),
    DEPS_NOT_SCANNED: (
        "the AUR dependency walk stopped before the closure was exhausted, so "
        "some packages this build will pull in were never analysed"
    ),
    RULESET_DRIFTED: (
        "the installed rules.toml differs from the shipped rule set in a "
        "field that changes what a rule detects, so this analysis did not "
        "run the checks this version documents"
    ),
    STAGE_DEGRADED: (
        "an analysis stage could not complete on this input, so the checks it "
        "performs did not run over all of the change"
    ),
}


# ---------------------------------------------------------------------------
# Stage failures.
# ---------------------------------------------------------------------------
#
# The gaps above are all *anticipated*: a bound was hit, a value was not
# resolvable.  This one covers the other kind, where a stage meant to run
# raised and the handler returned a neutral value.  Every such handler read
# as "no finding here", which is the same thing an analysis that ran and
# found nothing reports - so an unbalanced quote in a `source=` array, or a
# blob that would not stream, removed a whole check and left the verdict
# saying UNFLAGGED with no hint that anything had been skipped.  That is the
# exact condition B2 forbids.
#
# Thread-local, and for the reason the rules memo is: `review` analyses
# packages in a pool, and a shared set would attribute one package's failure
# to whichever report happened to be assembling.
_stages = threading.local()


def begin_stage_tracking() -> None:
    """Start a fresh stage-failure record for the calling thread."""
    _stages.failed = []


def note_stage_failure(stage: str) -> None:
    """Record that *stage* could not complete.

    Called from an exception handler that is about to return a neutral
    value.  Safe to call outside an analysis: without a prior
    :func:`begin_stage_tracking` the note is dropped rather than leaking
    into the next run on this thread.
    """
    failed = getattr(_stages, "failed", None)
    if failed is None:
        return
    if stage not in failed:
        failed.append(stage)


def stage_failures() -> list[str]:
    """The stages that failed since :func:`begin_stage_tracking`."""
    return list(getattr(_stages, "failed", []) or [])

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


#: A VCS source entry.  makepkg spells the scheme as `<vcs>+<url>`.
_VCS_SOURCE_RE = re.compile(
    r"\b(?:git|hg|svn|bzr|fossil)\+(?P<url>[^\s'\"()]+)", re.IGNORECASE
)

#: A fragment that names an immutable object.  Everything else - `#branch=`,
#: `#tag=`, or no fragment at all - resolves at build time.
_PINNED_FRAGMENT_RE = re.compile(
    r"#(?:commit|revision)=(?P<rev>[0-9a-f]{7,40}|\$\{?[A-Za-z_]\w*\}?)",
    re.IGNORECASE,
)


def unpinned_source_refs(text: str) -> list[str]:
    """VCS source entries whose content is chosen after this analysis.

    ``git+https://example/x.git#commit=<sha>`` names one immutable tree, and
    changing it changes the diff.  ``#branch=main``, ``#tag=v1`` and a bare
    ``git+url`` do not: makepkg resolves them when the package is built, so
    what gets compiled and run is whatever upstream publishes at that
    moment.  Two builds of the identical recipe can execute different code
    and neither the recipe nor its diff records that.

    R079 already reports the *transition* - a commit pin replaced by a
    movable ref is an edit, and an edit is evidence.  It cannot report the
    steady state, because a package that has always tracked a branch never
    edits anything, and that is the case this gap covers.  A tag is included
    deliberately: a tag is a name upstream can repoint, which is R079's own
    stated reasoning.

    Reported as P008, a declared-practice fact at weight 0, not as a
    coverage gap: the statement is true of every VCS package by design, and
    a gap fires 12.2% of the locked benign corpus into Inconclusive, which
    buys alert fatigue rather than information.  The reader is told what the
    recipe declares and the band is left alone.

    Returns the offending entries so the report can quote them.
    """
    found: list[str] = []
    for line in split_lines(text):
        if line.startswith(("---", "+++", "@@")):
            continue
        if line.startswith("-"):
            continue
        body = line[1:] if line[:1] in ("+", " ") else line
        stripped = body.strip()
        if stripped.startswith("#"):
            continue
        for match in _VCS_SOURCE_RE.finditer(body):
            entry = match.group(0)
            if _PINNED_FRAGMENT_RE.search(entry):
                continue
            if entry not in found:
                found.append(entry[:120])
    return found


def unresolved_source_lines(diff_text: str) -> list[str]:
    """Added ``source=`` entries whose value is computed, not written.

    Returns the offending lines, stripped, so the report can quote what it
    could not resolve rather than asserting it in the abstract.

    A ``source=(`` array spans several physical lines, and the command
    substitution usually rides a continuation line, not the opener.  The
    opener starts an *open array*; every added continuation up to the
    closing ``)`` is part of the same logical assignment and is checked too.
    The logical entry, not the physical line, is the unit the attacker
    controls, the same reason backslash continuations are joined before A5
    measures a line.
    """
    found: list[str] = []
    in_source_array = False
    for line in split_lines(diff_text):
        if line.startswith("+++") or line.startswith("---") or line.startswith("@@"):
            continue
        # A removal cannot introduce an unresolved source; context ("  ")
        # lines inside an added array still belong to the logical entry.
        if line.startswith("-"):
            continue
        body = line[1:] if line[:1] in ("+", " ") else line
        stripped = body.lstrip()

        if in_source_array:
            # A comment line inside the array carries no value.
            if not stripped.startswith("#") and _COMMAND_SUBSTITUTION_RE.search(body):
                found.append(body.strip()[:200])
            if ")" in body:
                in_source_array = False
            continue

        if stripped.startswith("#") or not _SOURCE_ASSIGN_RE.match(body):
            continue
        # The opener line itself, then decide whether the array stays open.
        if _COMMAND_SUBSTITUTION_RE.search(body):
            found.append(body.strip()[:200])
        # Open only when it is an array whose ``)`` has not arrived yet.
        if "(" in body and ")" not in body:
            in_source_array = True
    return found


def parse_time_substitution_lines(diff_text: str) -> list[str]:
    """Added top-level lines whose command substitution runs at parse time.

    makepkg *sources* the PKGBUILD to extract metadata, and so does every
    AUR helper's ``--printsrcinfo`` refresh: a ``$(...)`` or backtick
    substitution outside every function body executes on the machine doing
    the reading, before any build step and before any rule here has seen
    its output.  The recipe is then not statically analyzable as text, so
    the line is recorded as a gap rather than matched against rules.

    Lines inside a function body run at build time and are already the
    rule engine's territory; lines a ``source=`` assignment owns are the
    ``unresolved_source`` gap's.  Both are excluded here so each gap
    reports the lines only it can explain.  A continuation of a top-level
    array assignment (``_pinned=(`` ... ``"$(get_rev)"``) is parse time
    too: the whole assignment is evaluated when the file is sourced.
    """
    from .rules import _FUNCTION_CLOSE_RE, _FUNCTION_OPEN_RE

    found: list[str] = []
    depth = 0
    in_source_array = False
    for line in split_lines(diff_text):
        if line.startswith("+++") or line.startswith("---") or line.startswith("@@"):
            continue
        # Removals belong to the old file; context and added lines make up
        # the new one, so both move the function-depth and array state.
        if line.startswith("-"):
            continue
        body = line[1:] if line[:1] in ("+", " ") else line
        stripped = body.lstrip()

        if in_source_array:
            if ")" in body:
                in_source_array = False
            continue
        if _SOURCE_ASSIGN_RE.match(body) and "(" in body and ")" not in body:
            # An added source array whose command substitution rides a
            # continuation line: unresolved_source_lines reports it.
            if not stripped.startswith("#"):
                in_source_array = True
            continue

        opens = bool(_FUNCTION_OPEN_RE.search(stripped))
        if (
            line.startswith("+")
            and depth == 0
            and not opens
            and not stripped.startswith("#")
            and not _SOURCE_ASSIGN_RE.match(body)
            and _COMMAND_SUBSTITUTION_RE.search(body)
        ):
            found.append(body.strip()[:200])

        if opens:
            depth += 1
            # Opened and closed on one line: the counter must not stay up.
            if stripped.rstrip().endswith("}"):
                depth -= 1
        elif _FUNCTION_CLOSE_RE.search(stripped):
            depth = max(0, depth - 1)
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
    scan_truncated: bool = False,
    tree_analyzed: bool = True,
    companion_truncated: bool = False,
    unresolved_sources: list[str] | None = None,
    long_lines: int = 0,
    parse_time_substitutions: list[str] | None = None,
    snapshot_refused: bool = False,
    unpinned_build_deps: bool = False,
    deps_not_scanned: bool = False,
    ruleset_drifted: bool = False,
    degraded_stages: list[str] | None = None,
) -> list[str]:
    """Assemble the gap list for one analysis, in a stable order."""
    gaps: list[str] = []
    if diff_truncated:
        gaps.append(DIFF_TRUNCATED)
    # Distinct from DIFF_TRUNCATED rather than folded into it: both mean
    # content was dropped, but they point at different dials. A reader who
    # saw only "the diff was truncated" would raise `diff.max_diff_bytes`
    # and find it changed nothing, because the line count was the bound.
    if scan_truncated:
        gaps.append(SCAN_TRUNCATED)
    if long_lines:
        gaps.append(LINE_TRUNCATED)
    if not tree_analyzed:
        gaps.append(TREE_NOT_ANALYZED)
    # Separate from TREE_NOT_ANALYZED: that gap says no manifest was
    # available at all, this one says a file the recipe *executes* was read
    # only in part, which points at a different dial (MAX_COMPANION_BYTES).
    if companion_truncated:
        gaps.append(COMPANION_TRUNCATED)
    if unresolved_sources:
        gaps.append(UNRESOLVED_SOURCE)
    if parse_time_substitutions:
        gaps.append(UNRESOLVED_PARSE_TIME)
    # Reported alongside TREE_NOT_ANALYZED rather than instead of it: that
    # gap says the tree was not examined, and this one says a bound is why.
    # A14 requires a bound that drops content to be visible *as a bound*,
    # and "the manifest was unavailable" would read as an absent snapshot.
    if snapshot_refused:
        gaps.append(SNAPSHOT_REFUSED)
    if unpinned_build_deps:
        gaps.append(UNPINNED_BUILD_DEPS)
    # Only a walk cut short by a ceiling, or one that could not analyse a
    # dependency, is a gap.  Asking for depth 1 and getting depth 1 is a
    # complete answer to the question the operator asked, even though a
    # level 2 exists.
    if deps_not_scanned:
        gaps.append(DEPS_NOT_SCANNED)
    # `rules.toml` is written once, at install time, and never rewritten.
    # A user who never hand-edits rules therefore runs whatever the
    # defaults were on the day the tool first ran - and `sync-rules`
    # *reports* the divergence but refuses to adopt shipped patterns,
    # because it cannot tell a stale rule from a customised one except
    # through a hand-maintained list of superseded patterns.
    #
    # That is a defensible refusal: overwriting a user's edits would be
    # worse. What is not defensible is doing it silently. A run against a
    # drifted ruleset is a run whose detection surface is not the one this
    # version documents, and B2 says an analysis that could not do what it
    # claims must say so rather than report a clean verdict.
    if ruleset_drifted:
        gaps.append(RULESET_DRIFTED)
    # Last, because it is the least specific: when a named gap already
    # explains the same shortfall the reader wants that one first.
    if degraded_stages:
        gaps.append(STAGE_DEGRADED)
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

# How each gap reads when it is the *cause* of an Inconclusive verdict.
# A gap means "I could not watch that", and what was not watched may be
# where the payload is, so the wording is urgency, not description: it
# must read as more urgent than the cold-start case in inconclusive_label.
GAP_INCONCLUSIVE_REASONS = {
    DIFF_TRUNCATED: "diff truncated: payload may be hidden",
    LINE_TRUNCATED: "line truncated: payload may be hidden",
    TREE_NOT_ANALYZED: "repository files not examined: payload may be hidden",
    COMPANION_TRUNCATED: (
        "a committed file the recipe runs was not read in full: payload may "
        "be hidden"
    ),
    UNRESOLVED_SOURCE: (
        "source computed at build time: fetch destination unknown"
    ),
    UNRESOLVED_PARSE_TIME: (
        "code runs at parse time: recipe not statically analyzable"
    ),
    SNAPSHOT_REFUSED: (
        "snapshot refused by a read bound: file tree not examined"
    ),
    UNPINNED_BUILD_DEPS: (
        "build fetches unpinned dependencies: what will execute is unknown"
    ),
    DEPS_NOT_SCANNED: (
        "dependency walk cut short: part of the closure was never analysed"
    ),
    RULESET_DRIFTED: (
        "installed rules differ from shipped: checks did not run as documented"
    ),
    STAGE_DEGRADED: (
        "an analysis stage failed on this input: its checks did not run"
    ),
}


def inconclusive_label(gaps: list[str], cold_start_needed: int | None = None) -> str:
    """The Inconclusive band with its *cause* named, for human render.

    A bare "Inconclusive" flattens two very different situations into one
    string: a coverage gap ("I could not watch that", and that may be
    where the payload is) and a cold database ("I have not watched this
    for long enough yet", the routine reality of a new package).  What
    the flattening buys is alert fatigue, so the label says which one it
    is, and the gap case is worded as the more urgent of the two.

    When both causes are present the gap wording wins, and the cold-start
    count is omitted rather than stacked behind it: trailing a routine
    note after "payload may be hidden" would dilute exactly the signal
    this label exists to sharpen.

    A gap name this build does not know - one written by a newer version
    and read back from an old report - still surfaces, under a generic
    wording, rather than vanishing.
    """
    if gaps:
        reasons = [
            GAP_INCONCLUSIVE_REASONS.get(gap, f"{gap}: analysis incomplete")
            for gap in gaps
        ]
        return f"Inconclusive ({'; '.join(reasons)})"
    if cold_start_needed is not None:
        return f"Inconclusive (cold start: {cold_start_needed} more analyses needed)"
    return "Inconclusive"


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
