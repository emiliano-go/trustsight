"""Every output method reports the same information for the same input.

B11 says the surfaces differ in *form* and never in *information*. The gates
in ``scripts/security_gates.py`` compare the three JSON bodies to each other;
this module compares the JSON against the **terminal** renders, which is the
half a key-set comparison cannot reach.

There are seven output methods, and the point of the file is that a fact is
pushed through all of them rather than through whichever one is convenient
to call:

* ``review --json``      - ``report_body`` over a review row
* ``review`` rich        - ``review._render_results_rich``
* ``review`` plain       - ``review._render_results_plain``
* ``inspect --json``     - ``report_body`` over an evaluated fact
* ``inspect`` rich       - ``inspect._inspect_rich``
* ``inspect`` plain      - ``inspect._inspect_plain``
* the API                - ``Report.to_dict`` / attribute access

The fixture's values are deliberately short and distinctive so that finding
them in a rendered table is a real check rather than a fight with wrapping.
"""

import contextlib
import io

import pytest
from rich.console import Console

import trustsight.cli.display as display
import trustsight.cli.inspect as inspect_cli
import trustsight.cli.review as review_cli
from trustsight.api import _report_from_fact
from trustsight.coverage import GAP_REASONS
from trustsight.reporting import evaluate_fact, report_body
from trustsight.schema import (
    DiffSummary,
    ExecutionChanges,
    PackageFact,
    ScoreEntry,
    SourceChanges,
)

# Short, unmistakable tokens: each one either survives a render intact or is
# genuinely missing.  A long sentence would only prove the terminal wraps.
PKG = "parity-pkg"
OLD, NEW = "1.0", "1.1"
RULE = "R001"
REASON = "curlpipe"
FILE = "PKGBUILD"
CHANGE = "PKGBUILD modified"
SUPPRESSED = "R099"
GAP = "diff_truncated"
COMMAND = "curlpipe-cmd"
MAINTAINER = "Parity Maintainer"
URL = "https://parity.invalid/p.tar.gz"


def _fact() -> PackageFact:
    return PackageFact(
        package_name=PKG,
        old_version=OLD,
        new_version=NEW,
        current_maintainer=MAINTAINER,
        # The reconstructed command text a rule matched on. Left out of this
        # fixture, it was left out of the plain renderer too: the evidence
        # behind a finding was visible only where Rich happened to be
        # installed, and nothing here noticed.
        execution_changes=ExecutionChanges(resolved_commands=[COMMAND]),
        source_changes=SourceChanges(added_urls=[URL]),
        source_buckets={URL: "unknown"},
        diff_summary=DiffSummary(
            lines_added=1,
            lines_removed=0,
            files_changed=[FILE],
            file_changes=[{"path": FILE, "status": "modified"}],
        ),
        score_breakdown=[
            ScoreEntry(rule_id=RULE, severity="HIGH", weight=25,
                       reason=REASON, file=FILE, line=4),
        ],
        final_score=25,
        risk="Medium",
        coverage_gaps=[GAP],
        changes=[CHANGE],
        suppressed_rules=[{"rule_id": SUPPRESSED, "severity": "LOW",
                           "override_reason": "known"}],
    )


def _row(fact) -> dict:
    """The review engine's row shape for the same fact."""
    row = dict(evaluate_fact(fact))
    row["failed"] = False
    return row


def _rich(fn) -> str:
    buffer = io.StringIO()
    saved = display._console
    # Wide, so a missing token is missing rather than wrapped off the edge.
    display._console = Console(file=buffer, force_terminal=False, width=240)
    try:
        fn()
    finally:
        display._console = saved
    return buffer.getvalue()


def _plain(fn) -> str:
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        fn()
    return buffer.getvalue()


def _terminal_renders(fact, *, show_score=False, show_risk=False) -> dict[str, str]:
    """Every terminal render of *fact*, under one set of flags."""
    row = _row(fact)
    return {
        "review rich": _rich(lambda: review_cli._render_results_rich(
            [row], 1, False, show_score, show_risk, False)),
        "review plain": _plain(lambda: review_cli._render_results_plain(
            [row], 1, False, show_score, show_risk, False)),
        "inspect rich": _rich(lambda: inspect_cli._inspect_rich(
            fact, show_score=show_score, show_risk=show_risk)),
        "inspect plain": _plain(lambda: inspect_cli._inspect_plain(
            fact, show_score=show_score, show_risk=show_risk)),
    }


def _json_bodies(fact, *, include_score=False, verbose=False) -> dict[str, dict]:
    """Every machine-readable body of *fact*, under one set of flags."""
    evaluated = _row(fact)
    return {
        "review --json": report_body(evaluated, include_score=include_score,
                                     verbose=verbose),
        "inspect --json": report_body(evaluate_fact(fact),
                                      include_score=include_score,
                                      verbose=verbose),
        "api to_dict": _report_from_fact(fact).to_dict(
            include_score=include_score, verbose=verbose),
    }


# ---------------------------------------------------------------------------
# The JSON bodies agree with each other.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("flags", [
    {},
    {"include_score": True},
    {"verbose": True},
    {"include_score": True, "verbose": True},
])
def test_every_json_body_is_identical(flags):
    """Same fact, same flags, same body - whichever command produced it."""
    bodies = _json_bodies(_fact(), **flags)
    reference_name, reference = next(iter(bodies.items()))
    for name, body in bodies.items():
        assert set(body) == set(reference), (
            f"{name} and {reference_name} disagree on keys: "
            f"{sorted(set(body) ^ set(reference))}"
        )
        assert body == reference, f"{name} differs from {reference_name} in values"


# ---------------------------------------------------------------------------
# The terminal renders carry what the JSON carries.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("token,what", [
    (PKG, "the package name"),
    (RULE, "the rule that fired"),
    (REASON, "why it fired"),
    (CHANGE, "what changed (B7)"),
])
def test_every_terminal_render_shows_the_evidence(token, what):
    """Evidence in the JSON body reaches every terminal render.

    Not "some render shows it": a reviewer reads whichever one their
    terminal gave them, so a field present in one and absent from another is
    a difference in information, which B11 forbids.
    """
    body = _json_bodies(_fact())["inspect --json"]
    assert token in repr(body), f"fixture is wrong: {what} is not in the JSON"

    for name, out in _terminal_renders(_fact()).items():
        assert token in out, f"{name} does not show {what} ({token!r})"


@pytest.mark.parametrize("token,what", [
    (COMMAND, "the resolved command a rule matched on"),
    (MAINTAINER, "who maintains the package"),
    (URL, "the source URL that was added"),
    (FILE, "the file that changed"),
    (SUPPRESSED, "the suppressed rule"),
])
def test_the_two_terminal_renderers_show_the_same_sections(token, what):
    """Rich and plain differ in form, never in what they report.

    These are the sections the JSON body does not carry as keys of its own,
    so the test above cannot reach them: they exist only on the terminal,
    and only a render-against-render comparison can tell whether both
    renderers have them.

    That is not hypothetical. `_inspect_plain` had no "Resolved commands"
    section at all, so the reconstructed command text behind a finding -
    the deobfuscated `curl` a rule matched - was visible only where Rich
    happened to be installed. It went unnoticed because the fixture here
    never populated `execution_changes`, which is the same shape of gap one
    level up: a renderer that is exercised with an empty section is not
    exercised.
    """
    fact = _fact()
    rich = _rich(lambda: inspect_cli._inspect_rich(fact))
    plain = _plain(lambda: inspect_cli._inspect_plain(fact))

    assert token in rich, f"inspect rich does not show {what} ({token!r})"
    assert token in plain, f"inspect plain does not show {what} ({token!r})"


def test_verbose_review_gives_the_full_report_on_both_renderers():
    """`--verbose` is a request for detail, not for detail-if-Rich-is-there.

    The Rich path has always handed off to the inspect panel for a verbose
    row. The plain path did not, so asking for more returned the same
    summary.
    """
    fact = _fact()
    row = _row(fact)
    row["_verbose_fact"] = fact

    plain = _plain(lambda: review_cli._render_results_plain(
        [row], 1, False, False, False, True))
    summary = _plain(lambda: review_cli._render_results_plain(
        [row], 1, False, False, False, False))

    assert COMMAND in plain, "verbose plain review dropped the resolved command"
    assert COMMAND not in summary, "the summary was supposed to stay a summary"


def test_a_finding_names_its_rule_once():
    """Reported from a real `review` panel.

    `verdict._render` already ends every description with `[R001]`, and the
    Rich renderer added a second copy in front of it, so each finding read

        PKGBUILD line 4 [R001]  Remote Script Execution: ... [R001]

    The plain renderer added none, so the two disagreed about the same
    finding - which is the difference in *information* B11 forbids, in the
    form that is easiest to miss because both look plausible alone.
    """
    fact = _fact()
    for name, out in _terminal_renders(fact).items():
        assert out.count(RULE) == 1, f"{name} names the rule {out.count(RULE)} times"


def test_a_finding_with_no_file_does_not_open_with_a_gap():
    """An aggregate entry (`SOURCE_BUCKET`) has no file or line.

    The line was built as `f"{file}{suffix}  {desc}"`, so with an empty
    filename it opened with a stray space where the path would have been.
    """
    from trustsight.cli.review import _finding_line

    assert _finding_line({"description": "d", "rule_id": "SOURCE_BUCKET"}) == "d"
    assert _finding_line(
        {"file": "PKGBUILD", "line": 4, "description": "d"}
    ) == "PKGBUILD line 4  d"


def test_a_dependency_card_withholds_the_band_like_everything_else():
    """Reported from a real `review` panel: `Risk (High)` with no flag.

    Every other surface withholds the band unless `--score` or `--risk`
    asked for it. The dependency card showed it whenever it was known, and
    `--risk` changed nothing either way, because the flag was never passed
    down to the card at all.
    """
    from trustsight.cli.display import dependency_cards_rich, dependency_lines_plain

    dep = [{"name": "libhelper", "depth": 1, "score": 55, "risk": "High",
            "finding_count": 2, "coverage_gaps": []}]

    def rendered(**flags):
        return _rich(lambda: display._console.print(
            *dependency_cards_rich(dep, **flags)))

    assert "High" not in rendered()
    assert "High" in rendered(show_risk=True)
    assert "55/100" in rendered(show_score=True)

    assert "High" not in " ".join(dependency_lines_plain(dep))
    assert "High" in " ".join(dependency_lines_plain(dep, show_risk=True))


def test_every_terminal_render_shows_the_coverage_gap():
    """B2: the gap is never dropped from the terminal, band or no band.

    `inspect` used to show nothing at all about a partial read unless
    `--score` or `--risk` was passed, because the gap rode the band label
    and the default output withholds the band. The one light that must
    never be suppressible was suppressed by default on that command.
    """
    reason = GAP_REASONS[GAP]
    for name, out in _terminal_renders(_fact()).items():
        assert reason in out or GAP in out, f"{name} does not report the gap"


def test_the_coverage_gap_survives_every_flag_combination():
    for show_score, show_risk in ((False, False), (True, False), (False, True)):
        renders = _terminal_renders(_fact(), show_score=show_score,
                                    show_risk=show_risk)
        for name, out in renders.items():
            assert GAP_REASONS[GAP] in out or GAP in out, (
                f"{name} dropped the gap with "
                f"show_score={show_score} show_risk={show_risk}"
            )


def test_a_suppression_reaches_every_surface():
    """B5: a suppression a reader cannot see is one they cannot audit."""
    for body in _json_bodies(_fact()).values():
        assert [r["rule_id"] for r in body["suppressed_rules"]] == [SUPPRESSED]

    for name, out in _terminal_renders(_fact()).items():
        assert SUPPRESSED in out, f"{name} does not show the suppressed rule"


# ---------------------------------------------------------------------------
# The score is on request everywhere, by default nowhere.
# ---------------------------------------------------------------------------


def test_no_surface_volunteers_the_score():
    """The default output is evidence on every surface, terminal included."""
    for name, body in _json_bodies(_fact()).items():
        for key in ("score", "risk", "risk_label"):
            assert key not in body, f"{name} volunteers {key}"

    for name, out in _terminal_renders(_fact()).items():
        assert "25/100" not in out, f"{name} volunteers the score"
        assert "Score" not in out, f"{name} volunteers a score row"


def test_every_surface_shows_the_score_when_it_is_asked_for():
    """And the same number, in whichever form the surface uses."""
    for name, body in _json_bodies(_fact(), include_score=True).items():
        assert body["score"] == 25, f"{name} reports a different score"
        assert body["risk"] == "Medium", f"{name} reports a different band"

    for name, out in _terminal_renders(_fact(), show_score=True).items():
        assert "25" in out, f"{name} does not show the score when asked"


def test_the_api_matches_the_cli_on_the_flag_and_on_the_attribute():
    """Two ways to ask, one answer."""
    fact = _fact()
    report = _report_from_fact(fact)
    cli = report_body(evaluate_fact(fact), include_score=True)

    assert report.to_dict(include_score=True)["score"] == cli["score"]
    assert report.to_dict(include_score=True)["risk"] == cli["risk"]
    # Attribute access is the caller naming the field, so it always answers.
    assert report.score == cli["score"]
    assert report.risk == cli["risk"]
    # And it does not leak into the serialised default.
    assert "score" not in report.to_dict()


# ---------------------------------------------------------------------------
# Crossfire deferral: one write is scored once.
# ---------------------------------------------------------------------------


def test_x005_defers_to_h032_on_the_plain_spelling():
    """H032 owns `~/` and `$HOME/`; X005 owns the spellings that dodge it.

    Both firing on one line would score a single write twice, which is the
    double-count the persistence rules already avoid among themselves.
    """
    from trustsight.analysis import scan_diff

    def fired(command):
        diff = ("--- a/pkg.install\n+++ b/pkg.install\n@@ -1,3 +1,4 @@\n"
                " post_install() {\n+  " + command + "\n }\n")
        return {e.rule_id for e in scan_diff(diff, package_name="p").score_breakdown
                if e.weight}

    plain = fired("install -Dm755 tool ~/bin/tool")
    assert "H032" in plain and "X005" not in plain

    aliased = fired("install -Dm755 tool /home/$USER/bin/tool")
    assert "X005" in aliased and "H032" not in aliased


def test_h032_is_critical_in_an_install_scriptlet():
    """pacman runs scriptlets as root; the same write in build() is HIGH."""
    from trustsight.analysis import scan_diff

    def severity(function):
        diff = (f"--- a/p\n+++ b/p\n@@ -1,3 +1,4 @@\n {function}() {{\n"
                "+  install -Dm644 cfg $HOME/.bashrc\n }\n")
        return {e.rule_id: e.severity
                for e in scan_diff(diff, package_name="p").score_breakdown}

    assert severity("post_install")["H032"] == "CRITICAL"
    assert severity("build")["H032"] == "HIGH"
