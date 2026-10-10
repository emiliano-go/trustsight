"""Published figures must not drift from the code, the corpus or the fixtures.

Every number the docs and the site publish has one source. Rule counts come
from ``trustsight.categories``; the labelled-fixture count comes from the
committed ``expected.json`` records; the distribution figures come from the
corpus, measured by ``scripts/calibration_gates.py``; the seed counts and the
suite size are recorded once in ``tests/fixtures/published-figures.json``.

A document is prose, so nothing checks it unless a test does.  The failures
this catches are silent and were real: the docs cited a 175-fixture corpus
when the records held 179, and the whole distribution table lagged the
scoring changes that moved it.  The fix for both was a person noticing; this
module is the check that does not need one.
"""

import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

from trustsight.categories import RULE_CATEGORIES, rules_in

ROOT = Path(__file__).resolve().parent.parent
FIGURES = json.loads(
    (ROOT / "tests" / "fixtures" / "published-figures.json").read_text()
)
MALICIOUS = ROOT / "tests" / "fixtures" / "malicious"
CORPUS = ROOT / "tests" / "fixtures" / "benign-corpus"

#: Documents that publish a figure.  ``changelog.md`` is excluded: it is the
#: record of what was true at each release, and rewriting history to match
#: today would destroy the only evidence the baseline ever moved.
DOC_SOURCES = [
    ROOT / "README.md",
    *sorted(p for p in (ROOT / "docs").rglob("*.md") if p.name != "changelog.md"),
]


def test_every_published_claim_is_still_present():
    """The single source of truth for every prose figure is the JSON.

    Each claim is the exact substring a published number lives in.  A doc
    that changes the number, or drops the sentence, stops matching; the
    figure in ``published-figures.json`` then has to move with it in the
    same commit.
    """
    problems = []
    for rel, claims in FIGURES["doc_claims"].items():
        text = (ROOT / rel).read_text()
        for claim in claims:
            if claim not in text:
                problems.append(f"{rel}: no longer contains {claim!r}")
    assert not problems, "published figures drifted from the docs:\n" + "\n".join(
        problems
    )


def test_the_rule_counts_in_the_readme_match_the_catalog():
    """The README breaks the catalog into families; each count must hold.

    ``test_docs`` already ties the README's scoring total to the catalog.
    This adds the per-family counts, which are the numbers a reader uses to
    judge what the tool covers and the ones a family split moves.
    """
    by_letter: dict[str, int] = {}
    for rule_id in RULE_CATEGORIES:
        by_letter[rule_id[0]] = by_letter.get(rule_id[0], 0) + 1

    readme = (ROOT / "README.md").read_text()
    expected = {
        "R": "detection rules",
        "H": "heuristic rules",
        "C": "code-structure rules",
        "D": "dependency-graph rules",
        "S": "sabotage rules",
        "X": "crossfire anti-evasion rules",
        "M": "meta rules",
        "E": "entropy rules",
    }
    missing = [
        f"{by_letter[letter]} {label}"
        for letter, label in expected.items()
        if f"{by_letter[letter]} {label}" not in readme
    ]
    assert not missing, "README family counts drifted: " + ", ".join(missing)

    scoring = len(RULE_CATEGORIES) - by_letter.get("W", 0)
    assert f"{scoring} documented rules across eight scoring namespaces" in readme


def test_the_rules_index_legend_matches_the_catalog():
    """``index.md``'s category table is generated; its counts must be too.

    ``build_rules_index.py`` writes the table from ``RuleCategory``.  A rule
    added to the catalog without a rerun makes the table undercount, which
    the membership check in ``test_docs`` does not catch because the rule
    still has a row.
    """
    index = (ROOT / "docs" / "reference" / "rules" / "index.md").read_text()
    rows = re.findall(r"^\| \[([^\]]+)\]\([^)]+\) \| `([a-z-]+)` \| (\d+) \|",
                      index, re.M)
    assert rows, "index.md no longer carries the generated category legend"
    seen = {slug: int(count) for _title, slug, count in rows}
    expected = {
        category.value: len(rules_in(category)) for category in RULE_CATEGORIES.values()
    }
    assert seen == expected, (
        "rules index legend drifted from the catalog: "
        f"{ {k: (seen.get(k), v) for k, v in expected.items() if seen.get(k) != v} }"
    )


def test_the_labelled_fixture_count_matches_the_records():
    """The docs advertise a fixture total; the records are the count.

    ``scripts/verify_fixtures.py`` keeps every ``expected.json`` and every
    ``.diff`` in step.  The prose total was not tied to either, and sat at
    175 while the records held 179.
    """
    total = 0
    for expected in MALICIOUS.glob("*/expected.json"):
        total += len(json.loads(expected.read_text()))
    claimed = FIGURES["calibration"]["labelled_fixtures"]
    assert total == claimed, (
        f"published-figures.json claims {claimed} labelled fixtures; "
        f"the expected.json records hold {total}"
    )
    assert f"({total} labelled fixtures)" in (
        ROOT / "docs" / "reference" / "evidence-tiers.md"
    ).read_text()


def _suite_size() -> tuple[int, int]:
    """The collected test count and test-file count, measured, not asserted."""
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q", "tests/"],
        cwd=ROOT, capture_output=True, text=True,
    )
    match = re.search(r"(\d+) tests? collected", proc.stdout)
    assert match, f"could not read the collected count:\n{proc.stdout[-2000:]}"
    files = len(list((ROOT / "tests").rglob("test_*.py")))
    return int(match.group(1)), files


@pytest.mark.skipif(
    os.environ.get("TRUSTSIGHT_PUBLISHED_FIGURES_STRICT") != "1",
    reason="the published count is measured on the calibration runner: the "
           "collected set depends on the environment and the corpus; set "
           "TRUSTSIGHT_PUBLISHED_FIGURES_STRICT=1 there",
)
def test_the_published_suite_size_matches_the_suite():
    """The site quotes an exact test count, so it has to be exact.

    Adding a test moves the count.  The JSON is the published value, so a
    test that is added without refreshing it fails here rather than leaving
    the site quoting a stale number.

    The count is only the published one on the calibration runner: one module
    parametrizes over the corpus diffs, and the installed extras move the
    collected set too, so a checkout that merely has a corpus still collects a
    different number.  This assertion therefore runs only where the figure is
    defined, signalled by ``TRUSTSIGHT_PUBLISHED_FIGURES_STRICT``; everywhere
    else the whole module still runs, this test just skips.
    """
    count, files = _suite_size()
    assert (count, files) == (FIGURES["tests"]["count"], FIGURES["tests"]["files"]), (
        f"the suite holds {count} tests across {files} files; "
        f"published-figures.json says {FIGURES['tests']['count']} across "
        f"{FIGURES['tests']['files']}"
    )


def test_the_seed_counts_are_published_somewhere():
    """The seed has no committed metadata, so the docs are the record.

    A seed figure is only checkable against itself, but it must at least
    appear in the prose that describes the seed.  ``doc_claims`` already
    pins the exact strings; this is the guard that the JSON and the claims
    cannot diverge into two different sets of numbers.
    """
    seed = FIGURES["seed"]
    rendered = {f"{value:,}" for value in seed.values()}
    claims = "\n".join(
        claim for claims in FIGURES["doc_claims"].values() for claim in claims
    )
    missing = sorted(value for value in rendered if value not in claims)
    assert not missing, f"seed counts absent from the claims: {missing}"
