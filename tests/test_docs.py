"""Documentation must describe what the code actually does.

These are cheap structural checks, not prose review. They exist because
the failures they catch are silent: a rule pattern quoted in the docs
drifts from the shipped one, or a command ships without a reference
entry, and nothing fails until a user is misled.
"""

import re
from pathlib import Path

import tomllib

import pytest

from trustsight.categories import RULE_CATEGORIES, RuleCategory, category_of
from trustsight.cli import app
from trustsight.config import DEFAULT_CONFIG, DEFAULT_RULES

ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = ROOT / "docs" / "reference" / "rules"
SYSTEM_MD = RULES_DIR / "system.md"
INDEX_MD = RULES_DIR / "index.md"
CLI_MD = ROOT / "docs" / "reference" / "cli.md"
CONFIG_MD = ROOT / "docs" / "reference" / "configuration.md"
API_MD = ROOT / "docs" / "reference" / "python-api.md"
CLI_SRC = ROOT / "src" / "trustsight" / "cli"

SHIPPED_RULES = tomllib.loads(DEFAULT_RULES)["rules"]
PROGRAMMATIC_RULES = ["R004", "R005", "C001", "C002", "C003",
                      "C004", "C005", "C006", "C007"]

# Pages under RULES_DIR that hold no rule definitions.  `index.md` is the
# map and `system.md` is everything that is not an individual rule, so a
# rule section appearing on either is a routing bug rather than content.
NON_RULE_PAGES = {"index.md", "system.md"}

# A rule section, as opposed to the prose headings that share the level.
_RULE_SECTION_RE = re.compile(r"^### ([RCDSX]\d{3}):", re.M)


def _rule_page(rule_id: str) -> Path:
    """The page that must carry *rule_id*'s definition."""
    category = category_of(rule_id)
    assert category is not None, (
        f"{rule_id} has no RuleCategory; add it to "
        f"src/trustsight/categories.py before documenting it"
    )
    return RULES_DIR / category.doc_page


def _section(rule_id: str) -> str:
    """Return *rule_id*'s reference section from the page that owns it."""
    md = _rule_page(rule_id).read_text()
    match = re.search(rf"### {rule_id}:.*?(?=\n#{{2,3}} |\Z)", md, re.S)
    assert match, f"no section for {rule_id} in {_rule_page(rule_id).name}"
    return match.group(0)


@pytest.mark.parametrize("rule", SHIPPED_RULES, ids=lambda r: r["id"])
def test_every_shipped_rule_has_a_reference_entry(rule):
    assert f"### {rule['id']}:" in _rule_page(rule["id"]).read_text()


@pytest.mark.parametrize("rule_id", PROGRAMMATIC_RULES)
def test_every_programmatic_rule_has_a_reference_entry(rule_id):
    assert f"### {rule_id}:" in _rule_page(rule_id).read_text()


@pytest.mark.parametrize("rule", SHIPPED_RULES, ids=lambda r: r["id"])
def test_documented_pattern_matches_shipped_pattern(rule):
    """A quoted pattern that has drifted is worse than none: it tells the
    reader the tool does something it does not."""
    section = _section(rule["id"])
    quoted = re.search(r"\*\*Pattern:\*\* (?:`` (.+?) ``|`(.+?)`)\n", section, re.S)
    assert quoted, f"no pattern quoted for {rule['id']}"
    assert (quoted.group(1) or quoted.group(2)) == rule["pattern"]


@pytest.mark.parametrize("rule", SHIPPED_RULES, ids=lambda r: r["id"])
def test_documented_severity_matches_shipped_severity(rule):
    assert rule["severity"] in _section(rule["id"]), (
        f"{rule['id']} is {rule['severity']} but the docs say otherwise"
    )


# --- rule taxonomy --------------------------------------------------------
#
# The reference is split one page per RuleCategory.  Three things can drift
# and none of them is visible by reading either side alone: a rule can be
# documented on the wrong page, a category can lose its page, and a rule
# section can be left behind in system.md when it moves.  The checks below
# are cheap and pin all three.


def test_every_category_has_a_page():
    missing = sorted(
        c.value for c in RuleCategory if not (RULES_DIR / c.doc_page).exists()
    )
    assert missing == [], f"RuleCategory members with no reference page: {missing}"


def test_every_page_belongs_to_a_category():
    known = {c.doc_page for c in RuleCategory} | NON_RULE_PAGES
    stray = sorted(p.name for p in RULES_DIR.glob("*.md") if p.name not in known)
    assert stray == [], f"pages under docs/reference/rules/ with no category: {stray}"


@pytest.mark.parametrize("rule_id", sorted(RULE_CATEGORIES), ids=str)
def test_every_categorised_rule_is_documented_on_its_own_page(rule_id):
    page = _rule_page(rule_id)
    assert f"### {rule_id}:" in page.read_text(), (
        f"{rule_id} is categorised {RULE_CATEGORIES[rule_id].value} but has no "
        f"section in {page.name}"
    )


@pytest.mark.parametrize(
    "page",
    sorted(c.doc_page for c in RuleCategory),
    ids=lambda p: p,
)
def test_no_page_documents_a_rule_it_does_not_own(page):
    """A rule section on the wrong page is a broken link from the index and
    a rule a reader looking at the right page will never find."""
    category = RuleCategory((RULES_DIR / page).stem)
    misplaced = sorted(
        rid for rid in _RULE_SECTION_RE.findall((RULES_DIR / page).read_text())
        if category_of(rid) is not category
    )
    assert misplaced == [], f"{page} documents rules it does not own: {misplaced}"


def test_system_md_holds_no_rule_definitions():
    """system.md keeps a stub anchor per rule, never a definition: two
    copies of a pattern is exactly the drift these tests exist to catch."""
    defined = sorted(set(_RULE_SECTION_RE.findall(SYSTEM_MD.read_text())))
    assert defined == [], f"rule definitions left in system.md: {defined}"


@pytest.mark.parametrize("rule_id", sorted(RULE_CATEGORIES), ids=str)
def test_system_md_still_anchors_every_rule_id(rule_id):
    """Anchors like `rules.md#r129` were linked from other pages and from
    outside the repo before the split.  system.md keeps every one of them
    pointing at wherever the rule now lives."""
    md = SYSTEM_MD.read_text()
    assert re.search(rf"^### {rule_id} \{{#", md, re.M), (
        f"system.md lost its anchor stub for {rule_id}"
    )
    assert f"]({RULE_CATEGORIES[rule_id].doc_page}#" in md


@pytest.mark.parametrize("rule_id", sorted(RULE_CATEGORIES), ids=str)
def test_the_index_lists_every_rule(rule_id):
    assert f"[{rule_id}](" in INDEX_MD.read_text(), (
        f"{rule_id} is missing from the quick-reference table"
    )


def _cli_names() -> set[str]:
    names: set[str] = set()
    for cmd in app.registered_commands:
        name = cmd.name or cmd.callback.__name__.replace("_", "-")
        names.add(name)
    for group in app.registered_groups:
        if group.name:
            names.add(group.name)
    return names


def _cli_flags() -> set[str]:
    flags: set[str] = set()
    for py in sorted(CLI_SRC.glob("*.py")):
        text = py.read_text()
        flags.update(re.findall(r'typer\.Option\([^)]*"(--[a-z-]+)"', text))
    return flags


def test_every_command_and_subcommand_is_documented():
    md = CLI_MD.read_text()
    undocumented = sorted(n for n in _cli_names() if n not in md)
    assert undocumented == [], f"undocumented CLI names: {undocumented}"


def test_every_flag_is_documented():
    md = CLI_MD.read_text()
    undocumented = sorted(f for f in _cli_flags() if f not in md)
    assert undocumented == [], f"undocumented flags: {undocumented}"


def test_every_public_api_name_is_documented():
    """A public name nobody documented is one nobody meant to promise.

    The API surface is the thing callers pin to, so it may not grow by
    accident: adding an export without a reference entry fails here.
    """
    from trustsight import api

    md = API_MD.read_text()
    undocumented = sorted(n for n in api.__all__ if f"`{n}`" not in md)
    assert undocumented == [], f"undocumented API names: {undocumented}"


def test_the_package_root_reexports_exactly_the_api_surface():
    """`from trustsight import X` must mean the same X as `trustsight.api.X`."""
    import trustsight
    from trustsight import api

    assert sorted(api.__all__) == sorted(trustsight._API_NAMES)
    for name in api.__all__:
        assert getattr(trustsight, name) is getattr(api, name)


def test_every_config_section_is_documented():
    md = CONFIG_MD.read_text()
    sections = tomllib.loads(DEFAULT_CONFIG).keys()
    undocumented = sorted(
        k for k in sections if f"[{k}]" not in md and f"`{k}`" not in md
    )
    assert undocumented == [], f"undocumented config sections: {undocumented}"


def test_no_documented_command_is_missing_from_the_cli():
    """The inverse: docs must not promise a command that does not exist.
    `trustsight sandbox` was documented for a release without existing."""
    documented = set(re.findall(r"^## trustsight ([a-z-]+)", CLI_MD.read_text(), re.M))
    missing = sorted(c for c in documented if c not in _cli_names())
    assert missing == [], f"documented but not implemented: {missing}"


# --- prose conventions ----------------------------------------------------

# Standard punctuation only.  An em dash, an en dash and a spaced "--" all
# render inconsistently across the terminal, the rendered site and a plain
# `cat` of the file, and the project has settled on ":", ";", ",", "()" and
# "-" instead.  Pinned as a test because it has drifted back three times.
_BANNED_PUNCTUATION = {
    "—": "em dash",
    "–": "en dash",
    " -- ": "spaced double hyphen",
}


def test_docs_use_standard_punctuation():
    offenders = []
    for path in sorted((ROOT / "docs").rglob("*.md")):
        for lineno, line in enumerate(path.read_text().splitlines(), start=1):
            for char, name in _BANNED_PUNCTUATION.items():
                if char in line:
                    rel = path.relative_to(ROOT)
                    offenders.append(f"{rel}:{lineno} {name}: {line.strip()[:70]}")
    assert not offenders, "use : ; , () - instead\n" + "\n".join(offenders[:20])
