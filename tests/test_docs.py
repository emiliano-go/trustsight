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
from trustsight.scoring import DECLARED_REASONS

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
                      "C004", "C005", "C006", "C007", "C008", "C009"]

# Pages under RULES_DIR that hold no rule definitions.  `index.md` is the
# map and `system.md` is everything that is not an individual rule, so a
# rule section appearing on either is a routing bug rather than content.
NON_RULE_PAGES = {"index.md", "system.md"}

# A rule section, as opposed to the prose headings that share the level.
#
# `W` belongs here: the unverifiable series is documented as `### W001:`
# sections on its own page exactly like every other series, and leaving it
# out of the character class made all six invisible to the two checks below
# - a W rule could be documented on the wrong page, or left behind in
# system.md, and nothing would say so.
#
# `P` is deliberately absent. Declared-practice findings are rendered from
# `DECLARED_REASONS` and documented as one table in system.md rather than as
# per-rule sections, so there is no `### P00N:` heading to find.
_RULE_SECTION_RE = re.compile(r"^### ([RCDSXW]\d{3}):", re.M)


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


# --- rendered samples -----------------------------------------------------
#
# Every terminal sample in the docs was hand-written once and then drifted.
# The quickstart showed a three-column `Package / Risk Score / Verdict` table
# the tool had stopped rendering, with a score column it withholds by default;
# `reading-a-report.md` showed an `inspect` output that said 55/100 in one line
# and computed 60 two lines later; and the README's 30-second example carried a
# doubled rule id and `checksums checksum added or changed` verbatim - which is
# where the bug report about those defects came from. A sample nobody can check
# is a claim nobody can check.


DOC_SOURCES = sorted((ROOT / "docs").rglob("*.md")) + [ROOT / "README.md"]
WRITING_A_RULE_MD = ROOT / "docs" / "contributing" / "writing-a-rule.md"


def test_writing_a_rule_local_links_resolve():
    """Examples for rule documentation must not point outside the docs tree."""
    text = WRITING_A_RULE_MD.read_text()
    broken = []
    for target in re.findall(r"\[[^]]+\]\(([^)]+)\)", text):
        path, _, fragment = target.partition("#")
        if not path:
            continue
        destination = WRITING_A_RULE_MD.parent / path
        if not destination.is_file():
            broken.append(f"{target}: file does not exist")
        elif fragment and f"{{#{fragment}}}" not in destination.read_text():
            broken.append(f"{target}: anchor does not exist")
    assert broken == []


def _split_panels(block):
    """Slice a rendered block into top-level panels, keeping nested cards."""
    panels, current = [], []
    depth = 0
    for line in block.splitlines():
        if line.startswith("\u256d"):
            depth += 1
        current.append(line)
        if line.startswith("\u2570"):
            depth -= 1
            if depth == 0:
                panels.append("\n".join(current))
                current = []
    return panels or [block]


def _rendered_blocks():
    """Fenced blocks that are terminal output rather than a shell command."""
    for path in DOC_SOURCES:
        if path.name == "changelog.md" or not path.exists():
            continue
        text = path.read_text()
        for match in re.finditer(r"```[a-z]*\n(.*?)```", text, re.S):
            block = match.group(1)
            if "\u256d" in block or "TrustSight Inspect" in block:
                yield path, text[: match.start()].count("\n") + 1, block


@pytest.mark.parametrize("check", ["rule id once", "no empty markup",
                                   "status once", "band withheld"])
def test_no_rendered_sample_shows_a_fixed_defect(check):
    """Each of these was in a doc sample after it was fixed in the code."""
    offenders = []
    for path, line, block in _rendered_blocks():
        where = f"{path.name}:{line}"
        if check == "rule id once":
            for rule in set(re.findall(r"\[(R\d{3})\]", block)):
                if block.count(f"[{rule}]") > block.count("line") + 1:
                    continue
            # A finding line naming its rule twice: `... [R001]  ... [R001]`
            if re.search(r"\[(R\d{3})\][^\n]*\[\1\]", block):
                offenders.append(f"{where} names a rule twice on one line")
        elif check == "no empty markup":
            if "[]" in block:
                offenders.append(f"{where} contains a literal `[]`")
        elif check == "status once":
            # Status is printed once per panel; a multi-panel review block
            # legitimately shows one row per package.
            for panel in _split_panels(block):
                if panel.count("Status") > 1:
                    offenders.append(f"{where} shows Status more than once")
        elif check == "band withheld":
            # A dependency card showing a band inside a panel that shows no
            # Score and no Risk row of its own.
            if "Findings" in block and "Risk" in block:
                if "Score" not in block and not re.search(r"^\W*Risk\s", block, re.M):
                    offenders.append(f"{where} shows a dependency band with no flag")
    assert offenders == [], offenders


def test_the_docs_do_not_describe_the_plain_renderer_as_reduced():
    """Both renderers carry the same sections; saying otherwise invites the
    drop this project keeps finding. Negated references ("it is *not* a
    condensed subset") assert the same invariant and are fine."""
    offenders = []
    for path in DOC_SOURCES:
        if path.name == "changelog.md" or not path.exists():
            continue
        text = path.read_text()
        for phrase in ("condensed subset", "reduced subset", "subset of the same"):
            for match in re.finditer(phrase, text):
                if re.search(r"\bnot\b\s+\w+\s*\Z", text[: match.start()], re.M | re.S):
                    continue
                offenders.append(f"{path.name}: {phrase!r}")
    assert offenders == [], offenders


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
    """Prose punctuation, not code.

    The check reads every line of every page, and a fenced block is not
    prose: `set -- *.sh` is how the shell ends option parsing, and
    `--include` is a flag. Flagging those asks a documentation page to
    misquote the thing it documents.
    """
    offenders = []
    for path in sorted((ROOT / "docs").rglob("*.md")):
        in_code = False
        for lineno, line in enumerate(path.read_text().splitlines(), start=1):
            if line.lstrip().startswith("```"):
                in_code = not in_code
                continue
            if in_code:
                continue
            # An inline code span is code for the same reason.
            prose = re.sub(r"`[^`]*`", "", line)
            for char, name in _BANNED_PUNCTUATION.items():
                if char in prose:
                    rel = path.relative_to(ROOT)
                    offenders.append(f"{rel}:{lineno} {name}: {line.strip()[:70]}")
    assert not offenders, "use : ; , () - instead\n" + "\n".join(offenders[:20])


# --- published numbers are reproducible from this checkout -----------------


def test_the_documented_corpus_size_matches_the_lock():
    """A published figure has to be measurable from the tree that ships it.

    The docs cited a 3,739-diff locked corpus in fifteen places. The lock
    has only ever recorded 3,332 and then 3,246, and the fixtures directory
    holds exactly 3,246 diffs - so no checkout of this repository could ever
    reproduce the number every calibration claim rested on. It drifted
    silently because nothing tied the prose to the manifest.

    This is the tie. If the corpus grows, the lock changes and the figure
    has to follow it; the alternative is a benchmark table that says
    whatever it said last.
    """
    import json

    lock = json.loads((ROOT / "tests" / "fixtures" / "corpus.lock").read_text())
    size = lock["total_entries"]

    stale = []
    for path in sorted((ROOT / "docs").rglob("*.md")) + [ROOT / "README.md"]:
        if path.name == "changelog.md" or not path.exists():
            continue
        text = path.read_text()
        for match in re.finditer(r"([\d,]{3,9})-diff (?:locked )?(?:benign )?corpus", text):
            # The thousands separator is a style choice; the number is not.
            cited = match.group(1).replace(",", "")
            if not cited.isdigit() or int(cited) != size:
                line = text[: match.start()].count("\n") + 1
                stale.append(
                    f"{path.relative_to(ROOT)}:{line} cites {match.group(1)} "
                    f"but corpus.lock records {size:,}"
                )
    assert stale == [], stale


def test_the_corpus_lock_matches_the_files_on_disk():
    """The manifest and the directory are two claims about one corpus."""
    import json

    lock = json.loads((ROOT / "tests" / "fixtures" / "corpus.lock").read_text())
    corpus = ROOT / "tests" / "fixtures" / "benign-corpus"
    if not corpus.exists():
        pytest.skip("benign corpus absent; rebuild with scripts/build_corpus.py")
    on_disk = sum(1 for _ in corpus.rglob("*.diff"))
    assert on_disk == lock["total_entries"], (
        f"{on_disk} diffs on disk, lock records {lock['total_entries']}"
    )


def _series_bounds() -> dict[str, tuple[int, int]]:
    """Lowest and highest number actually shipped for each rule namespace."""
    seen: dict[str, list[int]] = {}
    for rule_id in RULE_CATEGORIES:
        match = re.fullmatch(r"([A-Z]+)(\d+)", rule_id)
        if match:
            seen.setdefault(match.group(1), []).append(int(match.group(2)))
    return {series: (min(nums), max(nums)) for series, nums in seen.items()}


#: Series a `001-NNN` range can only be describing in full.  The R space is
#: deliberately non-contiguous and is documented in subsets (`R039-R059` is
#: the expanded-rules block), so a range there says nothing about the total
#: and R is excluded.  P has one gap (`P004` is skipped and documented as
#: skipped) but is only ever written as the whole family, so its upper bound
#: is still checkable.
_WHOLE_FAMILY_SERIES = ("C", "D", "P", "S", "W", "X")


def test_documented_series_ranges_end_at_the_highest_shipped_rule():
    """A range like `X001-X007` is a claim about the catalog, not decoration.

    These ranges are written by hand on the overview pages, and adding a
    rule to a series does not touch them, so they decay quietly: the
    catalog reached X023 and C009 while six pages still advertised X007 and
    C007. Nothing failed, because every individual rule was documented on
    its own page and all the per-rule checks above passed. Only a reader
    counting the families would have caught it.
    """
    # `RULE_CATEGORIES` holds every scoring rule.  The declared-practice
    # series is not a detection and lives in `DECLARED_REASONS` instead, so
    # its bound comes from there or `P001-P007` stays green forever.
    bounds: dict[str, int] = {}
    for rule_id in (*RULE_CATEGORIES, *DECLARED_REASONS):
        match = re.fullmatch(r"([A-Z]+)(\d+)", rule_id)
        if match:
            series, number = match.group(1), int(match.group(2))
            bounds[series] = max(bounds.get(series, 0), number)

    offenders = []
    for path in sorted((ROOT / "docs").rglob("*.md")):
        if path.name == "changelog.md":
            continue
        for lineno, line in enumerate(path.read_text().splitlines(), start=1):
            # `` `P001`-`P008` `` is the same claim as `P001-P008`, and the
            # backticks sit between the digits and the hyphen.  Dropping them
            # first is what makes both forms one case; matching only the bare
            # form let three pages keep `P001`-`P007` after the series grew.
            plain = line.replace("`", "")
            for series, low, high in re.findall(
                r"\b([A-Z])(\d{3})\s*\-\s*(?:[A-Z])?(\d{3})\b", plain
            ):
                if series not in _WHOLE_FAMILY_SERIES or series not in bounds:
                    continue
                if int(low) != 1 or int(high) == bounds[series]:
                    continue
                offenders.append(
                    f"{path.relative_to(ROOT)}:{lineno} says "
                    f"{series}{low}-{series}{high}, but the catalog ends at "
                    f"{series}{bounds[series]:03d}"
                )
    assert not offenders, "stale rule-series ranges:\n" + "\n".join(offenders)


def test_the_landing_page_rule_count_matches_the_catalog():
    """`docs/index.md` advertises a total; it drifted to 145 against 171."""
    scoring = sum(
        1 for rule_id in RULE_CATEGORIES
        if category_of(rule_id) is not RuleCategory.UNVERIFIABLE
    )
    text = (ROOT / "docs" / "index.md").read_text()
    match = re.search(r"TrustSight ships ([\d,]+) documented scoring rules", text)
    assert match, "docs/index.md no longer states a scoring-rule count"
    claimed = int(match.group(1).replace(",", ""))
    assert claimed == scoring, (
        f"docs/index.md claims {claimed} scoring rules; the catalog holds {scoring}"
    )


def test_every_environment_variable_is_documented():
    """An env var is a public interface with no `--help` to discover it.

    `TRUSTSIGHT_OFFLINE` gates the release and AUR bulk channels and shipped
    undocumented, while `reference/index.md` advertised an "Environment
    variable reference" that did not exist. A flag is listed by `--help` and
    is covered by the flag check above; a variable is visible only where
    someone wrote it down.
    """
    read = set()
    for path in sorted((ROOT / "src" / "trustsight").rglob("*.py")):
        text = path.read_text()
        read.update(re.findall(r'environ(?:\.get)?\(\s*"([A-Z][A-Z0-9_]*)"', text))
        read.update(re.findall(r'getenv\(\s*"([A-Z][A-Z0-9_]*)"', text))

    documented = set(re.findall(r"`([A-Z][A-Z0-9_]{2,})`", CONFIG_MD.read_text()))
    undocumented = sorted(read - documented)
    assert undocumented == [], (
        "environment variables read by the code but absent from "
        f"docs/reference/configuration.md: {undocumented}"
    )


def test_the_llms_txt_generator_covers_every_page():
    """The templates promise `/llms.txt` and `/llms-full.txt` on every page.

    Both were advertised by `<link rel="alternate">` in `overrides/main.html`
    and produced by nothing, so all 57 pages pointed at a 404. The generator
    reads the nav, so this checks the two that can still drift: a page the
    nav does not reach would be absent from both files, and a nav entry with
    no file would put a dead link in them.
    """
    import sys

    sys.path.insert(0, str(ROOT / "scripts"))
    from build_llms_txt import _config, _sections, build

    meta = _config()
    docs = ROOT / meta.get("docs_dir", "docs")

    navigated = {path for _, pages in _sections(meta) for _, path in pages}
    on_disk = {str(p.relative_to(docs)) for p in docs.rglob("*.md")}
    assert navigated == on_disk, (
        f"only in nav: {sorted(navigated - on_disk)}; "
        f"only on disk: {sorted(on_disk - navigated)}"
    )

    index, full = build(docs, meta)
    base = meta["site_url"].rstrip("/") + "/"
    assert index.startswith(f"# {meta['site_name']}")
    for path in sorted(on_disk):
        slug = path.removesuffix(".md").removesuffix("/index")
        url = base if slug == "index" else f"{base}{slug}/"
        assert f"({url})" in index, f"{path} is missing from llms.txt"
        assert f"Source: {url}" in full, f"{path} is missing from llms-full.txt"

    # Every entry carries a summary; an index of bare links is not an index.
    bare = [line for line in index.splitlines()
            if line.startswith("- [") and "): " not in line]
    assert bare == [], f"llms.txt entries with no summary: {bare}"
