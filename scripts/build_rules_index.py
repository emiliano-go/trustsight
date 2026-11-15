"""Regenerate the rule reference pages and ``index.md`` from their sources.

The rule bodies are no longer hand-maintained in ``docs/rules/``:
a section's prose lives in ``docs_src/sections/<anchor>.md``, the prose above
a page's index in ``docs_src/pages/<page>.md``, the interpretation prose in
``docs_src/nature/<page>.md``, and the order the sections appear in
``docs_src/layout.json``.  A section's name and its ``Target`` /
``Severity`` / ``Category`` bullets come from ``registry_meta.json``; this
script reassembles the pages from both, writes each heading from the
section's *current* id (resolved from its permanent ``uid``), and derives
``index.md``'s legend and catalog.  It also writes the one-line rule index at
the top of each per-category page under ``docs/rules/``, so the
interpretation page never has to duplicate the names and mechanics the system
page owns.

``tests/test_generated_docs.py`` fails if a page or the index is stale, so a
rule author runs this after editing a section:

    uv run python scripts/build_rules_index.py

The recorded ``docs_src`` is produced once by ``scripts/split_rule_sources.py``
and ``scripts/build_registry_meta.py``.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from trustsight.categories import RuleCategory, rules_in  # noqa: E402
from trustsight.registry import SECTION_META, resolve  # noqa: E402

RULES_DIR = ROOT / "docs" / "rules"
INDEX = RULES_DIR / "index.md"
DEFINITIONS = RULES_DIR / "definitions.md"
COMPAT = ROOT / "docs" / "reference" / "rules" / "system.md"

SRC = ROOT / "docs_src"
PAGES = SRC / "pages"
SECTIONS = SRC / "sections"
NATURE_SRC = SRC / "nature"
LAYOUT = SRC / "layout.json"

LEGEND_START = "<!-- generated: legend -->"
LEGEND_END = "<!-- /generated: legend -->"
TABLE_START = "<!-- generated: catalog -->"
TABLE_END = "<!-- /generated: catalog -->"
PAGE_START = "<!-- generated: page-index -->"
PAGE_END = "<!-- /generated: page-index -->"
SERIES_START = "<!-- generated: series-counts -->"
SERIES_END = "<!-- /generated: series-counts -->"
NATURE_START = "<!-- generated: nature-rules -->"
NATURE_END = "<!-- /generated: nature-rules -->"
NATURE_RE = re.compile(
    rf"{re.escape(NATURE_START)}\n.*?\n{re.escape(NATURE_END)}", re.S
)

META = re.compile(r"^<!-- (uid|anchor|name): (.*) -->$")

SERIES_NAMES = {
    "C": "Integrity-change",
    "R": "Regex",
    "H": "Heuristic",
    "D": "Dependency",
    "S": "Sabotage",
    "X": "Crossfire",
    "W": "Unverifiable",
    "P": "Declared-practice",
    "M": "Meta",
    "E": "Entropy",
    "T": "Temporal",
    "G": "Correlation",
    "A": "Artifact",
    "I": "Indicator",
    "U": "Upstream",
}


def _section(anchor: str) -> tuple[dict[str, str], str]:
    """(header comments, prose) for one section source file."""
    text = (SECTIONS / f"{anchor}.md").read_text()
    lines = text.split("\n")
    meta: dict[str, str] = {}
    for index, line in enumerate(lines):
        found = META.match(line)
        if not found:
            body = "\n".join(lines[index:]).strip("\n")
            return meta, body
        meta[found.group(1)] = found.group(2)
    return meta, ""


def _bullets(meta: dict) -> str:
    """The structured facts a section opens with, rendered from the registry."""
    lines = []
    if meta.get("target"):
        lines.append(f"- **Target:** {meta['target']}")
    if meta.get("severity_text"):
        lines.append(f"- **Severity:** {meta['severity_text']}")
    if meta.get("capability"):
        lines.append(f"- **Category:** `{meta['capability']}`")
    return "\n".join(lines)


def _catalog() -> list[tuple[str, str, str, str, RuleCategory, str]]:
    """Every documented rule, as (id, name, severity, series, category, anchor).

    One row per rule, not per heading: ``H026`` is documented twice (the
    per-package path and the corpus path), and the catalog is a list of
    rules, so the second section does not add a row.
    """
    layout = json.loads(LAYOUT.read_text())
    by_page = {category.doc_page: category for category in RuleCategory}
    rows = []
    seen: set[str] = set()
    for page_name, anchors in layout.items():
        category = by_page[page_name]
        for anchor in anchors:
            comments, _body = _section(anchor)
            rule = resolve(comments["uid"])
            if rule is None:
                raise SystemExit(f"{anchor}: uid {comments['uid']} is unknown")
            if rule.uid in seen:
                continue
            seen.add(rule.uid)
            named = SECTION_META[anchor]
            series = SERIES_NAMES.get(rule.series, rule.series)
            rows.append(
                (rule.id, named["name"], named.get("severity") or "-",
                 series, category, anchor)
            )
    rows.sort(key=lambda row: (*resolve(row[0]).sort_key, row[5]))
    return rows


def _replace(text: str, start: str, end: str, body: str) -> str:
    pattern = re.compile(rf"{re.escape(start)}\n.*?\n{re.escape(end)}", re.S)
    updated, count = pattern.subn(lambda _: f"{start}\n{body}\n{end}", text, count=1)
    if count != 1:
        raise SystemExit(f"marker {start} not found in {INDEX}")
    return updated


def _page_blocks(catalog) -> dict[str, str]:
    """Page filename -> its generated index block, in catalog order."""
    by_page: dict[str, list] = {}
    for rid, name, sev, _series, cat, anchor in catalog:
        by_page.setdefault(cat.doc_page, []).append((rid, name, sev, anchor))

    blocks = {}
    for page_name, rules in by_page.items():
        body = "\n".join(
            f"| [{rid}](#{anchor}) | {name} | {sev} |" for rid, name, sev, anchor in rules
        )
        blocks[page_name] = (
            f"{PAGE_START}\n"
            f"| Rule | Name | Severity |\n|---|---|---|\n{body}\n"
            f"{PAGE_END}"
        )
    return blocks


def _nature_sections(page_name: str) -> dict[str, str]:
    """The hand-written interpretation prose for a category, by section."""
    text = (NATURE_SRC / page_name).read_text()
    text = NATURE_RE.sub("", text)
    text = re.sub(r"^<!-- description:.*?-->\n", "", text, count=1, flags=re.S)
    parts = re.split(r"^## ", text, flags=re.M)
    sections: dict[str, str] = {}
    for part in parts[1:]:
        title, _, body = part.partition("\n")
        sections[title.strip()] = body.strip()
    return sections


def render_page(page_name: str, layout, blocks) -> str:
    """The complete category page: mechanics and interpretation, one source."""
    header = (PAGES / page_name).read_text().rstrip()
    header = re.sub(
        r"Where these rules come from and what a finding means:.*?\n\n",
        "",
        header,
        count=1,
        flags=re.S,
    )
    header = re.sub(
        r"See \[the rule system reference\]\(system\.md\)[^\n]*\n",
        "",
        header,
        count=1,
    )
    header = re.sub(r"^(# .+)$", r"\1\n\n## Overview", header, count=1, flags=re.M)
    nature = _nature_sections(page_name)
    parts = [header]
    threat = nature.get("Where it comes from")
    if threat:
        parts.append(f"## Threat context\n\n{threat}")
    parts.append(
        "## Detection mechanisms\n\n"
        "The rules that make up this category are listed below, each with the "
        "series that implements it and the severity it carries. Scoring, "
        "matching and identifier allocation are shared across every category: "
        "see [Rule Mechanics](mechanics.md)."
    )
    parts.append(f"## Individual rules\n\n{blocks[page_name]}")
    for anchor in layout[page_name]:
        comments, body = _section(anchor)
        rule = resolve(comments["uid"])
        named = SECTION_META[anchor]
        section = f"### {rule.id}: {named['name']} {{#{anchor}}}"
        bullets = _bullets(named)
        if bullets:
            section += f"\n\n{bullets}"
        if body:
            section += f"\n\n{body}"
        parts.append(section)
    meaning = nature.get("What a finding means")
    if meaning:
        parts.append(f"## Interpretation\n\n{meaning}")
    see_also = nature.get("See also")
    if see_also:
        # The Nature source linked to its own system page; after the merge
        # that link points at the page it is already on, so drop it rather
        # than render a self-reference under "Related documentation".
        kept = [
            line for line in see_also.splitlines()
            if f"]({page_name})" not in line
        ]
        body = "\n".join(kept).strip()
        if body:
            parts.append(f"## Related documentation\n\n{body}")
    return "\n\n".join(parts) + "\n"


def render_index(text: str, catalog) -> str:
    """*text* with the generated category legend and series counts replaced."""
    legend = "\n".join(
        f"| [{c.title}]({c.doc_page}) | `{c.value}` | {len(rules_in(c))} | {c.summary} |"
        for c in RuleCategory
    )
    counts: dict[str, int] = {}
    for row in catalog:
        counts[row[3]] = counts.get(row[3], 0) + 1
    series = "\n".join(
        f"| `{letter}` | {name} | {counts.get(name, 0)} |"
        for letter, name in SERIES_NAMES.items()
    )
    text = _replace(
        text, LEGEND_START, LEGEND_END,
        "| Category | Slug | Rules | What a rule here claims |\n"
        "|----------|------|-------|-------------------------|\n"
        + legend,
    )
    scoring = sum(
        1 for row in catalog
        if row[4] not in (RuleCategory.UNVERIFIABLE, RuleCategory.ARTIFACT)
    )
    return _replace(
        text, SERIES_START, SERIES_END,
        "| Series | Mechanism | Rules |\n"
        "|--------|-----------|-------|\n"
        + series
        + f"\nThe catalog lists {len(catalog)} rule IDs across "
        f"{len(SERIES_NAMES)} series; {scoring} of them contribute to the "
        "heuristic score.",
    )


def render_definitions(text: str, catalog) -> str:
    """*text* with the generated full rule catalog replaced."""
    table = "\n".join(
        f"| [{rid}]({cat.doc_page}#{anchor}) | {name} | {series} | {sev} | "
        f"[{cat.title}]({cat.doc_page}) |"
        for rid, name, sev, series, cat, anchor in catalog
    )
    return _replace(
        text, TABLE_START, TABLE_END,
        "| Id | Name | Series | Severity | Category |\n"
        "|----|------|--------|----------|----------|\n"
        + table,
    )


def render_compat(catalog) -> str:
    """The old ``system.md`` URL as a short landing page plus anchor stubs.

    ``system.md#h077`` links were published, linked from other pages and cited
    from outside the repository.  The mechanics it used to hold now live on
    focused pages, so this file keeps a stub heading for every rule anchor and
    points each one at the category page that owns the definition.
    """
    anchors = "\n\n".join(
        f"### {rid} {{#{anchor}}}\n\n"
        f"See [{rid}: {name}](../../rules/{cat.doc_page}#{anchor})."
        for rid, name, _sev, _series, cat, anchor in catalog
    )
    return (
        "<!-- description: Compatibility landing for the former rule system "
        "reference: where scoring, matching, configuration, identifiers and "
        "every rule definition moved. -->"
    ) + f"""

# Rule System Reference

This page used to hold the whole rule engine reference. It is now split by
subject so each subject has one owner:

- [Rule Scoring](../../rules/scoring.md): severity weights, score calculation,
  FATAL behaviour and review thresholds.
- [Rule Matching](../../rules/matching.md): `match_target`, scope, resolved
  versus raw-line matching and its limits.
- [Rule Configuration](../../rules/configuration.md): `rules.toml` fields,
  `config.toml` overrides, structural rules and enablement.
- [Rule Identifiers](../../rules/identifiers.md): reserved, retired and
  unassigned identifiers.
- [Rule Series](../../rules/series.md): mechanism definitions and
  series-specific detection behaviour.
- [Rules Overview](../../rules/index.md): the category and series indexes.
- [Individual Rule Definitions](../../rules/definitions.md): the full catalog.

## Compatibility anchors

Every rule anchor that used to live here still resolves. Follow the link to
the category page that now owns the definition.

{anchors}
"""


def main() -> None:
    catalog = _catalog()
    layout = json.loads(LAYOUT.read_text())
    blocks = _page_blocks(catalog)

    for page_name in layout:
        (RULES_DIR / page_name).write_text(render_page(page_name, layout, blocks))
    INDEX.write_text(render_index(INDEX.read_text(), catalog))
    DEFINITIONS.write_text(render_definitions(DEFINITIONS.read_text(), catalog))
    COMPAT.write_text(render_compat(catalog))

    print(f"{INDEX.relative_to(ROOT)}: {len(catalog)} rules across "
          f"{len(RuleCategory)} categories; {len(blocks)} on-page indexes; "
          f"catalog written to {DEFINITIONS.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
