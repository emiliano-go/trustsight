"""Regenerate the rule reference pages and ``index.md`` from their sources.

The rule bodies are no longer hand-maintained in ``docs/reference/rules/``:
a section's prose lives in ``docs_src/sections/<anchor>.md``, the prose above
a page's index in ``docs_src/pages/<page>.md``, and the order the sections
appear in ``docs_src/layout.json``.  A section's name and its ``Target`` /
``Severity`` / ``Category`` bullets come from ``registry_meta.json``; this
script reassembles the pages from both, writes each heading from the
section's *current* id (resolved from its permanent ``uid``), and derives
``index.md``'s legend and catalog.  It also writes the one-line rule index at
the top of each per-category page under ``docs/reference/nature/``, so the
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

RULES_DIR = ROOT / "docs" / "reference" / "rules"
NATURE_DIR = ROOT / "docs" / "reference" / "nature"
INDEX = RULES_DIR / "index.md"

SRC = ROOT / "docs_src"
PAGES = SRC / "pages"
SECTIONS = SRC / "sections"
LAYOUT = SRC / "layout.json"

LEGEND_START = "<!-- generated: legend -->"
LEGEND_END = "<!-- /generated: legend -->"
TABLE_START = "<!-- generated: catalog -->"
TABLE_END = "<!-- /generated: catalog -->"
PAGE_START = "<!-- generated: page-index -->"
PAGE_END = "<!-- /generated: page-index -->"
PAGE_INDEX_RE = re.compile(
    rf"{re.escape(PAGE_START)}\n.*?\n{re.escape(PAGE_END)}", re.S
)
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
            f"## Rules on this page\n\n"
            f"| Rule | Name | Severity |\n|---|---|---|\n{body}\n"
            f"{PAGE_END}"
        )
    return blocks


def _nature_blocks(catalog) -> dict[str, str]:
    """Nature page filename -> its generated rule index, in catalog order."""
    by_page: dict[str, list] = {}
    for rid, _name, _sev, _series, cat, anchor in catalog:
        by_page.setdefault(cat.value, []).append((rid, anchor))

    blocks = {}
    for slug, rules in by_page.items():
        links = ", ".join(
            f"[{rid}](../rules/{slug}.md#{anchor})" for rid, anchor in rules
        )
        count = len(rules)
        blocks[f"{slug}.md"] = (
            f"{NATURE_START}\n"
            f"**Rules in this nature:** {links} ({count} "
            f"{'rule' if count == 1 else 'rules'}).\n"
            f"{NATURE_END}"
        )
    return blocks


def render_nature_page(page_name: str, block: str) -> str:
    """*page_name* with its generated rule index replaced or inserted."""
    text = (NATURE_DIR / page_name).read_text()
    if NATURE_START in text:
        updated, count = NATURE_RE.subn(lambda _: block, text, count=1)
        if count != 1:
            raise SystemExit(f"unterminated nature block in {page_name}")
        return updated
    pattern = re.compile(r"^(## )", re.M)
    updated, count = pattern.subn(
        lambda m: f"{block}\n\n{m.group(1)}", text, count=1
    )
    if count != 1:
        raise SystemExit(f"no section heading in {page_name}")
    return updated


def render_page(page_name: str, layout, blocks) -> str:
    """The complete page text, rebuilt from its header, index and sections."""
    header = (PAGES / page_name).read_text().rstrip()
    parts = [header, blocks[page_name]]
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
    return "\n\n".join(parts) + "\n"


def render_index(text: str, catalog) -> str:
    """*text* with the generated legend and catalog replaced."""
    legend = "\n".join(
        f"| [{c.title}]({c.doc_page}) | `{c.value}` | {len(rules_in(c))} | {c.summary} |"
        for c in RuleCategory
    )
    table = "\n".join(
        f"| [{rid}]({cat.doc_page}#{anchor}) | {name} | {series} | {sev} | "
        f"[{cat.title}]({cat.doc_page}) |"
        for rid, name, sev, series, cat, anchor in catalog
    )
    text = _replace(
        text, LEGEND_START, LEGEND_END,
        "| Category | Slug | Rules | What a rule here claims |\n"
        "|----------|------|-------|-------------------------|\n"
        + legend,
    )
    return _replace(
        text, TABLE_START, TABLE_END,
        "| Id | Name | Series | Severity | Category |\n"
        "|----|------|--------|----------|----------|\n"
        + table,
    )


def main() -> None:
    catalog = _catalog()
    layout = json.loads(LAYOUT.read_text())
    blocks = _page_blocks(catalog)

    for page_name in layout:
        (RULES_DIR / page_name).write_text(render_page(page_name, layout, blocks))
    INDEX.write_text(render_index(INDEX.read_text(), catalog))

    nature_blocks = _nature_blocks(catalog)
    for page_name, block in nature_blocks.items():
        (NATURE_DIR / page_name).write_text(render_nature_page(page_name, block))

    print(f"{INDEX.relative_to(ROOT)}: {len(catalog)} rules across "
          f"{len(RuleCategory)} categories; {len(blocks)} on-page indexes; "
          f"{len(nature_blocks)} nature indexes")


if __name__ == "__main__":
    main()
