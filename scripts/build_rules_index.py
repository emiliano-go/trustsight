"""Regenerate ``docs/reference/rules/index.md`` from the category pages.

The index is a map, not content: its legend counts the members of
:class:`~trustsight.categories.RuleCategory`, and its quick-reference table
is one row per ``### Rxxx:`` heading found on the category pages. Both are
derived, so writing them by hand means two places to update and one of them
silently going stale.

``tests/test_docs.py`` fails if a rule is missing from the table, so this
script is what a rule author runs after adding the rule's section:

    python scripts/build_rules_index.py

The prose above the table is hand-written and is preserved verbatim between
the markers below.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from trustsight.categories import RuleCategory, rules_in  # noqa: E402

RULES_DIR = ROOT / "docs" / "reference" / "rules"
INDEX = RULES_DIR / "index.md"

LEGEND_START = "<!-- generated: legend -->"
LEGEND_END = "<!-- /generated: legend -->"
TABLE_START = "<!-- generated: catalog -->"
TABLE_END = "<!-- /generated: catalog -->"

HEADING = re.compile(r"^### ([RCDSXW]\d{3}):\s*(.*?)\s*(?:\{#([^}]+)\})?\s*$")
SEVERITY = re.compile(r"\b(FATAL|CRITICAL|HIGH|MEDIUM|LOW|INFO)\b")


def _catalog() -> list[tuple[str, str, str, RuleCategory, str]]:
    """Every documented rule section, as (id, name, severity, category, anchor)."""
    rows = []
    for category in RuleCategory:
        page = RULES_DIR / category.doc_page
        if not page.exists():
            continue
        lines = page.read_text().split("\n")
        for index, line in enumerate(lines):
            match = HEADING.match(line)
            if not match:
                continue
            rule_id, name, anchor = match.group(1), match.group(2), match.group(3)
            rows.append(
                (rule_id, name, _severity(lines[index:index + 12]),
                 category, anchor or rule_id.lower())
            )
    # Sort by series then by number, so R100 follows R099 rather than R010.
    rows.sort(key=lambda row: (row[0][0], int(row[0][1:]), row[4]))
    return rows


def _severity(section: list[str]) -> str:
    """The severity a section declares, as a single word.

    Several rules carry a per-branch severity ("HIGH on replacement, MEDIUM
    on addition"); the table shows the worst one it opens with, which is
    what the full entry then qualifies.
    """
    for line in section:
        # Two spellings: the list form (`- **Severity:** HIGH (weight 25)`)
        # and the reference form, where the severity opens the entry
        # (`**HIGH** (weight 25) - category evasion`).
        if line.startswith("- **Severity:**") or line.startswith("**"):
            found = SEVERITY.search(line)
            if found:
                return found.group(1)
            return "tiered" if "tiered" in line else "-"
    return "-"


def _replace(text: str, start: str, end: str, body: str) -> str:
    pattern = re.compile(
        rf"{re.escape(start)}\n.*?\n{re.escape(end)}", re.S
    )
    replacement = f"{start}\n{body}\n{end}"
    updated, count = pattern.subn(lambda _: replacement, text, count=1)
    if count != 1:
        raise SystemExit(f"marker {start} not found in {INDEX}")
    return updated


PAGE_START = "<!-- generated: page-index -->"
PAGE_END = "<!-- /generated: page-index -->"


def _write_page_indexes(catalog) -> int:
    """Put a rule list at the top of every category page.

    A category page is a flat run of `###` sections, so its table of
    contents is one long unstructured list and a reader looking for a
    specific rule has to scroll. The list below is an `##` section, which
    gives the page a second level, and it links straight to each anchor.
    """
    by_category: dict[RuleCategory, list] = {}
    for rid, name, sev, cat, anchor in catalog:
        by_category.setdefault(cat, []).append((rid, name, sev, anchor))

    written = 0
    for category, rules in by_category.items():
        page = RULES_DIR / category.doc_page
        if not page.exists():
            continue
        body = "\n".join(
            f"| [{rid}](#{anchor}) | {name} | {sev} |" for rid, name, sev, anchor in rules
        )
        block = (
            f"{PAGE_START}\n"
            f"## Rules on this page\n\n"
            f"| Rule | Name | Severity |\n|---|---|---|\n{body}\n"
            f"{PAGE_END}"
        )
        text = page.read_text()
        if PAGE_START in text:
            pattern = re.compile(
                rf"{re.escape(PAGE_START)}\n.*?\n{re.escape(PAGE_END)}", re.S
            )
            text = pattern.sub(lambda _: block, text, count=1)
        else:
            # Before the first rule section, after the page's prose.
            first = text.find("\n### ")
            if first == -1:
                continue
            text = text[:first] + "\n" + block + "\n" + text[first:]
        page.write_text(text)
        written += 1
    return written


def main() -> None:
    catalog = _catalog()

    legend = "\n".join(
        f"| [{c.title}]({c.doc_page}) | `{c.value}` | {len(rules_in(c))} | {c.summary} |"
        for c in RuleCategory
    )
    table = "\n".join(
        f"| [{rid}]({cat.doc_page}#{anchor}) | {name} | {sev} | "
        f"[{cat.title}]({cat.doc_page}) |"
        for rid, name, sev, cat, anchor in catalog
    )

    text = INDEX.read_text()
    text = _replace(text, LEGEND_START, LEGEND_END, legend)
    text = _replace(text, TABLE_START, TABLE_END, table)
    INDEX.write_text(text)

    pages = _write_page_indexes(catalog)

    print(f"{INDEX.relative_to(ROOT)}: {len(catalog)} rules across "
          f"{len(RuleCategory)} categories; {pages} on-page indexes")


if __name__ == "__main__":
    main()
