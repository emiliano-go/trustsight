"""The generated rule pages cannot drift from their sources.

Every category page, the overview legend, the full catalog and the
compatibility anchor page are assembled by ``scripts/build_rules_index.py``
from ``docs_src/sections/``, ``docs_src/pages/``, ``docs_src/nature/`` and
``docs_src/layout.json``.  These render from those sources and assert the
committed pages already match, so a section edited without rebuilding fails
here instead of shipping a page that disagrees with its source.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

from trustsight.categories import RULE_CATEGORIES

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "build_rules_index.py"


def _generator():
    spec = importlib.util.spec_from_file_location("build_rules_index", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_catalog_lists_each_registered_rule_once():
    ids = [row[0] for row in _generator()._catalog()]
    assert len(ids) == len(set(ids)), "a rule is listed twice in the catalog"
    assert set(ids) == set(RULE_CATEGORIES)


def test_every_section_source_is_laid_out_and_resolves():
    build = _generator()
    layout = json.loads(build.LAYOUT.read_text())
    placed = [anchor for anchors in layout.values() for anchor in anchors]
    on_disk = sorted(p.stem for p in build.SECTIONS.glob("*.md"))
    assert sorted(placed) == on_disk, "a section is on disk but not laid out, or vice versa"
    for anchor in placed:
        meta, _body = build._section(anchor)
        assert build.resolve(meta["uid"]) is not None, f"{anchor}: unknown uid"


def test_index_matches_the_generator():
    build = _generator()
    on_disk = build.INDEX.read_text()
    assert on_disk == build.render_index(on_disk, build._catalog()), (
        "docs/rules/index.md is stale; "
        "run python scripts/build_rules_index.py"
    )


def test_definitions_match_the_generator():
    build = _generator()
    on_disk = build.DEFINITIONS.read_text()
    assert on_disk == build.render_definitions(on_disk, build._catalog()), (
        "docs/rules/definitions.md is stale; "
        "run python scripts/build_rules_index.py"
    )


def test_compatibility_page_matches_the_generator():
    build = _generator()
    assert build.COMPAT.read_text() == build.render_compat(build._catalog()), (
        "docs/rules/mechanics.md is stale; "
        "run python scripts/build_rules_index.py"
    )


def test_every_page_matches_its_sources():
    build = _generator()
    layout = json.loads(build.LAYOUT.read_text())
    blocks = build._page_blocks(build._catalog())
    stale = [
        page_name
        for page_name in layout
        if (build.RULES_DIR / page_name).read_text()
        != build.render_page(page_name, layout, blocks)
    ]
    assert stale == [], (
        f"stale pages: {stale}; run python scripts/build_rules_index.py"
    )


def test_every_category_page_merges_mechanics_and_interpretation():
    """The consolidation contract: one page, both halves, no Nature tab."""
    build = _generator()
    missing = []
    for category in build.RuleCategory:
        text = (build.RULES_DIR / category.doc_page).read_text()
        for heading in ("## Threat context", "## Individual rules", "## Interpretation"):
            if heading not in text:
                missing.append(f"{category.doc_page}: {heading}")
    assert missing == [], missing
