"""The generated rule pages cannot drift from their sources.

Every rule page and ``index.md`` is assembled by
``scripts/build_rules_index.py`` from ``docs_src/sections/``,
``docs_src/pages/`` and ``docs_src/layout.json``.  These render from those
sources and assert the committed pages already match, so a section edited
without rebuilding fails here instead of shipping a page that disagrees with
its source.
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
        "docs/reference/rules/index.md is stale; "
        "run python scripts/build_rules_index.py"
    )


def test_every_nature_page_matches_the_generator():
    build = _generator()
    blocks = build._nature_blocks(build._catalog())
    stale = [
        page_name
        for page_name, block in blocks.items()
        if (build.NATURE_DIR / page_name).read_text()
        != build.render_nature_page(page_name, block)
    ]
    assert stale == [], (
        f"stale nature pages: {stale}; run python scripts/build_rules_index.py"
    )


def test_nature_indexes_cover_every_category():
    build = _generator()
    blocks = build._nature_blocks(build._catalog())
    expected = {f"{category.value}.md" for category in build.RuleCategory}
    assert set(blocks) == expected


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


def test_generated_rule_pages_do_not_publish_source_markers():
    """Section metadata comments are source markers, not prose.

    A marker left in a generated page is invisible in a browser but shows up
    in copy/paste, search indexes and raw HTML.  The generator consumes all
    three markers (uid, name, anchor); none may reach the published page.
    """
    markers = ("<!-- uid:", "<!-- name:", "<!-- anchor:")
    offenders = [
        page.name
        for page in (ROOT / "docs" / "reference" / "rules").glob("*.md")
        if any(marker in page.read_text() for marker in markers)
    ]
    assert offenders == [], f"source markers leaked into generated pages: {offenders}"
