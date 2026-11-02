"""The missing-self predicates: positive shape, stand-down, and anergy."""

from __future__ import annotations

from trustsight.analysis import scan_diff


def _rules(fact, prefix=("T004", "T005", "C033", "C034")):
    return [(e.rule_id, e.weight) for e in fact.score_breakdown
            if e.rule_id in prefix]


def _pkgbuild_diff(old: str, new: str, context: str = " pkgname=demo\n") -> str:
    return (
        "--- a/PKGBUILD\n"
        "+++ b/PKGBUILD\n"
        "@@ -1,4 +1,4 @@\n"
        + context
        + f"-{old}\n+{new}\n"
        + " pkgver=1\n"
    )


def test_t004_partial_key_removal_is_anergic():
    diff = _pkgbuild_diff(
        "validpgpkeys=('KEYA' 'KEYB')", "validpgpkeys=('KEYA')")
    fact = scan_diff(diff, package_name="demo")
    assert _rules(fact, ("T004",)) == [("T004", 15)]


def test_t004_stands_down_for_whole_array_but_not_a_decoy_rotation():
    whole = _pkgbuild_diff(
        "validpgpkeys=('KEYA' 'KEYB')", "validpgpkeys=()")
    fact = scan_diff(whole, package_name="demo")
    assert not [r for r, _ in _rules(fact, ("T004",))]

    # A one-for-one "rotation" is the shape a decoy addition uses to hide a
    # removal; T004 cannot tell the two apart offline, so it reports both.
    rotation = _pkgbuild_diff(
        "validpgpkeys=('KEYA' 'KEYB')", "validpgpkeys=('KEYA' 'KEYC')")
    fact = scan_diff(rotation, package_name="demo")
    assert [r for r, _ in _rules(fact, ("T004",))] == ["T004"]


def test_t005_path_changed_downgrade_is_anergic():
    diff = _pkgbuild_diff(
        'source=("https://example.com/demo-1.tar.gz")',
        'source=("http://example.com/demo-2.tar.gz")',
        context=" pkgname=demo\n",
    )
    fact = scan_diff(diff, package_name="demo")
    assert _rules(fact, ("T005",)) == [("T005", 15)]


def test_t005_stands_down_for_exact_h019_and_host_change():
    exact = _pkgbuild_diff(
        'source=("https://example.com/demo-1.tar.gz")',
        'source=("http://example.com/demo-1.tar.gz")',
    )
    fact = scan_diff(exact, package_name="demo")
    assert not [r for r, _ in _rules(fact, ("T005",))]

    host = _pkgbuild_diff(
        'source=("https://example.com/demo-1.tar.gz")',
        'source=("http://other.example/demo-2.tar.gz")',
    )
    fact = scan_diff(host, package_name="demo")
    assert not [r for r, _ in _rules(fact, ("T005",))]


def _comment_diff(deleted: int) -> str:
    removed = "".join(f"-# comment {i}\n" for i in range(deleted))
    return (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n"
        f"@@ -1,{deleted + 3} +1,3 @@\n"
        " # kept\n" + removed + " pkgname=demo\n pkgver=1\n"
    )


def test_c033_gutting_comments_is_anergic():
    fact = scan_diff(_comment_diff(9), package_name="demo")
    assert _rules(fact, ("C033",)) == [("C033", 15)]


def test_c033_stands_down_below_the_floor_and_ratio():
    assert not [r for r, _ in _rules(scan_diff(_comment_diff(3), package_name="demo"), ("C033",))]


def test_c034_reports_srcinfo_version_drift():
    diff = (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,3 +1,3 @@\n"
        " pkgname=demo\n-pkgver=1.0\n+pkgver=2.0\n pkgrel=1\n"
    )
    pkg = "pkgname=demo\npkgver=2.0\npkgrel=1\n"
    src = "pkgbase = demo\n\tpkgver = 1.0\n\tpkgrel = 1\n"
    fact = scan_diff(
        diff, package_name="demo",
        tree_manifest=[(".SRCINFO", src.encode())], current_text=pkg)
    assert _rules(fact, ("C034",)) == [("C034", 0)]


def test_c034_stands_down_when_metadata_agrees():
    diff = (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,3 +1,3 @@\n"
        " pkgname=demo\n-pkgver=1.0\n+pkgver=2.0\n pkgrel=1\n"
    )
    pkg = "pkgname=demo\npkgver=2.0\npkgrel=1\n"
    src = "pkgbase = demo\n\tpkgver = 2.0\n\tpkgrel = 1\n"
    fact = scan_diff(
        diff, package_name="demo",
        tree_manifest=[(".SRCINFO", src.encode())], current_text=pkg)
    assert not [r for r, _ in _rules(fact, ("C034",))]
