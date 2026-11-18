"""C035: operator-owned namespace occupancy."""

from __future__ import annotations

from trustsight.analysis.namespaces import owned_namespace_findings


def _config(*owned: str) -> dict:
    return {"namespaces": {"owned": list(owned)}}


def test_c035_flags_a_source_outside_the_owned_prefix():
    recipe = 'pkgname=demo\nsource=("https://github.com/other/repo/archive/v1.tar.gz")\n'
    findings = owned_namespace_findings(recipe, _config("github.com/me"))
    assert [f["rule_id"] for f in findings] == ["C035"]


def test_c035_allows_a_source_inside_the_owned_prefix():
    recipe = 'pkgname=demo\nsource=("https://github.com/me/repo/archive/v1.tar.gz")\n'
    assert owned_namespace_findings(recipe, _config("github.com/me")) == []


def test_c035_is_inert_without_an_owned_namespace():
    recipe = 'pkgname=demo\nsource=("https://github.com/other/repo/archive/v1.tar.gz")\n'
    assert owned_namespace_findings(recipe, _config()) == []
