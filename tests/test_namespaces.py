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


def test_c035_normalises_dot_and_percent_segments():
    for url in ("https://github.com/me/../other/repo.tar.gz",
                "https://github.com/me/%2e%2e/other/repo.tar.gz"):
        recipe = f'pkgname=demo\nsource=("{url}")\n'
        assert owned_namespace_findings(recipe, _config("github.com/me")), url


def test_c035_reads_the_declared_upstream_url():
    recipe = ('pkgname=demo\nurl="https://github.com/other/repo"\n'
              'source=("x.tar.gz")\n')
    assert owned_namespace_findings(recipe, _config("github.com/me"))


def test_c035_path_prefix_is_case_insensitive():
    recipe = 'pkgname=demo\nsource=("https://github.com/ME/repo.tar.gz")\n'
    assert owned_namespace_findings(recipe, _config("github.com/me")) == []


def test_c035_normalises_the_owned_prefix():
    recipe = 'pkgname=demo\nsource=("https://github.com/other2/repo.tar.gz")\n'
    assert owned_namespace_findings(recipe, _config("github.com/me/../other"))
