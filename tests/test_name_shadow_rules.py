"""D005: official-repo name shadow (pkgname / conflicts, absolute state)."""

from __future__ import annotations

import pytest

from trustsight.analysis.dependencies import name_shadow_findings

OFFICIAL = frozenset({"bash", "foo"})


@pytest.fixture(autouse=True)
def _official(monkeypatch):
    import trustsight.db as db

    monkeypatch.setattr(db, "official_package_names", lambda: OFFICIAL)


def _recipe(name: str, extra: str = "") -> str:
    return (
        f"pkgname={name}\npkgver=1\npkgrel=1\narch=(any)\n{extra}"
        "package() { :; }\n"
    )


def test_pkgname_shadow_fires():
    findings = name_shadow_findings(_recipe("bash"), "bash")
    assert [f["rule_id"] for f in findings] == ["D005"]
    assert findings[0]["params"]["kind"] == "pkgname"
    assert findings[0]["weight_override"] == 0


def test_variant_conflict_is_related_and_suppressed():
    assert name_shadow_findings(
        _recipe("foo-git", 'conflicts=("foo")\n'), "foo-git") == []


def test_unrelated_conflict_fires():
    findings = name_shadow_findings(
        _recipe("mything", 'conflicts=("bash")\n'), "mything")
    assert {f["params"]["kind"] for f in findings} == {"conflicts"}


def test_skip_prevents_double_report_with_h064():
    assert name_shadow_findings(_recipe("bash"), "bash", skip={"bash"}) == []


def test_empty_text_is_silent():
    assert name_shadow_findings("", "bash") == []


def test_absolute_provides_shadow_fires():
    findings = name_shadow_findings(
        _recipe("mything", 'provides=("bash")\n'), "mything")
    assert {f["params"]["kind"] for f in findings} == {"provides"}
    assert findings[0]["params"]["dep_name"] == "bash"


def test_absolute_replaces_shadow_fires():
    findings = name_shadow_findings(
        _recipe("mything", 'replaces=("bash")\n'), "mything")
    assert {f["params"]["kind"] for f in findings} == {"replaces"}


def test_absolute_provides_soname_is_ignored():
    assert name_shadow_findings(
        _recipe("mything", 'provides=("libfoo.so=1-64")\n'), "mything") == []


def test_absolute_provides_variant_is_suppressed():
    assert name_shadow_findings(
        _recipe("foo-git", 'provides=("foo")\n'), "foo-git") == []


def test_absolute_provides_unresolved_entry_is_silent():
    assert name_shadow_findings(
        _recipe("mything", 'provides=("${unknown}")\n'), "mything") == []


def test_skip_prevents_double_report_for_a_provides_claim():
    assert name_shadow_findings(
        _recipe("mything", 'provides=("bash")\n'), "mything",
        skip={"bash"}) == []


def test_pkgname_does_not_shadow_itself_without_official_membership(monkeypatch):
    """The observation fallback counts the package's own corpus row.

    Without pacman, every established-by-observation package read as a shadow
    of its own name.  That arm now requires exact repository membership; the
    dependency-name arms keep the fallback.
    """
    import trustsight.db as db
    import trustsight.db._dependencies as deps

    monkeypatch.setattr(db, "official_package_names", lambda: frozenset())
    monkeypatch.setattr(deps, "dependency_observation_count", lambda name: 100)

    assert name_shadow_findings(_recipe("lotti-bin"), "lotti-bin") == []
    findings = name_shadow_findings(
        _recipe("mything", 'provides=("lotti-bin")\n'), "mything")
    assert {f["params"]["kind"] for f in findings} == {"provides"}
