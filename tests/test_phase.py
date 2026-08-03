"""Behavioural tests for Phase 4 - Class B rules (plan §6).

R115 fires only when ``epoch=`` is newly introduced by a diff (an unchanged
or pre-existing epoch is never a hunk here); R116 fires when a diff newly
claims a provides/replaces entry naming an established or corpus-widely-
provided package unrelated to the package itself, and must stay silent when
the name belongs to the same project or the corpus knows nothing.
"""

import pytest

from trustsight.analysis import _structural_findings
from trustsight.differ import extract_urls_from_diff


def structural(diff_text: str, *, package_name: str = "") -> list[dict]:
    source_changes = extract_urls_from_diff(diff_text)
    return _structural_findings(diff_text, source_changes, {}, config={},
                                package_name=package_name)


def ids(diff_text: str, *, package_name: str = "") -> set[str]:
    return {f["rule_id"] for f in structural(diff_text, package_name=package_name)}


# --- R115: epoch introduced ---


def test_r115_fires_when_epoch_introduced():
    d = "+epoch=1\n+pkgrel=1\n"
    assert "R115" in ids(d)
    finding = next(f for f in structural(d) if f["rule_id"] == "R115")
    assert finding["severity"] == "MEDIUM"
    assert finding["params"]["epoch"] == "1"


def test_r115_epoch_zero_is_info():
    finding = next(
        f for f in structural("+epoch=0\n") if f["rule_id"] == "R115"
    )
    assert finding["severity"] == "INFO"


def test_r115_does_not_fire_on_epoch_bump():
    assert "R115" not in ids("-epoch=1\n+epoch=2\n")


def test_r115_does_not_fire_without_epoch():
    assert "R115" not in ids("+pkgrel=2\n+pkgver=1.2\n")


def test_r115_ignores_comment_mention():
    assert "R115" not in ids("+# reset epoch here\n")


# --- R116: provides/replaces scope expansion ---


@pytest.fixture
def establish(monkeypatch):
    def set_established(value: bool) -> None:
        monkeypatch.setattr(
            "trustsight.analysis.dependencies.is_established_package",
            lambda name: value,
        )
    return set_established


@pytest.fixture
def observe(monkeypatch):
    def set_observation(count: int) -> None:
        monkeypatch.setattr(
            "trustsight.analysis.dependencies.dependency_observation_count",
            lambda name: count,
        )
    return set_observation


def test_r116_fires_on_established_unrelated_provides(establish):
    establish(True)
    d = "+provides=('openssl')\n"
    assert "R116" in ids(d)
    finding = next(f for f in structural(d) if f["rule_id"] == "R116")
    assert finding["severity"] == "HIGH"
    assert finding["params"]["dep_name"] == "openssl"


def test_r116_fires_on_replaces_too(establish):
    establish(True)
    assert "R116" in ids("+replaces=('vim')\n")


def test_r116_fires_on_widely_provided_medium(establish, observe):
    establish(False)
    observe(30)
    assert "R116" in ids("+provides=('glibc')\n")


def test_r116_below_threshold_is_quiet(establish, observe):
    establish(False)
    observe(5)
    assert "R116" not in ids("+provides=('obscure-lib')\n")


def test_r116_related_sibling_provides_is_quiet(establish):
    establish(True)
    d = "+provides=('foo-extra')\n"
    assert "R116" not in ids(d, package_name="foo")


def test_r116_cold_start_is_quiet(establish, observe):
    establish(False)
    observe(0)
    assert "R116" not in ids("+provides=('openssl')\n")


def test_r116_existing_provides_unchanged_is_quiet(establish):
    establish(True)
    d = "-provides=('openssl')\n+provides=('openssl')\n+pkgrel=2\n"
    assert "R116" not in ids(d, package_name="bar")
