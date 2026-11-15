"""Upstream manifest texts are IOC surfaces when the lane is active."""

from __future__ import annotations

from types import SimpleNamespace

from trustsight.full_aur.analyze import _fact


def test_an_ioc_in_an_upstream_manifest_is_matched(monkeypatch):
    def fake(diff_text, package_name, current_text=None):
        if "193.32.204.199" in (current_text or ""):
            return [SimpleNamespace(
                type="pkgbuild_pattern", value="193.32.204.199",
                source="local", surface="current_text")]
        return []

    monkeypatch.setattr(_fact, "ioc_baseline_matches", fake)
    matches = _fact._ioc_matches_for(
        "pkg", "pkgbuild", ("name: audit\nrun: curl 193.32.204.199\n",))
    assert [(m.type, m.value) for m in matches] == [
        ("pkgbuild_pattern", "193.32.204.199")]


def test_the_recipe_is_still_matched_without_upstream(monkeypatch):
    def fake(diff_text, package_name, current_text=None):
        return [SimpleNamespace(
            type="package", value="pkg", source="local",
            surface="current_text")]

    monkeypatch.setattr(_fact, "ioc_baseline_matches", fake)
    assert len(_fact._ioc_matches_for("pkg", "pkgbuild", ())) == 1
