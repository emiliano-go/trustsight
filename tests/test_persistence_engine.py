"""The persistence engine's table, dispatch and registry contract."""

from pathlib import Path

from trustsight import categories
from trustsight.analysis import persistence_engine
from trustsight.analysis.edges import build_context
from trustsight.analysis.pipeline import scan_diff
from trustsight.analysis.persistence_engine import (
    PERSISTENCE_INSTANCES,
    run_persistence_instances,
)

ROOT = Path(__file__).resolve().parent.parent


def _diff(body: str) -> str:
    added = "".join(f"+{line}\n" for line in body.splitlines())
    return (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,2 +1,3 @@\n"
        " pkgname=demo\n pkgver=1.0\n" + added
    )


def _ids(body: str) -> set[str]:
    fact = scan_diff(_diff(body), package_name="demo")
    return {entry.rule_id for entry in fact.score_breakdown}


def test_every_instance_is_a_registered_rule_with_docs_and_fixtures():
    for instance in PERSISTENCE_INSTANCES:
        assert instance.rule_id in categories.RULE_CATEGORIES, instance.rule_id
        assert (ROOT / instance.doc).exists(), (instance.rule_id, instance.doc)
        assert instance.fixtures, instance.rule_id
        for fixture in instance.fixtures:
            assert (ROOT / fixture).exists(), (instance.rule_id, fixture)


def test_run_persistence_instances_honours_only_and_skips_none_emitters():
    ctx = build_context(_diff("build() {\n  sudo true\n}\n"), {})
    seen: list[str] = []

    def add(rule_id, *_args, **_kwargs):
        seen.append(rule_id)

    run_persistence_instances(ctx, add, only=frozenset({"H004"}))
    assert seen == ["H004"]

    # A full dispatch must not raise on the manifest-scope H093 (no emitter).
    seen.clear()
    run_persistence_instances(ctx, add)
    assert "H093" not in seen


def test_every_emitter_is_reachable_through_the_dispatch():
    called: list[str] = []

    def spy(ctx, add):
        called.append("spy")

    original = persistence_engine.PERSISTENCE_INSTANCES
    persistence_engine.PERSISTENCE_INSTANCES = tuple(
        persistence_engine.PersistenceInstance(
            "H004", "spy", "privilege", False, "CRITICAL",
            "docs/rules/fetch-and-execution.md",
            ("tests/test_persistence_engine.py",), spy)
        for _ in range(3)
    )
    try:
        persistence_engine.run_persistence_instances(
            build_context(_diff("build() {\n  true\n}\n"), {}), lambda *a, **k: None)
    finally:
        persistence_engine.PERSISTENCE_INSTANCES = original
    assert called == ["spy", "spy", "spy"]


def test_a_privilege_escalation_fires_h004():
    assert "H004" in _ids("build() {\n  sudo pacman -S x\n}\n")


def test_a_home_rc_write_fires_h032():
    assert "H032" in _ids('build() {\n  install -Dm644 x "$HOME/.bashrc"\n}\n')
