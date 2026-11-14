"""Full-AUR upstream manifest and workflow state transitions."""

from trustsight.analysis.manifest_state import (
    build_manifest_state,
    manifest_state_delta,
)
from trustsight.full_aur.analyze import TemporalContext, analyze_package_text


def _state(git_url, workflows=()):
    return build_manifest_state(
        [("Cargo.toml", f'[dependencies]\nfoo = {{ git = "{git_url}" }}\n')],
        [(path, b"name: CI\n") for path in workflows],
    )


def test_manifest_state_deltas_reach_corpus_analysis():
    from trustsight.config import ensure_default_configs
    from trustsight.db import init_db

    ensure_default_configs()
    init_db()
    previous = _state("https://github.com/good/foo")
    current = _state(
        "https://github.com/evil/foo", [".github/workflows/ci.yml"])
    manifests, workflows = manifest_state_delta(previous, current)
    assert len(manifests) == 1
    assert manifests[0].origin_changes
    assert workflows[0].path == ".github/workflows/ci.yml"

    fact = analyze_package_text(
        pkg_name="demo",
        old_pkgbuild="pkgname=demo\npkgver=1\n",
        new_pkgbuild="pkgname=demo\npkgver=1\n",
        maintainer="tester",
        temporal=TemporalContext(),
        manifest_deltas=manifests,
        workflow_deltas=workflows,
    )
    ids = {entry.rule_id for entry in fact.score_breakdown}
    assert {"U011", "U009"} <= ids


def test_first_manifest_observation_is_a_baseline_not_a_delta():
    current = _state("https://github.com/good/foo")
    assert manifest_state_delta(None, current) == ((), ())
    assert manifest_state_delta(current, None) == ((), ())


def test_manifest_state_is_preserved_by_snapshots(tmp_path, monkeypatch):
    import trustsight.db as db

    monkeypatch.setattr(db, "DATA_DIR", tmp_path)
    db.init_db()
    state = _state("https://github.com/good/foo")
    db.save_pkgbuild_snapshot("demo", "pkgname=demo\n", "1", manifest_state=state)
    assert db.get_pkgbuild_snapshot("demo")["manifest_state"] == state
    db.save_pkgbuild_snapshot("demo", "pkgname=demo\npkgver=1\n", "1")
    assert db.get_pkgbuild_snapshot("demo")["manifest_state"] == state


def test_first_upstream_observation_is_a_baseline_not_an_added_manifest():
    def state(upstream_url):
        return build_manifest_state(
            [("Cargo.toml", "[dependencies]\nfoo = { git = \"https://github.com/good/foo\" }\n"),
             ("upstream/Cargo.toml", f'[dependencies]\nfoo = {{ git = "{upstream_url}" }}\n')],
            [],
        )

    first = state("https://github.com/good/foo")
    # The AUR state before the lane was enabled carries no upstream manifest.
    before = build_manifest_state(
        [("Cargo.toml", "[dependencies]\nfoo = { git = \"https://github.com/good/foo\" }\n")],
        [])
    assert manifest_state_delta(before, first) == ((), ())

    moved = state("https://github.com/evil/foo")
    manifests, _ = manifest_state_delta(first, moved)
    assert len(manifests) == 1
    assert manifests[0].path == "upstream/Cargo.toml"
    assert manifests[0].origin_changes
