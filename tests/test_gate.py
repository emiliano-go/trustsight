"""The yay/paru pre-build gate.

The gate is a hard, fail-closed approval: a refusal or a broken inspection
must stop the transaction, and an unattended run must never approve by
accident.  These tests pin the decision loop, the argv it hands to
``trustsight inspect``, and the report it renders.
"""

from __future__ import annotations

import io
import json
import os
import pty
import subprocess

import pytest

from trustsight import gate


def _body(**overrides):
    body = {
        "package": "demo",
        "verdict": "review",
        "risk": "Medium",
        "score": 35,
        "old_version": "1.0-1",
        "new_version": "1.1-1",
        "findings": [
            {"rule_id": "H017", "severity": "HIGH", "weight": 10,
             "description": "install hook changed"},
        ],
        "coverage_gaps": [],
    }
    body.update(overrides)
    return body


def test_srcinfo_lists_each_split_package_once():
    text = "\npkgbase = demo\npkgname = demo\npkgname = demo-docs\npkgname = demo\n"
    assert gate.parse_srcinfo(text) == ["demo", "demo-docs"]


def test_srcinfo_ignores_comments_and_empty_values():
    text = "# pkgname = nope\npkgname =\npkgname = real\n"
    assert gate.parse_srcinfo(text) == ["real"]


def test_targets_from_dir_uses_srcinfo_then_base_fallback(tmp_path):
    (tmp_path / ".SRCINFO").write_text("pkgname = one\npkgname = two\n")
    assert gate.targets_from_dir(tmp_path, "base") == ["one", "two"]

    empty = tmp_path / "empty"
    empty.mkdir()
    assert gate.targets_from_dir(empty, "base") == ["base"]


def test_targets_from_dir_without_fallback_is_empty(tmp_path):
    assert gate.targets_from_dir(tmp_path) == []


def test_inspect_argv_is_read_only_and_positional():
    argv = gate.build_inspect_argv(
        "evil package; rm -rf /", depth=2, full_recipe=True, binary="trustsight",
    )
    assert argv[0] == "trustsight"
    assert argv[1] == "inspect"
    assert "evil package; rm -rf /" in argv
    assert "--allow-uninstalled" in argv
    assert "--depth" in argv and argv[argv.index("--depth") + 1] == "2"
    assert "--full-recipe" in argv
    assert "--record" not in argv


def test_inspect_argv_omits_full_recipe_for_an_update():
    argv = gate.build_inspect_argv("demo", full_recipe=False, binary="trustsight")
    assert "--full-recipe" not in argv


def test_summarize_orders_and_caps_findings():
    findings = [
        {"rule_id": f"L{n}", "severity": "LOW", "weight": 1, "description": "low"}
        for n in range(gate.MAX_FINDINGS + 2)
    ]
    findings.append(
        {"rule_id": "C1", "severity": "CRITICAL", "weight": 50,
         "description": "critical"}
    )
    summary = gate.summarize(_body(findings=findings))
    assert summary.findings[0]["rule_id"] == "C1"
    assert len(summary.findings) == gate.MAX_FINDINGS


def test_summarize_tolerates_malformed_fields():
    summary = gate.summarize({
        "package": "demo",
        "verdict": None,
        "risk": 7,
        "score": True,
        "old_version": [],
        "new_version": "2.0-1",
        "findings": "not-a-list",
        "coverage_gaps": [None, "tree_not_analyzed", 3],
    })
    assert summary.verdict == ""
    assert summary.risk == ""
    assert summary.score is None
    assert summary.new_version == "2.0-1"
    assert summary.findings == ()
    assert summary.coverage_gaps == ("tree_not_analyzed",)


def test_summarize_rejects_a_body_without_a_package():
    with pytest.raises(gate.GateError):
        gate.summarize({"package": "", "findings": []})
    with pytest.raises(gate.GateError):
        gate.summarize(["not", "a", "dict"])


def test_render_shows_the_decision_facts():
    out = io.StringIO()
    gate.render(gate.summarize(_body()), out)
    text = out.getvalue()
    assert "demo" in text
    assert "review" in text
    assert "H017" in text
    assert "1.1-1 (from 1.0-1)" in text


def test_render_colors_only_a_terminal(monkeypatch):
    class Terminal(io.StringIO):
        def isatty(self):
            return True

    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.delenv("FORCE_COLOR", raising=False)
    monkeypatch.delenv("TRUSTSIGHT_FORCE_RICH", raising=False)
    terminal = Terminal()
    gate.render(gate.summarize(_body()), terminal)
    assert "\x1b[" in terminal.getvalue()

    plain = io.StringIO()
    gate.render(gate.summarize(_body()), plain)
    assert "\x1b[" not in plain.getvalue()

    monkeypatch.setenv("NO_COLOR", "1")
    disabled = Terminal()
    gate.render(gate.summarize(_body()), disabled)
    assert "\x1b[" not in disabled.getvalue()


def test_render_one_lines_a_long_verdict_and_skips_info():
    long_verdict = "This analysis was incomplete: " + "reason " * 80
    out = io.StringIO()
    body = _body(
        verdict=long_verdict,
        findings=[
            {"rule_id": "W011", "severity": "INFO", "weight": 0,
             "description": "upstream not read"},
            {"rule_id": "H026", "severity": "HIGH", "weight": 10,
             "description": "maintainer changed"},
        ],
        coverage_gaps=["ruleset_drifted"],
    )
    gate.render(gate.summarize(body), out)
    text = out.getvalue()
    assert long_verdict not in text
    assert "..." in text
    assert "W011" not in text
    assert "H026" in text
    assert "config sync-rules --update" in text


def test_read_answer_reads_a_real_terminal():
    master, slave = pty.openpty()
    try:
        os.write(master, b"y\n")
        answer = gate._read_answer("Continue? ", tty_path=os.ttyname(slave))
    finally:
        os.close(master)
        os.close(slave)
    assert answer == "y"


def test_read_answer_without_a_terminal_is_none():
    assert gate._read_answer("Continue? ", tty_path="/nonexistent/tty") is None


def test_run_gate_prompts_once_per_package_and_approves():
    seen: list[str] = []
    out = io.StringIO()
    code = gate.run_gate(
        ["one", "two"],
        inspect=lambda name: _body(package=name),
        answer=lambda prompt: seen.append(prompt) or "y",
        out=out,
    )
    assert code == gate.EXIT_APPROVED
    assert len(seen) == 2


def test_run_gate_refusal_is_a_hard_stop():
    asked: list[str] = []

    def answer(prompt):
        asked.append(prompt)
        return "n"

    out = io.StringIO()
    code = gate.run_gate(
        ["one", "two"],
        inspect=lambda name: _body(package=name),
        answer=answer,
        out=out,
    )
    assert code == gate.EXIT_REFUSED
    assert len(asked) == 1  # stops at the first no, never asks about "two"


def test_run_gate_without_terminal_fails_closed():
    out = io.StringIO()
    code = gate.run_gate(
        ["demo"],
        inspect=lambda name: _body(package=name),
        answer=lambda prompt: None,
        out=out,
    )
    assert code == gate.EXIT_NONINTERACTIVE
    assert "no terminal" in out.getvalue()


def test_run_gate_analysis_failure_fails_closed():
    def broken(name):
        raise gate.GateError("inspection failed")

    out = io.StringIO()
    code = gate.run_gate(
        ["demo"], inspect=broken, answer=lambda prompt: "y", out=out,
    )
    assert code == gate.EXIT_ERROR


def test_run_gate_rejects_an_empty_target_list():
    code = gate.run_gate(
        [], inspect=lambda name: _body(package=name),
        answer=lambda prompt: "y", out=io.StringIO(),
    )
    assert code == gate.EXIT_ERROR


def test_run_gate_yes_never_reads_the_terminal():
    def answer(prompt):
        raise AssertionError("must not prompt when --yes is set")

    assert gate.run_gate(
        ["demo"], inspect=lambda name: _body(package=name), answer=answer,
        out=io.StringIO(), approve_all=True,
    ) == gate.EXIT_APPROVED


def test_run_inspect_parses_the_body():
    def runner(argv, **kwargs):
        # The binary may be `trustsight` on PATH or the `-m trustsight` module
        # fallback; both put the subcommand after it.
        assert "inspect" in argv
        assert argv[argv.index("inspect") + 1] == "demo"
        return subprocess.CompletedProcess(argv, 0, json.dumps(_body()), "")

    body = gate.run_inspect("demo", full_recipe=False, runner=runner)
    assert body["package"] == "demo"


def test_run_inspect_nonzero_exit_is_an_error():
    def runner(argv, **kwargs):
        return subprocess.CompletedProcess(argv, 2, "", "no such package")

    with pytest.raises(gate.GateError, match="no such package"):
        gate.run_inspect("demo", full_recipe=False, runner=runner)


def test_run_inspect_invalid_json_is_an_error():
    def runner(argv, **kwargs):
        return subprocess.CompletedProcess(argv, 0, "not json", "")

    with pytest.raises(gate.GateError, match="invalid JSON"):
        gate.run_inspect("demo", full_recipe=False, runner=runner)


def test_run_inspect_timeout_is_an_error():
    def runner(argv, **kwargs):
        raise subprocess.TimeoutExpired(argv, 1)

    with pytest.raises(gate.GateError, match="timed out"):
        gate.run_inspect("demo", timeout=1, full_recipe=False, runner=runner)


def test_run_inspect_error_body_is_an_error():
    def runner(argv, **kwargs):
        return subprocess.CompletedProcess(
            argv, 0, json.dumps({"error": "analysis failed"}), "")

    with pytest.raises(gate.GateError, match="analysis failed"):
        gate.run_inspect("demo", full_recipe=False, runner=runner)


def test_run_inspect_auto_full_recipe_when_pacman_cannot_confirm(
    monkeypatch,
):
    seen: list[list[str]] = []

    def runner(argv, **kwargs):
        seen.append(argv)
        return subprocess.CompletedProcess(argv, 0, json.dumps(_body()), "")

    monkeypatch.setattr(gate, "_pacman_says_installed", lambda name: None)
    gate.run_inspect("demo", full_recipe=None, runner=runner)
    assert "--full-recipe" in seen[0]

    seen.clear()
    monkeypatch.setattr(gate, "_pacman_says_installed", lambda name: True)
    gate.run_inspect("demo", full_recipe=None, runner=runner)
    assert "--full-recipe" not in seen[0]


def test_main_yes_approves_explicit_packages(monkeypatch):
    monkeypatch.setattr(gate, "run_inspect", lambda name, **kw: _body(package=name))
    out = io.StringIO()
    assert gate.main(["--yes", "one", "two"], out=out) == gate.EXIT_APPROVED
    assert out.getvalue().count(":: TrustSight gate:") == 2


def test_main_reads_targets_from_srcinfo(monkeypatch, tmp_path):
    (tmp_path / ".SRCINFO").write_text("pkgname = split-a\npkgname = split-b\n")
    monkeypatch.setattr(gate, "run_inspect", lambda name, **kw: _body(package=name))
    out = io.StringIO()
    code = gate.main(["--yes", "--dir", str(tmp_path)], out=out)
    assert code == gate.EXIT_APPROVED
    assert "split-a" in out.getvalue() and "split-b" in out.getvalue()


def test_main_without_targets_is_an_error():
    out = io.StringIO()
    assert gate.main(["--yes"], out=out) == gate.EXIT_ERROR
    assert "no target packages" in out.getvalue()


def test_main_disable_bypass_is_visible(monkeypatch):
    monkeypatch.setenv("TRUSTSIGHT_GATE_DISABLE", "1")
    monkeypatch.setattr(
        gate, "run_inspect",
        lambda *a, **kw: (_ for _ in ()).throw(AssertionError("must not inspect")),
    )
    out = io.StringIO()
    assert gate.main(["--yes", "demo"], out=out) == gate.EXIT_APPROVED
    assert "disabled" in out.getvalue()


def test_render_sanitizes_untrusted_report_text():
    """The gate prints package-controlled evidence to a terminal."""
    out = io.StringIO()
    body = {
        "package": "demo\033[31mRED",
        "verdict": "safe\033]0;forged\007",
        "findings": [{
            "rule_id": "R001",
            "severity": "HIGH",
            "description": "payload\033[2Jwiped",
            "file": "PKGBUILD",
            "line": 1,
        }],
        "coverage_gaps": ["gap\033[0m"],
    }
    gate.render(gate.summarize(body), out)
    text = out.getvalue()
    assert "\033" not in text and "\007" not in text
    assert "RED" in text and "payload" in text


def test_run_gate_sanitizes_the_approval_prompt():
    prompts: list[str] = []

    def answer(prompt):
        prompts.append(prompt)
        return "y"

    code = gate.run_gate(
        ["demo\033[31m"], inspect=lambda name: _body(package=name),
        answer=answer, out=io.StringIO(),
    )
    assert code == gate.EXIT_APPROVED
    assert "\033" not in prompts[0]
    assert "demo" in prompts[0]


def test_run_inspect_falls_back_to_lint_for_a_local_package(tmp_path):
    (tmp_path / "PKGBUILD").write_text("pkgname=local\npkgver=1\n")
    calls: list[list[str]] = []

    def runner(argv, **kwargs):
        calls.append(argv)
        if "inspect" in argv:
            return subprocess.CompletedProcess(
                argv, 0,
                json.dumps({"error": "Package 'local' not found in the AUR."}),
                "",
            )
        return subprocess.CompletedProcess(
            argv, 0,
            json.dumps({
                "rules": [{
                    "rule_id": "H001",
                    "severity": "HIGH",
                    "message": "checksum disabled",
                }],
            }),
            "",
        )

    body = gate.run_inspect(
        "local", full_recipe=False, directory=str(tmp_path), runner=runner,
    )
    assert body["verdict"] == "local recipe (no diff)"
    assert body["findings"][0]["description"] == "checksum disabled"
    assert calls[1][1:3] == ["lint", "--json"]


def test_run_inspect_falls_back_when_a_banner_is_the_last_stderr_line(tmp_path):
    """The live shape: the AUR miss is JSON on stdout, the update notice on
    stderr.  Reading only the last stderr line skipped the local fallback."""
    (tmp_path / "PKGBUILD").write_text("pkgname=local\npkgver=1\n")

    def runner(argv, **kwargs):
        if "inspect" in argv:
            return subprocess.CompletedProcess(
                argv, 2,
                json.dumps({"error": "Package 'local' not found in the AUR."}),
                "trustsight: update with `git pull && makepkg -si`.\n",
            )
        return subprocess.CompletedProcess(
            argv, 0,
            json.dumps({"rules": [{
                "rule_id": "H001", "severity": "HIGH",
                "message": "checksum disabled"}]}),
            "",
        )

    body = gate.run_inspect(
        "local", full_recipe=False, directory=str(tmp_path), runner=runner)
    assert body["verdict"] == "local recipe (no diff)"
    assert body["findings"][0]["description"] == "checksum disabled"
