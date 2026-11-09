"""The yay/paru pre-build gate.

The gate is a hard, fail-closed approval: a refusal or a broken inspection
must stop the transaction, and an unattended run must never approve by
accident.  These tests pin the decision loop, the argv it hands to
``trustsight inspect``, and the report it renders.
"""

from __future__ import annotations

import io
import json
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
        assert argv[1] == "inspect"
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
