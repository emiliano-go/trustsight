"""Static runtime-surface rules H009-H013 (no execution)."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from trustsight.analysis.runtime_surface import runtime_surface_findings  # noqa: E402


def _ids(files):
    return {f["rule_id"] for f in runtime_surface_findings(files)}


def _unit(body: str) -> list:
    return [("pkg.service", body.encode())]


def test_h009_network_client_in_exec_line():
    assert "H009" in _ids(_unit(
        "[Service]\nExecStart=/usr/bin/curl https://example.com/ping\n"))


def test_h010_sensitive_write_in_exec_line():
    assert "H010" in _ids(_unit(
        "[Service]\nExecStart=/bin/sh -c 'echo x > /etc/foo.conf'\n"))


def test_h011_privilege_escalation_in_exec_line():
    assert "H011" in _ids(_unit("[Service]\nExecStart=/usr/bin/sudo /usr/bin/foo\n"))


def test_h012_tracerpid_probe_in_install_hook():
    assert "H012" in _ids([("pkg.install", b"post_install() {\n"
                                        b"  grep TracerPid /proc/self/status\n}\n")])


def test_h013_strace_log_truncation():
    assert "H013" in _ids([("usr/bin/run.sh",
                            b"#!/bin/sh\ntruncate -s 0 /var/log/strace.log\n")])


def test_benign_unit_and_script_are_quiet():
    assert _ids([
        ("pkg.service", b"[Service]\nExecStart=/usr/bin/true\n"),
        ("usr/bin/run.sh", b"#!/bin/sh\necho hi\n"),
    ]) == set()


def test_non_runtime_and_test_files_are_ignored():
    assert _ids([
        ("README.md", b"curl https://example.com\n"),
        ("tests/fixtures/p.service", b"[Service]\nExecStart=/usr/bin/curl x\n"),
    ]) == set()
