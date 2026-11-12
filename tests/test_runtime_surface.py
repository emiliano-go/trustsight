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


def test_h010_does_not_match_a_word_containing_tee():
    """`steep`/`committee` are not the `tee` command."""
    assert "H010" not in _ids(_unit(
        "[Service]\nExecStart=/usr/bin/steep /etc/steep.conf\n"))
    assert "H010" not in _ids(_unit(
        "[Service]\nExecStart=/usr/bin/report --committee /etc/report.conf\n"))


def test_h010_matches_tee_as_a_shell_word():
    assert "H010" in _ids(_unit(
        "[Service]\nExecStart=/usr/bin/tee /etc/foo.conf\n"))
    assert "H010" in _ids(_unit(
        "[Service]\nExecStart=/bin/sh -c 'printf x | tee /var/log/x'\n"))


def test_h010_ignores_a_redirect_character_inside_printed_text():
    """`/etc/passwd > README` is one quoted echo argument, not a write."""
    assert "H010" not in _ids(_unit(
        '[Service]\nExecStart=/bin/echo "see /etc/passwd > README"\n'))


def test_h010_reads_a_real_redirect_target():
    assert "H010" in _ids(_unit(
        "[Service]\nExecStart=/bin/echo x > /etc/motd\n"))


def test_h013_ignores_capturing_strace_output():
    """`strace ... > /tmp/log` records the trace; it is not truncation."""
    assert "H013" not in _ids([("usr/bin/run.sh",
                                b"#!/bin/sh\nstrace -f ./app > /tmp/log\n")])


def test_h013_matches_removal_of_the_strace_output_file():
    assert "H013" in _ids([("usr/bin/run.sh",
                            b"#!/bin/sh\nstrace -f -o /tmp/t ./app; rm -f /tmp/t\n")])


def test_h013_ignores_a_quoted_destructive_looking_string():
    assert "H013" not in _ids([("usr/bin/run.sh",
                                b"#!/bin/sh\necho 'rm /var/log/strace.log'\n")])
