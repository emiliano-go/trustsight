"""The suite's network guard must reach subprocesses, not only pytest.

``conftest.py`` patches ``socket.connect`` in this process.  Git and the
tokenizer worker are separate processes, where that patch does not apply, so
the guard is repeated there: a ``sitecustomize.py`` on ``PYTHONPATH`` for
Python children, and ``GIT_ALLOW_PROTOCOL=file`` for git.  These tests pin
both, and that loopback still works.
"""

import shutil
import socket
import subprocess
import sys

import pytest


def test_a_python_subprocess_cannot_open_a_non_loopback_connection():
    code = "import socket\nsocket.create_connection(('198.51.100.7', 80), timeout=2)\n"
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert out.returncode != 0
    assert "offline" in out.stderr


def test_a_python_subprocess_can_still_use_loopback():
    """Tests that bind a local server must keep working under the guard."""
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]
    code = (
        "import socket\n"
        f"s = socket.create_connection(('127.0.0.1', {port}), timeout=2)\n"
        "s.close()\n"
        "print('ok')\n"
    )
    try:
        out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    finally:
        server.close()
    assert out.returncode == 0, out.stderr
    assert "ok" in out.stdout


@pytest.mark.skipif(shutil.which("git") is None, reason="git is not available")
def test_git_subprocess_refuses_a_network_protocol(tmp_path):
    out = subprocess.run(
        ["git", "ls-remote", "https://198.51.100.7/x.git"],
        capture_output=True, text=True, cwd=tmp_path, timeout=30,
    )
    assert out.returncode != 0
    # The message is localised, so assert git refused and said something,
    # not the English wording: under LANG=de_DE.UTF-8 this read
    # "übertragungsart 'https' nicht erlaubt." and the phrase match failed.
    assert out.stderr.strip(), "git refused the transport but said nothing"
