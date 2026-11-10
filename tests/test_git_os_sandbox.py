"""The git worker's kernel confinement (A16).

These run the sandbox in a child process, because that is where it is applied:
the worker confines itself before its first request.  Each test asserts the
containment from the inside - a file outside the cache is unreadable, the
read role has no route, and a forbidden syscall kills the process - rather
than merely that the sandbox functions were called.
"""

from __future__ import annotations

import os
import signal
import socket
import subprocess
import sys
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parent.parent / "src"
PYTHON = sys.executable


def _run_after_sandbox(script: str, *args: str, cache: str) -> subprocess.CompletedProcess:
    env = {
        "PATH": "/usr/bin:/bin",
        "PYTHONPATH": str(SRC),
        "LANG": "C",
    }
    return subprocess.run(
        [PYTHON, "-c", script, cache, *args],
        env=env,
        capture_output=True,
        timeout=30,
    )


def _skip_without_userns(result: subprocess.CompletedProcess) -> None:
    stderr = result.stderr.decode("utf-8", "replace")
    if (
        result.returncode == 2
        and (
            "user namespace unavailable" in stderr
            or "unsupported platform" in stderr
            or "network namespace unavailable" in stderr
        )
    ):
        pytest.skip(stderr.strip())


_PROBE = """
import os, sys
from trustsight.sandbox._linux_sandbox import apply
cache = sys.argv[1]
failures, _ = apply("read", cache)
if failures:
    sys.stderr.write("; ".join(failures) + "\\n")
    os._exit(2)
"""


def test_landlock_denies_a_file_outside_the_cache(tmp_path):
    cache = tmp_path / "cache"
    cache.mkdir()
    secret = tmp_path / "secret"
    secret.write_text("operator-only")

    script = _PROBE + """
try:
    open(sys.argv[2]).read()
except PermissionError:
    os.write(1, b"DENIED\\n")
else:
    os.write(1, b"LEAK\\n")
os._exit(0)
"""
    result = _run_after_sandbox(script, str(secret), cache=str(cache))
    _skip_without_userns(result)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == b"DENIED"


def test_the_read_role_cannot_create_a_socket(tmp_path):
    cache = tmp_path / "cache"
    cache.mkdir()

    script = _PROBE + """
import socket
socket.socket(socket.AF_INET, socket.SOCK_STREAM)
os.write(1, b"LEAK\\n")
os._exit(0)
"""
    result = _run_after_sandbox(script, cache=str(cache))
    _skip_without_userns(result)
    assert result.returncode == -signal.SIGSYS, (
        result.returncode, result.stdout, result.stderr)


def test_seccomp_kills_a_forbidden_syscall(tmp_path):
    cache = tmp_path / "cache"
    cache.mkdir()

    script = _PROBE + """
os.execv("/bin/true", ["true"])
os.write(1, b"LEAK\\n")
os._exit(0)
"""
    result = _run_after_sandbox(script, cache=str(cache))
    _skip_without_userns(result)
    assert result.returncode == -signal.SIGSYS, (
        result.returncode, result.stdout, result.stderr)


def test_the_proxy_refuses_a_non_aur_authority(tmp_path):
    from trustsight.sandbox._aur_proxy import AurFetchProxy

    proxy = AurFetchProxy()
    try:
        client = socket.socket(fileno=os.dup(proxy.child_fds[0]))
        client.settimeout(5)
        client.sendall(b"CONNECT evil.example:443 HTTP/1.1\r\n\r\n")
        response = client.recv(4096)
        client.close()
    finally:
        proxy.close()
    assert b"403" in response
    assert b"200" not in response


def test_the_proxy_tunnels_the_aur_authority(tmp_path, monkeypatch):
    from trustsight.sandbox import _aur_proxy

    server_side, remote_side = socket.socketpair()
    monkeypatch.setattr(
        _aur_proxy.socket, "create_connection",
        lambda *_a, **_k: remote_side,
    )
    proxy = _aur_proxy.AurFetchProxy()
    try:
        client = socket.socket(fileno=os.dup(proxy.child_fds[0]))
        client.settimeout(5)
        client.sendall(
            b"CONNECT aur.archlinux.org:443 HTTP/1.1\r\n\r\n")
        status = client.recv(4096)
        assert b"200" in status
        client.sendall(b"tunnel-bytes")
        assert server_side.recv(4096) == b"tunnel-bytes"
        client.close()
    finally:
        proxy.close()
        server_side.close()


def test_a_fetch_session_uses_the_proxy_and_a_read_session_does_not(tmp_path):
    import pygit2

    from trustsight.sandbox import git_client

    cache = tmp_path / "cache"
    cache.mkdir()
    repo = pygit2.init_repository(str(cache / "demo"), bare=True)
    author = pygit2.Signature("Tester", "tester@example.com")
    blob = repo.create_blob(b"pkgver=1.0\n")
    builder = repo.TreeBuilder()
    builder.insert("PKGBUILD", blob, pygit2.GIT_FILEMODE_BLOB)
    repo.create_commit("refs/heads/master", author, author, "c",
                       builder.write(), [])
    repo.remotes.create("origin", "https://aur.archlinux.org/demo.git")

    session = git_client.GitSession()
    try:
        session.request("open_fetch", {
            "pkg": "demo", "cache_dir": str(cache), "upstream_mtime": None,
            "offline": True, "connect_timeout": 5, "transfer_timeout": 5,
        })
        assert session._role == "fetch"
        assert session._proxy is not None
        head = session.head("demo", str(cache))
        assert session._role == "read"
        assert session._proxy is None
        assert head
    finally:
        session.close()


def test_a_lost_os_protection_refuses_the_worker(monkeypatch):
    from trustsight.sandbox import git_worker

    monkeypatch.setattr(git_worker, "_SANDBOXED", False)
    monkeypatch.setattr(git_worker, "_ROLE", "read")
    monkeypatch.setattr(git_worker, "_PROXY_FDS", ())
    monkeypatch.setattr(
        git_worker._linux_sandbox, "apply",
        lambda *_a, **_k: (["OS sandbox not applied: seccomp unavailable"], ""),
    )
    body = b'{"op":"head","pkg":"demo","cache_dir":"/tmp"}'
    with pytest.raises(SystemExit) as caught:
        git_worker._sandbox_or_error(body)
    assert caught.value.code == 3


def test_the_fetch_bridge_uses_an_inherited_tunnel_and_refuses_af_unix(tmp_path):
    """The fetch role's only egress is the inherited proxy descriptor.

    A fresh AF_UNIX socket is what would reach a host service; it must be
    killed after confinement, while the inherited tunnel and its loopback
    bridge still work.
    """
    cache = tmp_path / "cache"
    cache.mkdir()
    parent_end, child_end = socket.socketpair()
    received = []

    def echo():
        try:
            while True:
                chunk = parent_end.recv(4096)
                if not chunk:
                    return
                received.append(chunk)
                parent_end.sendall(b"ECHO:" + chunk)
        except OSError:
            return

    import threading

    thread = threading.Thread(target=echo, daemon=True)
    thread.start()

    script = """
import os, socket, sys
from trustsight.sandbox._linux_sandbox import apply
cache = sys.argv[1]
fds = tuple(int(value) for value in sys.argv[2].split(",") if value)
failures, proxy_url = apply("fetch", cache, proxy_fds=fds)
if failures:
    sys.stderr.write("; ".join(failures) + "\\n")
    os._exit(2)
port = int(proxy_url.rsplit(":", 1)[1])
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.settimeout(5)
client.connect(("127.0.0.1", port))
client.sendall(b"ping")
reply = client.recv(4096)
if reply != b"ECHO:ping":
    os.write(1, b"BRIDGE-FAILED\\n")
    os._exit(3)
os.write(1, b"BRIDGE-OK\\n")
client.close()
socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
os.write(1, b"AF-UNIX-LEAK\\n")
os._exit(0)
"""
    env = {"PATH": "/usr/bin:/bin", "PYTHONPATH": str(SRC), "LANG": "C"}
    try:
        result = subprocess.run(
            [PYTHON, "-c", script, str(cache), str(child_end.fileno())],
            env=env, capture_output=True, timeout=30,
            pass_fds=(child_end.fileno(),),
        )
    finally:
        parent_end.close()
        child_end.close()
    assert result.returncode == -signal.SIGSYS, (
        result.returncode, result.stdout, result.stderr)
    assert b"BRIDGE-OK" in result.stdout
    assert b"AF-UNIX-LEAK" not in result.stdout
    assert received == [b"ping"]


def test_the_fetch_role_reaches_the_proxy_and_reports_a_refusal(tmp_path,
                                                               monkeypatch):
    """A real libgit2 fetch path must survive the fetch-role seccomp filter.

    The fake proxy refuses the CONNECT, so no network is touched.  What is
    checked is that libgit2 gets far enough to speak CONNECT (and therefore
    is not killed for a missing resolver/bridge syscall), and that its refusal
    travels back as an operation error rather than a dead worker.
    """
    from trustsight.sandbox import git_client

    class _RefusingProxy:
        def __init__(self):
            import threading

            self._pairs = []
            for _ in range(2):
                parent, child = socket.socketpair()
                self._pairs.append((parent, child))
                threading.Thread(
                    target=self._refuse, args=(parent,), daemon=True).start()

        @staticmethod
        def _refuse(connection):
            try:
                connection.settimeout(5)
                connection.recv(4096)
                connection.sendall(b"HTTP/1.1 403 Forbidden\r\n\r\n")
            except OSError:
                pass
            finally:
                try:
                    connection.close()
                except OSError:
                    pass

        @property
        def child_fds(self):
            return [child.fileno() for _, child in self._pairs]

        def release_child_fds(self):
            for _, child in self._pairs:
                try:
                    child.close()
                except OSError:
                    pass
            self._pairs = []

        def close(self):
            self.release_child_fds()

    monkeypatch.setattr(git_client, "AurFetchProxy", _RefusingProxy)
    cache = tmp_path / "cache"
    cache.mkdir()
    session = git_client.GitSession()
    try:
        with pytest.raises(git_client.GitOpError):
            session.request("open_fetch", {
                "pkg": "missing", "cache_dir": str(cache),
                "upstream_mtime": None, "offline": False,
                "connect_timeout": 5, "transfer_timeout": 5,
            })
    finally:
        session.close()
