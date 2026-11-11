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
except (PermissionError, FileNotFoundError):
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


class _FakeUpstream:
    """A socket-like TLS upstream that records the request and returns bytes."""

    def __init__(self, response: bytes):
        self.response = response
        self.requests: list[bytes] = []
        self._sent = False

    def settimeout(self, _value) -> None:
        pass

    def sendall(self, data: bytes) -> None:
        self.requests.append(data)

    def recv(self, _size: int) -> bytes:
        if self._sent:
            return b""
        self._sent = True
        return self.response

    def close(self) -> None:
        pass


def test_the_proxy_refuses_a_foreign_package_or_path(tmp_path):
    from trustsight.sandbox._aur_proxy import AurFetchProxy

    proxy = AurFetchProxy("demo")
    try:
        client = socket.socket(fileno=os.dup(proxy.child_fds[0]))
        client.settimeout(5)
        client.sendall(
            b"GET /other.git/info/refs?service=git-upload-pack HTTP/1.1\r\n"
            b"Host: 127.0.0.1\r\n\r\n")
        response = client.recv(4096)
        client.close()
    finally:
        proxy.close()
    assert b"400" in response


def test_the_proxy_forwards_only_a_validated_git_request(tmp_path):
    from trustsight.sandbox._aur_proxy import AurFetchProxy

    from trustsight.sandbox import _aur_proxy

    oid = "a" * 40
    advert = (
        _aur_proxy._pkt_line(b"# service=git-upload-pack\n")
        + b"0000"
        + _aur_proxy._pkt_line(
            f"{oid} HEAD\0symref=HEAD:refs/heads/master\n".encode("ascii"))
        + _aur_proxy._pkt_line(
            f"{oid} refs/heads/master\n".encode("ascii"))
        + b"0000"
    )
    proxy = AurFetchProxy("demo")
    upstream = _FakeUpstream(
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: application/x-git-upload-pack-advertisement\r\n"
        + f"Content-Length: {len(advert)}\r\n\r\n".encode("ascii")
        + advert)
    proxy._open_upstream = lambda: upstream
    try:
        client = socket.socket(fileno=os.dup(proxy.child_fds[0]))
        client.settimeout(5)
        client.sendall(
            b"GET /demo.git/info/refs?service=git-upload-pack HTTP/1.1\r\n"
            b"Host: 127.0.0.1\r\n"
            b"X-Attacker: ignored\r\n\r\n")
        response = client.recv(4096)
        # Extra bytes after the request are never forwarded upstream; the
        # proxy may already have closed the connection, which is also fine.
        try:
            client.sendall(b"exfil-attempt")
        except OSError:
            pass
        client.close()
    finally:
        proxy.close()
    assert response.startswith(b"HTTP/1.1 200")
    assert len(upstream.requests) == 1
    forwarded = upstream.requests[0]
    assert forwarded.startswith(
        b"GET /demo.git/info/refs?service=git-upload-pack HTTP/1.1\r\n")
    assert b"Host: aur.archlinux.org\r\n" in forwarded
    assert b"X-Attacker" not in forwarded
    assert b"exfil-attempt" not in forwarded


def test_the_proxy_parses_a_v0_ref_advertisement():
    from trustsight.sandbox import _aur_proxy

    oid = "a" * 40
    body = (
        _aur_proxy._pkt_line(b"# service=git-upload-pack\n")
        + b"0000"
        + _aur_proxy._pkt_line(
            f"{oid} HEAD\0symref=HEAD:refs/heads/master\n".encode("ascii"))
        + _aur_proxy._pkt_line(
            f"{oid} refs/heads/master\n".encode("ascii"))
        + b"0000"
    )
    head, oids = _aur_proxy._parse_advertisement(body)
    assert head == oid
    assert oid in oids


def test_the_proxy_synthesises_upload_pack_from_the_advertisement():
    from trustsight.sandbox import _aur_proxy

    proxy = _aur_proxy.AurFetchProxy("demo")
    oid_one = "a" * 40
    oid_two = "b" * 40
    try:
        with proxy._lock:
            proxy._advertised_head = oid_one
            proxy._advertised_oids = frozenset({oid_one, oid_two})
        request = proxy._build_upstream(
            "POST", "/demo.git/git-upload-pack")
    finally:
        proxy.close()
    assert f"want {oid_one}".encode() in request
    assert f"want {oid_two}".encode() in request
    assert b"multi_ack_detailed" in request
    assert request.endswith(_aur_proxy._pkt_line(b"done\n"))


def test_the_proxy_refuses_upload_pack_before_advertisement():
    from trustsight.sandbox import _aur_proxy

    proxy = _aur_proxy.AurFetchProxy("demo")
    try:
        with pytest.raises(_aur_proxy._BadRequest):
            proxy._build_upstream(
                "POST", "/demo.git/git-upload-pack")
    finally:
        proxy.close()


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

    The fake proxy refuses the HTTP request, so no network is touched.  What
    is checked is that libgit2 gets far enough to speak HTTP to the loopback
    proxy (and therefore is not killed for a missing resolver/bridge syscall),
    and that its refusal travels back as an operation error rather than a dead
    worker.
    """
    from trustsight.sandbox import git_client

    class _RefusingProxy:
        def __init__(self, package):
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


def test_landlock_limits_the_worker_to_its_own_repository(tmp_path):
    cache = tmp_path / "cache"
    own = cache / "demo"
    other = cache / "other"
    own.mkdir(parents=True)
    other.mkdir()
    (other / "PKGBUILD").write_text("operator-reviewed-package")

    script = """
import os, sys
from trustsight.sandbox._linux_sandbox import apply
repo = sys.argv[1]
failures, _ = apply("read", repo)
if failures:
    sys.stderr.write("; ".join(failures) + "\\n")
    os._exit(2)
try:
    open(sys.argv[2]).read()
except (PermissionError, FileNotFoundError):
    os.write(1, b"DENIED\\n")
else:
    os.write(1, b"LEAK\\n")
os._exit(0)
"""
    result = _run_after_sandbox(
        script, str(other / "PKGBUILD"), cache=str(own))
    _skip_without_userns(result)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == b"DENIED"


def test_a_real_git_fetch_works_through_the_validating_proxy(tmp_path,
                                                              monkeypatch):
    """End-to-end: plain-HTTP worker -> validating proxy -> a Git server.

    Uses ``git http-backend`` as the upstream so the request the proxy
    rebuilds is the request a real server parses.  Skipped when git is not
    installed; the suite already depends on pygit2 for object storage, but
    this test is specifically about the wire contract.
    """
    import http.server
    import shutil
    import threading
    import urllib.parse

    if shutil.which("git") is None:
        pytest.skip("git http-backend is unavailable")

    from trustsight.sandbox import _aur_proxy, git_client

    import pygit2

    repos = tmp_path / "repos"
    repos.mkdir()
    repo = pygit2.init_repository(str(repos / "demo.git"), bare=True)
    author = pygit2.Signature("Tester", "tester@example.com")
    blob = repo.create_blob(b"pkgver=1.0\n")
    builder = repo.TreeBuilder()
    builder.insert("PKGBUILD", blob, pygit2.GIT_FILEMODE_BLOB)
    repo.create_commit("refs/heads/master", author, author, "c",
                       builder.write(), [])

    posted: list[bytes] = []

    class _Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def _run(self):
            parsed = urllib.parse.urlsplit(self.path)
            env = {
                "PATH": "/usr/bin:/bin",
                "GIT_PROJECT_ROOT": str(repos),
                "GIT_HTTP_EXPORT_ALL": "1",
                "PATH_INFO": parsed.path,
                "QUERY_STRING": parsed.query,
                "REQUEST_METHOD": self.command,
                "CONTENT_TYPE": self.headers.get("Content-Type", ""),
                "CONTENT_LENGTH": self.headers.get("Content-Length", "0"),
                "REMOTE_ADDR": "127.0.0.1",
                "GATEWAY_INTERFACE": "CGI/1.1",
                "SERVER_PROTOCOL": "HTTP/1.1",
                "SERVER_NAME": "127.0.0.1",
                "SERVER_PORT": str(self.server.server_port),
            }
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length) if length else b""
            if self.command == "POST":
                posted.append(body)
            output = subprocess.run(
                ["git", "http-backend"], input=body, env=env,
                capture_output=True, timeout=30,
            ).stdout
            head, _, payload = output.partition(b"\r\n\r\n")
            status = 200
            headers = []
            for line in head.split(b"\r\n"):
                if line.lower().startswith(b"status:"):
                    status = int(line.split(b" ")[1])
                elif line:
                    headers.append(line)
            self.send_response(status)
            for line in headers:
                name, _, value = line.partition(b":")
                self.send_header(name.decode(), value.strip().decode())
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        do_GET = _run
        do_POST = _run

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    port = server.server_port
    threading.Thread(target=server.serve_forever, daemon=True).start()

    class _LocalProxy(_aur_proxy.AurFetchProxy):
        def _open_upstream(self):
            return socket.create_connection(("127.0.0.1", port), timeout=5)

    monkeypatch.setattr(git_client, "AurFetchProxy", _LocalProxy)
    cache = tmp_path / "cache"
    cache.mkdir()
    session = git_client.GitSession()
    try:
        result = session.request("open_fetch", {
            "pkg": "demo", "cache_dir": str(cache),
            "upstream_mtime": None, "offline": False,
            "connect_timeout": 5, "transfer_timeout": 5,
        })
        assert result["fetched"] is True
        assert session.received_bytes() > 0
        head = session.head("demo", str(cache))
        assert session.file_at(
            "demo", str(cache), head, "PKGBUILD", 4096) == "pkgver=1.0\n"
        assert posted and f"want {head}".encode() in posted[0]
        assert b"have " not in posted[0]

        # A second network fetch goes through the synthesised request too.
        new_blob = repo.create_blob(b"pkgver=2.0\n")
        new_builder = repo.TreeBuilder()
        new_builder.insert("PKGBUILD", new_blob, pygit2.GIT_FILEMODE_BLOB)
        repo.create_commit(
            "refs/heads/master", author, author, "second",
            new_builder.write(), [repo.head.peel().id])
        updated = str(repo.head.peel().id)
        result = session.request("open_fetch", {
            "pkg": "demo", "cache_dir": str(cache),
            "upstream_mtime": None, "offline": False,
            "connect_timeout": 5, "transfer_timeout": 5, "force": True,
        })
        assert result["fetched"] is True
        assert session.head("demo", str(cache)) == updated
        assert session.file_at(
            "demo", str(cache), updated, "PKGBUILD", 4096) == "pkgver=2.0\n"
        assert len(posted) >= 2
        assert f"want {updated}".encode() in posted[1]
        assert b"have " not in posted[1]
    finally:
        session.close()
        server.shutdown()
        server.server_close()


def _proxy_request(proxy, payload: bytes):
    left, right = socket.socketpair()
    try:
        right.sendall(payload)
        right.shutdown(socket.SHUT_WR)
        return proxy._read_request(left)
    finally:
        left.close()
        right.close()


def test_the_proxy_rejects_malformed_headers():
    from trustsight.sandbox import _aur_proxy

    proxy = _aur_proxy.AurFetchProxy("demo")
    try:
        cases = [
            b"GET /demo.git/info/refs?service=git-upload-pack HTTP/1.1\r\n"
            b"Content-Length: 1\r\nContent-Length: 2\r\n\r\n",
            b"GET /demo.git/info/refs?service=git-upload-pack HTTP/1.1\r\n"
            b"Content-Length: " + b"9" * 20 + b"\r\n\r\n",
            b"GET /demo.git/info/refs?service=git-upload-pack HTTP/1.1\r\n"
            b" continuation\r\n\r\n",
            b"GET /demo.git/info/refs?service=git-upload-pack HTTP/1.1\r\n"
            b"X: \x01\r\n\r\n",
        ]
        for payload in cases:
            with pytest.raises(_aur_proxy._BadRequest):
                _proxy_request(proxy, payload)
    finally:
        proxy.close()


def test_the_proxy_requires_ordered_get_then_post():
    from trustsight.sandbox import _aur_proxy

    proxy = _aur_proxy.AurFetchProxy("demo")
    try:
        with pytest.raises(_aur_proxy._BadRequest):
            proxy._charge("POST", b"x")
        proxy._charge("GET", b"x")
        proxy._charge("POST", b"x")
        with pytest.raises(_aur_proxy._BadRequest):
            proxy._charge("POST", b"x")
        with pytest.raises(_aur_proxy._BadRequest):
            proxy._charge("GET", b"x")
    finally:
        proxy.close()


def test_the_proxy_rejects_a_post_without_content_length():
    from trustsight.sandbox import _aur_proxy

    proxy = _aur_proxy.AurFetchProxy("demo")
    try:
        with pytest.raises(_aur_proxy._BadRequest):
            _proxy_request(
                proxy,
                b"POST /demo.git/git-upload-pack HTTP/1.1\r\n\r\n")
    finally:
        proxy.close()


def test_the_proxy_rejects_redirects_and_wrong_content_types():
    from trustsight.sandbox._aur_proxy import AurFetchProxy

    for response in (
        b"HTTP/1.1 302 Found\r\nLocation: https://evil.example/\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>",
    ):
        proxy = AurFetchProxy("demo")
        try:
            upstream = _FakeUpstream(response)
            proxy._open_upstream = lambda upstream=upstream: upstream
            client = socket.socket(fileno=os.dup(proxy.child_fds[0]))
            client.settimeout(5)
            client.sendall(
                b"GET /demo.git/info/refs?service=git-upload-pack HTTP/1.1\r\n"
                b"\r\n")
            reply = client.recv(4096)
            client.close()
            assert reply.startswith(b"HTTP/1.1 502")
        finally:
            proxy.close()


def test_a_slow_request_is_bounded_by_the_header_timeout(monkeypatch):
    import time

    from trustsight.sandbox import _aur_proxy

    proxy = _aur_proxy.AurFetchProxy("demo")
    left, right = socket.socketpair()
    try:
        monkeypatch.setattr(_aur_proxy, "GIT_PROXY_HEADER_SECONDS", 0.05)
        right.sendall(b"GET /demo.git/info/refs")
        started = time.monotonic()
        with pytest.raises(OSError):
            proxy._read_request(left)
        assert time.monotonic() - started < 2
    finally:
        left.close()
        right.close()
        proxy.close()


def test_the_proxy_fails_closed_without_its_explicit_ca_bundle(monkeypatch):
    from trustsight.sandbox import _aur_proxy

    proxy = _aur_proxy.AurFetchProxy("demo")
    try:
        monkeypatch.setattr(_aur_proxy.os.path, "exists", lambda _path: False)
        with pytest.raises(_aur_proxy._UpstreamError):
            proxy._open_upstream()
    finally:
        proxy.close()


def test_the_advertisement_ref_cap_is_enforced(monkeypatch):
    from trustsight.sandbox import _aur_proxy

    monkeypatch.setattr(_aur_proxy, "GIT_PROXY_MAX_REFS", 1)
    first = "a" * 40
    second = "b" * 40
    body = (
        _aur_proxy._pkt_line(b"# service=git-upload-pack\n")
        + b"0000"
        + _aur_proxy._pkt_line(
            f"{first} HEAD\0symref=HEAD:refs/heads/master\n".encode("ascii"))
        + _aur_proxy._pkt_line(
            f"{second} refs/heads/other\n".encode("ascii"))
        + b"0000"
    )
    with pytest.raises(_aur_proxy._BadRequest):
        _aur_proxy._parse_advertisement(body)


def test_metadata_syscalls_cannot_touch_host_files(tmp_path):
    cache = tmp_path / "cache"
    cache.mkdir()
    secret = tmp_path / "secret"
    secret.write_text("operator-only")
    secret.chmod(0o600)
    before = secret.stat()
    source_file = SRC / "trustsight" / "__init__.py"

    script = _PROBE + """
import os, sys
def denied(function, *args):
    try:
        function(*args)
    except OSError:
        return True
    return False
ok = (
    denied(os.chmod, sys.argv[2], 0o644)
    and denied(os.utime, sys.argv[2], None)
    and denied(os.chmod, sys.argv[3], 0o644)
    and denied(os.utime, sys.argv[3], None)
)
os.write(1, b"DENIED\\n" if ok else b"LEAK\\n")
os._exit(0)
"""
    result = _run_after_sandbox(
        script, str(secret), str(source_file), cache=str(cache))
    _skip_without_userns(result)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == b"DENIED"
    after = secret.stat()
    assert after.st_mode == before.st_mode
    assert after.st_mtime_ns == before.st_mtime_ns


def test_the_repository_usage_watchdog_counts_many_files(tmp_path):
    from trustsight.sandbox import git_client

    cache = tmp_path / "cache"
    repo = cache / "demo"
    repo.mkdir(parents=True)
    for index in range(5):
        (repo / f"f{index}").write_text("x")
    entries, _size = git_client._repo_usage(str(cache), "demo", 3)
    assert entries > 3


def test_the_repository_watchdog_does_not_follow_a_symlinked_repo(tmp_path):
    from trustsight.sandbox import git_client

    cache = tmp_path / "cache"
    cache.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "PKGBUILD").write_text("x")
    os.symlink(outside, cache / "demo")

    assert git_client._repo_usage(str(cache), "demo", 10) == (0, 0)
