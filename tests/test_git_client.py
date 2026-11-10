"""The isolated git client: subprocess transport, isolation and refusal (A16).

These run the real worker process against a local fixture repository (no
network), so they cover the framed channel, the isolated launch, and the
"a dead worker is a refusal" contract.
"""

from __future__ import annotations


import pygit2
import pytest

from trustsight.sandbox import git_client, _spawn


@pytest.fixture
def cache(tmp_path):
    root = tmp_path / "repos"
    root.mkdir()
    repo = pygit2.init_repository(str(root / "demo"), bare=True)
    author = pygit2.Signature("Tester", "tester@example.com")
    blob = repo.create_blob(b"pkgver=7.7\n")
    builder = repo.TreeBuilder()
    builder.insert("PKGBUILD", blob, pygit2.GIT_FILEMODE_BLOB)
    repo.create_commit("refs/heads/master", author, author, "c",
                       builder.write(), [])
    return root


def test_head_and_file_at_round_trip(cache):
    session = git_client.GitSession()
    try:
        head = session.head("demo", str(cache))
        assert head
        text = session.file_at("demo", str(cache), head, "PKGBUILD", 4096)
        assert text == "pkgver=7.7\n"
    finally:
        session.close()


def test_an_unknown_member_is_refused_across_the_boundary(cache):
    session = git_client.GitSession()
    try:
        head = session.head("demo", str(cache))
        with pytest.raises(git_client.GitOpError):
            session.file_at("demo", str(cache), head, "../../etc/passwd", 4096)
    finally:
        session.close()


def test_a_closed_session_refuses(cache):
    session = git_client.GitSession()
    session.close()
    with pytest.raises(git_client.GitSandboxUnavailable):
        session.head("demo", str(cache))


def test_a_timed_out_request_closes_the_session(cache):
    session = git_client.GitSession()
    try:
        with pytest.raises(git_client.GitSandboxUnavailable):
            session.request("head", {"pkg": "demo", "cache_dir": str(cache)},
                            timeout=0.0001)
        assert session._closed, "a timed-out request left the worker alive"
    finally:
        session.close()


def test_diff_round_trip(cache):
    repo = pygit2.init_repository(str(cache / "d"))
    author = pygit2.Signature("Tester", "tester@example.com")

    def commit(text, parents):
        blob = repo.create_blob(text)
        builder = repo.TreeBuilder()
        builder.insert("PKGBUILD", blob, pygit2.GIT_FILEMODE_BLOB)
        return str(repo.create_commit("HEAD", author, author, "c",
                                      builder.write(), parents))

    old = commit(b"pkgver=1.0\n", [])
    new = commit(b"pkgver=2.0\n", [pygit2.Oid(hex=old)])
    session = git_client.GitSession()
    try:
        out = session.diff("d", str(cache), old, new, context_lines=3)
    finally:
        session.close()
    assert "pkgver=2.0" in out["unified"]
    assert out["summary"]["files_changed"] == ["PKGBUILD"]


def test_the_worker_launch_is_isolated():
    args = _spawn.launch_args("trustsight.sandbox.git_worker")
    assert "-I" in args
    assert "-s" not in args
    assert "git_worker" in args[-1]


def test_the_worker_ignores_an_inherited_pythonpath(tmp_path, cache, monkeypatch):
    guard = tmp_path / "guard"
    guard.mkdir()
    sentinel = tmp_path / "sentinel"
    (guard / "sitecustomize.py").write_text(
        "import pathlib\n"
        f"pathlib.Path({str(sentinel)!r}).write_text('pwned')\n"
    )
    monkeypatch.setenv("PYTHONPATH", str(guard))

    result = git_client.run_op("head", {"pkg": "demo", "cache_dir": str(cache)})
    assert result["head"]
    assert not sentinel.exists(), "the worker executed a PYTHONPATH sitecustomize"


def test_tree_files_round_trip(cache):
    repo = pygit2.init_repository(str(cache / "t"))
    author = pygit2.Signature("Tester", "tester@example.com")
    blob = repo.create_blob(b"pkgver=1.0\n")
    builder = repo.TreeBuilder()
    builder.insert("PKGBUILD", blob, pygit2.GIT_FILEMODE_BLOB)
    head = str(repo.create_commit("HEAD", author, author, "c",
                                  builder.write(), []))
    session = git_client.GitSession()
    try:
        files, complete = session.tree_files("t", str(cache), head)
    finally:
        session.close()
    assert complete is True
    assert dict(files)["PKGBUILD"] == b"pkgver=1.0\n"


def test_walk_round_trip(cache):
    repo = pygit2.init_repository(str(cache / "h"))
    author = pygit2.Signature("Tester", "tester@example.com")

    def commit(text, parents):
        blob = repo.create_blob(text)
        builder = repo.TreeBuilder()
        builder.insert("PKGBUILD", blob, pygit2.GIT_FILEMODE_BLOB)
        return str(repo.create_commit("HEAD", author, author, "c",
                                      builder.write(), parents))

    c1 = commit(b"v1\n", [])
    c2 = commit(b"v2\n", [pygit2.Oid(hex=c1)])
    session = git_client.GitSession()
    try:
        commits = session.walk("h", str(cache), c2)
        meta = session.commit_meta("h", str(cache), [c1, c2])
    finally:
        session.close()
    assert {c["id"] for c in commits} == {c1, c2}
    assert {m["id"] for m in meta} == {c1, c2}


def test_an_oversized_request_is_refused_before_it_is_written(cache, monkeypatch):
    """A4: the parent caps its own frame, rather than learning from EOF.

    The worker refuses an over-cap frame by exiting, which the parent sees as
    an opaque closed channel.  The reason is still known on this side.
    """
    session = git_client.GitSession()
    try:
        monkeypatch.setattr(git_client.protocol, "MAX_FRAME_BYTES", 32)
        with pytest.raises(git_client.GitSandboxUnavailable, match="exceeds"):
            session.request("head", {"pkg": "x" * 100, "cache_dir": str(cache)})
    finally:
        session.close()


def test_a_worker_past_its_cpu_allowance_is_retired(cache, monkeypatch):
    """A16/A14: retire below RLIMIT_CPU, so the failure has the right owner."""
    session = git_client.GitSession()
    try:
        monkeypatch.setattr(git_client, "_worker_cpu_seconds",
                            lambda _pid: 10**6)
        session.head("demo", str(cache))
        assert session._closed, "a worker past its CPU allowance stayed alive"
        with pytest.raises(git_client.GitSandboxUnavailable, match="retired"):
            session.head("demo", str(cache))
    finally:
        session.close()


def test_a_worker_that_exits_at_startup_is_a_refusal(monkeypatch):
    import io
    from types import SimpleNamespace

    session = object.__new__(git_client.GitSession)
    session.proc = SimpleNamespace(
        poll=lambda: 3, stdin=io.BytesIO(), stdout=io.BytesIO()
    )
    session._closed = False
    session._retired = ""
    monkeypatch.setattr(session, "close", lambda: None)

    with pytest.raises(
        git_client.GitSandboxUnavailable, match="exited during startup"
    ):
        session.request("head", {"pkg": "demo", "cache_dir": "/tmp"})


def test_run_op_refuses_the_unverified_fetch_path():
    with pytest.raises(ValueError, match="clone_or_fetch"):
        git_client.run_op("open_fetch", {"pkg": "demo", "cache_dir": "/tmp"})
