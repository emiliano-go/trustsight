"""The isolated git worker's clone/fetch and projection logic (A16).

These exercise ``git_worker._open_fetch`` and friends directly, in-process,
with libgit2's clone/fetch calls stubbed the way the old fetcher tests did.
The subprocess transport and isolation are covered by ``test_git_client.py``.
"""

from __future__ import annotations

import base64
import time

import pygit2
import pytest

from trustsight.sandbox import git_project, git_worker as gw


@pytest.fixture
def cache(tmp_path, monkeypatch):
    root = tmp_path / "repos"
    root.mkdir()
    return root


@pytest.fixture
def repo(cache):
    """A cached clone standing in for an AUR checkout."""
    path = cache / "demo"
    created = pygit2.init_repository(str(path))
    author = pygit2.Signature("Tester", "tester@example.com")
    blob = created.create_blob(b"pkgver=1.0\n")
    builder = created.TreeBuilder()
    builder.insert("PKGBUILD", blob, pygit2.GIT_FILEMODE_BLOB)
    created.create_commit("HEAD", author, author, "initial", builder.write(), [])
    created.remotes.create("origin", "https://aur.archlinux.org/demo.git")
    return created


def _payload(cache, upstream_mtime=None, offline=False):
    return {
        "pkg": "demo", "cache_dir": str(cache),
        "upstream_mtime": upstream_mtime, "offline": offline,
        "connect_timeout": 5, "transfer_timeout": 5,
    }


def _head_time(repo) -> int:
    return int(repo[gw._head_commit_id(repo)].commit_time)


def test_open_fetch_clones_the_aur_host(tmp_path, cache, monkeypatch):
    source = tmp_path / "source"
    src = pygit2.init_repository(str(source))
    author = pygit2.Signature("Tester", "tester@example.com")
    blob = src.create_blob(b"pkgver=1.0\n")
    builder = src.TreeBuilder()
    builder.insert("PKGBUILD", blob, pygit2.GIT_FILEMODE_BLOB)
    src.create_commit("HEAD", author, author, "initial", builder.write(), [])

    cloned: list[str] = []
    real_clone = pygit2.clone_repository

    def fake_clone(url, dest, **kwargs):
        cloned.append(url)
        return real_clone(str(source), dest, bare=kwargs.get("bare", False))

    monkeypatch.setattr(gw.pygit2, "clone_repository", fake_clone)
    result = gw._open_fetch(_payload(cache))
    assert cloned == ["https://aur.archlinux.org/demo.git"]
    assert result["fetched"] is True
    assert result["head"]


def test_a_future_dated_commit_cannot_suppress_fetches(repo, cache, monkeypatch):
    author = pygit2.Signature(
        "Tester", "tester@example.com", int(time.time()) + 10 * 365 * 86400, 0
    )
    blob = repo.create_blob(b"pkgver=2.0\n")
    builder = repo.TreeBuilder()
    builder.insert("PKGBUILD", blob, pygit2.GIT_FILEMODE_BLOB)
    repo.create_commit("HEAD", author, author, "future", builder.write(),
                       [repo.head.peel().id])
    assert _head_time(repo) > time.time()

    gw._record_fetch(repo)
    calls = []
    monkeypatch.setattr(pygit2.Remote, "fetch",
                        lambda self, *a, **k: calls.append(1))
    gw._open_fetch(_payload(cache, int(time.time()) + 5))
    assert calls, "future-dated commit suppressed a needed fetch"


def test_an_empty_clone_is_rebuilt(tmp_path, cache, monkeypatch):
    pygit2.init_repository(str(cache / "demo"))  # unborn HEAD, no refs
    source = tmp_path / "source"
    src = pygit2.init_repository(str(source))
    author = pygit2.Signature("Tester", "tester@example.com")
    blob = src.create_blob(b"pkgver=1.0\n")
    builder = src.TreeBuilder()
    builder.insert("PKGBUILD", blob, pygit2.GIT_FILEMODE_BLOB)
    src.create_commit("HEAD", author, author, "initial", builder.write(), [])

    calls = []
    real_clone = pygit2.clone_repository

    def fake_clone(url, dest, **kwargs):
        calls.append(url)
        return real_clone(str(source), dest, bare=kwargs.get("bare", False))

    monkeypatch.setattr(gw.pygit2, "clone_repository", fake_clone)
    result = gw._open_fetch(_payload(cache))
    assert calls, "the empty clone was not rebuilt"
    assert result["head"]


def test_skips_the_network_when_current(repo, cache, monkeypatch):
    fetched = gw._record_fetch(repo)

    def explode(*args, **kwargs):
        raise AssertionError("fetch attempted despite an up-to-date clone")

    monkeypatch.setattr(pygit2.Remote, "fetch", explode)
    result = gw._open_fetch(_payload(cache, fetched))
    assert result["fetched"] is False


def test_still_fetches_when_upstream_is_newer(repo, cache, monkeypatch):
    fetched = gw._record_fetch(repo)
    calls = []
    monkeypatch.setattr(pygit2.Remote, "fetch",
                        lambda self, *a, **k: calls.append(1))
    gw._open_fetch(_payload(cache, fetched + 3600))
    assert calls, "expected a fetch for a clone behind upstream"


def test_a_successful_fetch_records_the_marker(repo, cache, monkeypatch):
    monkeypatch.setattr(pygit2.Remote, "fetch", lambda self, *a, **k: None)
    gw._open_fetch(_payload(cache))
    assert gw._last_fetch_time(repo) is not None


def test_a_failed_fetch_keeps_the_cached_clone(repo, cache, monkeypatch):
    path = cache / "demo"

    def explode(self, *args, **kwargs):
        raise pygit2.GitError("connection reset")

    monkeypatch.setattr(pygit2.Remote, "fetch", explode)
    with pytest.raises(gw._TransferAborted) as caught:
        gw._open_fetch(_payload(cache))
    assert caught.value.received_bytes == 0
    assert path.exists(), "a failed fetch deleted a usable clone"


def test_an_unreadable_clone_is_rebuilt(repo, cache, monkeypatch):
    path = cache / "demo"
    cloned = []

    def fake_clone(url, dest, **kwargs):
        cloned.append(url)
        return pygit2.init_repository(dest, bare=kwargs.get("bare", False))

    import shutil
    shutil.rmtree(path / ".git")
    monkeypatch.setattr(gw.pygit2, "clone_repository", fake_clone)
    gw._open_fetch(_payload(cache))
    assert cloned == ["https://aur.archlinux.org/demo.git"]


def test_offline_uses_the_cache_without_fetching(repo, cache, monkeypatch):
    fetched = gw._record_fetch(repo)

    def explode(*args, **kwargs):
        raise AssertionError("fetched while offline")

    monkeypatch.setattr(pygit2.Remote, "fetch", explode)
    result = gw._open_fetch(_payload(cache, fetched + 3600, offline=True))
    assert result["fetched"] is False


def test_offline_refuses_a_new_clone(cache):
    with pytest.raises(gw._OpError, match="TRUSTSIGHT_OFFLINE"):
        gw._open_fetch(_payload(cache, offline=True))


def test_an_unknown_member_is_refused():
    with pytest.raises(gw._OpError, match="refuses unknown member"):
        gw._file_at({"pkg": "demo", "cache_dir": "/tmp", "oid": "",
                     "name": "../../etc/passwd", "max_bytes": 10})


def test_a_path_outside_the_cache_is_refused():
    with pytest.raises(gw._OpError):
        gw._contained_repo_path("/tmp/cache", "../escape")


def test_diff_projects_a_metadata_change(tmp_path, cache):
    repo = pygit2.init_repository(str(cache / "diffdemo"))
    author = pygit2.Signature("Tester", "tester@example.com")

    def commit(text, parents):
        blob = repo.create_blob(text)
        builder = repo.TreeBuilder()
        builder.insert("PKGBUILD", blob, pygit2.GIT_FILEMODE_BLOB)
        return str(repo.create_commit("HEAD", author, author, "c",
                                      builder.write(), parents))

    old = commit(b"pkgver=1.0\n", [])
    new = commit(b"pkgver=2.0\n", [pygit2.Oid(hex=old)])
    out = gw._diff({"pkg": "diffdemo", "cache_dir": str(cache),
                    "old": old, "new": new, "context_lines": 3,
                    "max_bytes": None})
    assert "pkgver=2.0" in out["unified"]
    assert out["summary"]["files_changed"] == ["PKGBUILD"]
    assert out["truncated"] is False


def test_diff_refuses_an_invalid_commit_id(cache):
    with pytest.raises(gw._OpError, match="invalid commit id"):
        gw._diff({"pkg": "d", "cache_dir": str(cache), "old": "not-an-oid",
                  "new": "", "context_lines": 3, "max_bytes": None})


def _commit_files(repo, files, parents):
    builder = repo.TreeBuilder()
    for name, data in files.items():
        builder.insert(name, repo.create_blob(data), pygit2.GIT_FILEMODE_BLOB)
    author = pygit2.Signature("Tester", "tester@example.com")
    return str(repo.create_commit("HEAD", author, author, "c",
                                  builder.write(), parents))


def test_tree_files_projects_blob_heads(cache):
    repo = pygit2.init_repository(str(cache / "tree"))
    oid = _commit_files(repo, {"PKGBUILD": b"pkgver=1.0\n",
                               "helper.sh": b"echo hi\n"}, [])
    result = gw._tree_files({"pkg": "tree", "cache_dir": str(cache), "oid": oid})
    assert result["complete"] is True
    by = {name: base64.b64decode(data) for name, data in result["files"]}
    assert set(by) == {"PKGBUILD", "helper.sh"}
    assert b"pkgver=1.0" in by["PKGBUILD"]


def test_opaque_changed_names_a_replaced_binary(cache):
    repo = pygit2.init_repository(str(cache / "opq"))
    old = _commit_files(repo, {"PKGBUILD": b"pkgver=1.0\n", "blob.bin": b"A"}, [])
    new = _commit_files(repo, {"PKGBUILD": b"pkgver=1.0\n", "blob.bin": b"B"},
                        [pygit2.Oid(hex=old)])
    names = gw._opaque_changed({"pkg": "opq", "cache_dir": str(cache),
                                "old": old, "new": new})["names"]
    assert names == ["blob.bin"]


def test_companion_hunks_emit_a_named_file(cache):
    repo = pygit2.init_repository(str(cache / "comp"))
    oid = _commit_files(repo, {
        "PKGBUILD": b"pkgname=x\nsource=(\"helper.sh\")\n",
        "helper.sh": b"echo hi\n",
    }, [])
    out = gw._companion_hunks({"pkg": "comp", "cache_dir": str(cache),
                               "oid": oid, "max_bytes": None})
    assert "helper.sh" in out["text"]
    assert "echo hi" in out["text"]


def test_companion_hunks_carry_the_baseline(cache):
    repo = pygit2.init_repository(str(cache / "comp-base"))
    old = _commit_files(repo, {
        "PKGBUILD": b"pkgname=x\nsource=(\"helper.sh\")\n",
        "helper.sh": b"trap 'rm x' EXIT\n",
    }, [])
    new = _commit_files(repo, {
        "PKGBUILD": b"pkgname=x\npkgver=2\nsource=(\"helper.sh\")\n",
        "helper.sh": b"trap 'rm x' EXIT\n",
    }, [pygit2.Oid(hex=old)])
    out = gw._companion_hunks({
        "pkg": "comp-base", "cache_dir": str(cache), "oid": new,
        "baseline": old, "max_bytes": None,
    })
    assert out["text"] == ""
    assert out["truncated"] is False


def test_tree_files_reports_incomplete_when_capped(cache, monkeypatch):
    repo = pygit2.init_repository(str(cache / "many"))
    oid = _commit_files(repo, {f"f{i}": b"x\n" for i in range(3)}, [])
    monkeypatch.setattr(gw, "GIT_TREE_MAX_ENTRIES", 2)
    result = gw._tree_files({"pkg": "many", "cache_dir": str(cache), "oid": oid})
    assert result["complete"] is False
    assert len(result["files"]) == 2


def test_the_tree_walk_stops_at_the_entry_cap(cache, monkeypatch):
    """A14: the entry cap bounds the walk, not just the returned list.

    The cap used to be applied after `collect_tree_files` had walked the
    whole tree, so a repository of millions of tiny blobs built the entire
    list before the worker truncated it.  Blobs here are large enough to be
    streamed, and `BlobIO` is a canary: a read past the cap proves the walk
    did not stop.
    """
    repo = pygit2.init_repository(str(cache / "cap"), bare=True)
    builder = repo.TreeBuilder()
    for index in range(3):
        builder.insert(f"f{index}", repo.create_blob(b"x" * (600 * 1024)),
                       pygit2.GIT_FILEMODE_BLOB)
    sig = pygit2.Signature("t", "t@example.invalid")
    oid = str(repo.create_commit("refs/heads/master", sig, sig, "c",
                                 builder.write(), []))
    reads = []

    class _Canary:
        def __init__(self, *_a, **_k):
            reads.append(True)
            raise RuntimeError("read past the cap")

    monkeypatch.setattr(git_project.pygit2, "BlobIO", _Canary)
    files, complete = git_project.collect_tree_files(repo, oid, max_entries=2)
    assert len(reads) == 2, "the walk read past its entry cap"
    assert len(files) == 0
    assert complete is False


def test_walk_and_commit_meta(cache):
    repo = pygit2.init_repository(str(cache / "hist"))
    c1 = _commit_files(repo, {"PKGBUILD": b"v1\n"}, [])
    c2 = _commit_files(repo, {"PKGBUILD": b"v2\n"}, [pygit2.Oid(hex=c1)])
    c3 = _commit_files(repo, {"PKGBUILD": b"v3\n"}, [pygit2.Oid(hex=c2)])

    commits = gw._walk({"pkg": "hist", "cache_dir": str(cache), "head": c3,
                        "limit": None})["commits"]
    assert {c["id"] for c in commits} == {c1, c2, c3}
    assert next(c for c in commits if c["id"] == c1)["parents"] == []

    meta = gw._commit_meta({"pkg": "hist", "cache_dir": str(cache),
                            "oids": [c1, c3]})["commits"]
    assert {m["id"] for m in meta} == {c1, c3}


def test_merge_parents_are_commit_ids_not_objects(cache):
    repo = pygit2.init_repository(str(cache / "m"))
    c1 = _commit_files(repo, {"PKGBUILD": b"v1\n"}, [])
    c2 = _commit_files(repo, {"PKGBUILD": b"v2\n"}, [pygit2.Oid(hex=c1)])
    tip = _commit_files(repo, {"PKGBUILD": b"v3\n"}, [pygit2.Oid(hex=c2)])
    merge = _commit_files(repo, {"PKGBUILD": b"m\n"},
                          [pygit2.Oid(hex=tip), pygit2.Oid(hex=c1)])
    rec = next(c for c in gw._walk({"pkg": "m", "cache_dir": str(cache),
                                    "head": merge, "limit": None})["commits"]
               if c["id"] == merge)
    assert rec["parents"] == [tip, c1]
    assert all(len(p) == 40 for p in rec["parents"])


def test_walk_treats_a_nonpositive_limit_as_empty(cache):
    repo = pygit2.init_repository(str(cache / "lim"))
    oid = _commit_files(repo, {"PKGBUILD": b"v\n"}, [])
    for limit in (0, -5):
        assert gw._walk({"pkg": "lim", "cache_dir": str(cache),
                         "head": oid, "limit": limit})["commits"] == []


def test_walk_refuses_an_uncoercible_limit(cache):
    repo = pygit2.init_repository(str(cache / "wl"))
    oid = _commit_files(repo, {"PKGBUILD": b"v\n"}, [])
    with pytest.raises(gw._OpError, match="invalid walk limit"):
        gw._walk({"pkg": "wl", "cache_dir": str(cache),
                  "head": oid, "limit": "abc"})


def test_file_at_refuses_a_non_string_oid(cache):
    repo = pygit2.init_repository(str(cache / "fa"))
    _commit_files(repo, {"PKGBUILD": b"v\n"}, [])
    with pytest.raises(gw._OpError, match="invalid commit id"):
        gw._file_at({"pkg": "fa", "cache_dir": str(cache), "oid": 123,
                     "name": "PKGBUILD"})


def test_diff_refuses_a_missing_new_commit(cache):
    repo = pygit2.init_repository(str(cache / "dn"))
    _commit_files(repo, {"PKGBUILD": b"v\n"}, [])
    with pytest.raises(gw._OpError, match="missing new commit"):
        gw._diff({"pkg": "dn", "cache_dir": str(cache), "old": "",
                  "new": "", "context_lines": 3, "max_bytes": None})


def test_infinity_and_nan_arguments_do_not_leak_overflows(cache):
    repo = pygit2.init_repository(str(cache / "inf"))
    oid = _commit_files(repo, {"PKGBUILD": b"v\n"}, [])
    inf, nan = float("inf"), float("nan")
    with pytest.raises(gw._OpError, match="invalid walk limit"):
        gw._walk({"pkg": "inf", "cache_dir": str(cache), "head": oid, "limit": inf})
    with pytest.raises(gw._OpError, match="invalid walk limit"):
        gw._walk({"pkg": "inf", "cache_dir": str(cache), "head": oid, "limit": nan})
    # Nonsensical diff/file arguments fall back to their defaults.
    assert "unified" in gw._diff({"pkg": "inf", "cache_dir": str(cache), "old": "",
                                  "new": oid, "context_lines": inf, "max_bytes": inf})
    assert gw._file_at({"pkg": "inf", "cache_dir": str(cache), "oid": oid,
                        "name": "PKGBUILD", "max_bytes": inf})["text"] == "v\n"


def test_an_oversized_response_is_refused_not_framed(monkeypatch):
    monkeypatch.setattr(gw.protocol, "MAX_RESPONSE_BYTES", 32)
    small = gw._encode_response({"result": "ok"})
    assert b'"result"' in small
    huge = gw._encode_response({"result": "x" * 1000})
    assert b"exceeds" in huge and b"xxxx" not in huge


def test_a_surrogate_in_a_response_is_sanitised_not_raised():
    """A path or message git stores as invalid UTF-8 must not kill the loop.

    `json.dumps(..., ensure_ascii=False).encode("utf-8")` raises on a lone
    surrogate, and the encoder sits outside the handler that turns a defect
    into an error frame.  The encoded value is what travels.
    """
    payload = gw._encode_response({"result": "a\udcffb"})
    assert b"\\udcff" not in payload
    assert b"?" in payload


def test_read_blob_head_refuses_an_unknown_declared_size():
    from trustsight.sandbox import git_project as gp

    class _Blob:
        def __init__(self, size):
            self.size = size

        @property
        def data(self):
            return b"x" * 20

    for size in (None, -1, True, "x"):
        assert gp.read_blob_head(_Blob(size), 5) is None


def test_offline_is_only_the_boolean_true(tmp_path, cache, monkeypatch):
    source = tmp_path / "src"
    src = pygit2.init_repository(str(source))
    author = pygit2.Signature("Tester", "tester@example.com")
    blob = src.create_blob(b"pkgver=1.0\n")
    builder = src.TreeBuilder()
    builder.insert("PKGBUILD", blob, pygit2.GIT_FILEMODE_BLOB)
    src.create_commit("HEAD", author, author, "c", builder.write(), [])
    real = pygit2.clone_repository
    monkeypatch.setattr(gw.pygit2, "clone_repository",
                        lambda url, dest, **kw: real(str(source), dest, bare=kw.get("bare", False)))
    # offline=False (a bool) and offline="false" (a string) must both clone a
    # missing cache; only `True` refuses.
    for value in (False, "false"):
        result = gw._open_fetch({"pkg": "new", "cache_dir": str(cache),
                                 "upstream_mtime": None, "offline": value,
                                 "connect_timeout": 5, "transfer_timeout": 5})
        assert result["fetched"] is True
        import shutil
        shutil.rmtree(cache / "new", ignore_errors=True)
    with pytest.raises(gw._OpError, match="TRUSTSIGHT_OFFLINE"):
        gw._open_fetch({"pkg": "new", "cache_dir": str(cache),
                        "upstream_mtime": None, "offline": True,
                        "connect_timeout": 5, "transfer_timeout": 5})


def test_commit_meta_skips_non_commit_objects(cache):
    repo = pygit2.init_repository(str(cache / "obj"))
    commit = _commit_files(repo, {"PKGBUILD": b"v\n"}, [])
    blob = str(repo.create_blob(b"x"))
    out = gw._commit_meta({"pkg": "obj", "cache_dir": str(cache),
                           "oids": [blob, commit]})["commits"]
    assert [c["id"] for c in out] == [commit]


def test_a_missing_repository_is_refused_cleanly(cache):
    with pytest.raises(gw._OpError, match="repository unavailable"):
        gw._walk({"pkg": "nope", "cache_dir": str(cache), "head": "0" * 40,
                  "limit": None})


def test_commit_meta_refuses_too_many_ids(cache):
    with pytest.raises(gw._OpError, match="too many"):
        gw._commit_meta({"pkg": "hist", "cache_dir": str(cache),
                         "oids": ["0" * 40] * 65})


@pytest.mark.parametrize("url,allowed", [
    ("https://aur.archlinux.org/demo.git", True),
    ("https://aur.archlinux.org:443/demo.git", True),
    ("https://AUR.archlinux.org/demo.git", True),
    ("ssh://git@aur.archlinux.org/demo.git", False),
    ("git@aur.archlinux.org:demo.git", False),
    ("http://aur.archlinux.org/demo.git", False),
    ("https://aur.archlinux.org.evil.example/demo.git", False),
    ("https://aur.archlinux.org:22/demo.git", False),
    ("https://user@aur.archlinux.org/demo.git", False),
    ("file:///etc/passwd", False),
    ("", False),
])
def test_only_https_aur_remotes_are_accepted(url, allowed):
    assert gw._is_safe_aur_url(url) is allowed


def test_open_fetch_refuses_a_cached_ssh_remote(cache, repo):
    """CVE-2026-5917: a shell-backed remote is never a fetch target."""
    repo.remotes.set_url("origin", "ssh://git@evil.example/x.git")
    with pytest.raises(gw._OpError, match="HTTPS"):
        gw._open_fetch({
            "pkg": "demo", "cache_dir": str(cache),
            "upstream_mtime": int(time.time()) + 3600,
        })
