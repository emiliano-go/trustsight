import shutil
from unittest.mock import patch, MagicMock

import pytest

import trustsight.discovery as _discovery_module

pytestmark = pytest.mark.skipif(
    not shutil.which("pacman"),
    reason="pacman not available (non-Arch system)",
)

# conftest's autouse fixture replaces ``discovery.get_aur_package_info`` with
# an empty answer for every test.  Tests of that function itself restore the
# real one, captured here at import time before any fixture has run.
_REAL_GET_AUR_PACKAGE_INFO = _discovery_module.get_aur_package_info


# --- _vercmp ---

@pytest.mark.parametrize("v1,v2,expected", [
    ("1.0", "2.0", -1),
    ("2.0", "1.0", 1),
    ("1.0", "1.0", 0),
    ("1.9", "1.10", -1),
    ("2:1.0", "1:2.0", 1),
    ("1.0-1", "1.0-2", -1),
    ("1.0.r3", "1.0", 1),
])
def test_vercmp(v1, v2, expected):
    from trustsight.discovery import _vercmp
    assert _vercmp(v1, v2) == expected


# --- get_installed_from_repo ---

@patch("trustsight.discovery.subprocess.run")
def test_get_installed_from_repo(mock_run):
    from trustsight.discovery import get_installed_from_repo

    mock_run.side_effect = [
        MagicMock(returncode=0, stdout="myrepo  pkg-a 1.0\nmyrepo  pkg-b 2.0-1\n"),
        MagicMock(returncode=0, stdout="pkg-a 1.0\npkg-b 2.0-1\nsome-other 3.0\n"),
    ]

    result = get_installed_from_repo("myrepo")
    assert result == [("pkg-a", "1.0"), ("pkg-b", "2.0-1")]
    # first call: pacman -Sl
    # "--" ends option parsing: a repo name is data, never a flag.
    assert mock_run.call_args_list[0][0][0][:4] == ["pacman", "-Sl", "--", "myrepo"]
    # second call: pacman -Q
    assert mock_run.call_args_list[1][0][0] == ["pacman", "-Q"]


@patch("trustsight.discovery.subprocess.run")
def test_get_installed_from_repo_nonzero_exit(mock_run):
    from trustsight.discovery import get_installed_from_repo

    # pacman -Sl fails → repo does not exist
    mock_run.return_value = MagicMock(returncode=1, stdout="")

    result = get_installed_from_repo("nonexistent")
    assert result == []


@patch("trustsight.discovery.subprocess.run")
def test_get_installed_from_repo_repo_empty(mock_run):
    from trustsight.discovery import get_installed_from_repo

    mock_run.return_value = MagicMock(returncode=0, stdout="")

    result = get_installed_from_repo("emptyrepo")
    assert result == []


# --- get_installed_foreign ---

@patch("trustsight.discovery.subprocess.run")
def test_get_installed_foreign(mock_run):
    from trustsight.discovery import get_installed_foreign

    mock_run.return_value = MagicMock(
        returncode=0,
        stdout="foreign-a 3.0\nforeign-b 4.5-2\n",
    )

    result = get_installed_foreign()
    assert result == [("foreign-a", "3.0"), ("foreign-b", "4.5-2")]
    mock_run.assert_called_once()
    args = mock_run.call_args[0][0]
    assert args == ["pacman", "-Qm"]


# --- get_local_repos_from_pacman_conf ---

@patch("trustsight.discovery.subprocess.run")
def test_get_local_repos_filters_official(mock_run):
    from trustsight.discovery import get_local_repos_from_pacman_conf

    mock_run.return_value = MagicMock(
        returncode=0,
        stdout="core\nextra\nmultilib\ntesting\nomarchy\nmy-custom\n",
    )

    result = get_local_repos_from_pacman_conf()
    assert result == ["omarchy", "my-custom"]


@patch("trustsight.discovery.subprocess.run")
def test_get_local_repos_no_custom(mock_run):
    from trustsight.discovery import get_local_repos_from_pacman_conf

    mock_run.return_value = MagicMock(
        returncode=0,
        stdout="core\nextra\nmultilib\n",
    )

    result = get_local_repos_from_pacman_conf()
    assert result == []


@patch("trustsight.discovery.subprocess.run")
def test_get_local_repos_pacman_conf_fails(mock_run):
    from trustsight.discovery import get_local_repos_from_pacman_conf

    mock_run.return_value = MagicMock(
        returncode=1,
        stdout="",
        stderr="error reading config",
    )

    with pytest.raises(RuntimeError, match="Failed to read pacman.conf"):
        get_local_repos_from_pacman_conf()


# --- find_outdated_from_list ---

@patch("trustsight.discovery.get_aur_package_info")
def test_find_outdated_from_list(mock_info):
    from trustsight.discovery import find_outdated_from_list

    mock_info.return_value = {
        "pkg-a": {"Name": "pkg-a", "Version": "2.0"},
        "pkg-b": {"Name": "pkg-b", "Version": "2.0"},
        "pkg-c": {"Name": "pkg-c", "Version": "3.0"},
    }

    pkgs = [
        ("pkg-a", "1.0"),
        ("pkg-b", "2.0"),
        ("pkg-c", "1.0"),
    ]

    result = find_outdated_from_list(pkgs)
    assert result == [
        {"name": "pkg-a", "current_version": "1.0", "latest_version": "2.0"},
        {"name": "pkg-c", "current_version": "1.0", "latest_version": "3.0"},
    ]


@patch("trustsight.discovery.get_aur_package_info")
def test_find_outdated_from_list_skips_non_aur(mock_info):
    from trustsight.discovery import find_outdated_from_list

    mock_info.return_value = {"pkg-a": {"Name": "pkg-a", "Version": "2.0"}}

    pkgs = [("pkg-a", "1.0"), ("not-on-aur", "1.0")]

    result = find_outdated_from_list(pkgs)
    assert len(result) == 1
    assert result[0]["name"] == "pkg-a"


@patch("trustsight.discovery.get_aur_latest_versions")
def test_find_outdated_from_list_empty_input(mock_latest):
    from trustsight.discovery import find_outdated_from_list

    result = find_outdated_from_list([])
    assert result == []
    mock_latest.assert_not_called()


# --- discover_packages ---

@patch("trustsight.discovery.get_installed_foreign")
@patch("trustsight.discovery.get_installed_from_repo")
@patch("trustsight.discovery.find_outdated_from_list")
def test_discover_packages_foreign_default(
    mock_outdated, mock_repo, mock_foreign
):
    from trustsight.discovery import discover_packages

    mock_foreign.return_value = [("foreign-a", "1.0")]
    mock_outdated.return_value = [
        {"name": "foreign-a", "current_version": "1.0", "latest_version": "2.0"},
    ]

    result = discover_packages()

    mock_foreign.assert_called_once()
    mock_repo.assert_not_called()
    assert len(result) == 1
    assert result[0]["name"] == "foreign-a"


@patch("trustsight.discovery.get_installed_foreign")
@patch("trustsight.discovery.get_installed_from_repo")
@patch("trustsight.discovery.get_repo_newest_versions")
@patch("trustsight.discovery.find_outdated_from_list")
def test_discover_packages_with_repos(
    mock_outdated, mock_newest, mock_repo, mock_foreign
):
    from trustsight.discovery import discover_packages

    mock_repo.side_effect = [
        [("repo-a-pkg", "1.0")],
        [("repo-b-pkg", "2.0")],
    ]
    mock_newest.side_effect = [
        {"repo-a-pkg": "2.0"},
        {"repo-b-pkg": "3.0"},
    ]

    result = discover_packages(
        repos=["myrepo-a", "myrepo-b"],
    )

    assert mock_repo.call_count == 2
    mock_repo.assert_any_call("myrepo-a")
    mock_repo.assert_any_call("myrepo-b")
    mock_foreign.assert_not_called()
    # Repo packages are compared locally; the AUR is never asked.
    mock_outdated.assert_not_called()
    assert len(result) == 2


@patch("trustsight.discovery.get_installed_foreign")
@patch("trustsight.discovery.get_installed_from_repo")
@patch("trustsight.discovery.get_repo_newest_versions")
@patch("trustsight.discovery.find_outdated_from_list")
def test_discover_packages_repo_plus_foreign(
    mock_outdated, mock_newest, mock_repo, mock_foreign
):
    from trustsight.discovery import discover_packages

    mock_repo.return_value = [("repo-pkg", "1.0")]
    mock_newest.return_value = {"repo-pkg": "2.0"}
    mock_foreign.return_value = [("foreign-pkg", "2.0")]
    mock_outdated.return_value = [
        {"name": "foreign-pkg", "current_version": "2.0", "latest_version": "3.0"},
    ]

    result = discover_packages(
        repos=["myrepo"],
        include_foreign=True,
    )

    mock_repo.assert_called_once_with("myrepo")
    mock_foreign.assert_called_once()
    # Only the foreign package reaches the AUR.
    args, _kwargs = mock_outdated.call_args
    assert args[0] == [("foreign-pkg", "2.0")]
    assert len(result) == 2


@patch("trustsight.discovery.get_installed_foreign")
@patch("trustsight.discovery.get_installed_from_repo")
@patch("trustsight.discovery.get_local_repos_from_pacman_conf")
@patch("trustsight.discovery.get_repo_newest_versions")
@patch("trustsight.discovery.find_outdated_from_list")
def test_discover_packages_all_repos(
    mock_outdated, mock_newest, mock_pacman_conf, mock_repo, mock_foreign
):
    from trustsight.discovery import discover_packages

    mock_pacman_conf.return_value = ["custom", "local-repo"]
    mock_repo.side_effect = [
        [("custom-pkg", "1.0")],
        [("local-pkg", "2.0")],
    ]
    mock_newest.side_effect = [
        {"custom-pkg": "2.0"},
        {"local-pkg": "2.0"},
    ]
    mock_foreign.return_value = []  # not included without --foreign

    result = discover_packages(
        all_repos=True,
    )

    mock_pacman_conf.assert_called_once()
    assert mock_repo.call_count == 2
    mock_repo.assert_any_call("custom")
    mock_repo.assert_any_call("local-repo")
    mock_foreign.assert_not_called()
    # Auto-detected repo names never reach the AUR.
    mock_outdated.assert_not_called()
    assert [e["name"] for e in result] == ["custom-pkg"]


@patch("trustsight.discovery.get_installed_foreign")
@patch("trustsight.discovery.get_installed_from_repo")
@patch("trustsight.discovery.get_local_repos_from_pacman_conf")
@patch("trustsight.discovery.get_repo_newest_versions")
@patch("trustsight.discovery.find_outdated_from_list")
def test_discover_packages_all_repos_plus_foreign(
    mock_outdated, mock_newest, mock_pacman_conf, mock_repo, mock_foreign
):
    from trustsight.discovery import discover_packages

    mock_pacman_conf.return_value = ["custom"]
    mock_repo.return_value = [("custom-pkg", "1.0")]
    mock_newest.return_value = {"custom-pkg": "2.0"}
    mock_foreign.return_value = [("foreign-pkg", "2.0")]
    mock_outdated.return_value = [
        {"name": "foreign-pkg", "current_version": "2.0", "latest_version": "3.0"},
    ]

    result = discover_packages(
        all_repos=True,
        include_foreign=True,
    )

    assert {e["name"] for e in result} == {"custom-pkg", "foreign-pkg"}


@patch("trustsight.discovery.get_installed_foreign")
@patch("trustsight.discovery.get_installed_from_repo")
@patch("trustsight.discovery.get_repo_newest_versions")
@patch("trustsight.discovery.find_outdated_from_list")
@patch("trustsight.discovery._repo_exists")
def test_discover_packages_empty_repo_warns(
    mock_exists, mock_outdated, mock_newest, mock_repo, mock_foreign
):
    from trustsight.discovery import discover_packages

    mock_repo.return_value = []
    mock_newest.return_value = {}
    mock_foreign.return_value = [("foreign-pkg", "1.0")]
    mock_outdated.return_value = [
        {"name": "foreign-pkg", "current_version": "1.0", "latest_version": "2.0"},
    ]

    # repo does not exist
    mock_exists.return_value = False

    warnings = []
    result = discover_packages(
        repos=["empty-repo"],
        include_foreign=True,
        _warn_func=lambda msg: warnings.append(msg),
    )

    assert len(warnings) == 1
    assert "does not exist" in warnings[0]
    assert "empty-repo" in warnings[0]
    assert len(result) == 1

    # repo exists but no packages installed from it
    mock_exists.return_value = True
    warnings.clear()
    result = discover_packages(
        repos=["empty-repo"],
        include_foreign=True,
        _warn_func=lambda msg: warnings.append(msg),
    )
    assert len(warnings) == 1
    assert "exists but no packages" in warnings[0]
    assert "empty-repo" in warnings[0]


@patch("trustsight.discovery.subprocess.run")
def test_vercmp_fallback_on_missing_binary(mock_run):
    from trustsight.discovery import _vercmp, _simple_vercmp

    mock_run.side_effect = FileNotFoundError("vercmp not found")

    result = _vercmp("1.0", "2.0")
    assert result == _simple_vercmp("1.0", "2.0")


@patch("trustsight.discovery.subprocess.run")
def test_get_installed_from_repo_special_chars(mock_run):
    from trustsight.discovery import get_installed_from_repo

    mock_run.side_effect = [
        MagicMock(returncode=0, stdout="my-custom_repo+  pkg-foo 1.0\n"),
        MagicMock(returncode=0, stdout="pkg-foo 1.0\nother-pkg 2.0\n"),
    ]

    result = get_installed_from_repo("my-custom_repo+")
    assert result == [("pkg-foo", "1.0")]
    # first call uses pacman -Sl with the special-char repo name
    assert mock_run.call_args_list[0][0][0][:4] == ["pacman", "-Sl", "--", "my-custom_repo+"]


def test_discover_packages_empty_repos_list():
    from trustsight.discovery import discover_packages

    result = discover_packages(repos=[])
    assert result == []


@patch("trustsight.discovery.get_installed_foreign")
@patch("trustsight.discovery.get_installed_from_repo")
@patch("trustsight.discovery.get_repo_newest_versions")
@patch("trustsight.discovery.find_outdated_from_list")
def test_discover_packages_deduplicates(
    mock_outdated, mock_newest, mock_repo, mock_foreign
):
    from trustsight.discovery import discover_packages

    mock_repo.return_value = [("shared-pkg", "1.0")]
    mock_newest.return_value = {"shared-pkg": "2.0"}
    mock_foreign.return_value = [("shared-pkg", "1.0")]
    mock_outdated.return_value = [
        {"name": "shared-pkg", "current_version": "1.0", "latest_version": "2.0"},
    ]

    result = discover_packages(
        repos=["repo-x"],
        include_foreign=True,
    )

    assert len(result) == 1
    assert result[0]["name"] == "shared-pkg"


# --- A4: the RPC response is byte-capped ---


def test_load_rpc_json_accepts_a_small_response():
    import io

    from trustsight.discovery import _load_rpc_json

    resp = io.BytesIO(b'{"resultcount": 0, "results": []}')
    assert _load_rpc_json(resp, limit=1024) == {"resultcount": 0, "results": []}


def test_load_rpc_json_rejects_an_oversized_response():
    import io

    from trustsight.discovery import _RpcResponseTooLarge, _load_rpc_json

    resp = io.BytesIO(b"[" + b"0," * 10_000 + b"0]")
    with pytest.raises(_RpcResponseTooLarge):
        _load_rpc_json(resp, limit=64)


def test_get_aur_package_info_degrades_on_oversized_rpc(monkeypatch):
    """An over-cap RPC reply is treated as a failed query, not buffered."""
    import io
    from contextlib import contextmanager

    import trustsight.db as db
    import trustsight.discovery as disc

    monkeypatch.setattr(disc, "_MAX_RPC_BYTES", 64)
    monkeypatch.setattr(db, "read_aur_cache", lambda names, ttl_minutes=60: {})
    monkeypatch.setattr(db, "write_aur_cache", lambda entries: None)

    @contextmanager
    def fake_urlopen(url, timeout=0):
        yield io.BytesIO(b'{"results": [' + b'{"Name": "x"},' * 1000 + b'{"Name": "y"}]}')

    monkeypatch.setattr(disc.urllib.request, "urlopen", fake_urlopen)
    # Nothing raises out; the oversized reply degrades to an empty result.
    assert disc.get_aur_package_info(["somepkg"]) == {}


@pytest.mark.parametrize("exc", [
    TimeoutError("timed out"),
    ConnectionResetError(104, "reset"),
])
def test_get_aur_package_info_degrades_on_a_dropped_connection(monkeypatch, exc):
    """A dropped RPC connection raises ``OSError`` (``TimeoutError``,
    ``ConnectionResetError``, ``RemoteDisconnected``), not ``URLError``, so
    it must be treated as a failed lookup rather than escaping as a
    traceback from ``inspect``."""
    import trustsight.db as db
    import trustsight.discovery as disc

    monkeypatch.setattr(db, "read_aur_cache", lambda names, ttl_minutes=60: {})
    monkeypatch.setattr(db, "write_aur_cache", lambda entries: None)

    def fake_urlopen(url, timeout=0):
        raise exc

    monkeypatch.setattr(disc.urllib.request, "urlopen", fake_urlopen)
    assert disc.get_aur_package_info(["somepkg"]) == {}


def test_get_aur_package_info_degrades_on_an_undecodable_body(monkeypatch):
    """A malformed body raises ``UnicodeDecodeError`` (a ``ValueError``,
    not a ``JSONDecodeError``) and must degrade the same way."""
    import io
    from contextlib import contextmanager

    import trustsight.db as db
    import trustsight.discovery as disc

    monkeypatch.setattr(db, "read_aur_cache", lambda names, ttl_minutes=60: {})
    monkeypatch.setattr(db, "write_aur_cache", lambda entries: None)

    @contextmanager
    def fake_urlopen(url, timeout=0):
        yield io.BytesIO(b"\xff\xfe not utf-8")

    monkeypatch.setattr(disc.urllib.request, "urlopen", fake_urlopen)
    assert disc.get_aur_package_info(["somepkg"]) == {}


# --- Retry-After is clamped and the RPC reply shape is validated ----------


def test_rpc_retry_after_clamps_a_negative_value():
    """``Retry-After: -5`` from a broken endpoint must not reach
    ``time.sleep`` as a negative delay, which raises ``ValueError``."""
    from types import SimpleNamespace

    from trustsight.discovery import _RPC_BACKOFF_MAX, _rpc_retry_after

    assert _rpc_retry_after(SimpleNamespace(headers={"Retry-After": "-5"})) == 0.0
    assert _rpc_retry_after(SimpleNamespace(headers={"Retry-After": "3"})) == 3.0
    assert (
        _rpc_retry_after(SimpleNamespace(headers={"Retry-After": "999"}))
        == _RPC_BACKOFF_MAX
    )
    assert _rpc_retry_after(SimpleNamespace(headers={"Retry-After": "soon"})) is None
    assert _rpc_retry_after(SimpleNamespace(headers=None)) is None


def test_get_aur_package_info_survives_a_negative_retry_after(monkeypatch):
    """The retry loop used to pass the negative header value to
    ``time.sleep`` and escape as a ValueError; now it is a failed lookup."""
    import io
    import urllib.error

    import trustsight.db as db
    import trustsight.discovery as disc

    monkeypatch.delenv("TRUSTSIGHT_OFFLINE")
    monkeypatch.setattr(disc, "get_aur_package_info", _REAL_GET_AUR_PACKAGE_INFO)
    monkeypatch.setattr(db, "read_aur_cache", lambda names, ttl_minutes=60: {})
    monkeypatch.setattr(db, "write_aur_cache", lambda entries: None)
    sleeps = []
    monkeypatch.setattr(disc.time, "sleep", sleeps.append)

    def fake_urlopen(url, timeout=0):
        raise urllib.error.HTTPError(
            disc.AUR_RPC_BASE, 429, "Too Many Requests",
            {"Retry-After": "-5"}, io.BytesIO(b""),
        )

    monkeypatch.setattr(disc.urllib.request, "urlopen", fake_urlopen)
    assert disc.get_aur_package_info(["somepkg"]) == {}
    assert sleeps and all(s >= 0 for s in sleeps)


@pytest.mark.parametrize("body", [
    b"[]",
    b'"error"',
    b'{"results": ["error"]}',
    b'{"results": [{"Version": "1.0"}]}',
])
def test_get_aur_package_info_degrades_on_a_wrong_shape_reply(monkeypatch, body):
    """JSON that parses but is not an RPC envelope used to escape as
    ``AttributeError``/``KeyError``/``TypeError``; it is a failed lookup."""
    import io
    from contextlib import contextmanager

    import trustsight.db as db
    import trustsight.discovery as disc

    monkeypatch.delenv("TRUSTSIGHT_OFFLINE")
    monkeypatch.setattr(disc, "get_aur_package_info", _REAL_GET_AUR_PACKAGE_INFO)
    monkeypatch.setattr(db, "read_aur_cache", lambda names, ttl_minutes=60: {})
    monkeypatch.setattr(db, "write_aur_cache", lambda entries: None)
    monkeypatch.setattr(disc.time, "sleep", lambda s: None)

    @contextmanager
    def fake_urlopen(url, timeout=0):
        yield io.BytesIO(body)

    monkeypatch.setattr(disc.urllib.request, "urlopen", fake_urlopen)
    assert disc.get_aur_package_info(["somepkg"]) == {}


# --- get_existing_aur_package_names: the authoritative answer prune needs -


def test_existing_names_confirms_what_the_rpc_returns(monkeypatch):
    """The answer is the subset the AUR confirmed; an absent name is
    authoritatively gone, which is exactly what prune prunes on."""
    import io
    from contextlib import contextmanager

    import trustsight.db as db
    import trustsight.discovery as disc

    monkeypatch.delenv("TRUSTSIGHT_OFFLINE")
    monkeypatch.setattr(db, "read_aur_cache", lambda names, ttl_minutes=60: {})
    monkeypatch.setattr(db, "write_aur_cache", lambda entries: None)
    monkeypatch.setattr(disc.time, "sleep", lambda s: None)

    @contextmanager
    def fake_urlopen(url, timeout=0):
        yield io.BytesIO(
            b'{"resultcount": 1, "results": [{"Name": "keep", "Version": "1.0"}]}'
        )

    monkeypatch.setattr(disc.urllib.request, "urlopen", fake_urlopen)
    assert disc.get_existing_aur_package_names(["keep", "gone"]) == {"keep"}


def test_existing_names_is_none_when_the_rpc_fails(monkeypatch):
    """A dropped connection is not an answer: prune must refuse to act."""
    import trustsight.db as db
    import trustsight.discovery as disc

    monkeypatch.delenv("TRUSTSIGHT_OFFLINE")
    monkeypatch.setattr(db, "read_aur_cache", lambda names, ttl_minutes=60: {})
    monkeypatch.setattr(db, "write_aur_cache", lambda entries: None)
    monkeypatch.setattr(disc.time, "sleep", lambda s: None)

    def fake_urlopen(url, timeout=0):
        raise ConnectionResetError(104, "reset")

    monkeypatch.setattr(disc.urllib.request, "urlopen", fake_urlopen)
    assert disc.get_existing_aur_package_names(["somepkg"]) is None


@pytest.mark.parametrize("body", [b"[]", b'"error"', b'{"results": ["error"]}'])
def test_existing_names_is_none_on_a_wrong_shape_reply(monkeypatch, body):
    """A reply that is not an RPC envelope is no answer either."""
    import io
    from contextlib import contextmanager

    import trustsight.db as db
    import trustsight.discovery as disc

    monkeypatch.delenv("TRUSTSIGHT_OFFLINE")
    monkeypatch.setattr(db, "read_aur_cache", lambda names, ttl_minutes=60: {})
    monkeypatch.setattr(db, "write_aur_cache", lambda entries: None)
    monkeypatch.setattr(disc.time, "sleep", lambda s: None)

    @contextmanager
    def fake_urlopen(url, timeout=0):
        yield io.BytesIO(body)

    monkeypatch.setattr(disc.urllib.request, "urlopen", fake_urlopen)
    assert disc.get_existing_aur_package_names(["somepkg"]) is None


def test_existing_names_counts_the_fresh_cache(monkeypatch):
    """Fresh cache entries count as existing; the RPC is only asked for
    the rest, and when the cache covers every name it is not asked at all."""
    import io
    from contextlib import contextmanager

    import trustsight.db as db
    import trustsight.discovery as disc

    monkeypatch.delenv("TRUSTSIGHT_OFFLINE")
    monkeypatch.setattr(db, "write_aur_cache", lambda entries: None)
    monkeypatch.setattr(disc.time, "sleep", lambda s: None)
    monkeypatch.setattr(db, "read_aur_cache", lambda names, ttl_minutes=60: {
        "keep": {"version": "1.0", "last_modified": None},
    })

    @contextmanager
    def fake_urlopen(url, timeout=0):
        yield io.BytesIO(
            b'{"resultcount": 1, "results": [{"Name": "other", "Version": "2.0"}]}'
        )

    monkeypatch.setattr(disc.urllib.request, "urlopen", fake_urlopen)
    assert disc.get_existing_aur_package_names(["keep", "other"]) == {"keep", "other"}

    # Every name fresh in the cache: the network stays off.
    def boom(url, timeout=0):
        raise AssertionError("the RPC must not run when the cache answers")

    monkeypatch.setattr(disc.urllib.request, "urlopen", boom)
    monkeypatch.setattr(db, "read_aur_cache", lambda names, ttl_minutes=60: {
        "keep": {"version": "1.0", "last_modified": None},
        "other": {"version": "2.0", "last_modified": None},
    })
    assert disc.get_existing_aur_package_names(["keep", "other"]) == {"keep", "other"}


def test_existing_names_offline_can_confirm_but_never_deny(monkeypatch):
    """Offline the fresh cache can still confirm a package exists, but a
    name missing from it can be neither confirmed nor denied: no answer."""
    import trustsight.db as db
    import trustsight.discovery as disc

    # TRUSTSIGHT_OFFLINE is set by the suite-wide fixture.
    monkeypatch.setattr(db, "read_aur_cache", lambda names, ttl_minutes=60: {
        "keep": {"version": "1.0", "last_modified": None},
    })
    assert disc.get_existing_aur_package_names(["keep"]) == {"keep"}
    assert disc.get_existing_aur_package_names(["keep", "gone"]) is None
