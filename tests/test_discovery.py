import shutil
from unittest.mock import patch, MagicMock

import pytest

pytestmark = pytest.mark.skipif(
    not shutil.which("pacman"),
    reason="pacman not available (non-Arch system)",
)


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
@patch("trustsight.discovery.find_outdated_from_list")
def test_discover_packages_with_repos(
    mock_outdated, mock_repo, mock_foreign
):
    from trustsight.discovery import discover_packages

    mock_repo.side_effect = [
        [("repo-a-pkg", "1.0")],
        [("repo-b-pkg", "2.0")],
    ]
    mock_outdated.return_value = [
        {"name": "repo-a-pkg", "current_version": "1.0", "latest_version": "2.0"},
        {"name": "repo-b-pkg", "current_version": "2.0", "latest_version": "3.0"},
    ]

    result = discover_packages(
        repos=["myrepo-a", "myrepo-b"],
    )

    assert mock_repo.call_count == 2
    mock_repo.assert_any_call("myrepo-a")
    mock_repo.assert_any_call("myrepo-b")
    mock_foreign.assert_not_called()
    assert len(result) == 2


@patch("trustsight.discovery.get_installed_foreign")
@patch("trustsight.discovery.get_installed_from_repo")
@patch("trustsight.discovery.find_outdated_from_list")
def test_discover_packages_repo_plus_foreign(
    mock_outdated, mock_repo, mock_foreign
):
    from trustsight.discovery import discover_packages

    mock_repo.return_value = [("repo-pkg", "1.0")]
    mock_foreign.return_value = [("foreign-pkg", "2.0")]
    mock_outdated.return_value = [
        {"name": "repo-pkg", "current_version": "1.0", "latest_version": "2.0"},
        {"name": "foreign-pkg", "current_version": "2.0", "latest_version": "3.0"},
    ]

    result = discover_packages(
        repos=["myrepo"],
        include_foreign=True,
    )

    mock_repo.assert_called_once_with("myrepo")
    mock_foreign.assert_called_once()
    assert len(result) == 2


@patch("trustsight.discovery.get_installed_foreign")
@patch("trustsight.discovery.get_installed_from_repo")
@patch("trustsight.discovery.get_local_repos_from_pacman_conf")
@patch("trustsight.discovery.find_outdated_from_list")
def test_discover_packages_all_repos(
    mock_outdated, mock_pacman_conf, mock_repo, mock_foreign
):
    from trustsight.discovery import discover_packages

    mock_pacman_conf.return_value = ["custom", "local-repo"]
    mock_repo.side_effect = [
        [("custom-pkg", "1.0")],
        [("local-pkg", "2.0")],
    ]
    mock_outdated.return_value = [
        {"name": "custom-pkg", "current_version": "1.0", "latest_version": "2.0"},
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
    assert len(result) == 1


@patch("trustsight.discovery.get_installed_foreign")
@patch("trustsight.discovery.get_installed_from_repo")
@patch("trustsight.discovery.get_local_repos_from_pacman_conf")
@patch("trustsight.discovery.find_outdated_from_list")
def test_discover_packages_all_repos_plus_foreign(
    mock_outdated, mock_pacman_conf, mock_repo, mock_foreign
):
    from trustsight.discovery import discover_packages

    mock_pacman_conf.return_value = ["custom"]
    mock_repo.return_value = [("custom-pkg", "1.0")]
    mock_foreign.return_value = [("foreign-pkg", "2.0")]
    mock_outdated.return_value = [
        {"name": "custom-pkg", "current_version": "1.0", "latest_version": "2.0"},
        {"name": "foreign-pkg", "current_version": "2.0", "latest_version": "3.0"},
    ]

    result = discover_packages(
        all_repos=True,
        include_foreign=True,
    )

    assert len(result) == 2


@patch("trustsight.discovery.get_installed_foreign")
@patch("trustsight.discovery.get_installed_from_repo")
@patch("trustsight.discovery.find_outdated_from_list")
@patch("trustsight.discovery._repo_exists")
def test_discover_packages_empty_repo_warns(
    mock_exists, mock_outdated, mock_repo, mock_foreign
):
    from trustsight.discovery import discover_packages

    mock_repo.return_value = []
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
@patch("trustsight.discovery.find_outdated_from_list")
def test_discover_packages_deduplicates(
    mock_outdated, mock_repo, mock_foreign
):
    from trustsight.discovery import discover_packages

    mock_repo.return_value = [("shared-pkg", "1.0")]
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
