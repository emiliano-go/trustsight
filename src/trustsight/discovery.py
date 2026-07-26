import json
import subprocess
import urllib.parse
import urllib.request
from typing import Optional

AUR_RPC_BASE = "https://aur.archlinux.org/rpc"

_OFFICIAL_REPOS = frozenset({
    "core", "extra", "community", "multilib",
    "testing", "core-testing", "extra-testing",
    "community-testing", "multilib-testing",
    "gnome-unstable", "kde-unstable",
})


def _simple_vercmp(v1: str, v2: str) -> int:
    import re
    def _split(v: str):
        return [int(x) if x.isdigit() else x for x in re.split(r"(\d+)", v)]
    p1, p2 = _split(v1), _split(v2)
    for a, b in zip(p1, p2):
        if a != b:
            if isinstance(a, int) and isinstance(b, int):
                return -1 if a < b else 1
            sa, sb = str(a), str(b)
            return -1 if sa < sb else 1
    return -1 if len(p1) < len(p2) else (1 if len(p1) > len(p2) else 0)


def _vercmp(v1: str, v2: str) -> int:
    import logging
    try:
        result = subprocess.run(
            ["vercmp", v1, v2], capture_output=True, text=True, check=False
        )
        return int(result.stdout.strip())
    except FileNotFoundError:
        logging.warning("vercmp not found; falling back to string comparison")
        return _simple_vercmp(v1, v2)
    except (ValueError, AttributeError):
        return 0


def get_installed_aur_packages() -> dict[str, str]:
    result = subprocess.run(
        ["pacman", "-Qm"], capture_output=True, text=True, check=False
    )
    packages = {}
    for line in result.stdout.strip().splitlines():
        if not line:
            continue
        parts = line.split()
        if len(parts) >= 2:
            name, version = parts[0], parts[1]
            packages[name] = version
    return packages


def get_aur_latest_versions(pkg_names: list[str]) -> dict[str, str]:
    if not pkg_names:
        return {}
    params = [("v", "5"), ("type", "info")]
    params.extend(("arg[]", name) for name in pkg_names)
    url = f"{AUR_RPC_BASE}?{urllib.parse.urlencode(params)}"
    try:
        with urllib.request.urlopen(url, timeout=30) as resp:
            data = json.load(resp)
            return {r["Name"]: r["Version"] for r in data.get("results", [])}
    except (urllib.error.URLError, json.JSONDecodeError):
        return {}


def find_outdated_packages(
    installed: dict[str, str], latest: dict[str, str]
) -> dict[str, tuple[str, str]]:
    outdated = {}
    for name, installed_ver in installed.items():
        latest_ver = latest.get(name)
        if latest_ver and installed_ver != latest_ver:
            outdated[name] = (installed_ver, latest_ver)
    return outdated


def fetch_package_info(name: str) -> Optional[dict]:
    # Encoded, not interpolated: an unescaped "&" or "#" in the name would
    # otherwise inject or truncate RPC query parameters.
    query = urllib.parse.urlencode([("v", "5"), ("type", "info"), ("arg[]", name)])
    url = f"{AUR_RPC_BASE}?{query}"
    try:
        with urllib.request.urlopen(url, timeout=10) as resp:
            data = json.load(resp)
            if data["resultcount"] > 0:
                return data["results"][0]
    except (urllib.error.URLError, json.JSONDecodeError):
        pass
    return None


def get_installed_from_repo(repo: str) -> list[tuple[str, str]]:
    result = subprocess.run(
        ["pacman", "-Q", "--repo", repo],
        capture_output=True, text=True, check=False,
    )
    if result.returncode != 0:
        return []
    packages = []
    for line in result.stdout.strip().splitlines():
        if not line:
            continue
        parts = line.split()
        if len(parts) >= 2:
            packages.append((parts[0], parts[1]))
    return packages


def get_installed_foreign() -> list[tuple[str, str]]:
    result = subprocess.run(
        ["pacman", "-Qm"], capture_output=True, text=True, check=False
    )
    packages = []
    for line in result.stdout.strip().splitlines():
        if not line:
            continue
        parts = line.split()
        if len(parts) >= 2:
            packages.append((parts[0], parts[1]))
    return packages


def get_local_repos_from_pacman_conf() -> list[str]:
    result = subprocess.run(
        ["pacman-conf", "--repo-list"],
        capture_output=True, text=True, check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"Failed to read pacman.conf: {result.stderr.strip()}"
        )
    all_repos = [
        line.strip()
        for line in result.stdout.strip().splitlines()
        if line.strip()
    ]
    return [repo for repo in all_repos if repo not in _OFFICIAL_REPOS]


def find_outdated_from_list(pkgs: list[tuple[str, str]]) -> list[dict]:
    if not pkgs:
        return []
    names = [name for name, _ in pkgs]
    latest = get_aur_latest_versions(names)
    outdated = []
    for name, current_version in pkgs:
        latest_version = latest.get(name)
        if latest_version and _vercmp(current_version, latest_version) < 0:
            outdated.append({
                "name": name,
                "current_version": current_version,
                "latest_version": latest_version,
            })
    return outdated


def discover_packages(
    repos: Optional[list[str]] = None,
    include_foreign: bool = False,
    all_repos: bool = False,
    _warn_func: Optional[callable] = None,
) -> list[dict]:
    sources: set[tuple[str, str]] = set()

    if all_repos:
        local_repos = get_local_repos_from_pacman_conf()
        for repo in local_repos:
            sources.update(get_installed_from_repo(repo))

    if repos:
        for repo in repos:
            pkg_list = get_installed_from_repo(repo)
            if not pkg_list and _warn_func:
                _warn_func(f"repo '{repo}' has no packages or does not exist.")
            sources.update(pkg_list)

    if include_foreign or (not all_repos and repos is None):
        sources.update(get_installed_foreign())

    unique_pkgs = list(sources)
    return find_outdated_from_list(unique_pkgs)
