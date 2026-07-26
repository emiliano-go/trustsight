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
    """simple numeric/semantic version comparison fallback"""
    import re
    def _split(v: str):
        """split version string into digit and non-digit parts"""
        return [int(x) if x.isdigit() else x for x in re.split(r"(\d+)", v)]
    p1, p2 = _split(v1), _split(v2)
    for a, b in zip(p1, p2):
        if a != b:
            if isinstance(a, int) and isinstance(b, int):
                return -1 if a < b else 1
            sa, sb = str(a), str(b)
            return -1 if sa < sb else 1
    return -1 if len(p1) < len(p2) else (1 if len(p1) > len(p2) else 0)


# pyalpm exposes the same comparison pacman itself uses, in-process.  It is
# not a hard dependency, so its absence just means falling back to forking
# the vercmp binary.  Resolved once: probing per call would cost more than
# it saves.
_pyalpm_vercmp = None
_pyalpm_checked = False


def _get_pyalpm_vercmp():
    """Return pyalpm's vercmp if it is installed, else None."""
    global _pyalpm_vercmp, _pyalpm_checked
    if not _pyalpm_checked:
        _pyalpm_checked = True
        try:
            import pyalpm

            _pyalpm_vercmp = pyalpm.vercmp
        except ImportError:
            _pyalpm_vercmp = None
    return _pyalpm_vercmp


def _vercmp(v1: str, v2: str) -> int:
    """compare version strings using pacman's vercmp, falling back to simple"""
    import logging

    # Discovery compares every installed foreign package against the AUR,
    # and the overwhelming majority are identical.  Answering those here
    # avoids a fork each, which on a normal system is most of them.
    if v1 == v2:
        return 0

    native = _get_pyalpm_vercmp()
    if native is not None:
        try:
            return native(v1, v2)
        except (TypeError, ValueError):
            return 0

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
    """Return a dict of installed AUR package names to versions."""
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


def _aur_info_url(names: list[str]) -> str:
    """Build an AUR RPC v5 info URL for one or more package names."""
    params = [("v", "5"), ("type", "info")]
    params.extend(("arg[]", n) for n in names)
    return f"{AUR_RPC_BASE}?{urllib.parse.urlencode(params)}"


def get_aur_package_info(pkg_names: list[str]) -> dict[str, dict]:
    """Return the full AUR RPC record for each of *pkg_names*, keyed by name."""
    if not pkg_names:
        return {}
    url = _aur_info_url(pkg_names)
    try:
        with urllib.request.urlopen(url, timeout=30) as resp:
            data = json.load(resp)
            return {r["Name"]: r for r in data.get("results", [])}
    except (urllib.error.URLError, json.JSONDecodeError):
        return {}


def get_aur_latest_versions(pkg_names: list[str]) -> dict[str, str]:
    """Return the latest available versions from the AUR for *pkg_names*."""
    return {
        name: record["Version"]
        for name, record in get_aur_package_info(pkg_names).items()
        if "Version" in record
    }


def find_outdated_packages(
    installed: dict[str, str], latest: dict[str, str]
) -> dict[str, tuple[str, str]]:
    """Compare installed vs latest, returning outdated name->(installed, latest)."""
    outdated = {}
    for name, installed_ver in installed.items():
        latest_ver = latest.get(name)
        if latest_ver and installed_ver != latest_ver:
            outdated[name] = (installed_ver, latest_ver)
    return outdated


def fetch_package_info(name: str) -> Optional[dict]:
    """Fetch full package info from the AUR RPC for *name*."""
    # Encoded, not interpolated: an unescaped "&" or "#" in the name would
    # otherwise inject or truncate RPC query parameters.
    url = _aur_info_url([name])
    try:
        with urllib.request.urlopen(url, timeout=10) as resp:
            data = json.load(resp)
            if data["resultcount"] > 0:
                return data["results"][0]
    except (urllib.error.URLError, json.JSONDecodeError):
        pass
    return None


def get_installed_from_repo(repo: str) -> list[tuple[str, str]]:
    """Return (name, version) pairs installed from *repo*."""
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
    """Return (name, version) pairs installed from foreign sources (AUR)."""
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
    """Return local repos from pacman.conf, excluding official ones."""
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
    """Return outdated packages from a (name, version) list by querying the AUR."""
    if not pkgs:
        return []
    names = [name for name, _ in pkgs]
    info = get_aur_package_info(names)
    outdated = []
    for name, current_version in pkgs:
        record = info.get(name) or {}
        latest_version = record.get("Version")
        if latest_version and _vercmp(current_version, latest_version) < 0:
            entry = {
                "name": name,
                "current_version": current_version,
                "latest_version": latest_version,
            }
            # Carried through so the fetcher can tell whether the cached
            # clone is already up to date and skip the network entirely.
            last_modified = record.get("LastModified")
            if isinstance(last_modified, int):
                entry["last_modified"] = last_modified
            outdated.append(entry)
    return outdated


def discover_packages(
    repos: Optional[list[str]] = None,
    include_foreign: bool = False,
    all_repos: bool = False,
    _warn_func: Optional[callable] = None,
) -> list[dict]:
    """Discover outdated packages across repos and optionally foreign sources."""
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
