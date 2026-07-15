import json
import subprocess
import urllib.request
from typing import Optional

AUR_RPC_BASE = "https://aur.archlinux.org/rpc?v=5&type=info"


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
    results = {}
    for name in pkg_names:
        url = f"{AUR_RPC_BASE}&arg[]={name}"
        try:
            with urllib.request.urlopen(url, timeout=10) as resp:
                data = json.load(resp)
                if data["resultcount"] > 0:
                    results[name] = data["results"][0]["Version"]
        except (urllib.error.URLError, json.JSONDecodeError):
            continue
    return results


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
    url = f"{AUR_RPC_BASE}&arg[]={name}"
    try:
        with urllib.request.urlopen(url, timeout=10) as resp:
            data = json.load(resp)
            if data["resultcount"] > 0:
                return data["results"][0]
    except (urllib.error.URLError, json.JSONDecodeError):
        pass
    return None
