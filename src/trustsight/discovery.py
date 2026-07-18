import json
import subprocess
import urllib.parse
import urllib.request
from typing import Optional

AUR_RPC_BASE = "https://aur.archlinux.org/rpc"


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
    url = f"{AUR_RPC_BASE}?v=5&type=info&arg[]={name}"
    try:
        with urllib.request.urlopen(url, timeout=10) as resp:
            data = json.load(resp)
            if data["resultcount"] > 0:
                return data["results"][0]
    except (urllib.error.URLError, json.JSONDecodeError):
        pass
    return None
