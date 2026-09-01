import json
import logging
import random
import re
import subprocess
import time
import urllib.parse
import urllib.request
from typing import Optional

AUR_RPC_BASE = "https://aur.archlinux.org/rpc"
log = logging.getLogger(__name__)

# Retry constants for AUR RPC queries (mirrors full_aur/fetch.py patterns).
_RPC_MAX_RETRIES = 3
_RPC_RETRYABLE_STATUS = frozenset({429, 500, 502, 503, 504})
_RPC_BACKOFF_BASE = 1.0
_RPC_BACKOFF_MAX = 15.0

# A4: every response has a byte cap, the RPC included.  A realistic multiinfo
# reply for any batch this tool sends is well under a megabyte; 64 MiB is far
# above that and still bounds what a hostile or malfunctioning endpoint can make
# json.load buffer.  A reply past the cap raises, is caught by the callers
# below, and degrades to "query failed" rather than exhausting memory.
_MAX_RPC_BYTES = 64 * 1024 * 1024


class _RpcResponseTooLarge(Exception):
    """The RPC response exceeded _MAX_RPC_BYTES."""


def _load_rpc_json(resp, limit: int | None = None):
    """Read at most *limit* bytes from *resp* and parse JSON, or raise.

    *limit* defaults to ``_MAX_RPC_BYTES``, resolved at call time so the cap
    stays a single tunable module constant.  One extra byte is read so an
    exactly-at-limit body is still distinguishable from an over-limit one.
    """
    if limit is None:
        limit = _MAX_RPC_BYTES
    raw = resp.read(limit + 1)
    if len(raw) > limit:
        raise _RpcResponseTooLarge(f"AUR RPC response exceeds {limit} bytes")
    return json.loads(raw)

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

# A pacman version: epoch, pkgver and pkgrel characters only, and never a
# leading "-".  Used to keep anything else off a command line - vercmp has
# no "--" separator, so shape is the only guard available.
_VERSION_ARG_RE = re.compile(r"^[A-Za-z0-9._+~:][A-Za-z0-9._+~:-]*$")


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

    # vercmp takes no "--" separator, so a version that looks like a flag
    # cannot be passed safely.  Versions come from the AUR, so they are
    # attacker-influenced; anything that is not version-shaped is compared
    # in-process instead of on a command line.
    if not (_VERSION_ARG_RE.match(v1) and _VERSION_ARG_RE.match(v2)):
        return _simple_vercmp(v1, v2)

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


def _run_pacman(args: list[str]) -> subprocess.CompletedProcess:
    """Run a pacman subcommand, or fail with a message instead of a bare
    FileNotFoundError when pacman is not on PATH (containers, non-Arch)."""
    try:
        return subprocess.run(args, capture_output=True, text=True, check=False)
    except FileNotFoundError:
        raise RuntimeError(
            f"{args[0]} is required but was not found on PATH; install "
            "pacman (Arch Linux) or run this command on an Arch system"
        ) from None


def get_installed_aur_packages() -> dict[str, str]:
    """Return a dict of installed AUR package names to versions."""
    result = _run_pacman(["pacman", "-Qm"])
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


def _rpc_backoff_delay(attempt: int) -> float:
    """Exponential backoff with jitter for AUR RPC retries."""
    return min(_RPC_BACKOFF_BASE * (2 ** attempt) + random.uniform(0, 0.5),
               _RPC_BACKOFF_MAX)


def _rpc_retry_after(http_error) -> Optional[float]:
    """Parse Retry-After header from an HTTP error."""
    headers = getattr(http_error, "headers", None)
    value = headers.get("Retry-After") if headers else None
    if not value:
        return None
    try:
        return min(float(value), _RPC_BACKOFF_MAX)
    except (TypeError, ValueError):
        return None


def get_aur_package_info(pkg_names: list[str]) -> dict[str, dict]:
    """Return the full AUR RPC record for each of *pkg_names*, keyed by name.

    Results are cached in the local database.  Cache TTL is controlled by
    ``[discovery] cache_ttl_minutes`` in the config (default: 60).
    """
    if not pkg_names:
        return {}

    # Check cache for fresh entries
    from .db import read_aur_cache, write_aur_cache
    from .config import load_config

    cfg = load_config().get("discovery", {})
    ttl = cfg.get("cache_ttl_minutes", 60)

    try:
        cached = read_aur_cache(pkg_names, ttl_minutes=ttl)
    except Exception:
        cached = {}

    missed = [n for n in pkg_names if n not in cached]
    if not missed:
        return {
            n: {"Version": v["version"], "LastModified": v.get("last_modified")}
            for n, v in cached.items()
        }

    # Query the AUR for packages not in cache, with retry on transient errors.
    url = _aur_info_url(missed)
    results = {}
    for attempt in range(_RPC_MAX_RETRIES + 1):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "trustsight/1.0"})
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = _load_rpc_json(resp)
                results = {r["Name"]: r for r in data.get("results", [])}
            break
        except urllib.error.HTTPError as exc:
            if exc.code in _RPC_RETRYABLE_STATUS and attempt < _RPC_MAX_RETRIES:
                delay = _rpc_retry_after(exc) or _rpc_backoff_delay(attempt)
                log.debug("AUR RPC HTTP %d; retrying in %.1fs (attempt %d/%d)",
                          exc.code, delay, attempt + 1, _RPC_MAX_RETRIES)
                time.sleep(delay)
                continue
            log.warning("AUR RPC query failed for %d package(s): HTTP %s",
                        len(missed), exc.code)
            break
        except (urllib.error.URLError, json.JSONDecodeError, _RpcResponseTooLarge) as exc:
            if attempt < _RPC_MAX_RETRIES:
                delay = _rpc_backoff_delay(attempt)
                log.debug("AUR RPC error %s; retrying in %.1fs (attempt %d/%d)",
                          exc, delay, attempt + 1, _RPC_MAX_RETRIES)
                time.sleep(delay)
                continue
            log.warning("AUR RPC query failed for %d package(s): %s", len(missed), exc)
            break

    # Write fresh results to cache (non-fatal on failure)
    if results:
        try:
            write_aur_cache({
                name: (r.get("Version", ""), r.get("LastModified"))
                for name, r in results.items()
            })
        except Exception:
            log.debug("failed to write AUR cache", exc_info=True)

    # Merge cached + fresh results
    out = {}
    for name, v in cached.items():
        out[name] = {"Version": v["version"], "LastModified": v.get("last_modified")}
    out.update(results)
    return out


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
            data = _load_rpc_json(resp)
            if data["resultcount"] > 0:
                return data["results"][0]
    except (urllib.error.URLError, json.JSONDecodeError, _RpcResponseTooLarge):
        pass
    return None


def get_all_installed() -> dict[str, str]:
    """Return all installed packages as {name: version}."""
    result = _run_pacman(["pacman", "-Q"])
    packages = {}
    for line in result.stdout.strip().splitlines():
        if not line:
            continue
        parts = line.split()
        if len(parts) >= 2:
            packages[parts[0]] = parts[1]
    return packages


def get_installed_from_repo(repo: str) -> list[tuple[str, str]]:
    """Return (name, version) pairs installed from *repo*.

    Uses ``pacman -Sl`` for the repo package listing and cross-references
    against ``pacman -Q`` (all installed, not just foreign) so that
    packages installed from a local repo are found regardless of how
    pacman tracks their origin.
    """
    # First check the repo listing exists and has packages.
    sl = _run_pacman(["pacman", "-Sl", "--", repo])
    if sl.returncode != 0:
        # repo does not exist; caller should handle the message.
        return []  # sentinel: caller can re-check with _repo_exists

    repo_pkgs = set()
    for line in sl.stdout.strip().splitlines():
        if not line:
            continue
        parts = line.split()
        if len(parts) >= 2:
            repo_pkgs.add(parts[1])

    if not repo_pkgs:
        return []

    all_installed = get_all_installed()
    return [
        (name, ver)
        for name, ver in all_installed.items()
        if name in repo_pkgs
    ]


def get_installed_foreign() -> list[tuple[str, str]]:
    """Return (name, version) pairs installed from foreign sources (AUR)."""
    result = _run_pacman(["pacman", "-Qm"])
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
    result = _run_pacman(["pacman-conf", "--repo-list"])
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


def find_outdated_from_list(
    pkgs: list[tuple[str, str]], all_packages: bool = False,
) -> list[dict]:
    """Return outdated packages from a (name, version) list by querying the AUR.

    When *all_packages* is true, every package found on the AUR is returned
    regardless of whether a newer version exists.
    """
    if not pkgs:
        return []
    names = [name for name, _ in pkgs]
    info = get_aur_package_info(names)
    outdated = []
    for name, current_version in pkgs:
        record = info.get(name) or {}
        latest_version = record.get("Version")
        if not latest_version:
            continue
        if all_packages or _vercmp(current_version, latest_version) < 0:
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


def _repo_exists(repo: str) -> bool:
    """Return True if *repo* is known to pacman."""
    result = _run_pacman(["pacman", "-Sl", "--", repo])
    return result.returncode == 0


def discover_packages(
    repos: Optional[list[str]] = None,
    include_foreign: bool = False,
    all_repos: bool = False,
    all_packages: bool = False,
    _warn_func: Optional[callable] = None,
) -> list[dict]:
    """Discover packages across repos and optionally foreign sources.

    Returns only outdated packages by default.  When *all_packages* is true,
    every AUR-resolvable package is included regardless of update status.
    """
    sources: set[tuple[str, str]] = set()

    if all_repos:
        local_repos = get_local_repos_from_pacman_conf()
        for repo in local_repos:
            sources.update(get_installed_from_repo(repo))

    if repos:
        for repo in repos:
            pkg_list = get_installed_from_repo(repo)
            if not pkg_list and _warn_func:
                if _repo_exists(repo):
                    _warn_func(
                        f"repo '{repo}' exists but no packages from it are installed."
                    )
                else:
                    _warn_func(f"repo '{repo}' does not exist.")
            sources.update(pkg_list)

    if include_foreign or (not all_repos and repos is None):
        sources.update(get_installed_foreign())

    unique_pkgs = list(sources)
    return find_outdated_from_list(unique_pkgs, all_packages=all_packages)
