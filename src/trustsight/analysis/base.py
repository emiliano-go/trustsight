import re
import subprocess
from urllib.parse import urlparse

from ..buckets import PINNING_ORDER, classify_pinning_level
from ..config import ensure_default_configs
from ..db import dependency_observation_counts, init_db
from ..differ import _has_checksum_in_post_diff

_initialized = False


def _ensure_init() -> None:
    global _initialized
    if not _initialized:
        ensure_default_configs()
        init_db()
        _initialized = True


def _rarities_of(deps: list[str]) -> list[float]:
    counts = dependency_observation_counts(deps)
    return [1.0 / (1.0 + counts.get(d, 0)) for d in deps]


def _pkgver_changed_in_diff(diff_text: str) -> bool:
    old_val: str | None = None
    new_val: str | None = None
    for line in diff_text.splitlines():
        if line.startswith("-pkgver="):
            old_val = line.removeprefix("-pkgver=").strip().strip("'\"")
        elif line.startswith("+pkgver="):
            new_val = line.removeprefix("+pkgver=").strip().strip("'\"")
    return old_val is not None and new_val is not None and old_val != new_val


_GLOBAL_URL_KEY = "\x00__global__"

_NO_CHECKSUM_BEHAVIORS = ("changed_from_sha256_to_skip", "checksum_array_emptied")

_EXPERIMENTAL_DEFAULTS = {
    "D001": True, "D002": True, "D003": True, "D004": True,
    "R060": True,
    "R061": True, "R062": True, "R063": True, "R064": True,
}


_INSTALL_FILE_IN_DIFF_RE = re.compile(
    r"(?:^|\n)(?:\+\s*install\s*=|"
    r"(?:---|^\+\+\+)\s+[ab]/.+\.install)\b",
    re.MULTILINE,
)


def _has_install_hook(diff_text: str) -> bool:
    if _INSTALL_FILE_IN_DIFF_RE.search(diff_text):
        return True
    from ..differ import _post_diff_lines
    post = "\n".join(_post_diff_lines(diff_text))
    return bool(re.search(r"^\s*install\s*=", post, re.MULTILINE))


def _url_domain(url: str) -> str:
    parsed = urlparse(url)
    return parsed.netloc.lower()


def _aggregate_pinning(
    diff_text: str, added_urls: list[str], checksum_behavior: str = ""
) -> str:
    has_checksum = (
        _has_checksum_in_post_diff(diff_text)
        and checksum_behavior not in _NO_CHECKSUM_BEHAVIORS
    )
    levels = [
        classify_pinning_level(url, checksum_present=has_checksum)
        for url in added_urls
    ]
    if not levels:
        return "unpinned"
    return PINNING_ORDER[max(PINNING_ORDER.index(p) for p in levels)]


def _experimental_enabled(config: dict, rule_id: str) -> bool:
    section = config.get("experimental_rules") if config else None
    if section is None:
        return _EXPERIMENTAL_DEFAULTS.get(rule_id, False)
    return bool(section.get(rule_id, _EXPERIMENTAL_DEFAULTS.get(rule_id, False)))


def _get_installed_version(pkg_name: str) -> str:
    try:
        result = subprocess.run(
            ["pacman", "-Q", pkg_name],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode == 0 and result.stdout:
            parts = result.stdout.strip().split()
            if len(parts) >= 2:
                return parts[1]
    except (subprocess.SubprocessError, FileNotFoundError):
        pass
    return ""
