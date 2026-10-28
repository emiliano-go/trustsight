"""Small path/version helpers with lazy access to the config dir."""

import os
import re
from pathlib import Path

from ._default_rules import SHIPPED_RULESET_VERSION

_RULESET_VERSION_RE = re.compile(r"^#\s*ruleset-version:\s*(\d+)", re.MULTILINE)

def _config_dir():
    from . import CONFIG_DIR
    return CONFIG_DIR


def local_ruleset_version() -> int:
    path = _config_dir() / "rules.toml"
    if not path.exists():
        return SHIPPED_RULESET_VERSION
    match = _RULESET_VERSION_RE.search(path.read_text(errors="replace"))
    return int(match.group(1)) if match else 0


def ruleset_age_drift(releases: int = 1) -> bool:
    return SHIPPED_RULESET_VERSION - local_ruleset_version() > releases


def write_default_file(path: Path, content: str):
    """Write a default file to disk if it does not exist, mode 0600."""
    if not path.exists():
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
