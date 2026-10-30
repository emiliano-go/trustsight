"""Refresh configuration values shipped by earlier releases."""

import re
import sys
import tomllib

from . import _log
from ._default_config import DEFAULT_IOCS, _toml_str_list, _toml_value
from ._default_rules import LEGACY_DEFAULT_REVIEW_LIMIT, LEGACY_IOCS_STUBS
from ._defaults_executor import (
    DEFAULT_FOREIGN_PKG_MANAGERS,
    DEFAULT_NETWORK_TOOLS,
    GETENT_ENUMERATION_FRAGMENT,
    H067_LEGACY_SYSTEMD_DETECT_VIRT,
    H067_SYSTEMD_DETECT_VIRT_PROBE,
    LEGACY_FOREIGN_PKG_MANAGER_LISTS,
    LEGACY_NETWORK_TOOL_LISTS,
)


def _config_dir():
    from . import CONFIG_DIR
    return CONFIG_DIR


def _toml_cache():
    return sys.modules[__package__]._toml_cache


def _refresh_legacy_iocs() -> bool:
    """Replace an untouched pre-H056 iocs.toml.  True when rewritten."""
    path = _config_dir() / "iocs.toml"
    try:
        if path.read_text() in LEGACY_IOCS_STUBS:
            path.write_text(DEFAULT_IOCS)
            _toml_cache().pop("iocs.toml", None)
            return True
    except OSError:
        pass
    return False

_LEGACY_REVIEW_LIMIT_RE = re.compile(
    rf"^(\s*default_review_limit\s*=\s*){LEGACY_DEFAULT_REVIEW_LIMIT}(\s*)$"
)

def _refresh_legacy_review_limit() -> bool:
    """Repair the stale shipped ``default_review_limit``.  True when rewritten."""
    path = _config_dir() / "config.toml"
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return False
    out: list[str] = []
    section = ""
    changed = False
    for line in text.splitlines(keepends=True):
        newline = "\n" if line.endswith("\n") else ""
        body = line[:-1] if newline else line
        stripped = body.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            section = stripped
        if section == "[limits]" and _LEGACY_REVIEW_LIMIT_RE.match(body):
            out.append(_LEGACY_REVIEW_LIMIT_RE.sub(r"\g<1>0\g<2>", body) + newline)
            changed = True
        else:
            out.append(line)
    if not changed:
        return False
    path.write_text("".join(out), encoding="utf-8")
    _toml_cache().pop("config.toml", None)
    _log.info("repaired the legacy default_review_limit to 0 (read everything)")
    return True

_LEGACY_GETENT_FRAGMENT = r"(?:\A\s*|[;&|]\s*)getent\b"

def _refresh_legacy_recon_commands() -> bool:
    """Repair the stale shipped H040 ``getent`` fragment in patterns.toml.

    The fragment used to fire on targeted lookups (``getent passwd <name>``
    - the standard provisioning step before ``useradd``) as well as keyless
    enumeration.  patterns.toml is written once at install and never
    synced, so existing installs keep the old fragment; when the file still
    carries it, the one line is swapped in place (the surrounding list, and
    any user customisation of it, is preserved).  True when rewritten.
    """
    path = _config_dir() / "patterns.toml"
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return False
    old_line = "    " + _toml_value(_LEGACY_GETENT_FRAGMENT) + ",\n"
    new_line = "    " + _toml_value(GETENT_ENUMERATION_FRAGMENT) + ",\n"
    if text.count(old_line) != 1:
        return False
    path.write_text(text.replace(old_line, new_line, 1), encoding="utf-8")
    _toml_cache().pop("patterns.toml", None)
    _log.info("repaired the legacy H040 getent fragment in patterns.toml")
    return True

def _refresh_legacy_network_tools() -> bool:
    """Repair the shipped D003 list when it still has the pre-expansion set.

    ``patterns.toml`` is written once at install and never synced, so an
    install from before the transfer-client expansion keeps the old list
    forever.  The parsed value must equal the exact legacy list: a user who
    added or removed an entry keeps their table untouched.
    """
    path = _config_dir() / "patterns.toml"
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return False
    try:
        parsed = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return False
    current = (parsed.get("patterns") or {}).get("network_tools")
    legacy = next(
        (table for table in LEGACY_NETWORK_TOOL_LISTS
         if current == list(table)),
        None,
    )
    if legacy is None:
        return False
    old_block = "network_tools = " + _toml_str_list(legacy)
    new_block = "network_tools = " + _toml_str_list(DEFAULT_NETWORK_TOOLS)
    if old_block not in text:
        return False
    path.write_text(text.replace(old_block, new_block, 1), encoding="utf-8")
    _toml_cache().pop("patterns.toml", None)
    _log.info("repaired the legacy D003 network_tools list in patterns.toml")
    return True


def _refresh_legacy_foreign_pkg_managers() -> bool:
    """Repair the shipped H035 list when it still has the pre-expansion set.

    ``patterns.toml`` is written once at install and never synced.  The
    parsed value must equal the exact legacy list; a user who added or
    removed an entry keeps their table untouched.
    """
    path = _config_dir() / "patterns.toml"
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return False
    try:
        parsed = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return False
    current = (parsed.get("patterns") or {}).get("foreign_pkg_managers")
    legacy = next(
        (table for table in LEGACY_FOREIGN_PKG_MANAGER_LISTS
         if current == list(table)),
        None,
    )
    if legacy is None:
        return False
    old_block = "foreign_pkg_managers = " + _toml_str_list(legacy)
    new_block = "foreign_pkg_managers = " + _toml_str_list(
        DEFAULT_FOREIGN_PKG_MANAGERS)
    if old_block not in text:
        return False
    path.write_text(text.replace(old_block, new_block, 1), encoding="utf-8")
    _toml_cache().pop("patterns.toml", None)
    _log.info("repaired the legacy H035 foreign_pkg_managers list in patterns.toml")
    return True


def _refresh_legacy_anti_analysis_probes() -> bool:
    """Repair the stale shipped H067 ``systemd-detect-virt`` probe.

    The probe fired on ``systemd-detect-virt --chroot``, the udev/chroot
    availability guard an install scriptlet legitimately runs.  patterns.toml
    is written once at install and never synced, so an existing install keeps
    the broad fragment; when the file still carries it, that one line is
    swapped in place and user customisation of the rest is preserved.
    """
    path = _config_dir() / "patterns.toml"
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return False
    old_line = "    " + _toml_value(H067_LEGACY_SYSTEMD_DETECT_VIRT) + ",\n"
    new_line = "    " + _toml_value(H067_SYSTEMD_DETECT_VIRT_PROBE) + ",\n"
    if text.count(old_line) != 1:
        return False
    path.write_text(text.replace(old_line, new_line, 1), encoding="utf-8")
    _toml_cache().pop("patterns.toml", None)
    _log.info("repaired the legacy H067 systemd-detect-virt probe in patterns.toml")
    return True
