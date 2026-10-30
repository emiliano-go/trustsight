"""Read release channels, fallback tags, and signing keys."""

import tomllib

from . import _log
from ._default_config import (
    DEFAULT_BASELINE_TAG,
    DEFAULT_IOC_TAG,
    DEFAULT_RELEASE_CHANNEL,
    DEFAULT_RELEASE_KEY,
    DEFAULT_WATCHLIST_TAG,
)


def _config_dir():
    from . import CONFIG_DIR
    return CONFIG_DIR


_PARSE_WARNED: set[str] = set()

def _warn_unparsable_config(exc: Exception) -> None:
    """Warn once when config.toml cannot be parsed.

    These accessors deliberately do not raise: they run while a URL is built
    or a command starts, and a broken file must not take the whole tool down.
    But swallowing the error silently would drop an operator's pinned
    ``[release] key`` and fall back to the official channel without a word, so
    say so - once per process.
    """
    if str(_config_dir()) in _PARSE_WARNED:
        return
    _PARSE_WARNED.add(str(_config_dir()))
    _log.warning(
        "config.toml could not be parsed (%s); using shipped defaults, so any "
        "release channel or key set there is being ignored", exc)

def configured_baseline_tag() -> str | None:
    """The fallback baseline tag for the release channel, or ``None``.

    Read without creating a config file: the release channel builds a URL
    during a download and must not materialise operator state as a side
    effect of a lookup.  An unreadable or absent file falls back to the
    shipped default; an explicit empty value disables the fallback.
    """
    path = _config_dir() / "config.toml"
    try:
        with open(path, "rb") as f:
            section = tomllib.load(f).get("seed") or {}
    except (OSError, tomllib.TOMLDecodeError) as exc:
        _warn_unparsable_config(exc)
        section = {}
    # An explicit key wins, including an empty one: setting ``baseline_tag =
    # ""`` turns the fallback off and makes a discovery failure fail closed.
    if "baseline_tag" in section:
        value = str(section["baseline_tag"] or "").strip()
    else:
        value = str(DEFAULT_BASELINE_TAG or "").strip()
    return value or None

def configured_ioc_tag() -> str | None:
    """The fallback tag for the dedicated IOC channel, or ``None``.

    Read from ``[baselines.ioc] tag`` without creating a config file, for the
    same reason as :func:`configured_baseline_tag`: this runs while a download
    URL is built.  An unset or empty value returns ``None``, which means
    "resolve the newest ``ioc-*`` release".
    """
    path = _config_dir() / "config.toml"
    try:
        with open(path, "rb") as f:
            section = tomllib.load(f).get("baselines", {}).get("ioc") or {}
    except (OSError, tomllib.TOMLDecodeError) as exc:
        _warn_unparsable_config(exc)
        section = {}
    if "tag" in section:
        value = str(section["tag"] or "").strip()
    else:
        value = str(DEFAULT_IOC_TAG or "").strip()
    return value or None

def configured_watchlist_tag() -> str | None:
    """The fallback tag for the watchlist channel, or ``None``.

    Read from ``[baselines.watchlist] tag`` without creating a config file,
    for the same reason as :func:`configured_baseline_tag`: this runs while a
    download URL is built.  An unset or empty value returns ``None``, which
    means "resolve the newest ``watchlist-*`` release".
    """
    path = _config_dir() / "config.toml"
    try:
        with open(path, "rb") as f:
            section = tomllib.load(f).get("baselines", {}).get("watchlist") or {}
    except (OSError, tomllib.TOMLDecodeError) as exc:
        _warn_unparsable_config(exc)
        section = {}
    if "tag" in section:
        value = str(section["tag"] or "").strip()
    else:
        value = str(DEFAULT_WATCHLIST_TAG or "").strip()
    return value or None

def _release_section() -> dict:
    """The ``[release]`` table, read without creating a config file."""
    path = _config_dir() / "config.toml"
    try:
        with open(path, "rb") as f:
            return tomllib.load(f).get("release") or {}
    except (OSError, tomllib.TOMLDecodeError) as exc:
        _warn_unparsable_config(exc)
        return {}

def configured_release_channel() -> str | None:
    """The followed release channel as an ``owner/repo`` slug, or ``None``.

    ``None`` means the canonical official channel.  Read without creating a
    config file, for the same reason as :func:`configured_baseline_tag`: this
    runs while a download URL is built.
    """
    section = _release_section()
    if "channel" in section:
        value = str(section["channel"] or "").strip()
    else:
        value = str(DEFAULT_RELEASE_CHANNEL or "").strip()
    return value or None

def configured_release_key() -> str | None:
    """The pinned ed25519 key for a non-official release channel, or ``None``.

    A path to a raw 32-byte key file, or 64 hex characters.  ``None`` means
    "use the pinned official key"; the caller only consults this for a
    non-official channel.
    """
    section = _release_section()
    if "key" in section:
        value = str(section["key"] or "").strip()
    else:
        value = str(DEFAULT_RELEASE_KEY or "").strip()
    return value or None
