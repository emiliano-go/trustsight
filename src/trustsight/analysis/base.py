import re
import subprocess
from urllib.parse import urlparse

from ..buckets import PINNING_ORDER, classify_pinning_level
from ..config import ensure_default_configs
from ..db import dependency_observation_counts, init_db
from ..differ import _has_checksum_in_post_diff
from ..tokenizer import split_lines

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
    for line in split_lines(diff_text):
        if line.startswith("-pkgver="):
            old_val = line.removeprefix("-pkgver=").strip().strip("'\"")
        elif line.startswith("+pkgver="):
            new_val = line.removeprefix("+pkgver=").strip().strip("'\"")
    return old_val is not None and new_val is not None and old_val != new_val


_GLOBAL_URL_KEY = "\x00__global__"

# Scheme characters per RFC 3986, and the default delimiters that end a URL
# token inside a shell line.
_SCHEME_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+.-"
)
_DEFAULT_URL_STOP = frozenset(" \t\r\n'\"();|>")


def iter_scheme_urls(text: str, stop_chars: frozenset = _DEFAULT_URL_STOP):
    """Yield ``(scheme, url)`` for every ``scheme://...`` token in *text*.

    This is a scan, not a regex, on purpose.  ``[a-zA-Z][a-zA-Z0-9+.-]*://``
    is quadratic on a line that has no ``://``: at every start position the
    character class runs to the end of the line before the match fails, so a
    single 200 KB word - which a PKGBUILD may legally contain, and which an
    attacker may choose to contain - took ~30s to *not* match.  Anchoring on
    the literal ``://`` and expanding outwards is linear and cannot be made
    to backtrack.
    """
    index = text.find("://")
    while index != -1:
        start = index
        while start > 0 and text[start - 1] in _SCHEME_CHARS:
            start -= 1
        if start < index and text[start].isalpha():
            end = index + 3
            while end < len(text) and text[end] not in stop_chars:
                end += 1
            if end > index + 3:
                yield text[start:index], text[start:end]
        index = text.find("://", index + 3)

_NO_CHECKSUM_BEHAVIORS = ("changed_from_sha256_to_skip", "checksum_array_emptied")

_EXPERIMENTAL_DEFAULTS = {
    "D001": True, "D002": True, "D003": True, "D004": True,
    "H015": True,
    "H016": True, "H017": True, "H018": True, "H019": True,
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
        # "--" ends option parsing: a package name is attacker-influenced
        # data (it comes from the AUR metadata dump), and a name beginning
        # with "-" would otherwise be read by pacman as a flag.
        result = subprocess.run(
            ["pacman", "-Q", "--", pkg_name],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode == 0 and result.stdout:
            parts = result.stdout.strip().split()
            if len(parts) >= 2:
                return parts[1]
    except (subprocess.SubprocessError, FileNotFoundError):
        pass
    return ""


# ---------------------------------------------------------------------------
# File scoping inside a multi-file diff
# ---------------------------------------------------------------------------

_DIFF_FILE_RE = re.compile(r"^\+\+\+ [ab]/(.+?)\s*$")


def mask_to_recipe(lines: list[str]) -> list[str]:
    """Blank the hunk lines that belong to files other than the recipe.

    An AUR commit carries more than the PKGBUILD: the .SRCINFO, install
    hooks, and any patch files the package ships.  A rule about what the
    *recipe* declares must not read a Makefile fragment inside a shipped
    patch as if the PKGBUILD had written it - ``LDFLAGS = @LDFLAGS@`` in a
    vendored configure script is not the packager overriding the build
    flags.

    Lines are blanked rather than dropped so that indices stay aligned with
    ``resolve_added_lines``/``_classify_enclosing_function`` and with the
    diff's own line numbers.
    """
    out: list[str] = []
    in_recipe = True
    for line in lines:
        match = _DIFF_FILE_RE.match(line)
        if match:
            name = match.group(1).rsplit("/", 1)[-1]
            in_recipe = name == "PKGBUILD" or name.endswith(".install")
        out.append(line if in_recipe else "")
    return out
