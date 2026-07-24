import re
import unicodedata
from urllib.parse import urlparse

import tldextract

from .config import load_domains

CONFUSABLES = {
    "g": "ɡ", "a": "а", "e": "е", "o": "о", "c": "с",
    "p": "р", "x": "х", "y": "у", "i": "і", "l": "ӏ",
}

# Scripts whose letters are commonly used to build confusable domains.
# A label mixing two of these is a homograph attack; a label written
# wholly in one of them is a legitimate internationalised domain.
_SCRIPT_PREFIXES = (
    "LATIN", "CYRILLIC", "GREEK", "ARMENIAN", "HEBREW", "ARABIC",
    "CHEROKEE", "GEORGIAN", "COPTIC", "DEVANAGARI", "BENGALI", "THAI",
    "HIRAGANA", "KATAKANA", "HANGUL", "BOPOMOFO",
)

# Script combinations that occur in legitimate domains.  Japanese mixes
# Han with kana, Korean mixes Han with Hangul, and all of them mix with
# ASCII.  Latin paired with Cyrillic or Greek has no legitimate use and
# is the classic confusable construction.
_COMPATIBLE_GROUPS = (
    {"LATIN"},
    {"LATIN", "HAN", "HIRAGANA", "KATAKANA"},
    {"LATIN", "HAN", "HANGUL"},
    {"LATIN", "HAN", "BOPOMOFO"},
)


def _script_of(ch: str) -> str:
    """Return the script name for *ch*, or ``"COMMON"`` for non-letters.

    Digits, hyphens and dots belong to every script, so they are reported
    as ``COMMON`` and never contribute to a mixed-script verdict.
    """
    if not ch.isalpha():
        return "COMMON"
    if ch.isascii():
        return "LATIN"
    name = unicodedata.name(ch, "")
    if name.startswith("CJK"):
        return "HAN"
    for prefix in _SCRIPT_PREFIXES:
        if name.startswith(prefix):
            return prefix
    return "OTHER"


def _decode_punycode(label: str) -> str:
    """Decode an ``xn--`` label, returning it unchanged if undecodable.

    Without this, an attacker can bypass detection by writing the
    punycode form (``xn--githb-6rd.com``) directly into ``source=()``.
    """
    if not label.lower().startswith("xn--"):
        return label
    try:
        return label.encode("ascii").decode("idna")
    except (UnicodeError, ValueError):
        return label


def has_homograph(domain: str) -> bool:
    """Detect confusable characters in a domain.

    Two independent signals:

    1. **Mixed script within a label**: ``github.cоm`` with a Cyrillic
       ``о`` reads as Latin but is not.  A label wholly in one non-Latin
       script is a legitimate IDN and is not flagged.
    2. **Non-ASCII Latin**: ``githuḅ.com`` stays within the Latin script,
       so mixed-script detection cannot see it, but a Latin letter with a
       diacritic in a domain is still a confusable.
    """
    host = domain.split("@")[-1].split(":")[0]
    for raw_label in host.split("."):
        if not raw_label:
            continue
        label = _decode_punycode(raw_label)
        scripts = {_script_of(ch) for ch in label} - {"COMMON"}
        if len(scripts) > 1 and not any(
            scripts <= group for group in _COMPATIBLE_GROUPS
        ):
            return True
        if any(not ch.isascii() and _script_of(ch) == "LATIN" for ch in label):
            return True
    return False


def classify_url(url: str, domain_config: dict | None = None) -> tuple[str, str]:
    if domain_config is None:
        domain_config = load_domains()

    parsed = urlparse(url)
    domain = parsed.netloc.lower()

    if has_homograph(domain):
        return "homograph_attack", domain

    extracted = tldextract.extract(url)
    registered = f"{extracted.domain}.{extracted.suffix}"

    raw_hosting = domain_config.get("raw_hosting", {}).get("domains", [])
    for d in raw_hosting:
        if domain == d:
            return "raw_hosting", domain

    trusted_forges = domain_config.get("trusted_forges", {}).get("domains", [])
    for d in trusted_forges:
        if registered == d or domain.endswith("." + d):
            return "trusted_forge", registered

    official = domain_config.get("official_projects", {}).get("domains", [])
    for d in official:
        if domain == d or domain.endswith("." + d):
            return "official", domain

    return "unknown", domain


def classify_urls(
    urls: list[str], domain_config: dict | None = None
) -> dict[str, str]:
    result = {}
    for url in urls:
        bucket, matched_domain = classify_url(url, domain_config)
        result[url] = bucket
    return result


# A path component that looks like a version number (e.g. v1.0.0, 2.0, 3.1.4)
_VERSION_LIKE_RE = re.compile(r"(?:^|/)(?:v\d+(?:\.\d+)*|\d+(?:\.\d+){1,})(?:/|$|\.)")
# Explicit branch refs
_BRANCH_REF_RE = re.compile(
    r"(?:/branches?/|/heads/|/refs/heads/|/master[\./\"]|/main[\./\"]|/develop[\./\"])",
    re.IGNORECASE,
)
# Tag or release paths
_TAG_PATH_RE = re.compile(
    r"(?:/releases?/|/tags?/|/download/)",
    re.IGNORECASE,
)


def classify_pinning_level(url: str, checksum_present: bool = False) -> str:
    """Return the pinning level for a source URL.

    Levels from most to least pinned:
    - ``checksum_pinned``: URL covered by a valid sha256 checksum
    - ``tag_pinned``: URL references a tag or version (immutable ref)
    - ``branch_pinned``: URL references a mutable branch
    - ``unpinned``: none of the above
    """
    if checksum_present:
        return "checksum_pinned"
    if _BRANCH_REF_RE.search(url):
        return "branch_pinned"
    if _TAG_PATH_RE.search(url) or _VERSION_LIKE_RE.search(url):
        return "tag_pinned"
    return "unpinned"
