import re
import unicodedata
from urllib.parse import urlparse

import tldextract

from .config import load_domains

CONFUSABLES = {
    "g": "ɡ", "a": "а", "e": "е", "o": "о", "c": "с",
    "p": "р", "x": "х", "y": "у", "i": "і", "l": "ӏ",
}


def has_homograph(domain: str) -> bool:
    for ch in domain:
        if unicodedata.name(ch, "").startswith("LATIN") and ord(ch) > 127:
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
