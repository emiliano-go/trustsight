import re
import unicodedata
from urllib.parse import urlparse

from .config import load_domains

# tldextract is imported lazily.  It pulls in requests and urllib3, which
# together cost ~98ms of the CLI's startup, and nothing outside URL
# classification needs it; `trustsight --help` should not pay for it.
_extractor = None


def _extract(url: str):
    """Split *url* using a tldextract instance that never hits the network.

    The default instance fetches the public suffix list over HTTP on first
    use, which turns the first classification on a fresh machine into a
    network round-trip that can fail.  ``suffix_list_urls=()`` pins it to
    the snapshot bundled with the package.
    """
    global _extractor
    if _extractor is None:
        import tldextract

        _extractor = tldextract.TLDExtract(suffix_list_urls=())
    return _extractor(url)

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

    Only script mixing within a single label is a homograph signal.
    Single-script labels (e.g. ``münchen.de``, ``café.fr``) are legitimate
    internationalised domains regardless of whether the script is ASCII.
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
    return False


def _prepare(domain_config: dict) -> tuple[frozenset, frozenset, frozenset]:
    """Return ``(raw_hosting, trusted_forges, official)`` as frozensets.

    Membership tests replace the linear scan the classifier used to run
    over each of the three lists for every URL.  Building these is cheap
    enough to do per batch; ``classify_urls`` does it once and passes the
    result down rather than repeating it per URL.
    """
    return (
        frozenset(domain_config.get("raw_hosting", {}).get("domains", [])),
        frozenset(domain_config.get("trusted_forges", {}).get("domains", [])),
        frozenset(domain_config.get("official_projects", {}).get("domains", [])),
    )


def _parent_domains(domain: str):
    """Yield *domain* and each of its parent domains.

    ``a.b.example.com`` yields itself, ``b.example.com``, ``example.com``
    and ``com``.  Testing membership of these against a set replaces an
    ``endswith`` scan over every configured domain.
    """
    yield domain
    rest = domain
    while "." in rest:
        rest = rest.split(".", 1)[1]
        yield rest


def classify_url(url: str, domain_config: dict | None = None) -> tuple[str, str]:
    """Classify a single URL into a provenance bucket"""
    if domain_config is None:
        domain_config = load_domains()
    return _classify_prepared(url, _prepare(domain_config))


def _classify_prepared(
    url: str, prepared: tuple[frozenset, frozenset, frozenset]
) -> tuple[str, str]:
    """Classify *url* against already-prepared domain sets."""
    parsed = urlparse(url)
    domain = parsed.netloc.lower()

    if has_homograph(domain):
        return "homograph_attack", domain

    raw_hosting, trusted_forges, official = prepared

    if domain in raw_hosting:
        return "raw_hosting", domain

    # The registered domain is only needed for the forge comparison, and
    # computing it is the expensive part of this function.
    extracted = _extract(url)
    registered = f"{extracted.domain}.{extracted.suffix}"

    if registered in trusted_forges:
        return "trusted_forge", registered
    # ``domain.endswith("." + d)`` for a configured d is exactly "one of the
    # proper parents of domain is d", so skip the domain itself here.
    for parent in _parent_domains(domain):
        if parent != domain and parent in trusted_forges:
            return "trusted_forge", registered

    for parent in _parent_domains(domain):
        if parent in official:
            return "official", domain

    return "unknown", domain


def classify_urls(
    urls: list[str], domain_config: dict | None = None
) -> dict[str, str]:
    """Classify each URL in a list into a provenance bucket"""
    # Loaded and prepared once here rather than once per URL.
    if domain_config is None:
        domain_config = load_domains()
    prepared = _prepare(domain_config)
    result = {}
    for url in urls:
        bucket, matched_domain = _classify_prepared(url, prepared)
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


PINNING_ORDER = ["checksum_pinned", "tag_pinned", "branch_pinned", "unpinned"]


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
