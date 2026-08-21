import re
import unicodedata
from urllib.parse import urlparse

from .config import load_domains, load_hosts

# tldextract is imported lazily.  It pulls in requests and urllib3, which
# together cost ~98ms of the CLI's startup, and nothing outside URL
# classification needs it; `trustsight --help` should not pay for it.
_extractor = None


def canonical_host(netloc: str) -> str:
    """One host spelling, for every part of the program that reads one.

    A host has several spellings that name the same machine: case
    (`GITHUB.com`), the root-label dot (`github.com.`), the default port
    (`github.com:443`) and userinfo (`user@github.com`). Each subsystem
    normalised a different subset, so they disagreed - `classify_url`
    lowercased the host for the raw-hosting check and then handed the
    *raw* URL to the suffix extractor, which is why `https://GITHUB.com/…`
    classified as `unknown` while the lowercase form classified as
    `trusted_forge`.

    Novelty had the mirror of the same problem: five spellings of one
    resource are five first-seen events, so a maintainer rotating the
    spelling never accumulates history.
    """
    host = netloc
    if "@" in host:
        host = host.rsplit("@", 1)[1]
    if host.startswith("["):
        # IPv6 literal: the brackets end the host, a colon after them is
        # the port.
        close = host.find("]")
        if close != -1:
            host = host[: close + 1] + host[close + 1:].split(":", 1)[0]
    elif ":" in host:
        host, _, port = host.partition(":")
        if port not in ("", "80", "443"):
            host = f"{host}:{port}"
    return host.rstrip(".").lower()


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

# Reverse map: confusable character → the ASCII it reads as.  R013b uses it
# to check whether a script-mixed label is confusable with a configured
# popular domain, not merely script-mixed.
_CONFUSABLE_TO_LATIN = {conf: latin for latin, conf in CONFUSABLES.items()}

# Fullwidth Latin (U+FF01-U+FF5E) folds onto ASCII by a fixed offset of
# 0xFEE0.  It is a whole homoglyph alphabet rather than the handful of
# lookalikes the configured table lists, and a command word written in it -
# `ｃｕｒｌ` - renders as the real name and executes as a name that does not
# exist. Generated rather than enumerated: the mapping is arithmetic, and
# writing out ninety-four entries invites one of them to go missing.
_CONFUSABLE_TO_LATIN.update(
    {chr(cp): chr(cp - 0xFEE0) for cp in range(0xFF01, 0xFF5F)}
)

# Memoized confusable-target set (config rarely changes mid-process).
_confusable_targets_cache: frozenset[str] | None = None

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


def _confusable_targets(confusable_domains=None) -> frozenset[str]:
    """Return the configured homoglyph target domains, lowercased."""
    global _confusable_targets_cache
    if confusable_domains is not None:
        return frozenset(d.lower() for d in confusable_domains)
    if _confusable_targets_cache is None:
        from .config import DEFAULT_CONFUSABLE_DOMAINS
        hosts = load_hosts().get("hosts", {})
        _confusable_targets_cache = frozenset(
            d.lower() for d in
            (hosts.get("confusable_domains") or DEFAULT_CONFUSABLE_DOMAINS)
        )
    return _confusable_targets_cache


def has_homograph(domain: str, confusable_domains=None) -> bool:
    """Detect confusable characters in a domain (R013b).

    Two conditions must both hold for a label to be a homoglyph:

    - the label mixes scripts within itself (e.g. Cyrillic ``о`` inside a
      Latin label), and
    - normalizing its confusable characters to ASCII yields a configured
      popular target domain (``[hosts] confusable_domains``).

    Single-script labels (``münchen.de``, ``café.fr``) and script mixes
    that read as nothing configured are legitimate internationalised
    domains and never fire.
    """
    host = domain.split("@")[-1].split(":")[0]
    mixed = False
    for raw_label in host.split("."):
        if not raw_label:
            continue
        label = _decode_punycode(raw_label)
        scripts = {_script_of(ch) for ch in label} - {"COMMON"}
        if len(scripts) > 1 and not any(
            scripts <= group for group in _COMPATIBLE_GROUPS
        ):
            mixed = True
            break
    if not mixed:
        return False

    decoded = [_decode_punycode(label) for label in host.split(".")]
    normalized = ".".join(
        "".join(_CONFUSABLE_TO_LATIN.get(ch, ch) for ch in label)
        for label in decoded
    )
    for target in _confusable_targets(confusable_domains):
        if normalized == target or normalized.endswith("." + target):
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


#: A hostname's real limits, from DNS: 253 bytes total, 127 labels, 63 bytes
#: per label. A `source=` URL is attacker-written, and nothing past these is
#: a hostname anyone can resolve - but classification walked every label and
#: computed every parent domain, which is quadratic in label count. One
#: 8 KiB host of dots cost 421 ms, and the extraction cap allows 4,096 URLs
#: per side, so a single package could spend half an hour here. A14 says no
#: package-controlled input decides how much CPU this process uses.
MAX_HOST_BYTES = 253
MAX_HOST_LABELS = 127


def _bounded_host(domain: str) -> str:
    """*domain* truncated to what DNS permits.

    Truncating rather than refusing: an over-length host still classifies,
    it simply classifies on the part that could be real. The alternative -
    returning early - would let a padded host skip the homograph check.
    """
    # Kept from the *right*. The registrable domain is the rightmost labels,
    # and it is the part every classification decision reads; truncating from
    # the left would throw it away and turn `a.a....example.com` into a host
    # with no recognisable suffix at all.
    labels = domain.split(".")
    if len(labels) > MAX_HOST_LABELS:
        labels = labels[-MAX_HOST_LABELS:]
        domain = ".".join(labels)
    while len(domain) > MAX_HOST_BYTES and len(labels) > 1:
        labels = labels[1:]
        domain = ".".join(labels)
    return domain[-MAX_HOST_BYTES:] if len(domain) > MAX_HOST_BYTES else domain


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
    domain = _bounded_host(canonical_host(parsed.netloc))

    if has_homograph(domain):
        return "homograph_attack", domain

    raw_hosting, trusted_forges, official = prepared

    if domain in raw_hosting:
        return "raw_hosting", domain

    # The registered domain is only needed for the forge comparison, and
    # computing it is the expensive part of this function.
    #
    # The *canonical* host, not the raw URL: handing the raw one over is
    # what made `GITHUB.com` produce `GITHUB.com` as its registrable
    # domain, which matches nothing in a lowercase configuration set.
    extracted = _extract(domain.split(":", 1)[0])
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
