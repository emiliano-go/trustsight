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
