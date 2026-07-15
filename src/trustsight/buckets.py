from urllib.parse import urlparse

import tldextract

from .config import load_domains


def classify_url(url: str, domain_config: dict | None = None) -> tuple[str, str]:
    if domain_config is None:
        domain_config = load_domains()

    parsed = urlparse(url)
    domain = parsed.netloc.lower()

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
