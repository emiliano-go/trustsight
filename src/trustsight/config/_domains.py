"""Domain, pattern and fingerprint loaders."""

import hashlib
import json
import re
import tomllib

from . import _log
from ._default_rules import DEFAULT_DOMAINS
from ._defaults_executor import (
    DEFAULT_FREE_HOSTING_DOMAINS,
    DEFAULT_FREE_REGISTRAR_TLDS,
    DEFAULT_STANDARD_PORTS,
)


def load_toml(*args, **kwargs):
    from . import load_toml as _load
    return _load(*args, **kwargs)


def load_config(*args, **kwargs):
    from . import load_config as _load
    return _load(*args, **kwargs)


def load_rules(*args, **kwargs):
    from . import load_rules as _load
    return _load(*args, **kwargs)


def load_structural_rules(*args, **kwargs):
    from . import load_structural_rules as _load
    return _load(*args, **kwargs)


_NON_ROUTABLE_IPV4 = (
    r"127\.", r"10\.", r"192\.168\.",
    r"172\.(?:1[6-9]|2\d|3[01])\.", r"169\.254\.", r"0\.0\.0\.0",
)


def _non_routable_lookahead() -> str:
    return "(?!(?:" + "|".join(_NON_ROUTABLE_IPV4) + "))"


def _ip_url_pattern() -> str:
    """Generate the R046 raw-IP pattern, non-routable hosts excluded."""
    return (
        "https?://" + _non_routable_lookahead()
        + r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    )


def _standard_port_pattern() -> str:
    """Generate the R047 non-standard-port exclusion pattern from config."""
    hosts = load_hosts().get("hosts", {})
    cfg = load_config()
    ports = (
        hosts.get("standard_ports")
        or cfg.get("ports", {}).get("standard")
        or DEFAULT_STANDARD_PORTS
    )
    # Escaped: these come from hosts.toml, which is a *list*, not a
    # pattern language.  An unescaped entry silently becomes regex - at
    # best a broken rule, at worst one that matches everything or nothing.
    joined = "|".join(re.escape(str(p)) for p in ports)
    return (
        "https?://" + _non_routable_lookahead()
        + f'[^/\\s:]+:(?!(?:{joined})(?:[/\\s"\\x27]|$))\\d{{2,5}}'
    )

def _free_registrar_tld_pattern() -> str:
    """Generate the R048 free-registrar-TLD pattern from config."""
    hosts = load_hosts().get("hosts", {})
    cfg = load_config()
    tlds = (
        hosts.get("free_registrar_tlds")
        or cfg.get("domains", {}).get("free_registrar_tlds")
        or DEFAULT_FREE_REGISTRAR_TLDS
    )
    joined = "|".join(re.escape(str(t)) for t in tlds)
    return f'https?://[^/\\s]*\\.(?:{joined})(?:[:/]|["\\x27\\s)]|$)'

def _free_hosting_pattern() -> str:
    """Generate the R152 free-hosting / dynamic-DNS / tunnel pattern.

    The providers are multi-label suffixes (``evil.duckdns.org``), so the
    leading ``\\.`` is what makes this a subdomain match rather than a
    substring one: ``duckdns.org.evil.com`` must not fire.
    """
    hosts = load_hosts().get("hosts", {})
    cfg = load_config()
    domains = (
        hosts.get("free_hosting_domains")
        or cfg.get("domains", {}).get("free_hosting_domains")
        or DEFAULT_FREE_HOSTING_DOMAINS
    )
    joined = "|".join(re.escape(str(d)) for d in domains)
    return f'https?://[^/\\s]*\\.(?:{joined})(?:[:/]|["\\x27\\s)]|$)'

#: The shipped trust tables, parsed once.  ``trusted_domains.toml`` is written
#: on first install and never rewritten, so an older file is missing every
#: host a later release added.  Treating the user's file as an overlay on these
#: defaults keeps the effective table current; the file stays the place the
#: operator adds their own entries.
_DEFAULT_DOMAIN_TABLE = tomllib.loads(DEFAULT_DOMAINS)
_DOMAIN_TABLE_CACHE: tuple[tuple, dict] | None = None


def _merge_shipped_domains(user: dict) -> dict:
    """Union the shipped domain lists under the user's file.

    Shipped entries are appended when the user's section omits them; user
    entries keep their order and win on duplicates.  Sections the user added
    are preserved verbatim.
    """
    merged: dict = {}
    for section, table in _DEFAULT_DOMAIN_TABLE.items():
        values = list(table.get("domains", ()))
        for value in user.get(section, {}).get("domains", ()):
            if value not in values:
                values.append(value)
        merged[section] = {**table, "domains": values}
    for section, table in user.items():
        merged.setdefault(section, table)
    return merged


def load_domains() -> dict:
    """Load trusted domains from trusted_domains.toml, filled from defaults.

    The on-disk file is a user overlay, not a full replacement: a file written
    by an older release lacks the hosts later releases classified.  Merging at
    read time is what keeps those hosts from scoring ``unknown`` forever.  The
    result is cached by ``(path, mtime, size)`` because classification asks
    for it per URL.
    """
    import sys
    config_mod = sys.modules[__package__]
    user = load_toml("trusted_domains.toml", copy_result=False)
    path = config_mod.CONFIG_DIR / "trusted_domains.toml"
    try:
        st = path.stat()
        stamp: tuple = (str(path), st.st_mtime_ns, st.st_size)
    except OSError:
        stamp = ()
    cache = getattr(config_mod, "_DOMAIN_TABLE_CACHE", None)
    if cache is not None and cache[0] == stamp:
        return cache[1]
    merged = _merge_shipped_domains(user)
    missing = sorted(
        f"{section}:{domain}"
        for section, table in _DEFAULT_DOMAIN_TABLE.items()
        for domain in table.get("domains", ())
        if domain not in user.get(section, {}).get("domains", ())
    )
    if missing:
        _log.info(
            "trusted_domains.toml is missing %d shipped entr%s; using the "
            "shipped defaults beside the user's entries: %s",
            len(missing), "y" if len(missing) == 1 else "ies",
            ", ".join(missing),
        )
    config_mod._DOMAIN_TABLE_CACHE = (stamp, merged)
    return merged

def load_patterns() -> dict:
    """Load pattern tables from patterns.toml (H035/H036/D003)."""
    return load_toml("patterns.toml", copy_result=False)

def load_naming() -> dict:
    """Load naming tables from naming.toml (D002/D004/H029)."""
    return load_toml("naming.toml", copy_result=False)

def load_hosts() -> dict:
    """Load host tables from hosts.toml (R047/R048/H041)."""
    return load_toml("hosts.toml", copy_result=False)

def load_thresholds() -> dict:
    """Load thresholds from thresholds.toml (H036/H073/H074)."""
    return load_toml("thresholds.toml", copy_result=False)

def load_iocs() -> dict:
    """Load the versioned indicator list from iocs.toml (H056)."""
    return load_toml("iocs.toml", copy_result=False)

def load_ioc_sources() -> list[str]:
    """Return the configured IOC baseline source names to consult.

    An empty list means "all sources currently imported into the local
    database".  The ``[baselines.ioc]`` table may not exist on legacy
    installs; in that case the baseline stage runs against every source.
    """
    cfg = load_config()
    section = cfg.get("baselines", {}).get("ioc", {})
    sources = section.get("sources", [])
    if not sources:
        return []
    if isinstance(sources, str):
        return [sources]
    return [str(s).strip() for s in sources if str(s).strip()]

def config_fingerprint() -> str:
    """A digest of the instrument: ruleset, thresholds and overrides.

    B1's determinism is *algorithmic*, not configurational.  Two operators
    with different `rules.toml` get different scores by design, so "the
    same input always produces the same score" is only true holding the
    configuration fixed.  Publishing the fingerprint makes that precise:
    same input and same fingerprint must give the same number, and a
    different fingerprint is a different instrument rather than a
    nondeterministic one.

    Covers what can change a score: every rule's id, pattern, severity,
    match target and scope; the scoring weight tables; the thresholds; and
    the active overrides.  Cosmetic fields (a rule's prose description) are
    excluded, because editing a comment is not a different instrument.
    """

    def rule_key(rule: dict) -> dict:
        return {
            k: rule.get(k) for k in
            ("id", "pattern", "severity", "category", "match_target",
             "scope", "added_only", "include_comments", "experimental",
              "enabled", "weight_override", "exclude_if_matches",
              "escalates_when")
        }

    def structural_key(rule: dict) -> dict:
        return {
            k: rule.get(k) for k in
            ("id", "field", "match", "pattern", "severity", "category",
             "enabled", "weight_override")
        }

    import sys
    cfg_mod = sys.modules[__package__]
    config = cfg_mod.load_config()
    material = {
        "rules": sorted((rule_key(r) for r in cfg_mod.load_rules()),
                        key=lambda r: r.get("id") or ""),
        "structural_rules": sorted(
            (structural_key(r) for r in cfg_mod.load_structural_rules()),
            key=lambda r: r.get("id") or ""),
        "severity_weights": config.get("severity_weights", {}),
        "source_bucket_weights": config.get("source_bucket_weights", {}),
        "novelty_weights": config.get("novelty_weights", {}),
        # The trust tables decide which hosts are classified official/forge,
        # which in turn silences SOURCE_BUCKET and C011 for that host.  Two
        # operators with different effective tables are different instruments.
        "trusted_domains": cfg_mod.load_domains(),
        # C011's allowlist changes which prebuilt packages are reported, so
        # two operators with different lists are different instruments.
        "source_host_divergence": config.get("source_host_divergence", {}),
        # The selected review policy changes which reports are flagged, even
        # though it deliberately leaves score arithmetic unchanged.
        "review_policy": _review_policy_material(config),
        "thresholds": cfg_mod.load_thresholds(),
        "limits": config.get("limits", {}),
        "diff": config.get("diff", {}),
    }
    try:
        from ..override import load_overrides

        # TTL and the indicator cross-check change the effective ruleset (an
        # expired override no longer suppresses), so they belong in the
        # fingerprint beside the rule id and scope.
        material["overrides"] = sorted(
            (o.rule_id, o.package or "", int(o.ttl_observations or 0),
             bool(o.requires_clear_indicators))
            for o in load_overrides()
        )
    except Exception:
        material["overrides"] = []

    canonical = json.dumps(material, sort_keys=True, separators=(",", ":"),
                           default=str).encode()
    return "sha256:" + hashlib.sha256(canonical).hexdigest()

def _review_policy_material(config: dict) -> dict:
    """Return the non-arithmetic policy fields covered by the fingerprint."""
    from ..review_policy import review_policy

    policy = review_policy(config)
    return {"name": policy.name, "threshold": policy.threshold}
