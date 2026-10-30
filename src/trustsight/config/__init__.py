"""config.py facade."""

import copy
import logging
import os
import re
from pathlib import Path
import tomllib
from ._default_config import (
    DEFAULT_BASELINE_TAG,
    DEFAULT_CONFIG,
    DEFAULT_HOSTS,
    DEFAULT_IOCS,
    DEFAULT_IOC_TAG,
    DEFAULT_NAMING,
    DEFAULT_NOVELTY_WEIGHTS,
    DEFAULT_PATTERNS,
    DEFAULT_RELEASE_CHANNEL,
    DEFAULT_RELEASE_KEY,
    DEFAULT_SOURCE_DIVERGENCE_ALLOW,
    DEFAULT_THRESHOLDS,
    DEFAULT_WATCHLIST_TAG,
    STRUCTURAL_MATCHES,
    STRUCTURAL_SEVERITY_CEILING,
    _STRUCTURAL_CLAMPED,
    _toml_escape_str,
    _toml_str_list,
    _toml_value,
)
from ._default_rules import (
    DEFAULT_DOMAINS,
    DEFAULT_RULES,
    INT_WEIGHT_GROUPS,
    KNOWN_BOOL_KEYS,
    LEGACY_DEFAULT_REVIEW_LIMIT,
    LEGACY_IOCS_STUBS,
    SHIPPED_RULESET_VERSION,
    _SEMANTIC_FIELDS,
)
from ._defaults_executor import (
    ANY_EXECUTOR,
    CATALOGUED_FETCH_ALTERNATIVES,
    DECOMPRESSOR,
    DEFAULT_ANTI_ANALYSIS_PROBES,
    DEFAULT_CONFUSABLE_CHARS,
    DEFAULT_CONFUSABLE_DOMAINS,
    DEFAULT_COVERT_EGRESS_CLIENTS,
    DEFAULT_COVERT_EGRESS_ENDPOINTS,
    DEFAULT_ECOSYSTEM_PREFIXES,
    DEFAULT_FOREIGN_PKG_MANAGERS,
    DEFAULT_FREE_HOSTING_DOMAINS,
    DEFAULT_FREE_REGISTRAR_TLDS,
    DEFAULT_H029_MIN_OBSERVATIONS,
    DEFAULT_H029_PLAIN_MIN_OBSERVATIONS,
    DEFAULT_KNOWN_SUFFIXES,
    DEFAULT_MANIFEST_FILENAMES,
    DEFAULT_NETWORK_TOOLS,
    DEFAULT_OBFUSCATION_INDICATORS,
    DEFAULT_PARSE_TIME_FETCH,
    DEFAULT_PASTE_HOSTS,
    DEFAULT_RECON_COMMANDS,
    DEFAULT_SECURITY_RELEVANT_FLAGS,
    DEFAULT_SECURITY_RELEVANT_LIBRARIES,
    DEFAULT_SOURCE_SCHEMES,
    DEFAULT_STANDARD_PORTS,
    DEFAULT_UPLOAD_FLAGS,
    DEFAULT_VARIANT_SUFFIXES,
    EXEC_WRAPPER,
    GETENT_ENUMERATION_FRAGMENT,
    H067_LEGACY_SYSTEMD_DETECT_VIRT as H067_LEGACY_SYSTEMD_DETECT_VIRT,
    H067_SYSTEMD_DETECT_VIRT_PROBE as H067_SYSTEMD_DETECT_VIRT_PROBE,
    LEGACY_FOREIGN_PKG_MANAGER_LISTS,
    LEGACY_NETWORK_TOOL_LISTS,
    LEGACY_NETWORK_TOOLS,
    NETWORK_CLIENT,
    NETWORK_CLIENT_ALTERNATIVES,
    OTHER_FETCH_CLIENT,
    PACKAGE_MANAGER_INSTALL,
    PAYLOAD_PRODUCER,
    SCRIPT_EXECUTOR,
    SHELL_EXECUTOR,
    STRUCTURED_EXTRACTOR,
    _SUBCOMMAND_OPTS,
)

_log = logging.getLogger(__name__)
_DOMAIN_TABLE_CACHE = None

from ._legacy import (  # noqa: E402,F401
    _LEGACY_REVIEW_LIMIT_RE,
    _refresh_legacy_anti_analysis_probes,
    _refresh_legacy_foreign_pkg_managers,
    _refresh_legacy_iocs,
    _refresh_legacy_network_tools,
    _refresh_legacy_recon_commands,
    _refresh_legacy_review_limit,
)
from ._release import (  # noqa: E402,F401
    _PARSE_WARNED,
    _release_section,
    _warn_unparsable_config,
    configured_baseline_tag,
    configured_ioc_tag,
    configured_release_channel,
    configured_release_key,
    configured_watchlist_tag,
)
from ._rule_sync import (  # noqa: E402,F401
    LEGACY_RULE_PATTERNS,
    _replace_rule_block,
    _rule_blocks,
    _shipped_rule_fields,
    drifted_shipped_rules,
    missing_shipped_rules,
    outdated_shipped_rules,
    sync_rules,
)

CONFIG_DIR = Path.home() / ".config" / "trustsight"

DATA_DIR = Path.home() / ".local" / "share" / "trustsight"

CACHE_DIR = Path.home() / ".cache" / "trustsight" / "repos"

def ensure_dirs():
    """Create config, data, and cache directories if missing.

    Created 0700: the database and the config can carry package names,
    maintainers and analysis history, none of which belong to other local
    users.  An explicit chmod follows the mkdir because the mode argument is
    masked by the umask.
    """
    for d in (CONFIG_DIR, DATA_DIR, CACHE_DIR):
        d.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            os.chmod(d, 0o700)
        except OSError:
            pass

def ensure_default_configs():
    """Write default config files if they do not exist, and add missing shipped rules."""
    ensure_dirs()
    write_default_file(CONFIG_DIR / "config.toml", DEFAULT_CONFIG)
    write_default_file(CONFIG_DIR / "rules.toml", DEFAULT_RULES)
    write_default_file(CONFIG_DIR / "trusted_domains.toml", DEFAULT_DOMAINS)
    write_default_file(CONFIG_DIR / "hosts.toml", DEFAULT_HOSTS)
    write_default_file(CONFIG_DIR / "patterns.toml", DEFAULT_PATTERNS)
    write_default_file(CONFIG_DIR / "naming.toml", DEFAULT_NAMING)
    write_default_file(CONFIG_DIR / "thresholds.toml", DEFAULT_THRESHOLDS)
    write_default_file(CONFIG_DIR / "iocs.toml", DEFAULT_IOCS)
    _refresh_legacy_iocs()
    _refresh_legacy_recon_commands()
    _refresh_legacy_anti_analysis_probes()
    _refresh_legacy_network_tools()
    _refresh_legacy_foreign_pkg_managers()
    _refresh_legacy_review_limit()
    # Append any shipped rules the user's file is missing.  The file is
    # written once at install time, so an older install can lack rules
    # that shipped after it.  Appending is always safe; replacements
    # require an explicit `config sync-rules`.
    added, _updated = sync_rules()
    if added:
        _log.info("added %d missing shipped rule(s) to rules.toml", len(added))

_toml_cache: dict[str, tuple[tuple, dict]] = {}

def load_toml(name: str, copy_result: bool = True) -> dict:
    """Load and parse a TOML file from the config directory.

    *copy_result* may be set False only by an accessor whose callers treat
    the result as read-only.  The deepcopy is not free: the analysis path
    asks for these tables several times per diff, and copying them was
    about 6% of a corpus scan.  ``load_rules`` keeps the copy because
    ``apply_rules`` really does assign to ``rule["pattern"]`` for the three
    generated patterns, and ``load_config`` keeps it because it is handed
    to every caller in the program.
    """
    path = CONFIG_DIR / name
    if not path.exists():
        ensure_default_configs()
    try:
        st = path.stat()
        stamp = (str(path), st.st_mtime_ns, st.st_size)
    except OSError:
        stamp = None
    if stamp is not None:
        cached = _toml_cache.get(name)
        if cached is not None and cached[0] == stamp:
            # Callers treat this as their own dict and some of them edit it
            # (overriding a rule toggle, say), so handing out the cached
            # object itself would let one caller's edit reach every later
            # one.  Copying is still an order of magnitude cheaper than
            # re-reading and re-parsing the file.
            return copy.deepcopy(cached[1]) if copy_result else cached[1]
    with open(path, "rb") as f:
        data = tomllib.load(f)
    if stamp is not None:
        _toml_cache[name] = (stamp, copy.deepcopy(data))
    return data

def set_config(key: str, value: str):
    """Set a config key to a new value in config.toml"""
    if key in KNOWN_BOOL_KEYS:
        if value.strip().lower() in ("true", "1", "yes", "on"):
            value = "true"
        elif value.strip().lower() in ("false", "0", "no", "off"):
            value = "false"
        else:
            raise ValueError(
                f"{key} expects true or false, got {value!r}"
            )
    else:
        section = key.split(".", 1)[0] if "." in key else ""
        if section not in INT_WEIGHT_GROUPS:
            raise ValueError(
                f"unknown config key {key!r}; set seed.auto_import, "
                "rules.experimental, or a weight in "
                + ", ".join(INT_WEIGHT_GROUPS)
            )
        try:
            value = str(int(value))
        except ValueError:
            raise ValueError(
                f"weight {key} expects an integer, got {value!r}"
            ) from None
    path = CONFIG_DIR / "config.toml"
    if not path.exists():
        ensure_default_configs()
    text = path.read_text()
    section_path = key.rsplit(".", 1)
    section = section_path[0] if len(section_path) > 1 else ""
    key_name = section_path[-1] if len(section_path) > 1 else key

    if section:
        header = f"[{section}]"
        if header in text:
            new_text = []
            in_section = False
            replaced = False
            for line in text.splitlines(keepends=True):
                stripped = line.strip()
                if stripped == header:
                    in_section = True
                    new_text.append(line)
                    continue
                if in_section:
                    if stripped.startswith("["):
                        in_section = False
                        if not replaced:
                            new_text.append(f'{key_name} = {_toml_value(value)}\n')
                            replaced = True
                        new_text.append(line)
                        continue
                    if stripped.startswith(f"{key_name} ") or stripped.startswith(f"{key_name}="):
                        new_text.append(f'{key_name} = {_toml_value(value)}\n')
                        replaced = True
                        continue
                    new_text.append(line)
                    continue
                new_text.append(line)
            if not replaced:
                new_text.append(f'{key_name} = {_toml_value(value)}\n')
            text = "".join(new_text)
        else:
            text += f"\n{header}\n{key_name} = {_toml_value(value)}\n"
    else:
        pattern = re.compile(rf"^{re.escape(key_name)}\s*=\s*.*", re.MULTILINE)
        if pattern.search(text):
            text = pattern.sub(f'{key_name} = {_toml_value(value)}', text)
        else:
            text += f'\n{key_name} = {_toml_value(value)}\n'

    path.write_text(text)

def load_config() -> dict:
    """Load the user config.toml"""
    return load_toml("config.toml")

_shipped_rules_cache: list[dict] | None = None

def shipped_rules() -> list[dict]:
    """The rule set this build ships, parsed from ``DEFAULT_RULES``.

    Read-only reference: it is what ``rules.toml`` is written from, and
    what the FATAL integrity check compares an on-disk file against.
    """
    global _shipped_rules_cache
    if _shipped_rules_cache is None:
        _shipped_rules_cache = tomllib.loads(DEFAULT_RULES).get("rules", [])
    return _shipped_rules_cache

def shipped_fatal_rule_ids() -> list[str]:
    """Ids of the shipped rules whose severity is FATAL.

    Derived, never hardcoded: a rule promoted to FATAL is protected the
    moment it ships, and the docs and the security gates read this list
    rather than restating it.
    """
    return [r["id"] for r in shipped_rules() if r.get("severity") == "FATAL"]

def enforce_fatal_rules(rules: list[dict]) -> tuple[list[dict], list[str]]:
    """Restore any shipped FATAL rule the on-disk file dropped or downgraded.

    ``rules.toml`` is user-editable, which is the point: an operator must
    be able to tune a noisy pattern.  What they must not be able to do,
    quietly, is switch off the two rules an attacker would most want gone.
    Prompt injection and unicode deception target the *reviewer*, not the
    machine, so a run that skips them is not a tuned run, it is a run whose
    output cannot be trusted at all - and ``override.py`` already refuses
    to suppress a FATAL finding for exactly that reason.  Enforcing it at
    load time closes the other half: deleting the rule instead of
    overriding its finding.

    The restore is in memory only.  Nothing is written back, so a user who
    edited the file still has their file; they just do not get an analysis
    that pretends the rule was never there.  Returns the effective rule
    list and the ids that had to be restored.
    """
    by_id = {r.get("id"): r for r in rules}
    restored: list[str] = []
    effective = list(rules)
    for shipped in shipped_rules():
        if shipped.get("severity") != "FATAL":
            continue
        rid = shipped["id"]
        on_disk = by_id.get(rid)
        if on_disk is None:
            effective.append(dict(shipped))
            restored.append(rid)
        elif on_disk.get("severity") != "FATAL":
            effective[effective.index(on_disk)] = dict(shipped)
            restored.append(rid)
    return effective, restored

def load_rules() -> list[dict]:
    """Load rules from rules.toml, applying per-rule config.toml controls.

    ``[rules.R001]`` controls apply only to rules defined in rules.toml,
    which since the R/H split is every ``R`` id and no other: an ``H`` rule
    is a heuristic emitted from an analysis module, has no TOML definition,
    and intentionally keeps its own configuration paths.
    """
    data = load_toml("rules.toml")
    rules, restored = enforce_fatal_rules(data.get("rules", []))
    controls = load_config().get("rules", {})
    for rule in rules:
        control = controls.get(rule.get("id"), {})
        if not isinstance(control, dict):
            continue
        for key in ("enabled", "weight_override"):
            if key in control:
                rule[key] = control[key]
        if rule.get("severity") == "FATAL" and rule.get("enabled") is False:
            rule["enabled"] = True
            _log.warning("refusing to disable FATAL rule %s", rule["id"])
    if restored:
        _log.warning(
            "rules.toml is missing or has downgraded FATAL rule(s) %s; "
            "the shipped definition is being used instead",
            ", ".join(restored),
        )
    return rules

def clamp_structural_severity(severity: str) -> str:
    """Return *severity* capped at :data:`STRUCTURAL_SEVERITY_CEILING`."""
    return _STRUCTURAL_CLAMPED.get(severity, severity)

def load_structural_rules(on_skip=None) -> list[dict]:
    """Load ``[[structural]]`` recipe rules from rules.toml.

    The table is user-only: it ships empty and is never synced, so the
    entries on disk are the only ones that exist.  A malformed entry is
    skipped and logged rather than failing a whole analysis; ``trustsight
    lint-rules`` reports the same conditions as errors.  ``[rules.R###]``
    controls in ``config.toml`` apply by id, exactly as for a line rule.

    *on_skip* is called with the skipped rule's id when an entry is
    dropped.  An analysis passes a callback that marks the run degraded,
    so an operator's broken rule shrinks the detection surface loudly
    instead of silently.
    """
    raw = load_toml("rules.toml").get("structural", [])
    controls = load_config().get("rules", {})
    rules: list[dict] = []

    def skipped(label: str) -> None:
        if on_skip is not None:
            on_skip(label)

    for entry in raw:
        if not isinstance(entry, dict):
            _log.warning("ignoring non-table structural rule %r", entry)
            skipped("unparsed")
            continue
        rule = dict(entry)
        rid = rule.get("id")
        match = rule.get("match")
        field = rule.get("field")
        pattern = rule.get("pattern")
        if not (isinstance(rid, str) and rid and isinstance(match, str)
                and isinstance(field, str) and field
                and isinstance(pattern, str) and pattern):
            _log.warning("ignoring structural rule with missing fields: %r", rule)
            skipped(str(rid or "unidentified"))
            continue
        if match not in STRUCTURAL_MATCHES:
            _log.warning("ignoring structural rule %s: unknown match %r", rid, match)
            skipped(rid)
            continue
        is_scalar = field.startswith("scalars.")
        if is_scalar != (match == "scalar_changed"):
            _log.warning(
                "ignoring structural rule %s: match %r does not apply to field %r",
                rid, match, field,
            )
            skipped(rid)
            continue
        severity = str(rule.get("severity") or "MEDIUM")
        if severity in _STRUCTURAL_CLAMPED:
            _log.warning(
                "capping structural rule %s severity %s at %s",
                rid, severity, STRUCTURAL_SEVERITY_CEILING,
            )
            severity = _STRUCTURAL_CLAMPED[severity]
        rule["severity"] = severity
        if not rule.get("name"):
            rule["name"] = rid
        if not rule.get("category"):
            rule["category"] = "structural"
        control = controls.get(rid, {})
        if isinstance(control, dict):
            for key in ("enabled", "weight_override"):
                if key in control:
                    rule[key] = control[key]
        rules.append(rule)
    return rules

#: IPv4 literals that name a non-routable address: loopback, the RFC1918
#: blocks, the link-local block and the unspecified address.  Such a host
#: resolves only on the machine reading the recipe, so it can never be a
#: distribution source; R046/R047 must not read a URL a recipe merely
#: *printed* (a local admin console) as a source.  Kept in step with
#: ``buckets.host_is_non_routable``, which the code paths call.

from ._domains import (  # noqa: E402,F401
    _NON_ROUTABLE_IPV4,
    _non_routable_lookahead,
    _ip_url_pattern,
    _standard_port_pattern,
    _free_registrar_tld_pattern,
    _free_hosting_pattern,
    _DEFAULT_DOMAIN_TABLE,
    _DOMAIN_TABLE_CACHE,
    _merge_shipped_domains,
    load_domains,
    load_patterns,
    load_naming,
    load_hosts,
    load_thresholds,
    load_iocs,
    load_ioc_sources,
    config_fingerprint,
    _review_policy_material,
)

from ._paths import (  # noqa: E402,F401
    _RULESET_VERSION_RE,
    local_ruleset_version,
    ruleset_age_drift,
    write_default_file,
)

__all__ = ['ANY_EXECUTOR', 'CACHE_DIR', 'CATALOGUED_FETCH_ALTERNATIVES', 'CONFIG_DIR', 'DATA_DIR', 'DECOMPRESSOR', 'DEFAULT_ANTI_ANALYSIS_PROBES', 'DEFAULT_BASELINE_TAG', 'DEFAULT_CONFIG', 'DEFAULT_CONFUSABLE_CHARS', 'DEFAULT_CONFUSABLE_DOMAINS', 'DEFAULT_COVERT_EGRESS_CLIENTS', 'DEFAULT_COVERT_EGRESS_ENDPOINTS', 'DEFAULT_DOMAINS', 'DEFAULT_ECOSYSTEM_PREFIXES', 'DEFAULT_FOREIGN_PKG_MANAGERS', 'DEFAULT_FREE_HOSTING_DOMAINS', 'DEFAULT_FREE_REGISTRAR_TLDS', 'DEFAULT_H029_MIN_OBSERVATIONS', 'DEFAULT_H029_PLAIN_MIN_OBSERVATIONS', 'DEFAULT_HOSTS', 'DEFAULT_IOCS', 'DEFAULT_IOC_TAG', 'DEFAULT_KNOWN_SUFFIXES', 'DEFAULT_MANIFEST_FILENAMES', 'DEFAULT_NAMING', 'DEFAULT_NETWORK_TOOLS', 'DEFAULT_NOVELTY_WEIGHTS', 'DEFAULT_OBFUSCATION_INDICATORS', 'DEFAULT_PARSE_TIME_FETCH', 'DEFAULT_PASTE_HOSTS', 'DEFAULT_PATTERNS', 'DEFAULT_RECON_COMMANDS', 'DEFAULT_RELEASE_CHANNEL', 'DEFAULT_RELEASE_KEY', 'DEFAULT_RULES', 'DEFAULT_SECURITY_RELEVANT_FLAGS', 'DEFAULT_SECURITY_RELEVANT_LIBRARIES', 'DEFAULT_SOURCE_DIVERGENCE_ALLOW', 'DEFAULT_SOURCE_SCHEMES', 'DEFAULT_STANDARD_PORTS', 'DEFAULT_THRESHOLDS', 'DEFAULT_UPLOAD_FLAGS', 'DEFAULT_VARIANT_SUFFIXES', 'DEFAULT_WATCHLIST_TAG', 'EXEC_WRAPPER', 'GETENT_ENUMERATION_FRAGMENT', 'INT_WEIGHT_GROUPS', 'KNOWN_BOOL_KEYS', 'LEGACY_DEFAULT_REVIEW_LIMIT', 'LEGACY_IOCS_STUBS', 'LEGACY_FOREIGN_PKG_MANAGER_LISTS', 'LEGACY_NETWORK_TOOL_LISTS', 'LEGACY_NETWORK_TOOLS', 'LEGACY_RULE_PATTERNS', 'NETWORK_CLIENT', 'NETWORK_CLIENT_ALTERNATIVES', 'OTHER_FETCH_CLIENT', 'PACKAGE_MANAGER_INSTALL', 'PAYLOAD_PRODUCER', 'Path', 'SCRIPT_EXECUTOR', 'SHELL_EXECUTOR', 'SHIPPED_RULESET_VERSION', 'STRUCTURAL_MATCHES', 'STRUCTURAL_SEVERITY_CEILING', 'STRUCTURED_EXTRACTOR', '_LEGACY_REVIEW_LIMIT_RE', '_RULESET_VERSION_RE', '_SEMANTIC_FIELDS', '_STRUCTURAL_CLAMPED', '_SUBCOMMAND_OPTS', '_free_hosting_pattern', '_free_registrar_tld_pattern', '_log', '_refresh_legacy_iocs', '_refresh_legacy_recon_commands', '_refresh_legacy_review_limit', '_replace_rule_block', '_review_policy_material', '_rule_blocks', '_shipped_rule_fields', '_shipped_rules_cache', '_standard_port_pattern', '_toml_cache', '_toml_escape_str', '_toml_str_list', '_toml_value', 'clamp_structural_severity', 'config_fingerprint', 'configured_baseline_tag', 'configured_release_channel', 'configured_release_key', 'configured_ioc_tag', 'configured_watchlist_tag', 'copy', 'drifted_shipped_rules', 'enforce_fatal_rules', 'ensure_default_configs', 'ensure_dirs', 'load_config', 'load_domains', 'load_hosts', 'load_ioc_sources', 'load_iocs', 'load_naming', 'load_patterns', 'load_rules', 'load_structural_rules', 'load_thresholds', 'load_toml', 'local_ruleset_version', 'logging', 'missing_shipped_rules', 'os', 'outdated_shipped_rules', 're', 'ruleset_age_drift', 'set_config', 'shipped_fatal_rule_ids', 'shipped_rules', 'sync_rules', 'tomllib', 'write_default_file']
