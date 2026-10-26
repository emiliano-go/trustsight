import tomllib

from trustsight.config import (
    DEFAULT_THRESHOLDS,
    GETENT_ENUMERATION_FRAGMENT,
    configured_baseline_tag,
    configured_ioc_tag,
    ensure_default_configs,
    load_config,
    load_domains,
    load_patterns,
    load_rules,
)


def _cfg_dirs(tmp_path, monkeypatch):
    cfg_dir = tmp_path / ".config" / "trustsight"
    monkeypatch.setattr("trustsight.config.CONFIG_DIR", cfg_dir)
    monkeypatch.setattr(
        "trustsight.config.DATA_DIR", tmp_path / ".local" / "share" / "trustsight")
    monkeypatch.setattr(
        "trustsight.config.CACHE_DIR", tmp_path / ".cache" / "trustsight")
    return cfg_dir


def test_refresh_legacy_recon_commands_repairs_the_old_getent_fragment(
        tmp_path, monkeypatch):
    """Installs that predate the getent narrowing carry the old fragment in
    patterns.toml forever (the file is written once, never synced); the
    repair swaps the one line in place and leaves user edits alone."""
    import trustsight.config as config_module

    cfg_dir = _cfg_dirs(tmp_path, monkeypatch)
    ensure_default_configs()
    path = cfg_dir / "patterns.toml"
    new_line = "    \"" + GETENT_ENUMERATION_FRAGMENT.replace("\\", "\\\\") + "\",\n"
    old_line = "    \"(?:\\\\A\\\\s*|[;&|]\\\\s*)getent\\\\b\",\n"
    text = path.read_text()
    assert new_line in text
    path.write_text(text.replace(new_line, old_line))
    config_module._toml_cache.pop("patterns.toml", None)

    assert config_module._refresh_legacy_recon_commands() is True
    assert old_line not in path.read_text()
    assert "getent" in path.read_text()
    # The cache is invalidated so the next load sees the repair.
    assert any(
        "getent\\s+" in frag
        for frag in load_patterns()["patterns"]["recon_commands"]
    )
    # A second run is a no-op.
    assert config_module._refresh_legacy_recon_commands() is False


def test_refresh_legacy_recon_commands_preserves_custom_probes(
        tmp_path, monkeypatch):
    import trustsight.config as config_module

    cfg_dir = _cfg_dirs(tmp_path, monkeypatch)
    ensure_default_configs()
    path = cfg_dir / "patterns.toml"
    text = path.read_text()
    new_line = "    \"" + GETENT_ENUMERATION_FRAGMENT.replace("\\", "\\\\") + "\",\n"
    old_line = "    \"(?:\\\\A\\\\s*|[;&|]\\\\s*)getent\\\\b\",\n"
    text = text.replace(new_line, old_line)
    # A user-added probe alongside the stale fragment: the repair swaps
    # only the shipped line and keeps the customisation.
    text = text.replace(
        "recon_commands = [\n",
        "recon_commands = [\n    \"custom-probe\",\n", 1)
    path.write_text(text)
    config_module._toml_cache.pop("patterns.toml", None)
    assert config_module._refresh_legacy_recon_commands() is True
    repaired = path.read_text()
    assert "custom-probe" in repaired
    assert old_line not in repaired


def test_load_config_creates_default(tmp_path, monkeypatch):
    cfg_dir = tmp_path / ".config" / "trustsight"
    monkeypatch.setattr("trustsight.config.CONFIG_DIR", cfg_dir)
    data_dir = tmp_path / ".local" / "share" / "trustsight"
    monkeypatch.setattr("trustsight.config.DATA_DIR", data_dir)
    cache_dir = tmp_path / ".cache" / "trustsight"
    monkeypatch.setattr("trustsight.config.CACHE_DIR", cache_dir)

    config = load_config()
    assert "severity_weights" in config
    assert config["severity_weights"]["CRITICAL"] == 40
    assert config["severity_weights"]["HIGH"] == 25
    assert config["severity_weights"]["MEDIUM"] == 15
    assert config["severity_weights"]["LOW"] == 5
    assert "source_bucket_weights" in config
    assert "novelty_weights" in config
    # Calibrated after tier C became live; see
    # test_novelty_weights_keep_a_borderline_package_out_of_high.
    assert config["novelty_weights"]["url_first_globally"] == 10
    assert config["novelty_weights"]["maintainer_first_in_package"] == 15
    assert config["review"]["profile"] == "default"
    assert config["review"]["profiles"] == {"default": 20, "quiet": 40, "strict": 10}
    assert config["seed"]["baseline_tag"].startswith("baseline-")


def test_review_profiles_are_validated_and_change_the_fingerprint(monkeypatch):
    import trustsight.config as config_module
    import trustsight.review_policy as policy_module

    default = {"review": {"profile": "default"}}
    quiet = {"review": {"profile": "quiet"}}
    monkeypatch.setattr(policy_module, "load_config", lambda: default)
    assert policy_module.review_policy().threshold == 20
    assert policy_module.review_policy(quiet).threshold == 40
    assert policy_module.review_policy({"review": {"profile": "strict"}}).threshold == 10

    import pytest

    with pytest.raises(ValueError, match="review.profile"):
        policy_module.review_policy({"review": {"profile": "unknown"}})
    with pytest.raises(ValueError, match=r"\[review\]"):
        policy_module.review_policy({"review": "quiet"})
    with pytest.raises(ValueError, match="threshold"):
        policy_module.review_policy({"review": {"profiles": {"quiet": True}}})

    monkeypatch.setattr(config_module, "load_rules", lambda: [])
    monkeypatch.setattr(config_module, "load_thresholds", lambda: {})
    monkeypatch.setattr(config_module, "load_config", lambda: default)
    first = config_module.config_fingerprint()
    monkeypatch.setattr(config_module, "load_config", lambda: quiet)
    quiet_fingerprint = config_module.config_fingerprint()
    assert quiet_fingerprint != first
    monkeypatch.setattr(
        config_module, "load_config",
        lambda: {"review": {"profile": "quiet", "profiles": {"quiet": 35}}},
    )
    assert config_module.config_fingerprint() != quiet_fingerprint


def test_rule_suppression_changes_the_fingerprint(monkeypatch):
    import trustsight.config as config_module

    rule = {
        "id": "R017",
        "pattern": "chmod.*\\+s",
        "severity": "HIGH",
        "category": "privilege",
        "exclude_if_matches": ["R053"],
    }
    monkeypatch.setattr(config_module, "load_config", lambda: {})
    monkeypatch.setattr(config_module, "load_thresholds", lambda: {})
    monkeypatch.setattr(config_module, "load_rules", lambda: [rule])
    first = config_module.config_fingerprint()
    rule["exclude_if_matches"] = ["R059"]
    assert config_module.config_fingerprint() != first


def test_configured_baseline_tag_reads_without_creating_a_config(tmp_path, monkeypatch):
    """The release channel's fallback tag, read-only.

    ``asset_url`` runs during a download and must not create operator
    state, so an absent file returns the shipped default rather than
    writing one; an explicit empty value turns the fallback off.
    """
    from trustsight.config import DEFAULT_BASELINE_TAG

    cfg_dir = tmp_path / ".config" / "trustsight"
    monkeypatch.setattr("trustsight.config.CONFIG_DIR", cfg_dir)

    assert configured_baseline_tag() == DEFAULT_BASELINE_TAG
    assert not cfg_dir.exists()  # the lookup created nothing

    cfg_dir.mkdir(parents=True)
    (cfg_dir / "config.toml").write_text('[seed]\nbaseline_tag = "baseline-2026-09-24"\n')
    assert configured_baseline_tag() == "baseline-2026-09-24"

    (cfg_dir / "config.toml").write_text('[seed]\nbaseline_tag = ""\n')
    assert configured_baseline_tag() is None


def test_configured_ioc_tag_reads_without_creating_a_config(tmp_path, monkeypatch):
    """The dedicated IOC channel's fallback tag, read-only.

    An unset or empty ``[baselines.ioc] tag`` means "resolve the live
    channel"; an explicit value pins it.  The lookup never creates a config.
    """
    from trustsight.config import DEFAULT_IOC_TAG

    cfg_dir = tmp_path / ".config" / "trustsight"
    monkeypatch.setattr("trustsight.config.CONFIG_DIR", cfg_dir)

    assert configured_ioc_tag() == DEFAULT_IOC_TAG
    assert DEFAULT_IOC_TAG is None  # ships unset: resolve, do not pin
    assert not cfg_dir.exists()  # the lookup created nothing

    cfg_dir.mkdir(parents=True)
    (cfg_dir / "config.toml").write_text(
        '[baselines.ioc]\ntag = "ioc-2026-10-18"\n'
    )
    assert configured_ioc_tag() == "ioc-2026-10-18"

    (cfg_dir / "config.toml").write_text('[baselines.ioc]\ntag = ""\n')
    assert configured_ioc_tag() is None


def test_load_config_bucket_weights(tmp_path, monkeypatch):
    cfg_dir = tmp_path / ".config" / "trustsight"
    monkeypatch.setattr("trustsight.config.CONFIG_DIR", cfg_dir)
    monkeypatch.setattr("trustsight.config.DATA_DIR", tmp_path / ".local" / "share" / "trustsight")
    monkeypatch.setattr("trustsight.config.CACHE_DIR", tmp_path / ".cache" / "trustsight")

    config = load_config()
    weights = config["source_bucket_weights"]
    assert weights["trusted_forge"] == 0  # B10: reported, not credited
    assert weights["unknown"] == 20
    assert weights["raw_hosting"] == 15


def test_load_rules_creates_default(tmp_path, monkeypatch):
    cfg_dir = tmp_path / ".config" / "trustsight"
    monkeypatch.setattr("trustsight.config.CONFIG_DIR", cfg_dir)
    monkeypatch.setattr("trustsight.config.DATA_DIR", tmp_path / ".local" / "share" / "trustsight")
    monkeypatch.setattr("trustsight.config.CACHE_DIR", tmp_path / ".cache" / "trustsight")

    rules = load_rules()
    assert len(rules) >= 11
    rule_ids = [r["id"] for r in rules]
    assert "R001" in rule_ids
    assert "R002" in rule_ids
    assert "R003" in rule_ids
    assert "R007" in rule_ids
    assert "R012" in rule_ids
    assert "R013" in rule_ids


def test_load_rules_has_required_keys(tmp_path, monkeypatch):
    cfg_dir = tmp_path / ".config" / "trustsight"
    monkeypatch.setattr("trustsight.config.CONFIG_DIR", cfg_dir)
    monkeypatch.setattr("trustsight.config.DATA_DIR", tmp_path / ".local" / "share" / "trustsight")
    monkeypatch.setattr("trustsight.config.CACHE_DIR", tmp_path / ".cache" / "trustsight")

    rules = load_rules()
    for rule in rules:
        assert "id" in rule
        assert "pattern" in rule
        assert "severity" in rule
        assert "category" in rule
        assert "match_target" in rule
        assert rule["match_target"] in ("resolved", "raw_line")
        assert rule["severity"] in ("FATAL", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")


def test_per_rule_controls_apply_to_toml_defined_rules(tmp_path, monkeypatch):
    import trustsight.config as cfg

    monkeypatch.setattr(cfg, "CONFIG_DIR", tmp_path)
    cfg._toml_cache.clear()
    (tmp_path / "rules.toml").write_text(
        '[[rules]]\nid = "R900"\nname = "Test"\npattern = "test"\n'
        'severity = "LOW"\ncategory = "test"\nmatch_target = "raw_line"\n'
    )
    (tmp_path / "config.toml").write_text(
        "[rules.R900]\nenabled = false\nweight_override = 17\n"
    )

    rule = cfg.load_rules()[0]
    assert rule["enabled"] is False
    assert rule["weight_override"] == 17


def test_disabled_toml_rule_does_not_match():
    from trustsight.rules import apply_rules

    rules = [{
        "id": "R900", "name": "Test", "pattern": "payload",
        "severity": "LOW", "category": "test", "match_target": "raw_line",
        "enabled": False,
    }]
    assert apply_rules([], ["+payload"], rules) == []


def test_load_domains_creates_default(tmp_path, monkeypatch):
    cfg_dir = tmp_path / ".config" / "trustsight"
    monkeypatch.setattr("trustsight.config.CONFIG_DIR", cfg_dir)
    monkeypatch.setattr("trustsight.config.DATA_DIR", tmp_path / ".local" / "share" / "trustsight")
    monkeypatch.setattr("trustsight.config.CACHE_DIR", tmp_path / ".cache" / "trustsight")

    domains = load_domains()
    assert "trusted_forges" in domains
    assert "github.com" in domains["trusted_forges"]["domains"]
    assert "gitlab.com" in domains["trusted_forges"]["domains"]
    assert "sourceforge.net" in domains["trusted_forges"]["domains"]
    assert "freedesktop.org" in domains["trusted_forges"]["domains"]
    assert "official_projects" in domains
    assert "python.org" in domains["official_projects"]["domains"]
    assert "kernel.org" in domains["official_projects"]["domains"]
    assert "qoder-ide.oss-accelerate.aliyuncs.com" in (
        domains["official_projects"]["domains"])
    assert "raw_hosting" in domains
    assert "raw.githubusercontent.com" in domains["raw_hosting"]["domains"]
    assert "pastebin.com" in domains["raw_hosting"]["domains"]
    assert "downloader.disk.yandex.ru" in domains["raw_hosting"]["domains"]


def test_domains_not_empty(tmp_path, monkeypatch):
    cfg_dir = tmp_path / ".config" / "trustsight"
    monkeypatch.setattr("trustsight.config.CONFIG_DIR", cfg_dir)
    monkeypatch.setattr("trustsight.config.DATA_DIR", tmp_path / ".local" / "share" / "trustsight")
    monkeypatch.setattr("trustsight.config.CACHE_DIR", tmp_path / ".cache" / "trustsight")

    domains = load_domains()
    for category in ("trusted_forges", "official_projects", "raw_hosting"):
        assert len(domains[category]["domains"]) > 0


def test_ensure_default_configs_creates_all_files(tmp_path, monkeypatch):
    cfg_dir = tmp_path / ".config" / "trustsight"
    monkeypatch.setattr("trustsight.config.CONFIG_DIR", cfg_dir)
    monkeypatch.setattr("trustsight.config.DATA_DIR", tmp_path / ".local" / "share" / "trustsight")
    monkeypatch.setattr("trustsight.config.CACHE_DIR", tmp_path / ".cache" / "trustsight")

    ensure_default_configs()
    assert (cfg_dir / "config.toml").exists()
    assert (cfg_dir / "rules.toml").exists()
    assert (cfg_dir / "trusted_domains.toml").exists()
    assert (cfg_dir / "hosts.toml").exists()
    assert (cfg_dir / "patterns.toml").exists()
    assert (cfg_dir / "naming.toml").exists()
    assert (cfg_dir / "thresholds.toml").exists()
    assert (cfg_dir / "iocs.toml").exists()


def test_load_pattern_tables_round_trip(tmp_path, monkeypatch):
    """The shipped pattern/naming/host/threshold tables must parse and match
    the code defaults exactly, so rules built from them keep their behaviour."""
    from trustsight.config import (
        DEFAULT_ANTI_ANALYSIS_PROBES,
        DEFAULT_ECOSYSTEM_PREFIXES,
        DEFAULT_FOREIGN_PKG_MANAGERS,
        DEFAULT_FREE_REGISTRAR_TLDS,
        DEFAULT_KNOWN_SUFFIXES,
        DEFAULT_NETWORK_TOOLS,
        DEFAULT_OBFUSCATION_INDICATORS,
        DEFAULT_PASTE_HOSTS,
        DEFAULT_STANDARD_PORTS,
        DEFAULT_VARIANT_SUFFIXES,
        load_hosts,
        load_naming,
        load_patterns,
        load_thresholds,
    )

    monkeypatch.setattr("trustsight.config.CONFIG_DIR", tmp_path)
    monkeypatch.setattr("trustsight.config.DATA_DIR", tmp_path / ".local" / "share" / "trustsight")
    monkeypatch.setattr("trustsight.config.CACHE_DIR", tmp_path / ".cache" / "trustsight")

    patterns = load_patterns()["patterns"]
    assert patterns["foreign_pkg_managers"] == DEFAULT_FOREIGN_PKG_MANAGERS
    assert patterns["obfuscation_indicators"] == DEFAULT_OBFUSCATION_INDICATORS
    assert patterns["anti_analysis_probes"] == DEFAULT_ANTI_ANALYSIS_PROBES
    assert patterns["network_tools"] == DEFAULT_NETWORK_TOOLS

    naming = load_naming()["naming"]
    assert naming["variant_suffixes"] == list(DEFAULT_VARIANT_SUFFIXES)
    assert naming["ecosystem_prefixes"] == DEFAULT_ECOSYSTEM_PREFIXES
    assert naming["known_suffixes"] == list(DEFAULT_KNOWN_SUFFIXES)

    hosts = load_hosts()["hosts"]
    assert hosts["paste_hosts"] == DEFAULT_PASTE_HOSTS
    assert hosts["standard_ports"] == DEFAULT_STANDARD_PORTS
    assert hosts["free_registrar_tlds"] == DEFAULT_FREE_REGISTRAR_TLDS

    assert load_thresholds()["h036"]["obfuscation_density"] == 3


def test_ensure_default_configs_idempotent(tmp_path, monkeypatch):
    cfg_dir = tmp_path / ".config" / "trustsight"
    monkeypatch.setattr("trustsight.config.CONFIG_DIR", cfg_dir)
    monkeypatch.setattr("trustsight.config.DATA_DIR", tmp_path / ".local" / "share" / "trustsight")
    monkeypatch.setattr("trustsight.config.CACHE_DIR", tmp_path / ".cache" / "trustsight")

    ensure_default_configs()
    config = (cfg_dir / "config.toml").read_text()
    ensure_default_configs()
    assert (cfg_dir / "config.toml").read_text() == config


# --- Shipped-rule synchronisation ---

def _install_partial_rules(tmp_path, monkeypatch, count=11, edit=True):
    """Simulate an install predating a rule addition."""
    import trustsight.config as cfg

    monkeypatch.setattr(cfg, "CONFIG_DIR", tmp_path)
    blocks = cfg.DEFAULT_RULES.split("[[rules]]")[1:]
    text = "".join("[[rules]]" + b for b in blocks[:count])
    if edit:
        text = text.replace(
            'severity = "CRITICAL"\ncategory = "privilege"',
            'severity = "HIGH"\ncategory = "privilege"',
        )
    (tmp_path / "rules.toml").write_text(text)
    return cfg


def test_missing_shipped_rules_detects_stale_config(tmp_path, monkeypatch):
    """write_default_file only writes when absent, so an existing install
    never receives newly shipped rules."""
    cfg = _install_partial_rules(tmp_path, monkeypatch)
    missing = cfg.missing_shipped_rules()
    assert "R041" in missing
    assert "R058" in missing
    assert "R001" not in missing


def test_sync_rules_never_resurrects_a_retired_id(tmp_path, monkeypatch):
    """A retired id is an alias, not a re-addable rule."""
    cfg = _install_partial_rules(tmp_path, monkeypatch)
    from trustsight import rule_id_history

    monkeypatch.setitem(rule_id_history.RETIRED_RULE_IDS, "R041", "R001")
    assert "R041" not in cfg.missing_shipped_rules()
    added, _ = cfg.sync_rules()
    assert "R041" not in added


def test_sync_rules_appends_missing_rules(tmp_path, monkeypatch):
    cfg = _install_partial_rules(tmp_path, monkeypatch)
    added, _ = cfg.sync_rules()
    ids = {r["id"] for r in cfg.load_rules()}
    assert set(added) <= ids
    assert "R058" in ids


def test_sync_rules_preserves_user_edits(tmp_path, monkeypatch):
    """A user who retuned a severity must not lose it to a sync."""
    cfg = _install_partial_rules(tmp_path, monkeypatch)
    cfg.sync_rules()
    by_id = {r["id"]: r for r in cfg.load_rules()}
    assert by_id["R008"]["severity"] == "HIGH"


def test_sync_rules_is_idempotent(tmp_path, monkeypatch):
    cfg = _install_partial_rules(tmp_path, monkeypatch)
    cfg.sync_rules()
    assert cfg.sync_rules() == ([], [])


def test_sync_rules_produces_valid_toml(tmp_path, monkeypatch):
    cfg = _install_partial_rules(tmp_path, monkeypatch)
    cfg.sync_rules()
    parsed = tomllib.loads((tmp_path / "rules.toml").read_text())
    assert len(parsed["rules"]) == len(cfg.missing_shipped_rules()) + len(parsed["rules"])


def test_no_missing_rules_on_a_fresh_install(tmp_path, monkeypatch):
    import trustsight.config as cfg

    monkeypatch.setattr(cfg, "CONFIG_DIR", tmp_path)
    cfg.ensure_default_configs()
    assert cfg.missing_shipped_rules() == []


# --- Replacing superseded shipped patterns ---

def _install_with_legacy_r013(tmp_path, monkeypatch, edited=False):
    """An install carrying the pre-0.2.1 R013 pattern."""

    import trustsight.config as cfg

    monkeypatch.setattr(cfg, "CONFIG_DIR", tmp_path)
    legacy = next(iter(cfg.LEGACY_RULE_PATTERNS["R013"]))
    blocks = cfg.DEFAULT_RULES.split("[[rules]]")[1:]
    text = "".join("[[rules]]" + b for b in blocks[:11])
    current = [r for r in tomllib.loads(text)["rules"] if r["id"] == "R013"][0]["pattern"]
    text = text.replace(current, "MY-OWN-PATTERN" if edited else legacy)
    (tmp_path / "rules.toml").write_text(text)
    return cfg, legacy


def test_superseded_pattern_is_detected(tmp_path, monkeypatch):
    """rules.toml is written once, so a corrected pattern otherwise never
    reaches an existing install."""
    cfg, _ = _install_with_legacy_r013(tmp_path, monkeypatch)
    assert cfg.outdated_shipped_rules() == ["R013"]


def test_update_replaces_superseded_pattern(tmp_path, monkeypatch):
    cfg, _ = _install_with_legacy_r013(tmp_path, monkeypatch)
    _, updated = cfg.sync_rules(update_outdated=True)
    assert updated == ["R013"]
    r013 = {r["id"]: r for r in cfg.load_rules()}["R013"]
    assert "(?<![^" in r013["pattern"]


def test_update_never_overwrites_a_customised_rule(tmp_path, monkeypatch):
    """A pattern matching neither the current default nor a known legacy
    one was edited by the user and must survive."""
    cfg, _ = _install_with_legacy_r013(tmp_path, monkeypatch, edited=True)
    assert cfg.outdated_shipped_rules() == []
    _, updated = cfg.sync_rules(update_outdated=True)
    assert updated == []
    r013 = {r["id"]: r for r in cfg.load_rules()}["R013"]
    assert r013["pattern"] == "MY-OWN-PATTERN"


def test_sync_without_update_leaves_superseded_pattern(tmp_path, monkeypatch):
    cfg, legacy = _install_with_legacy_r013(tmp_path, monkeypatch)
    _, updated = cfg.sync_rules(update_outdated=False)
    assert updated == []
    r013 = {r["id"]: r for r in cfg.load_rules()}["R013"]
    assert r013["pattern"] == legacy


def test_superseded_r051_and_r057_patterns_are_repaired(tmp_path, monkeypatch):
    """The shipped R051 client list and R057 flag list both grew; an install
    holding either old pattern must be recognized and repaired, or it fails
    closed on `ruleset_drifted` forever."""
    import trustsight.config as cfg

    monkeypatch.setattr(cfg, "CONFIG_DIR", tmp_path)
    cfg.ensure_default_configs()
    path = tmp_path / "rules.toml"
    text = path.read_text()
    shipped = {r["id"]: r["pattern"] for r in cfg.shipped_rules()}
    for rid in ("R051", "R057"):
        legacy = next(iter(cfg.LEGACY_RULE_PATTERNS[rid]))
        assert shipped[rid] in text
        text = text.replace(shipped[rid], legacy)
    path.write_text(text)

    assert set(cfg.outdated_shipped_rules()) >= {"R051", "R057"}
    _, updated = cfg.sync_rules(update_outdated=True)
    assert set(updated) >= {"R051", "R057"}
    repaired = {r["id"]: r["pattern"] for r in cfg.load_rules()}
    assert repaired["R051"] == shipped["R051"]
    assert repaired["R057"] == shipped["R057"]
    assert cfg.drifted_shipped_rules() == []


def test_r051_registers_the_spelling_0_17_2_to_0_17_4_shipped():
    """0.18.0 taught the R051 client list git's global options, so an install
    that synced on 0.17.2-0.17.4 holds that spelling, not the oldest legacy
    one.  Both have to be registered or `sync-rules --update` leaves it
    failing closed on `ruleset_drifted` forever."""
    from trustsight import config as cfg

    assert any(
        r"git\s+(?:clone|fetch|pull|ls-remote|archive)" in pattern
        for pattern in cfg.LEGACY_RULE_PATTERNS["R051"]
    )


def test_sync_rules_full_is_honoured_under_json(tmp_path, monkeypatch):
    """`config sync-rules --full --json` silently ignored --full: the JSON
    branch ran only the additive sync, so a customised rule survived a
    command documented to overwrite it, under a success report."""
    import json

    from typer.testing import CliRunner

    import trustsight.cli.config as cli_config
    import trustsight.config as cfg
    from trustsight.cli.app import app

    monkeypatch.setattr(cfg, "DATA_DIR", tmp_path / "data")
    monkeypatch.setattr(cfg, "CONFIG_DIR", tmp_path / ".config")
    monkeypatch.setattr(cfg, "CACHE_DIR", tmp_path / ".cache")
    monkeypatch.setattr(cli_config, "CONFIG_DIR", tmp_path / ".config")
    cfg.ensure_default_configs()

    rules_path = tmp_path / ".config" / "rules.toml"
    text = rules_path.read_text()
    # A cosmetic user edit: `name` is not a semantic field, so neither the
    # additive sync nor drift detection would ever overwrite it.
    edited = text.replace('name = ', 'name = "USER EDITED" # ', 1)
    assert edited != text
    rules_path.write_text(edited)

    result = CliRunner().invoke(app, ["config", "sync-rules", "--full", "--json"])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["drift"] == []
    assert "USER EDITED" not in rules_path.read_text()


# --- parsed-TOML cache ---

def test_load_toml_picks_up_an_edit_on_disk(tmp_path, monkeypatch):
    """Caching must not make a config change invisible.

    The parse is cached against the file's stat, so rewriting the file has
    to invalidate it; otherwise a user editing config.toml would see no
    effect until the process restarted.
    """
    from trustsight.config import load_toml

    monkeypatch.setattr("trustsight.config.CONFIG_DIR", tmp_path)
    path = tmp_path / "config.toml"
    path.write_text("[limits]\ndefault_review_limit = 5\n")
    assert load_toml("config.toml")["limits"]["default_review_limit"] == 5

    path.write_text("[limits]\ndefault_review_limit = 99\n")
    assert load_toml("config.toml")["limits"]["default_review_limit"] == 99


def test_the_legacy_review_limit_is_repaired(tmp_path, monkeypatch):
    """`default_review_limit` shipped set to 20 and was read by nothing; once
    the key became effective, that stale shipped value silently narrowed every
    review to 20.  It is repaired to 0, while a value the user chose is kept.
    """
    import trustsight.config as cfg

    monkeypatch.setattr(cfg, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(cfg, "DATA_DIR", tmp_path)
    monkeypatch.setattr(cfg, "CACHE_DIR", tmp_path)
    (tmp_path / "config.toml").write_text(
        "[limits]\ndefault_review_limit = 20\nnetwork_connect_timeout = 10\n"
    )
    cfg.ensure_default_configs()
    text = (tmp_path / "config.toml").read_text()
    assert "default_review_limit = 0" in text
    assert "default_review_limit = 20" not in text
    assert "network_connect_timeout = 10" in text, "other keys must survive"

    (tmp_path / "config.toml").write_text("[limits]\ndefault_review_limit = 7\n")
    cfg.ensure_default_configs()
    assert "default_review_limit = 7" in (tmp_path / "config.toml").read_text()


def test_load_toml_hands_out_independent_copies(tmp_path, monkeypatch):
    """A caller that edits the result must not corrupt the next caller's.

    The cached parse is shared, so it is handed out as a copy; mutating
    one result previously leaked into every later load.
    """
    from trustsight.config import load_toml

    monkeypatch.setattr("trustsight.config.CONFIG_DIR", tmp_path)
    (tmp_path / "config.toml").write_text("[seed]\nauto_import = true\n")

    first = load_toml("config.toml")
    first["seed"]["auto_import"] = False
    first["injected"] = True

    second = load_toml("config.toml")
    assert second["seed"]["auto_import"] is True
    assert "injected" not in second


# --- shipped-rule drift ---

def test_drift_reports_a_stale_match_target(tmp_path, monkeypatch):
    """An install whose rules.toml predates a match_target change is flagged.

    rules.toml is written once and only ever gains rules, so a shipped
    rule that later moved to match_target = "resolved" keeps its old
    behaviour forever, silently missing payloads built from shell
    variables.
    """
    from trustsight.config import drifted_shipped_rules

    monkeypatch.setattr("trustsight.config.CONFIG_DIR", tmp_path)
    (tmp_path / "rules.toml").write_text(
        "[[rules]]\n"
        'id = "R001"\n'
        'name = "Remote Script Execution"\n'
        "pattern = 'curl'\n"
        'severity = "CRITICAL"\n'
        'category = "network_execution"\n'
        'match_target = "raw_line"\n'
    )
    drift = drifted_shipped_rules()
    assert ("R001", "match_target", "raw_line", "resolved") in drift


def test_no_drift_reported_for_a_current_rules_file(tmp_path, monkeypatch):
    from trustsight.config import DEFAULT_RULES, drifted_shipped_rules

    monkeypatch.setattr("trustsight.config.CONFIG_DIR", tmp_path)
    (tmp_path / "rules.toml").write_text(DEFAULT_RULES)
    assert drifted_shipped_rules() == []


def _rules_with_legacy_generated_patterns(cfg) -> dict[str, str]:
    """DEFAULT_RULES with R046/R047 carrying their pre-exclusion spelling."""
    shipped = {r["id"]: r["pattern"] for r in tomllib.loads(cfg.DEFAULT_RULES)["rules"]}
    text = cfg.DEFAULT_RULES
    for rid in ("R046", "R047"):
        legacy = next(iter(cfg.LEGACY_RULE_PATTERNS[rid]))
        assert shipped[rid] in text
        text = text.replace(shipped[rid], legacy)
    return shipped, text


def test_generated_pattern_drift_is_not_reported(tmp_path, monkeypatch):
    """R046/R047 patterns are regenerated from config before matching, so an
    install holding an older spelling must not report as drifted: the on-disk
    text is inert, and failing closed on it downgrades every verdict forever.
    """
    import trustsight.config as cfg

    monkeypatch.setattr(cfg, "CONFIG_DIR", tmp_path)
    _, text = _rules_with_legacy_generated_patterns(cfg)
    (tmp_path / "rules.toml").write_text(text)

    assert cfg.drifted_shipped_rules() == []


def test_generated_r046_r047_legacy_spellings_are_repaired(tmp_path, monkeypatch):
    """A stale spelling that is *inert* is still worth rewriting on disk, so
    `config sync-rules --update` recognizes and replaces it."""
    import trustsight.config as cfg

    monkeypatch.setattr(cfg, "CONFIG_DIR", tmp_path)
    shipped, text = _rules_with_legacy_generated_patterns(cfg)
    (tmp_path / "rules.toml").write_text(text)

    assert set(cfg.outdated_shipped_rules()) >= {"R046", "R047"}
    _, updated = cfg.sync_rules(update_outdated=True)
    assert set(updated) >= {"R046", "R047"}
    repaired = {r["id"]: r["pattern"] for r in cfg.load_rules()}
    assert repaired["R046"] == shipped["R046"]
    assert repaired["R047"] == shipped["R047"]
    assert cfg.drifted_shipped_rules() == []


def test_a_pre_h056_iocs_stub_is_replaced(tmp_path, monkeypatch):
    """The schema must reach installs that predate H056.

    Config files are written once, at install time, so a placeholder from
    before the rule existed would otherwise keep its user forever without
    the entry schema, the confidence tiers, or the warning that a miss
    proves nothing.
    """
    import trustsight.config as config

    monkeypatch.setattr(config, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(config, "DATA_DIR", tmp_path / "data")
    monkeypatch.setattr(config, "CACHE_DIR", tmp_path / "cache")
    config._toml_cache.clear()

    stub = next(iter(config.LEGACY_IOCS_STUBS))
    (tmp_path / "iocs.toml").write_text(stub)

    config.ensure_default_configs()

    refreshed = (tmp_path / "iocs.toml").read_text()
    assert refreshed == config.DEFAULT_IOCS
    assert "[[entries]]" in refreshed
    assert "A MISS IS UNINFORMATIVE" in refreshed


def test_an_edited_iocs_file_is_never_overwritten(tmp_path, monkeypatch):
    """A user's own indicators outrank the shipped schema."""
    import trustsight.config as config

    monkeypatch.setattr(config, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(config, "DATA_DIR", tmp_path / "data")
    monkeypatch.setattr(config, "CACHE_DIR", tmp_path / "cache")
    config._toml_cache.clear()

    mine = ('[meta]\nversion = 4\n\n[[entries]]\ntype = "domain"\n'
            'value = "mine.example"\nconfidence = "confirmed"\n')
    (tmp_path / "iocs.toml").write_text(mine)

    config.ensure_default_configs()
    assert (tmp_path / "iocs.toml").read_text() == mine


def test_the_legacy_r012_pattern_is_upgradable(tmp_path, monkeypatch):
    """An install carrying the one-phrasing R012 must be able to catch up."""
    import trustsight.config as config

    monkeypatch.setattr(config, "CONFIG_DIR", tmp_path)
    config._toml_cache.clear()
    # The pre-2026-08-03 one-phrasing pattern; deterministic pick (the
    # set also holds the pre-2026-10-16 eight-alternative pattern,
    # which contains quotes and cannot sit in a TOML literal string).
    legacy = next(p for p in config.LEGACY_RULE_PATTERNS["R012"]
                  if "claude" not in p)
    (tmp_path / "rules.toml").write_text(
        '[[rules]]\nid = "R012"\nname = "LLM Prompt Injection"\n'
        f"pattern = '{legacy}'\n"
        'severity = "FATAL"\ncategory = "injection"\nmatch_target = "resolved"\n'
    )

    assert "R012" in config.outdated_shipped_rules()
    _, updated = config.sync_rules(update_outdated=True)
    config._toml_cache.clear()

    assert "R012" in updated
    rule = [r for r in config.load_rules() if r["id"] == "R012"][0]
    assert rule["include_comments"] is True
    assert "do not" not in rule["pattern"]  # escaped form, not prose
    assert "assistant" in rule["pattern"]


def test_the_2026_10_16_legacy_r012_pattern_is_upgradable(tmp_path, monkeypatch):
    """An install carrying the object-less alternative 8 must catch up too."""
    import json
    import trustsight.config as config

    monkeypatch.setattr(config, "CONFIG_DIR", tmp_path)
    config._toml_cache.clear()
    legacy = next(p for p in config.LEGACY_RULE_PATTERNS["R012"]
                  if "claude" in p)
    (tmp_path / "rules.toml").write_text(
        '[[rules]]\nid = "R012"\nname = "LLM Prompt Injection"\n'
        f"pattern = {json.dumps(legacy)}\n"
        'severity = "FATAL"\ncategory = "injection"\nmatch_target = "resolved"\n'
    )

    assert "R012" in config.outdated_shipped_rules()
    _, updated = config.sync_rules(update_outdated=True)
    config._toml_cache.clear()

    assert "R012" in updated
    rule = [r for r in config.load_rules() if r["id"] == "R012"][0]
    assert "this|that|the" in rule["pattern"]  # the object requirement


# --- the test fixture must not describe a config the tool does not ship ----

def test_shared_config_has_no_keys_the_tool_no_longer_reads():
    """A fixture key with no shipped counterpart hides shipped behaviour.

    `SHARED_CONFIG` carried `verification_evidence` and `pinning_weights`
    after both were removed from `DEFAULT_CONFIG`. Nothing failed, because
    the fixture kept feeding the old weights to the scorer, and `P007` was
    dead in production while green in the suite.

    Values may legitimately differ (tests pick round novelty weights so the
    arithmetic is readable). Whole *sections* may not: a section the tool
    never loads is a description of a program that does not exist.
    """
    from trustsight.config import DEFAULT_CONFIG

    from tests.conftest import SHARED_CONFIG

    shipped = tomllib.loads(DEFAULT_CONFIG)
    orphans = sorted(set(SHARED_CONFIG) - set(shipped))
    assert not orphans, (
        f"fixture declares sections the shipped config does not have: {orphans}"
    )


def test_shared_config_covers_every_bucket_the_tool_ships():
    """A bucket missing from the fixture is a bucket no test exercises."""
    from trustsight.config import DEFAULT_CONFIG


    from tests.conftest import SHARED_CONFIG

    shipped = tomllib.loads(DEFAULT_CONFIG)["source_bucket_weights"]
    fixture = SHARED_CONFIG["source_bucket_weights"]
    missing = sorted(set(shipped) - set(fixture))
    assert not missing, f"buckets never exercised by the shared fixture: {missing}"


def test_load_overrides_tolerates_a_latin1_file(tmp_path, monkeypatch):
    """A hand-edited overrides.json saved in a non-UTF-8 encoding loads as
    empty rather than crashing every analysis with UnicodeDecodeError.

    The loader already tolerates invalid JSON and unreadable files; the
    decode step above json.loads raised through filter_triggered_rules,
    which runs inside every analysis.
    """
    from trustsight import override as override_mod

    path = tmp_path / "overrides.json"
    path.write_bytes(
        '{"overrides": [{"rule_id": "H001", "reason": "déjà vu"}]}'.encode("latin-1")
    )
    monkeypatch.setattr(override_mod, "OVERRIDES_PATH", path)
    assert override_mod.load_overrides() == []


def test_structural_rules_load_clamped_and_controlled(tmp_path, monkeypatch):
    import trustsight.config as cfg

    monkeypatch.setattr(cfg, "CONFIG_DIR", tmp_path)
    cfg._toml_cache.clear()
    (tmp_path / "rules.toml").write_text(
        '[[structural]]\nid = "R900"\nfield = "source"\nmatch = "host_added"\n'
        'pattern = "evil"\nseverity = "CRITICAL"\n\n'
        '[[structural]]\nid = "R901"\nfield = "scalars.install"\n'
        'match = "entry_added"\npattern = "x"\n\n'
        '[[structural]]\nid = "R902"\nfield = "source"\n'
        'match = "bogus"\npattern = "x"\n'
    )
    (tmp_path / "config.toml").write_text("[rules.R900]\nweight_override = 3\n")

    rules = cfg.load_structural_rules()
    assert [r["id"] for r in rules] == ["R900"]
    assert rules[0]["severity"] == "HIGH"
    assert rules[0]["name"] == "R900"
    assert rules[0]["category"] == "structural"
    assert rules[0]["weight_override"] == 3


def test_structural_rules_are_part_of_the_fingerprint(tmp_path, monkeypatch):
    import trustsight.config as cfg

    monkeypatch.setattr(cfg, "CONFIG_DIR", tmp_path)
    cfg._toml_cache.clear()
    (tmp_path / "rules.toml").write_text(
        '[[structural]]\nid = "R900"\nfield = "source"\nmatch = "host_added"\n'
        'pattern = "evil"\n'
    )
    first = cfg.config_fingerprint()
    (tmp_path / "rules.toml").write_text(
        '[[structural]]\nid = "R900"\nfield = "source"\nmatch = "host_added"\n'
        'pattern = "other"\n'
    )
    cfg._toml_cache.clear()
    assert cfg.config_fingerprint() != first


def test_local_ruleset_version_reads_the_marker(tmp_path, monkeypatch):
    from trustsight import config

    cfg_dir = tmp_path / ".config" / "trustsight"
    cfg_dir.mkdir(parents=True)
    monkeypatch.setattr("trustsight.config.CONFIG_DIR", cfg_dir)

    # Missing file reads as current: nothing to sync.
    assert config.local_ruleset_version() == config.SHIPPED_RULESET_VERSION
    assert config.ruleset_age_drift() is False

    # A pre-marker install reads as generation 0, which is age-drifting.
    (cfg_dir / "rules.toml").write_text("[[rules]]\nid = 'R001'\n")
    assert config.local_ruleset_version() == 0
    assert config.ruleset_age_drift() is True

    # Exactly one generation behind does not prompt; more than one does.
    one_behind = config.SHIPPED_RULESET_VERSION - 1
    (cfg_dir / "rules.toml").write_text(f"# ruleset-version: {one_behind}\n")
    assert config.ruleset_age_drift() is False
    (cfg_dir / "rules.toml").write_text(
        f"# ruleset-version: {config.SHIPPED_RULESET_VERSION - 2}\n")
    assert config.ruleset_age_drift() is True


def test_shipped_rules_toml_carries_the_version_marker():
    from trustsight import config

    assert f"# ruleset-version: {config.SHIPPED_RULESET_VERSION}" in config.DEFAULT_RULES


def test_sync_rules_stamps_the_current_generation(tmp_path, monkeypatch):
    from trustsight import config

    cfg_dir = tmp_path / ".config" / "trustsight"
    cfg_dir.mkdir(parents=True)
    monkeypatch.setattr("trustsight.config.CONFIG_DIR", cfg_dir)
    monkeypatch.setattr("trustsight.config.DATA_DIR", tmp_path / "data")
    # A pre-marker file with a rule that is present, so nothing is "added".
    (cfg_dir / "rules.toml").write_text(
        config._rule_blocks(config.DEFAULT_RULES)["R001"])

    config.sync_rules()
    assert config.local_ruleset_version() == config.SHIPPED_RULESET_VERSION


def test_fingerprint_covers_override_ttl(monkeypatch):
    from trustsight import config
    from trustsight.override import RuleOverride

    base = config.config_fingerprint()
    monkeypatch.setattr(
        "trustsight.override.load_overrides",
        lambda: [RuleOverride(rule_id="H029", reason="r", package="p",
                              ttl_observations=10)],
    )
    assert config.config_fingerprint() != base


def test_every_historical_shipped_pattern_is_recognised_and_repaired(
        tmp_path, monkeypatch):
    """A pattern an earlier release shipped is never a user edit.

    ``LEGACY_RULE_PATTERNS`` is now merged with the tag-derived history, so
    every old spelling of every current rule must be flagged and replaced
    (issue #47).  The hand list kept missing releases; this pins the whole
    generated set rather than the four spellings that were reported.
    """
    import re

    from trustsight import config
    from trustsight.config._legacy_shipped_patterns import HISTORICAL_RULE_PATTERNS

    monkeypatch.setattr(config, "CONFIG_DIR", tmp_path)
    config.ensure_default_configs()
    path = tmp_path / "rules.toml"
    base = path.read_text()
    blocks = config._rule_blocks(config.DEFAULT_RULES)
    shipped = {r["id"]: r["pattern"] for r in config.shipped_rules()}

    checked = 0
    for rule_id, patterns in HISTORICAL_RULE_PATTERNS.items():
        for legacy in patterns:
            assert legacy != shipped[rule_id]
            replacement = "pattern = " + config._toml_escape_str(legacy)
            block = re.sub(
                r"^pattern\s*=\s*.*$", lambda _match: replacement,
                blocks[rule_id], count=1, flags=re.MULTILINE,
            )
            path.write_text(
                config._replace_rule_block(base, rule_id, block))
            assert rule_id in config.outdated_shipped_rules(), rule_id
            _, updated = config.sync_rules(update_outdated=True)
            assert rule_id in updated
            repaired = {r["id"]: r["pattern"] for r in config.load_rules()}
            assert repaired[rule_id] == shipped[rule_id]
            checked += 1
    assert checked >= 25, "the generated history looks empty"


def test_generated_shipped_pattern_history_is_current():
    """The committed data file must match a fresh extraction from the tags."""
    import shutil
    import subprocess
    import sys
    from pathlib import Path

    from trustsight.config._legacy_shipped_patterns import HISTORICAL_RULE_PATTERNS

    root = Path(__file__).resolve().parent.parent
    if shutil.which("git") is None or not (root / ".git").exists():
        import pytest

        pytest.skip("no git checkout")
    tags = subprocess.run(
        ["git", "tag"], cwd=root, capture_output=True, text=True)
    if not tags.stdout.strip():
        import pytest

        pytest.skip("no tags in this checkout")

    sys.path.insert(0, str(root / "scripts"))
    try:
        import build_legacy_shipped_patterns as builder
    finally:
        sys.path.pop(0)

    assert builder.collect() == {
        rule_id: set(patterns)
        for rule_id, patterns in HISTORICAL_RULE_PATTERNS.items()
    }


def test_refresh_legacy_network_tools_repairs_the_old_list(tmp_path, monkeypatch):
    """Installs that predate the transfer-client expansion keep the old list."""
    import trustsight.config as config_module
    from trustsight.config import DEFAULT_NETWORK_TOOLS, LEGACY_NETWORK_TOOLS

    cfg_dir = _cfg_dirs(tmp_path, monkeypatch)
    ensure_default_configs()
    path = cfg_dir / "patterns.toml"
    new = "network_tools = " + config_module._toml_str_list(DEFAULT_NETWORK_TOOLS)
    old = "network_tools = " + config_module._toml_str_list(LEGACY_NETWORK_TOOLS)
    path.write_text(path.read_text().replace(new, old))
    config_module._toml_cache.pop("patterns.toml", None)

    assert config_module._refresh_legacy_network_tools() is True
    assert "openssh" in path.read_text()
    assert config_module._refresh_legacy_network_tools() is False


def test_refresh_legacy_network_tools_preserves_custom_entries(
        tmp_path, monkeypatch):
    import trustsight.config as config_module
    from trustsight.config import DEFAULT_NETWORK_TOOLS, LEGACY_NETWORK_TOOLS

    cfg_dir = _cfg_dirs(tmp_path, monkeypatch)
    ensure_default_configs()
    path = cfg_dir / "patterns.toml"
    new = "network_tools = " + config_module._toml_str_list(DEFAULT_NETWORK_TOOLS)
    old = "network_tools = " + config_module._toml_str_list(LEGACY_NETWORK_TOOLS)
    custom = old.replace("]", '    "custom-tool",\n]', 1)
    path.write_text(path.read_text().replace(new, custom))
    config_module._toml_cache.pop("patterns.toml", None)

    assert config_module._refresh_legacy_network_tools() is False
    repaired = path.read_text()
    assert "custom-tool" in repaired
    assert "openssh" not in repaired


def test_refresh_legacy_network_tools_repairs_an_older_shipped_list(
        tmp_path, monkeypatch):
    """The watcher and long-lived installs may carry either shipped table."""
    import trustsight.config as config_module
    from trustsight.config import (
        DEFAULT_NETWORK_TOOLS,
        LEGACY_NETWORK_TOOL_LISTS,
    )

    cfg_dir = _cfg_dirs(tmp_path, monkeypatch)
    ensure_default_configs()
    path = cfg_dir / "patterns.toml"
    new = "network_tools = " + config_module._toml_str_list(DEFAULT_NETWORK_TOOLS)
    oldest = "network_tools = " + config_module._toml_str_list(
        LEGACY_NETWORK_TOOL_LISTS[0])
    path.write_text(path.read_text().replace(new, oldest))
    config_module._toml_cache.pop("patterns.toml", None)

    assert config_module._refresh_legacy_network_tools() is True
    assert "openssh" in path.read_text()


def test_g011_thresholds_ship():
    assert "[g011]" in DEFAULT_THRESHOLDS
    assert "placeholder_share = 0.5" in DEFAULT_THRESHOLDS
    assert "placeholder_escalation = true" in DEFAULT_THRESHOLDS
