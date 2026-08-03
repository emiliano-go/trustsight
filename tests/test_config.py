import tomllib

from trustsight.config import (
    ensure_default_configs,
    load_config,
    load_domains,
    load_rules,
)


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


def test_load_config_bucket_weights(tmp_path, monkeypatch):
    cfg_dir = tmp_path / ".config" / "trustsight"
    monkeypatch.setattr("trustsight.config.CONFIG_DIR", cfg_dir)
    monkeypatch.setattr("trustsight.config.DATA_DIR", tmp_path / ".local" / "share" / "trustsight")
    monkeypatch.setattr("trustsight.config.CACHE_DIR", tmp_path / ".cache" / "trustsight")

    config = load_config()
    weights = config["source_bucket_weights"]
    assert weights["trusted_forge"] == -10
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
    assert "R009" in rule_ids
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


def test_load_domains_creates_default(tmp_path, monkeypatch):
    cfg_dir = tmp_path / ".config" / "trustsight"
    monkeypatch.setattr("trustsight.config.CONFIG_DIR", cfg_dir)
    monkeypatch.setattr("trustsight.config.DATA_DIR", tmp_path / ".local" / "share" / "trustsight")
    monkeypatch.setattr("trustsight.config.CACHE_DIR", tmp_path / ".cache" / "trustsight")

    domains = load_domains()
    assert "trusted_forges" in domains
    assert "github.com" in domains["trusted_forges"]["domains"]
    assert "gitlab.com" in domains["trusted_forges"]["domains"]
    assert "official_projects" in domains
    assert "python.org" in domains["official_projects"]["domains"]
    assert "kernel.org" in domains["official_projects"]["domains"]
    assert "raw_hosting" in domains
    assert "raw.githubusercontent.com" in domains["raw_hosting"]["domains"]
    assert "pastebin.com" in domains["raw_hosting"]["domains"]


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

    assert load_thresholds()["r082"]["obfuscation_density"] == 3


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
    assert "R040" in missing
    assert "R058" in missing
    assert "R001" not in missing


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
    assert by_id["R009"]["severity"] == "HIGH"


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
