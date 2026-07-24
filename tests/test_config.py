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


def test_load_config_llm_defaults(tmp_path, monkeypatch):
    cfg_dir = tmp_path / ".config" / "trustsight"
    monkeypatch.setattr("trustsight.config.CONFIG_DIR", cfg_dir)
    monkeypatch.setattr("trustsight.config.DATA_DIR", tmp_path / ".local" / "share" / "trustsight")
    monkeypatch.setattr("trustsight.config.CACHE_DIR", tmp_path / ".cache" / "trustsight")

    config = load_config()
    assert config["llm"]["provider"] == "openai"
    assert config["llm"]["enabled"] is True
    assert config["llm"]["max_tokens"] == 1024
    assert "openai" in config["llm"]
    assert "api_key" in config["llm"]["openai"]
    assert "base_url" in config["llm"]["openai"]


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
    assert "R006" in rule_ids
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
    assert "R039" in missing
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
    import tomllib

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
    import tomllib

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
