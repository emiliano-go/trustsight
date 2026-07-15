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
    assert config["novelty_weights"]["url_first_globally"] == 15
    assert config["novelty_weights"]["maintainer_first_in_package"] == 20


def test_load_config_llm_defaults(tmp_path, monkeypatch):
    cfg_dir = tmp_path / ".config" / "trustsight"
    monkeypatch.setattr("trustsight.config.CONFIG_DIR", cfg_dir)
    monkeypatch.setattr("trustsight.config.DATA_DIR", tmp_path / ".local" / "share" / "trustsight")
    monkeypatch.setattr("trustsight.config.CACHE_DIR", tmp_path / ".cache" / "trustsight")

    config = load_config()
    assert config["llm"]["provider"] == "ollama"
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
    assert "R004" in rule_ids
    assert "R005" in rule_ids
    assert "R009" in rule_ids


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
        assert rule["severity"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")


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
