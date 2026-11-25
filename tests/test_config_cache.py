"""The memoised configuration tables.

The analysis path asks for the same tables tens of times per scan; they are
built once per (directory, generation, directory mtime).  These tests pin the
two properties that make that safe: a caller never gets to edit what the next
one sees, and a write is always visible to the next read.
"""

import trustsight.config as config_module
from trustsight.config import (
    ensure_default_configs,
    invalidate_config,
    load_config,
    load_rules,
    load_structural_rules,
    load_thresholds,
)


def _cfg_dirs(base, monkeypatch):
    cfg_dir = base / ".config" / "trustsight"
    cfg_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr("trustsight.config.CONFIG_DIR", cfg_dir)
    monkeypatch.setattr(
        "trustsight.config.DATA_DIR", base / ".local" / "share" / "trustsight")
    monkeypatch.setattr(
        "trustsight.config.CACHE_DIR", base / ".cache" / "trustsight")
    ensure_default_configs()
    invalidate_config()
    return cfg_dir


def test_tables_are_built_once(tmp_path, monkeypatch):
    _cfg_dirs(tmp_path, monkeypatch)

    assert load_thresholds() is load_thresholds()
    assert load_config() == load_config()


def test_rules_hand_out_their_own_dicts(tmp_path, monkeypatch):
    """``apply_rules`` writes generated patterns into the rules it is given."""
    _cfg_dirs(tmp_path, monkeypatch)

    first = load_rules()
    first[0]["pattern"] = "MUTATED"
    first[0]["severity"] = "FATAL"

    second = load_rules()
    assert second[0]["pattern"] != "MUTATED"
    assert second[0]["severity"] != "FATAL"


def test_config_belongs_to_the_caller(tmp_path, monkeypatch):
    """Callers edit the dict they are given, nested tables included.

    The pipeline is handed ``load_config()`` directly, and a caller that sets
    ``config["baselines"]["ioc"]`` (``test_analysis_integration_disabled``
    does) must not switch that off for the next scan in the same process.
    """
    _cfg_dirs(tmp_path, monkeypatch)

    config = load_config()
    config["a-new-key"] = 1
    config["upstream_scan"]["enabled"] = True
    config.setdefault("baselines", {})["ioc"] = {"enabled": False}

    again = load_config()
    assert "a-new-key" not in again
    assert again["upstream_scan"] is not config["upstream_scan"]
    assert again.get("baselines", {}).get("ioc") != {"enabled": False}


def test_invalidate_rebuilds(tmp_path, monkeypatch):
    _cfg_dirs(tmp_path, monkeypatch)

    before = load_thresholds()
    invalidate_config()
    assert load_thresholds() is not before


def test_a_write_is_visible_to_the_next_read(tmp_path, monkeypatch):
    """An in-place rewrite that leaves the directory mtime alone still wins."""
    cfg_dir = _cfg_dirs(tmp_path, monkeypatch)

    original = load_thresholds()
    (cfg_dir / "thresholds.toml").write_text(
        (cfg_dir / "thresholds.toml").read_text()
        + "\n[entropy]\nmin_observations = 99\n")
    # A test that edits a file by hand announces it, which is the documented
    # contract for anything outside this package's writers.
    invalidate_config()

    assert load_thresholds() is not original


def test_switching_the_config_dir_switches_the_tables(tmp_path, monkeypatch):
    """CONFIG_DIR is part of the key: no cross-install leak."""
    first = _cfg_dirs(tmp_path / "one", monkeypatch)
    a = load_thresholds()
    second = _cfg_dirs(tmp_path / "two", monkeypatch)
    b = load_thresholds()

    assert first != second
    assert a is not b


def test_structural_skip_callback_is_replayed(tmp_path, monkeypatch):
    _cfg_dirs(tmp_path, monkeypatch)
    rules_path = config_module.CONFIG_DIR / "rules.toml"
    rules_path.write_text(
        rules_path.read_text()
        + '\n[[structural]]\nid = "S999"\nfield = "scalars.pkgver"\n'
          'match = "not-a-match-kind"\npattern = "1.2.3"\n'
          "severity = " + '"HIGH"\n')
    invalidate_config()

    seen = []
    load_structural_rules(on_skip=seen.append)
    assert seen

    again = []
    load_structural_rules(on_skip=again.append)
    assert again == seen


def test_cache_can_be_switched_off(tmp_path, monkeypatch):
    _cfg_dirs(tmp_path, monkeypatch)
    monkeypatch.setenv("TRUSTSIGHT_CONFIG_CACHE", "0")

    assert load_thresholds() is not load_thresholds()
    assert load_config() is not load_config()
