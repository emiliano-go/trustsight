"""Issue #118: sync-rules --update --json reported pre-sync drift."""

from __future__ import annotations

import json

from typer.testing import CliRunner

import trustsight.cli.config as cli_config
import trustsight.config as cfg
from trustsight.cli.app import app


def _configured(tmp_path, monkeypatch):
    monkeypatch.setattr(cfg, "DATA_DIR", tmp_path / "data")
    monkeypatch.setattr(cfg, "CONFIG_DIR", tmp_path / ".config")
    monkeypatch.setattr(cfg, "CACHE_DIR", tmp_path / ".cache")
    monkeypatch.setattr(cli_config, "CONFIG_DIR", tmp_path / ".config")
    cfg.ensure_default_configs()
    return tmp_path / ".config" / "rules.toml"


def test_update_json_reports_no_drift_after_fixing_it(tmp_path, monkeypatch):
    rules_path = _configured(tmp_path, monkeypatch)
    text = rules_path.read_text()
    drifted = text.replace(
        'match_target = "resolved"', 'match_target = "raw_line"', 1)
    assert drifted != text
    rules_path.write_text(drifted)

    result = CliRunner().invoke(
        app, ["config", "sync-rules", "--update", "--json"])

    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["drift"] == []
    from trustsight.config import _rule_blocks

    assert 'match_target = "raw_line"' not in _rule_blocks(
        rules_path.read_text())["R001"]

    again = CliRunner().invoke(
        app, ["config", "sync-rules", "--update", "--json"])
    assert again.exit_code == 0, again.output
    assert json.loads(again.output)["drift"] == []


def test_post_sync_drift_still_names_a_user_edited_pattern(tmp_path, monkeypatch):
    """--update must not overwrite a user pattern; drift must still say so."""
    rules_path = _configured(tmp_path, monkeypatch)
    import re

    from trustsight.config import _rule_blocks, _replace_rule_block

    text = rules_path.read_text()
    block = _rule_blocks(text)["R001"]
    edited_block = re.sub(
        r"^pattern = .*$", 'pattern = "user-owned-pattern"', block,
        count=1, flags=re.MULTILINE)
    assert edited_block != block
    rules_path.write_text(_replace_rule_block(text, "R001", edited_block))

    result = CliRunner().invoke(
        app, ["config", "sync-rules", "--update", "--json"])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert any(row["rule_id"] == "R001" for row in payload["drift"])
    assert "user-owned-pattern" in rules_path.read_text()
