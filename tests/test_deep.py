"""Deep-analysis mode decisions (analysis/deep.py)."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from trustsight.analysis.deep import deep_decision  # noqa: E402


def test_disabled_never_triggers():
    assert deep_decision({"deep": {"enabled": False, "threshold": 80}}, 100)["triggered"] is False


def test_enabled_below_threshold_does_not_trigger():
    assert deep_decision({"deep": {"enabled": True, "threshold": 80}}, 50)["triggered"] is False


def test_enabled_at_threshold_triggers_without_l9_by_default():
    decision = deep_decision({"deep": {"enabled": True, "threshold": 80}}, 80)
    assert decision["triggered"] is True
    assert decision["l9_requested"] is False


def test_l9_requires_the_verify_lane():
    config = {"deep": {"enabled": True, "threshold": 80},
              "verify": {"enabled": True}}
    assert deep_decision(config, 90)["l9_requested"] is True


def test_explicit_deep_overrides_the_config():
    decision = deep_decision(
        {"deep": {"enabled": False, "threshold": 80},
         "verify": {"enabled": True}}, 0, explicit=True)
    assert decision["triggered"] is True
    assert decision["l9_requested"] is True


def test_non_numeric_score_never_triggers():
    assert deep_decision({"deep": {"enabled": True, "threshold": 80}}, None)["triggered"] is False
