"""An external monitor can compare the signer head with an anchored value."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from trustsight.audit_anchor import AnchorError, check, watch

ROOT = Path(__file__).resolve().parent.parent


def _module():
    spec = importlib.util.spec_from_file_location(
        "check_audit_anchor", ROOT / "scripts" / "check_audit_anchor.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _head(tmp_path, chain):
    path = tmp_path / "head.json"
    path.write_text(json.dumps({"chain_sha256": chain}))
    return path


def test_a_matching_head_is_accepted(tmp_path):
    chain = "a" * 64
    assert _module().main([str(_head(tmp_path, chain)),
                           "--expected", chain]) == 0


def test_a_mismatched_head_is_refused(tmp_path):
    assert _module().main([str(_head(tmp_path, "a" * 64)),
                           "--expected", "b" * 64]) == 2


def test_an_unreadable_head_is_refused(tmp_path):
    assert _module().main([str(tmp_path / "missing.json")]) == 2


def test_the_module_checks_and_refuses(tmp_path):
    chain = "c" * 64
    head = _head(tmp_path, chain)
    assert check(str(head), expected=chain) == chain
    with pytest.raises(AnchorError):
        check(str(head), expected="d" * 64)


def test_watch_alerts_before_exiting_on_a_mismatch(tmp_path, monkeypatch):
    head = _head(tmp_path, "c" * 64)
    calls = []
    import trustsight.alerts as alerts
    monkeypatch.setattr(alerts, "send",
                        lambda url, payload: calls.append((url, payload)) or True)
    with pytest.raises(AnchorError):
        watch(str(head), expected="d" * 64,
              notify_url="https://alerts.example/anchor")
    assert calls[0][0] == "https://alerts.example/anchor"
    assert calls[0][1]["event"] == "trustsight.anchor"
