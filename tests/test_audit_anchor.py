"""An external monitor can compare the signer head with an anchored value."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

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
