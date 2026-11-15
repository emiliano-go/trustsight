"""The host guard only admits the proxy port from the watcher bridge."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "host_egress_guard", ROOT / "scripts" / "host_egress_guard.py")
assert SPEC and SPEC.loader
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


def test_the_guard_drops_everything_but_the_proxy_port():
    rules = module.render("br-watcher", "172.20.0.10")
    assert 'iifname "br-watcher" ip daddr 172.20.0.10 tcp dport 3128 accept' in rules
    assert 'iifname "br-watcher" drop' in rules
    assert "policy accept" in rules
    assert "ct state established,related accept" in rules


def test_an_invalid_proxy_address_is_refused():
    with pytest.raises(ValueError):
        module.render("br-watcher", "not-an-ip")
