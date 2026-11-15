"""The deployment validator names each control departure."""

from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "validate_containment", ROOT / "scripts" / "validate_containment.py")
assert SPEC and SPEC.loader
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


def _container(**overrides):
    container = {
        "Name": "/trustsight-watch",
        "Config": {"User": "1000:1000"},
        "HostConfig": {
            "ReadonlyRootfs": True,
            "Privileged": False,
            "CapAdd": [],
            "CapDrop": ["ALL"],
            "SecurityOpt": ["no-new-privileges:true",
                            "seccomp=/tmp/seccomp.json",
                            "apparmor=docker-default"],
            "PidsLimit": 256,
            "Memory": 1073741824,
            "NetworkMode": "watcher-internal",
        },
    }
    container["HostConfig"].update(overrides)
    return container


def test_a_hardened_container_passes():
    assert module.check(_container()) == []


def test_each_departure_is_named():
    problems = module.check(_container(
        ReadonlyRootfs=False, Privileged=True, CapAdd=["SYS_ADMIN"],
        CapDrop=[], SecurityOpt=["seccomp=unconfined"],
        PidsLimit=0, Memory=0, NetworkMode="bridge"))
    assert len(problems) >= 7
    assert any("writable" in problem for problem in problems)
    assert any("privileged" in problem for problem in problems)
    assert any("unconfined" in problem for problem in problems)
