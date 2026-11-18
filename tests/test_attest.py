"""Deterministic tree attestations."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from trustsight.attest import AttestError, check_tree, digest_tree, write_attestation


def _tree(tmp_path: Path) -> Path:
    root = tmp_path / "pkg"
    root.mkdir()
    (root / "PKGBUILD").write_text("pkgname=demo\n", encoding="utf-8")
    (root / "source.txt").write_text("payload\n", encoding="utf-8")
    return root


def test_digest_is_stable_and_path_sensitive(tmp_path):
    root = _tree(tmp_path)
    first = digest_tree(root)
    assert first == digest_tree(root)
    (root / "source.txt").write_text("changed\n", encoding="utf-8")
    assert digest_tree(root)["digest"] != first["digest"]


def test_attestation_round_trip_and_tamper(tmp_path):
    root = _tree(tmp_path)
    out = tmp_path / "attest.json"
    write_attestation(root, out)
    assert check_tree(root, out)["files"] == 2
    (root / "PKGBUILD").write_text("pkgname=other\n", encoding="utf-8")
    with pytest.raises(AttestError, match="changed"):
        check_tree(root, out)


def test_attestation_is_deterministic_and_omits_git(tmp_path):
    root = _tree(tmp_path)
    (root / ".git").mkdir()
    (root / ".git" / "HEAD").write_text("ref: refs/heads/main\n")
    a = tmp_path / "a.json"
    b = tmp_path / "b.json"
    write_attestation(root, a)
    write_attestation(root, b)
    assert a.read_text() == b.read_text()
    assert json.loads(a.read_text())["files"] == 2
