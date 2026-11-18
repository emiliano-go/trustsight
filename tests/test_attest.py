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


def test_a_failed_write_does_not_replace_the_previous_file(tmp_path, monkeypatch):
    root = _tree(tmp_path)
    out = tmp_path / "attest.json"
    out.write_text("previous")
    import trustsight.attest as attest

    def fail(*args, **kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(attest.json, "dumps", fail)
    with pytest.raises(OSError):
        write_attestation(root, out)
    assert out.read_text() == "previous"
    assert not list(tmp_path.glob(".*.tmp"))


def test_unreadable_tree_fails_closed(tmp_path):
    root = tmp_path / "pkg"
    root.mkdir()
    blocked = root / "blocked"
    blocked.mkdir()
    (blocked / "file").write_text("x")
    blocked.chmod(0)
    try:
        with pytest.raises(AttestError, match="could not walk"):
            digest_tree(root)
    finally:
        blocked.chmod(0o700)


def test_unpinned_sources_lists_vcs_skip_and_unchecksummed(tmp_path):
    from trustsight.attest import unpinned_sources

    root = tmp_path / "pkg"
    root.mkdir()
    (root / "PKGBUILD").write_text(
        'pkgname=demo\n'
        'source=("git+https://example.invalid/a.git" "skip.tar.gz" '
        '"plain.tar.gz" "pinned.tar.gz")\n'
        'sha256sums=("SKIP" "SKIP" "" "abc")\n'
    )
    assert unpinned_sources(root) == [
        {"name": "git+https://example.invalid/a.git",
         "url": "git+https://example.invalid/a.git", "reason": "vcs"},
        {"name": "skip.tar.gz", "url": "skip.tar.gz", "reason": "skip"},
        {"name": "plain.tar.gz", "url": "plain.tar.gz", "reason": "unpinned"},
    ]
    out = tmp_path / "a.json"
    from trustsight.attest import write_attestation
    write_attestation(root, out)
    assert len(json.loads(out.read_text())["unpinned_sources"]) == 3


def test_unpinned_sources_does_not_follow_a_symlinked_pkgbuild(tmp_path):
    from trustsight.attest import unpinned_sources

    root = tmp_path / "pkg"
    root.mkdir()
    target = tmp_path / "outside"
    target.write_text(
        'pkgname=x\nsource=("git+https://example.invalid/x.git")\n'
    )
    (root / "PKGBUILD").symlink_to(target)
    assert unpinned_sources(root) == []


def test_attestation_refuses_a_tampered_source_inventory(tmp_path):
    root = _tree(tmp_path)
    (root / "PKGBUILD").write_text('pkgname=x\nsource=("x")\nsha256sums=("abc")\n')
    out = tmp_path / "a.json"
    write_attestation(root, out)
    payload = json.loads(out.read_text())
    payload["unpinned_sources"] = [{"name": "x", "url": "x", "reason": "vcs"}]
    out.write_text(json.dumps(payload))
    with pytest.raises(AttestError, match="source inventory"):
        check_tree(root, out)
