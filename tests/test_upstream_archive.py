"""Bounded extraction of manifests from a declared source archive."""

from __future__ import annotations

import io
import tarfile
import zipfile

from trustsight.analysis.upstream_archive import parse_upstream_archive


def _tar(entries) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, data, kind in entries:
            info = tarfile.TarInfo(name=name)
            if kind == "file":
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
            elif kind == "symlink":
                info.type = tarfile.SYMTYPE
                info.linkname = "pkg"
                tar.addfile(info)
    return buf.getvalue()


def _zip(entries) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as archive:
        for name, data in entries:
            archive.writestr(name, data)
    return buf.getvalue()


def test_tar_selects_manifests_and_workflows_only():
    data = _tar([
        ("pkg/Cargo.toml", b"[package]\nname='x'\n", "file"),
        ("pkg/.github/workflows/ci.yml", b"on: push\n", "file"),
        ("pkg/README.md", b"# docs\n", "file"),
        ("pkg/logo.png", b"\x00\x01\x02", "file"),
    ])
    out = parse_upstream_archive(data)
    assert out["malformed"] is False
    paths = [path for path, _ in out["manifest_texts"]]
    assert "pkg/Cargo.toml" in paths
    assert "pkg/.github/workflows/ci.yml" in paths
    assert "pkg/README.md" not in paths


def test_tar_refuses_traversal_and_symlinks():
    data = _tar([
        ("pkg/../Cargo.toml", b"[package]\n", "file"),
        ("pkg/link", b"", "symlink"),
        ("pkg/package.json", b'{"name":"x"}', "file"),
    ])
    out = parse_upstream_archive(data)
    assert out["refused"] is True
    assert [path for path, _ in out["manifest_texts"]] == ["pkg/package.json"]


def test_zip_selects_manifests():
    data = _zip([
        ("pkg/go.mod", b"module x\n"),
        ("pkg/Cargo.toml", b"[package]\n"),
        ("pkg/LICENSE", b"MIT\n"),
    ])
    out = parse_upstream_archive(data)
    paths = [path for path, _ in out["manifest_texts"]]
    assert "pkg/go.mod" in paths
    assert "pkg/Cargo.toml" in paths
    assert "pkg/LICENSE" not in paths


def test_bounds_refuse_an_oversized_archive():
    data = _tar([("pkg/Cargo.toml", b"x" * 100, "file")])
    out = parse_upstream_archive(data, max_total_bytes=10)
    assert out["refused"] is True
    assert out["complete"] is False


def test_a_non_archive_is_malformed_not_a_crash():
    out = parse_upstream_archive(b"not an archive")
    assert out["malformed"] is True
    assert out["manifest_texts"] == []
