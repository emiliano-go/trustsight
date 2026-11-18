"""Bounded extraction of manifests from a declared source archive."""

from __future__ import annotations

import struct

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


def test_duplicate_members_are_ambiguous_not_silently_overridden():
    tar_out = parse_upstream_archive(_tar([
        ("pkg/Cargo.toml", b"[package]\nname='one'\n", "file"),
        ("pkg/Cargo.toml", b"[package]\nname='two'\n", "file"),
    ]))
    assert tar_out["ambiguous"]
    assert tar_out["complete"] is False
    zip_out = parse_upstream_archive(_zip([
        ("pkg/Cargo.toml", b"[package]\nname='one'\n"),
        ("pkg/Cargo.toml", b"[package]\nname='two'\n"),
    ]))
    assert zip_out["ambiguous"]
    assert zip_out["complete"] is False


def test_sparse_member_is_ambiguous():
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        info = tarfile.TarInfo("pkg/Cargo.toml")
        info.size = 1
        info.pax_headers = {"GNU.sparse.map": "0,1"}
        tar.addfile(info, io.BytesIO(b"x"))
    out = parse_upstream_archive(buf.getvalue())
    assert out["ambiguous"]
    assert out["complete"] is False


def test_bounds_refuse_an_oversized_archive():
    data = _tar([("pkg/Cargo.toml", b"x" * 100, "file")])
    out = parse_upstream_archive(data, max_total_bytes=10)
    assert out["refused"] is True
    assert out["complete"] is False


def test_a_non_archive_is_malformed_not_a_crash():
    out = parse_upstream_archive(b"not an archive")
    assert out["malformed"] is True
    assert out["manifest_texts"] == []


def test_zip_with_too_many_entries_is_refused():
    data = _zip([(f"pkg/f{i}.txt", b"x") for i in range(10)])
    out = parse_upstream_archive(data, max_members=2)
    assert out["refused"] is True
    assert out["complete"] is False


def test_gzip_bomb_is_refused_by_the_decompressed_cap():
    # 50 KiB of zeros compresses to a few hundred bytes.  The decompressed
    # cap must refuse before the member is materialised.
    data = _tar([("pkg/Cargo.toml", b"x" * 50_000, "file")])
    out = parse_upstream_archive(data, max_total_bytes=1024)
    assert out["refused"] is True
    assert out["manifest_texts"] == []


def test_bounds_are_clamped_to_hard_ceilings():
    # A caller cannot raise the decompressed cap past the hard ceiling.
    data = _tar([("pkg/Cargo.toml", b"[package]\n", "file")])
    out = parse_upstream_archive(data, max_total_bytes=10**12,
                                 max_members=10**9)
    assert out["malformed"] is False


def test_zip_entry_count_is_read_before_the_archive_is_opened(monkeypatch):
    data = _zip([(f"pkg/f{i}.txt", b"x") for i in range(10)])
    import zipfile as _zipfile

    def _boom(*_args, **_kwargs):
        raise AssertionError("the archive was opened before the count check")

    monkeypatch.setattr(_zipfile, "ZipFile", _boom)
    out = parse_upstream_archive(data, max_members=2)
    assert out["refused"] is True
    assert out["complete"] is False


def _tar_modes(entries) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, data, mode in entries:
            info = tarfile.TarInfo(name=name)
            info.mode = mode
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def test_artifacts_report_elf_binaries_and_setuid_bits():
    data = _tar_modes([
        ("pkg/bin/tool", b"\x7fELF\x02\x01\x01\x00rest", 0o755),
        ("pkg/bin/suid", b"#!/bin/sh\n", 0o4755),
        ("pkg/Cargo.toml", b"[package]\n", 0o644),
    ])
    out = parse_upstream_archive(data)
    artifacts = {a["path"]: a for a in out["artifacts"]}
    assert artifacts["pkg/bin/tool"]["elf"] is True
    assert artifacts["pkg/bin/suid"]["setuid"] is True
    assert "pkg/Cargo.toml" not in artifacts


def _tiny_elf64() -> bytes:
    header = bytearray(64)
    header[:4] = b"\x7fELF"
    header[4] = 2
    header[5] = 1
    header[6] = 1
    struct.pack_into("<HHI", header, 16, 2, 0x3E, 1)
    struct.pack_into("<HHHHHH", header, 52, 64, 56, 0, 64, 0, 0)
    return bytes(header)


def test_multiple_small_elves_are_all_parsed():
    elf = _tiny_elf64()
    data = _tar_modes([("pkg/a", elf, 0o755), ("pkg/b", elf, 0o755)])
    out = parse_upstream_archive(data)
    infos = [a for a in out["artifacts"] if a["path"].startswith("pkg/")]
    assert len(infos) == 2
    assert all(a["elf_info"] is not None for a in infos)
    assert all(not a["elf_info"]["truncated"] for a in infos)
    assert out["refused"] is False
