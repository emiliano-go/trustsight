"""The manifest producer's bounded, execution-free contract."""

from __future__ import annotations

import io
import json
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import artifact_manifest  # noqa: E402

pytestmark = pytest.mark.skipif(
    shutil.which("zstd") is None, reason="zstd not installed")


def _archive(tmp_path: Path, members: list[tuple[tarfile.TarInfo, bytes]]) -> Path:
    raw = tmp_path / "fixture.tar"
    with tarfile.open(raw, "w") as tar:
        for member, data in members:
            tar.addfile(member, io.BytesIO(data))
    out = tmp_path / "fixture.pkg.tar.zst"
    subprocess.run(["zstd", "-q", "-f", str(raw), "-o", str(out)], check=True)
    return out


def _member(name: str, size: int = 0) -> tarfile.TarInfo:
    member = tarfile.TarInfo(name)
    member.size = size
    member.mode = 0o644
    return member


def test_paths_cannot_escape_the_package_root():
    assert artifact_manifest._safe_path("../../etc/passwd") is None
    assert artifact_manifest._safe_path("usr/../../etc/passwd") is None
    assert artifact_manifest._safe_path("/etc/passwd") is None
    assert artifact_manifest._safe_path("C:/windows/system32") is None
    assert artifact_manifest._safe_path("./usr/bin/tool") == "/usr/bin/tool"
    assert artifact_manifest._safe_path("usr//bin/../bin/tool") == "/usr/bin/tool"


def test_install_text_is_read_under_the_declared_cap(tmp_path, monkeypatch):
    monkeypatch.setattr(artifact_manifest, "MAX_DECLARED_TEXT_BYTES", 16)
    archive = _archive(tmp_path, [
        (_member(".INSTALL", 4096), b"x" * 4096),
        (_member("usr/bin/tool"), b""),
    ])
    doc = artifact_manifest.build_manifest(archive)
    assert doc["declared"]["built_install_text"] == "x" * 16


def test_a_decompression_bomb_is_refused(tmp_path, monkeypatch):
    monkeypatch.setattr(artifact_manifest, "MAX_DECOMPRESSED_BYTES", 4096)
    archive = _archive(tmp_path, [
        (_member("usr/share/blob", 1024 * 1024), b"\0" * (1024 * 1024)),
    ])
    with pytest.raises(artifact_manifest.ArchiveTooLarge):
        artifact_manifest.build_manifest(archive)


def test_the_archive_digest_is_streamed_and_correct(tmp_path):
    import hashlib

    archive = _archive(tmp_path, [(_member("usr/bin/tool"), b"")])
    expected = hashlib.sha256(archive.read_bytes()).hexdigest()
    doc = artifact_manifest.build_manifest(archive)
    assert doc["provenance"]["archive_sha256"] == expected


def test_the_producer_records_the_capability_xattr(tmp_path):
    member = _member("usr/bin/tool")
    member.pax_headers = {"SCHILY.xattr.security.capability": "cap_net_raw+ep"}
    archive = _archive(tmp_path, [(member, b"")])
    doc = artifact_manifest.build_manifest(archive)
    entry = next(e for e in doc["manifest"] if e["path"] == "/usr/bin/tool")
    assert entry["caps"].startswith("0x")
    assert json.dumps(doc)  # the document stays serialisable
