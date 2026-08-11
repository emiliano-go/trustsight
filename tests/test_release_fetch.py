"""The release channel: verified baseline downloads (v0.12.0).

Every baseline the tool consumes (the novelty seed, IOC baselines, the
corpus baseline) ships as a signed ``baseline-*`` release asset.  This
suite covers the one rule of that channel: a download that does not
verify against the pinned distribution key is refused, never imported.
"""

import sys
import tarfile
from pathlib import Path

import pytest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from trustsight import release
from trustsight.db import get_connection, init_db, seed_observation_count

# ---------------------------------------------------------------------------
# URL building
# ---------------------------------------------------------------------------


def test_asset_url_uses_the_declared_release_host():
    url = release.asset_url("baseline-seed.tar.gz")
    assert url.startswith("https://github.com/emiliano-go/trustsight/releases/")
    assert url.endswith("/latest/download/baseline-seed.tar.gz")


def test_asset_url_pins_a_tag_when_given():
    url = release.asset_url("baseline-seed.tar.gz", "v0.12.0")
    assert url.endswith("/download/v0.12.0/baseline-seed.tar.gz")


def test_is_release_url_accepts_only_the_channel():
    assert release.is_release_url(release.RELEASE_BASE_URL)
    assert release.is_release_url(release.RELEASE_BASE_URL + "/latest/download")
    assert not release.is_release_url("https://example.org/trustsight/ioc-baseline/")
    assert not release.is_release_url("https://gitlab.com/trustsight/releases")


# ---------------------------------------------------------------------------
# Bounded download
# ---------------------------------------------------------------------------


def _fake_response(chunks: list[bytes]):
    class FakeResponse:
        def __init__(self, chunks):
            self._chunks = iter(chunks)

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def read(self, n: int):
            try:
                data = next(self._chunks)
            except StopIteration:
                return b""
            return data[:n]

    return FakeResponse(chunks)


def test_download_reads_with_an_explicit_timeout(monkeypatch):
    captured = {}

    def fake_urlopen(url, timeout=None, **kwargs):
        captured["timeout"] = timeout
        return _fake_response([b"abc", b""])

    monkeypatch.setattr(release.urllib.request, "urlopen", fake_urlopen)
    data = release.download_asset("baseline-seed.tar.gz")
    assert data == b"abc"
    assert captured["timeout"] == release._REQUEST_TIMEOUT_SECONDS


def test_download_refuses_a_payload_over_the_bound(monkeypatch):
    monkeypatch.setattr(
        release.urllib.request,
        "urlopen",
        lambda url, timeout=None: _fake_response([b"x" * 10_000, b""]),
    )
    with pytest.raises(release.ReleaseTooLargeError):
        release.download_asset("baseline-seed.tar.gz", max_bytes=1024)


def test_download_is_disabled_offline(monkeypatch):
    monkeypatch.setenv("TRUSTSIGHT_OFFLINE", "1")
    with pytest.raises(release.ReleaseFetchError):
        release.download_asset("baseline-seed.tar.gz")


# ---------------------------------------------------------------------------
# Signature verification
# ---------------------------------------------------------------------------


@pytest.fixture
def keys(tmp_path):
    private = Ed25519PrivateKey.generate()
    pubkey = tmp_path / "pubkey"
    pubkey.write_bytes(private.public_key().public_bytes_raw())
    return private, pubkey


def test_fetch_verified_asset_accepts_a_good_signature(keys, monkeypatch):
    private, pubkey = keys
    payload = b"baseline payload\n"
    signature = private.sign(payload)

    def fake_download(asset_name, **kwargs):
        if asset_name.endswith(".sig"):
            return signature
        return payload

    monkeypatch.setattr(release, "download_asset", fake_download)
    assert release.fetch_verified_asset("baseline-x", pubkey_path=pubkey) == payload


def test_fetch_verified_asset_refuses_a_false_signature(keys, monkeypatch):
    _, pubkey = keys
    payload = b"baseline payload\n"
    forged_signature = Ed25519PrivateKey.generate().sign(payload)

    def fake_download(asset_name, **kwargs):
        if asset_name.endswith(".sig"):
            return forged_signature
        return payload

    monkeypatch.setattr(release, "download_asset", fake_download)
    with pytest.raises(release.ReleaseSignatureError):
        release.fetch_verified_asset("baseline-x", pubkey_path=pubkey)


def test_fetch_verified_asset_refuses_a_tampered_payload(keys, monkeypatch):
    private, pubkey = keys
    payload = b"baseline payload\n"
    signature = private.sign(payload)

    def fake_download(asset_name, **kwargs):
        if asset_name.endswith(".sig"):
            return signature
        return b"tampered payload\n"

    monkeypatch.setattr(release, "download_asset", fake_download)
    with pytest.raises(release.ReleaseSignatureError):
        release.fetch_verified_asset("baseline-x", pubkey_path=pubkey)


def test_fetch_verified_asset_missing_signature_is_a_refusal(keys, monkeypatch):
    _, pubkey = keys

    def fake_download(asset_name, **kwargs):
        if asset_name.endswith(".sig"):
            raise release.ReleaseFetchError("404")
        return b"whatever"

    monkeypatch.setattr(release, "download_asset", fake_download)
    with pytest.raises(release.ReleaseSignatureError):
        release.fetch_verified_asset("baseline-x", pubkey_path=pubkey)


# ---------------------------------------------------------------------------
# First-run auto-import from the channel
# ---------------------------------------------------------------------------


def _build_v2_seed_tar(tmp_path) -> bytes:
    """Build a small valid v2 hashed seed as the release asset would carry it."""
    from trustsight.seed_build import build_seed

    seed_dir = tmp_path / "seed-v2"
    build_seed(
        [
            {"name": "Alice Example", "email": "alice@example.com", "package_count": 2},
            {"name": "bob example", "package_count": 1},
        ],
        seed_dir,
    )
    v2_dir = seed_dir / "trustsight-seed-v2"
    tar_path = tmp_path / "seed.tar.gz"
    with tarfile.open(tar_path, "w:gz") as tf:
        for item in sorted(v2_dir.rglob("*")):
            arcname = f"trustsight-seed-v2/{item.relative_to(v2_dir).as_posix()}"
            tf.add(item, arcname=arcname)
    return tar_path.read_bytes()


def test_auto_import_fetches_and_verifies_a_missing_seed(tmp_path, monkeypatch):
    import trustsight.db as dbmod

    monkeypatch.setattr("trustsight.db.DATA_DIR", tmp_path)
    init_db()
    seed_bytes = _build_v2_seed_tar(tmp_path)

    # The channel path verifies against the pinned key before importing;
    # here the verified payload is simulated by returning the asset bytes
    # directly from fetch_verified_asset (whose own verification is covered
    # by the signature tests above).
    monkeypatch.setattr(release, "fetch_verified_asset", lambda name, **kw: seed_bytes)
    monkeypatch.setattr(
        dbmod, "bundled_seed_path", lambda: tmp_path / "absent-seed.db.gz"
    )

    stats = dbmod.maybe_auto_import_seed(quiet=True, allow_release_fetch=True)
    assert stats is not None
    assert stats["maintainers"] == 2
    with get_connection() as conn:
        salt = conn.execute(
            "SELECT value FROM seed_meta WHERE key = 'salt'"
        ).fetchone()
    assert salt is not None
    assert seed_observation_count() > 0


def test_auto_import_is_silent_when_the_channel_fails(tmp_path, monkeypatch):
    import trustsight.db as dbmod

    monkeypatch.setattr("trustsight.db.DATA_DIR", tmp_path)
    init_db()

    def boom(asset_name, **kwargs):
        raise release.ReleaseFetchError("offline")

    monkeypatch.setattr(release, "download_asset", boom)
    monkeypatch.setattr(
        dbmod, "bundled_seed_path", lambda: tmp_path / "absent-seed.db.gz"
    )

    assert dbmod.maybe_auto_import_seed(
        quiet=True, allow_release_fetch=True
    ) is None
    assert seed_observation_count() == 0


def test_release_seed_failure_logs_reason(tmp_path, monkeypatch, caplog):
    """The unavailable-seed path must log its reason, not raise a stray
    NameError from an undefined logger (ruff F821, previously masked by
    the broad except in maybe_auto_import_seed)."""
    import logging

    import trustsight.db as dbmod

    monkeypatch.setattr("trustsight.db.DATA_DIR", tmp_path)
    init_db()

    def boom(asset_name, **kwargs):
        raise release.ReleaseFetchError("offline")

    monkeypatch.setattr(release, "download_asset", boom)
    monkeypatch.setattr(
        dbmod, "bundled_seed_path", lambda: tmp_path / "absent-seed.db.gz"
    )

    with caplog.at_level(logging.INFO, logger="trustsight.db"):
        assert dbmod.maybe_auto_import_seed(
            quiet=True, allow_release_fetch=True
        ) is None
    assert "release seed unavailable" in caplog.text


# ---------------------------------------------------------------------------
# ioc update through the channel
# ---------------------------------------------------------------------------


def _build_ioc_pair(tmp_path, curator_private) -> tuple[bytes, bytes]:
    from build_ioc_baseline import _normalise_entries, build

    key_path = tmp_path / "curator.raw"
    key_path.write_bytes(curator_private.private_bytes_raw())
    entries = _normalise_entries(
        [
            {"type": "domain", "value": "evil.example", "confidence": "confirmed",
             "provenance": "ASA-2026-06", "campaign": "asa-2026",
             "expires_at": "2026-12-31T00:00:00Z"},
        ],
        "emo-asa-2026",
    )
    build(entries, "emo-asa-2026", tmp_path, "asa-2026", 30, key_path)
    return (tmp_path / "manifest.json").read_bytes(), (tmp_path / "iocs.jsonl").read_bytes()


def test_update_feed_fetches_verifies_and_imports(tmp_path, monkeypatch):
    from trustsight.cli import ioc as ioc_mod

    monkeypatch.setattr("trustsight.db.DATA_DIR", tmp_path)
    init_db()

    curator = Ed25519PrivateKey.generate()
    manifest_bytes, iocs_bytes = _build_ioc_pair(tmp_path, curator)
    fetched = []

    def fake_fetch(asset_name, **kwargs):
        fetched.append(asset_name)
        if asset_name.endswith("-manifest.json"):
            return manifest_bytes
        if asset_name.endswith("-iocs.jsonl"):
            return iocs_bytes
        raise AssertionError(f"unexpected asset {asset_name}")

    monkeypatch.setattr(release, "fetch_verified_asset", fake_fetch)

    feed = {"name": "emo-asa-2026", "url": release.RELEASE_BASE_URL, "enabled": True}
    result = ioc_mod._update_feed(feed)
    assert result["status"] == "ok"
    assert result["entries_imported"] == 1
    assert result["source"] == "emo-asa-2026"
    assert "baseline-ioc-emo-asa-2026-manifest.json" in fetched
    assert "baseline-ioc-emo-asa-2026-iocs.jsonl" in fetched
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT value FROM ioc_entries WHERE source = ?", ("emo-asa-2026",)
        ).fetchall()
    assert [r["value"] for r in rows] == ["evil.example"]


def test_update_feed_refuses_a_foreign_url(tmp_path, monkeypatch):
    from trustsight.cli import ioc as ioc_mod

    feed = {"name": "foreign", "url": "https://example.org/ioc/", "enabled": True}
    result = ioc_mod._update_feed(feed)
    assert result["status"] == "error"
    assert "release channel" in result["error"]


def test_update_feed_refuses_a_bad_asset_prefix(tmp_path, monkeypatch):
    from trustsight.cli import ioc as ioc_mod

    feed = {"name": "../evil", "url": release.RELEASE_BASE_URL, "enabled": True}
    result = ioc_mod._update_feed(feed)
    assert result["status"] == "error"