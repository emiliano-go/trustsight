"""The release channel: verified baseline downloads (v0.12.0).

Every baseline the tool consumes (the novelty seed, IOC baselines, the
corpus baseline) ships as a signed ``baseline-*`` release asset.  This
suite covers the one rule of that channel: a download that does not
verify against the pinned distribution key is refused, never imported.
"""

import hashlib
import json
import sys
import tarfile
from pathlib import Path

import pytest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from trustsight import release
from trustsight.db import get_connection, init_db, seed_observation_count


@pytest.fixture(autouse=True)
def _the_channel_is_the_subject(monkeypatch):
    """This file tests the release channel, so it opts out of offline mode.

    The suite sets ``TRUSTSIGHT_OFFLINE`` for every test, and everything
    that would reach the channel checks it first - which would make these
    tests assert that a refusal happened rather than that a download
    verifies. Every test here mocks the transport, so nothing leaves the
    machine; the socket guard in `conftest` still holds the line.

    ``_resolve_baseline_tag`` is also mocked to prevent the GitHub API
    call during URL construction; individual tests can override this
    mock to exercise the baseline-tag path.
    """
    monkeypatch.delenv("TRUSTSIGHT_OFFLINE", raising=False)
    # Reset the module-level tag cache so each test starts fresh.
    release._TAGS_RESOLVED.clear()
    release._TAG_CACHE.clear()
    # Nothing here may reach the API, and the configured fallbacks are pinned to
    # fixed tags so the tests never read (or create) the operator's config.
    monkeypatch.setattr(release, "_resolve_baseline_tag", lambda channel=None: None)
    monkeypatch.setattr(release, "_resolve_ioc_tag", lambda channel=None: None)
    monkeypatch.setattr(
        release, "_configured_baseline_tag", lambda: "baseline-2026-08-10"
    )
    monkeypatch.setattr(release, "_configured_ioc_tag", lambda: None)

# ---------------------------------------------------------------------------
# URL building
# ---------------------------------------------------------------------------


def test_asset_url_uses_the_declared_release_host():
    url = release.asset_url("baseline-seed.tar.gz")
    assert url.startswith("https://github.com/emiliano-go/trustsight/releases/")
    assert url.endswith("/baseline-seed.tar.gz")


def test_asset_url_pins_a_tag_when_given():
    url = release.asset_url("baseline-seed.tar.gz", "v0.12.0")
    assert url.endswith("/download/v0.12.0/baseline-seed.tar.gz")


def test_asset_url_refuses_a_tag_that_is_not_a_path_segment():
    """A tag is a URL path segment; a slash or dot-dot never reaches the URL."""
    with pytest.raises(release.ReleaseFetchError):
        release.asset_url("baseline-seed.tar.gz", "../evil")


def test_asset_url_discovers_baseline_tag_for_seed(monkeypatch):
    monkeypatch.setattr(release, "_resolve_baseline_tag", lambda channel=None: "baseline-2026-08-10")
    url = release.asset_url("baseline-seed.tar.gz")
    assert url == (
        "https://github.com/emiliano-go/trustsight/releases"
        "/download/baseline-2026-08-10/baseline-seed.tar.gz"
    )


def test_asset_url_falls_back_to_the_configured_tag(monkeypatch):
    """Discovery failure uses the configured tag, never ``latest``.

    The seed lives only on ``baseline-*`` releases, so ``latest`` (a
    ``v*`` release) can never serve it; the old fallback built a URL that
    404s the moment the unauthenticated releases API is rate-limited.
    """
    monkeypatch.setattr(release, "_resolve_baseline_tag", lambda channel=None: None)
    monkeypatch.setattr(
        release, "_configured_baseline_tag", lambda: "baseline-2026-09-24"
    )
    url = release.asset_url("baseline-seed.tar.gz")
    assert url.endswith("/download/baseline-2026-09-24/baseline-seed.tar.gz")
    assert "/latest/" not in url


def test_asset_url_fails_closed_without_any_tag(monkeypatch):
    """No discovery and no fallback is a refusal, not a ``latest`` guess."""
    monkeypatch.setattr(release, "_resolve_baseline_tag", lambda channel=None: None)
    monkeypatch.setattr(release, "_configured_baseline_tag", lambda: None)
    with pytest.raises(release.ReleaseFetchError):
        release.asset_url("baseline-seed.tar.gz")


def test_asset_url_ignores_baseline_discovery_for_non_baseline_assets(monkeypatch):
    """Non-baseline assets (e.g. source tarballs) always use /latest/."""
    called = []
    monkeypatch.setattr(release, "_resolve_baseline_tag", lambda channel=None: (called.append(1) or "baseline-2026-08-10"))
    url = release.asset_url("trustsight-0.15.6.tar.gz")
    assert called == []  # _resolve_baseline_tag was NOT called
    assert url.endswith("/latest/download/trustsight-0.15.6.tar.gz")


def test_asset_url_resolves_the_dedicated_ioc_channel(monkeypatch):
    """An ioc pair resolves the newest ioc-* release, never baseline-*."""
    called = []
    monkeypatch.setattr(release, "_resolve_ioc_tag", lambda channel=None: "ioc-2026-10-18")
    monkeypatch.setattr(
        release, "_resolve_baseline_tag", lambda channel=None: (called.append(1) or "baseline-2026-08-10"))
    url = release.asset_url("baseline-ioc-emo-asa-2026-manifest.json")
    assert url.endswith(
        "/download/ioc-2026-10-18/baseline-ioc-emo-asa-2026-manifest.json")
    assert called == []  # the baseline channel was NOT consulted


def test_asset_url_uses_the_configured_ioc_tag_when_discovery_fails(monkeypatch):
    monkeypatch.setattr(release, "_resolve_ioc_tag", lambda channel=None: None)
    monkeypatch.setattr(release, "_configured_ioc_tag", lambda: "ioc-2026-10-01")
    url = release.asset_url("baseline-ioc-emo-asa-2026-iocs.jsonl")
    assert url.endswith(
        "/download/ioc-2026-10-01/baseline-ioc-emo-asa-2026-iocs.jsonl")


def test_asset_url_refuses_an_ioc_pair_with_no_reachable_ioc_channel(monkeypatch):
    """The pairs live only on ioc-* releases; there is no baseline copy."""
    monkeypatch.setattr(release, "_resolve_ioc_tag", lambda channel=None: None)
    monkeypatch.setattr(release, "_configured_ioc_tag", lambda: None)
    monkeypatch.setattr(release, "_resolve_baseline_tag",
                        lambda channel=None: "baseline-2026-09-24")
    with pytest.raises(release.ReleaseFetchError):
        release.asset_url("baseline-ioc-emo-asa-2026-manifest.json")


def test_is_release_url_accepts_only_the_channel():
    assert release.is_release_url(release.RELEASE_BASE_URL)
    assert release.is_release_url(release.RELEASE_BASE_URL + "/latest/download")
    assert not release.is_release_url("https://example.org/trustsight/ioc-baseline/")
    assert not release.is_release_url("https://gitlab.com/trustsight/releases")


# ---------------------------------------------------------------------------
# Bounded download
# ---------------------------------------------------------------------------


def _fake_response(chunks: list[bytes], headers: dict | None = None):
    class FakeResponse:
        def __init__(self, chunks):
            self._chunks = iter(chunks)
            self.headers = headers or {}

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


def test_download_reports_progress(monkeypatch):
    monkeypatch.setattr(
        release.urllib.request,
        "urlopen",
        lambda url, timeout=None: _fake_response(
            [b"abc", b"de", b""], {"Content-Length": "5"}
        ),
    )
    seen = []
    data = release.download_asset(
        "baseline-seed.tar.gz",
        on_progress=lambda pos, total: seen.append((pos, total)),
    )
    assert data == b"abcde"
    assert seen == [(0, 5), (3, 5), (5, 5)]


def test_download_progress_total_is_none_without_a_length(monkeypatch):
    monkeypatch.setattr(
        release.urllib.request,
        "urlopen",
        lambda url, timeout=None: _fake_response([b"abc", b""], {}),
    )
    seen = []
    release.download_asset(
        "baseline-seed.tar.gz",
        on_progress=lambda pos, total: seen.append((pos, total)),
    )
    assert seen == [(0, None), (3, None)]


def test_download_progress_ignores_an_implausible_length(monkeypatch):
    """A declared length over the byte cap is not a denominator.

    The value is remote-declared; a bar drawn against it would be a lie
    the cap then refuses.  It reads as unknown instead.
    """
    monkeypatch.setattr(
        release.urllib.request,
        "urlopen",
        lambda url, timeout=None: _fake_response(
            [b"abc", b""], {"Content-Length": "999999999"}
        ),
    )
    seen = []
    release.download_asset(
        "baseline-seed.tar.gz",
        max_bytes=1024,
        on_progress=lambda pos, total: seen.append((pos, total)),
    )
    assert seen == [(0, None), (3, None)]


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


def test_fetch_verified_asset_reports_only_the_payload(keys, monkeypatch):
    """The 64-byte signature is not worth a second bar."""
    private, pubkey = keys
    payload = b"baseline payload\n"
    signature = private.sign(payload)
    calls = []

    def fake_download(asset_name, **kwargs):
        calls.append((asset_name, kwargs.get("on_progress")))
        return signature if asset_name.endswith(".sig") else payload

    def progress(pos, total):
        return None

    monkeypatch.setattr(release, "download_asset", fake_download)
    assert release.fetch_verified_asset(
        "baseline-x", pubkey_path=pubkey, on_progress=progress
    ) == payload
    assert calls == [("baseline-x", progress), ("baseline-x.sig", None)]


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
    manifest = json.dumps({
        "version": 1,
        "expires_at": "",
        "assets": [{
            "name": "baseline-seed.tar.gz",
            "sha256": hashlib.sha256(seed_bytes).hexdigest(),
            "size": len(seed_bytes),
        }],
    }).encode("utf-8")

    def fake_fetch(name, **kw):
        return manifest if name == "baseline-manifest.json" else seed_bytes

    monkeypatch.setattr(release, "fetch_verified_asset", fake_fetch)
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
    monkeypatch.setattr(release, "_resolve_ioc_tag",
                        lambda channel=None: "ioc-2026-10-18")
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


def test_update_feed_refuses_a_foreign_url_without_a_key(tmp_path, monkeypatch):
    """A non-release URL is a federation directory; without a pinned key it is refused."""
    from trustsight.cli import ioc as ioc_mod

    feed = {"name": "foreign", "url": "https://example.org/ioc/", "enabled": True}
    result = ioc_mod._update_feed(feed)
    assert result["status"] == "error"
    assert "key" in result["error"]


def test_update_feed_refuses_a_bad_asset_prefix(tmp_path, monkeypatch):
    from trustsight.cli import ioc as ioc_mod

    feed = {"name": "../evil", "url": release.RELEASE_BASE_URL, "enabled": True}
    result = ioc_mod._update_feed(feed)
    assert result["status"] == "error"


def test_update_feed_pins_the_feed_tag(tmp_path, monkeypatch):
    """A feed's own ``tag`` pins the exact channel release for both assets."""
    from trustsight.cli import ioc as ioc_mod

    monkeypatch.setattr("trustsight.db.DATA_DIR", tmp_path)
    init_db()

    curator = Ed25519PrivateKey.generate()
    manifest_bytes, iocs_bytes = _build_ioc_pair(tmp_path, curator)
    seen = {}

    def fake_fetch(asset_name, tag=None, **kwargs):
        seen[asset_name] = tag
        if asset_name.endswith("-manifest.json"):
            return manifest_bytes
        return iocs_bytes

    monkeypatch.setattr(release, "fetch_verified_asset", fake_fetch)
    monkeypatch.setattr(
        release, "asset_url", lambda name, tag=None, channel=None: f"https://x/{tag}/{name}")

    feed = {"name": "emo-asa-2026", "url": release.RELEASE_BASE_URL,
            "enabled": True, "tag": "ioc-2026-10-18"}
    result = ioc_mod._update_feed(feed)
    assert result["status"] == "ok"
    assert seen == {
        "baseline-ioc-emo-asa-2026-manifest.json": "ioc-2026-10-18",
        "baseline-ioc-emo-asa-2026-iocs.jsonl": "ioc-2026-10-18",
    }


def test_update_feed_refuses_a_tag_that_is_not_a_path_segment(tmp_path, monkeypatch):
    """A tag is a URL path segment; a slash or dot-dot is refused up front."""
    from trustsight.cli import ioc as ioc_mod

    feed = {"name": "emo", "url": release.RELEASE_BASE_URL, "enabled": True,
            "tag": "../evil"}
    result = ioc_mod._update_feed(feed)
    assert result["status"] == "error"
    assert "invalid release tag" in result["error"]


# ---------------------------------------------------------------------------
# Progress rendering
# ---------------------------------------------------------------------------


def test_download_progress_disabled_is_a_noop():
    from trustsight.cli import display

    with display.download_progress("Downloading x...", enabled=False) as on_progress:
        assert on_progress(5, 10) is None


def test_download_progress_draws_on_stderr_and_stops(monkeypatch):
    import io

    from rich.console import Console

    from trustsight.cli import display

    buf = io.StringIO()
    monkeypatch.setattr(
        display,
        "err_console",
        lambda: Console(file=buf, force_terminal=False, width=100),
    )
    with display.download_progress("Downloading x...", enabled=True) as on_progress:
        on_progress(0, 10)
        on_progress(10, 10)
    assert "Downloading x..." in buf.getvalue()

# --- release-listing reads carry the total deadline ------------------------

def test_releases_json_uses_the_bounded_reader(monkeypatch):
    class Good:
        def __init__(self):
            self.chunks = [b'[{"tag_name": "baseline-2026-10-22"}]', b""]

        def read1(self, n):
            return self.chunks.pop(0)

        def read(self, n):  # pragma: no cover - read1 must be preferred
            raise AssertionError("read1 must be preferred")

    assert b"baseline-2026-10-22" in release._read_releases_json(Good())


def test_releases_json_returns_none_on_a_slow_drip(monkeypatch):
    import time

    class Slow:
        def read1(self, n):
            return b"x"

        def read(self, n):  # pragma: no cover
            raise AssertionError("read1 must be preferred")

    clock = iter([0.0, 0.0, release._DOWNLOAD_DEADLINE_SECONDS + 1])
    monkeypatch.setattr(time, "monotonic", lambda: next(clock))

    assert release._read_releases_json(Slow()) is None


def test_releases_json_returns_none_over_the_byte_cap():
    class Huge:
        def read1(self, n):
            return b"x" * (release._MAX_RELEASES_JSON_BYTES + 1)

        def read(self, n):  # pragma: no cover
            raise AssertionError("read1 must be preferred")

    assert release._read_releases_json(Huge()) is None


# --- baseline manifest rollback and asset binding --------------------------

def _manifest(**fields):
    data = {"version": 1, "expires_at": "", "assets": []}
    data.update(fields)
    return data


def test_baseline_manifest_refuses_an_expired_release(monkeypatch, tmp_path):
    import trustsight.db as dbmod
    from trustsight import channels

    monkeypatch.setattr(dbmod, "DATA_DIR", tmp_path)
    init_db()
    with pytest.raises(release.ReleaseExpiredError):
        channels.check_baseline_manifest(
            _manifest(expires_at="2000-01-01T00:00:00+00:00"))


def test_baseline_manifest_refuses_a_replay(monkeypatch, tmp_path):
    import trustsight.db as dbmod
    from trustsight import channels

    monkeypatch.setattr(dbmod, "DATA_DIR", tmp_path)
    init_db()
    dbmod.set_metadata(dbmod.BASELINE_MANIFEST_VERSION_KEY, "10")

    with pytest.raises(release.ReleaseRollbackError):
        channels.check_baseline_manifest(_manifest(version=9))
    assert channels.check_baseline_manifest(_manifest(version=11)) == 11
    channels.record_baseline_manifest_version(_manifest(version=11))
    assert dbmod.get_metadata(dbmod.BASELINE_MANIFEST_VERSION_KEY) == "11"


def test_baseline_manifest_requires_the_asset_hash_and_size():
    from trustsight import channels

    data = b"payload"
    manifest = _manifest(assets=[{
        "name": "baseline-seed.tar.gz",
        "sha256": hashlib.sha256(data).hexdigest(),
        "size": len(data),
    }])
    channels.verify_manifest_asset(manifest, "baseline-seed.tar.gz", data)
    with pytest.raises(release.ReleaseManifestError):
        channels.verify_manifest_asset(manifest, "baseline-seed.tar.gz", b"other")
    with pytest.raises(release.ReleaseManifestError):
        channels.verify_manifest_asset(manifest, "missing", data)


def test_an_older_seed_is_refused_unless_downgrade_is_allowed(
        monkeypatch, tmp_path):
    import trustsight.db as dbmod

    monkeypatch.setattr("trustsight.db.DATA_DIR", tmp_path)
    init_db()
    seed_path = tmp_path / "seed.tar.gz"
    seed_path.write_bytes(_build_v2_seed_tar(tmp_path))
    dbmod.set_metadata(dbmod.SEED_VERSION_KEY, "2099-01-01")

    with pytest.raises(ValueError, match="older"):
        dbmod.import_seed(seed_path)
    stats = dbmod.import_seed(seed_path, allow_downgrade=True)
    assert stats["maintainers"] == 2
