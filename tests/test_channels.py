"""The shared verified-pull path and the pending-pull record.

``seed fetch``, ``corpus fetch``, ``ioc update`` and the watcher's
``--auto-pull-*`` options all funnel through :mod:`trustsight.channels`, so a
mistake here is a weaker import on every surface.  These tests pin the parts
that are easy to get silently wrong: which key verifies which channel, which
URL shape routes to which flow, and whether an already-pulled release is pulled
again.
"""

from __future__ import annotations

import hashlib
import json

import pytest

from trustsight import channel_state, channels, release


# --- channel_state --------------------------------------------------------


@pytest.fixture(autouse=True)
def _isolated_cache(tmp_path, monkeypatch):
    import trustsight.config as config

    monkeypatch.setattr(config, "CACHE_DIR", tmp_path / "cache")
    (tmp_path / "cache").mkdir(parents=True, exist_ok=True)
    import trustsight.db as dbmod

    monkeypatch.setattr(dbmod, "DATA_DIR", tmp_path / "data")
    (tmp_path / "data").mkdir(parents=True, exist_ok=True)
    dbmod.init_db()


def test_a_pull_is_recorded_and_read_back():
    channel_state.record_pull(channel_state.BASELINE, "baseline-2026-01-01",
                              "emiliano-go/trustsight")
    assert channel_state.pulled_tag(channel_state.BASELINE) == "baseline-2026-01-01"
    assert channel_state.pulled(channel_state.BASELINE)["channel"] == \
        "emiliano-go/trustsight"
    assert channel_state.pulled_tag(channel_state.IOC) is None


def test_an_unknown_kind_is_ignored():
    channel_state.record_pull("something-else", "x")
    assert channel_state.pulled("something-else") is None


def test_an_empty_tag_reads_back_as_never_pulled():
    channel_state.record_pull(channel_state.IOC, None)
    assert channel_state.pulled_tag(channel_state.IOC) is None


def test_a_corrupt_record_is_a_miss_not_an_error(tmp_path):
    (tmp_path / "cache" / "channel-pulls.json").write_text("{not json")
    assert channel_state.pulled(channel_state.BASELINE) is None


# --- channel identity -----------------------------------------------------


def _channel(repo="someone/else", key_bytes=None):
    return release.Channel(
        repo=repo,
        base_url=f"https://github.com/{repo}/releases",
        api_url=f"https://api.github.com/repos/{repo}",
        key_path=None,
        key_bytes=key_bytes,
        official=False,
    )


def test_the_official_channel_has_no_warning():
    assert channels.non_official_warning(release.official_channel()) is None


def test_a_non_official_channel_warns_and_names_its_key():
    warning = channels.non_official_warning(_channel(key_bytes=b"\x01" * 32))
    assert "non-official release channel" in warning
    assert "someone/else" in warning
    assert release.OFFICIAL_REPO in warning
    assert "sha256:" in warning


def test_a_key_fingerprint_needs_a_32_byte_key():
    fingerprint = channels.channel_key_fingerprint(_channel(key_bytes=b"\x01" * 32))
    assert fingerprint is not None and fingerprint.startswith("sha256:")
    assert channels.channel_key_fingerprint(_channel()) is None
    assert channels.channel_key_fingerprint(
        _channel(key_bytes=b"\x01" * 31)) is None


def test_a_federation_publisher_warns():
    warning = channels.publisher_warning("https://example.test/iocs")
    assert "non-official publisher" in warning
    assert "example.test" in warning


# --- pull_ioc_feed routing ------------------------------------------------


def test_a_local_path_feed_is_refused():
    result = channels.pull_ioc_feed({"name": "x", "url": "/tmp/not-a-url"})
    assert result["status"] == "error"
    assert "unsupported feed URL" in result["error"]


def test_a_federation_feed_without_a_key_is_refused():
    result = channels.pull_ioc_feed(
        {"name": "x", "url": "https://example.test/iocs"})
    assert result["status"] == "error"
    assert "pinned publisher key" in result["error"]


HEX_KEY = "3bc5a24d09072c4aed2165f29d5a8fd42aeacb9f96962c12eccde64c79786210"


@pytest.mark.parametrize("key_value", [HEX_KEY, "/tmp/some-pubkey.raw"])
def test_a_federation_feed_key_is_hex_or_a_path(monkeypatch, key_value):
    """A feed `key` is documented as 64 hex characters *or* a path.

    Reading a hex key as a path (the pre-fix behaviour) fails with ENOENT on a
    file named like the digest, so the two shapes must route to the same
    verifier the way a channel `[release] key` does.
    """
    seen = {}

    def _fetch(url, asset, *, pubkey_path=None, pubkey=None):
        seen.setdefault("calls", []).append((asset, pubkey_path, pubkey))
        return b"data"

    monkeypatch.setattr(release, "fetch_verified_url", _fetch)
    monkeypatch.setattr("trustsight.ioc_baseline.import_baseline",
                        lambda *a, **k: {"entries_imported": 1, "verified": True})

    result = channels.pull_ioc_feed(
        {"name": "x", "url": "https://example.test/iocs", "key": key_value})

    assert result["status"] == "ok", result
    assert [asset for asset, _, _ in seen["calls"]] == ["manifest.json", "iocs.jsonl"]
    for _, pubkey_path, pubkey in seen["calls"]:
        if key_value == HEX_KEY:
            assert pubkey is not None and len(pubkey) == 32
            assert pubkey_path is None
        else:
            assert pubkey is None
            assert str(pubkey_path) == key_value


def test_fetch_verified_url_requires_a_key(monkeypatch):
    monkeypatch.setattr(release, "offline", lambda: False)
    monkeypatch.setattr(release, "_download_url", lambda *a, **k: b"x")
    with pytest.raises(release.ReleaseSignatureError):
        release.fetch_verified_url("https://example.test/iocs", "manifest.json")


def test_fetch_verified_url_verifies_raw_key_bytes(monkeypatch):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
    )

    monkeypatch.setattr(release, "offline", lambda: False)
    key = Ed25519PrivateKey.generate()
    payload = b'{"version": 1}'
    signature = key.sign(payload)

    def _download(url, *a, **k):
        return signature if url.endswith(".sig") else payload

    monkeypatch.setattr(release, "_download_url", _download)
    raw = key.public_key().public_bytes_raw()

    assert release.fetch_verified_url(
        "https://example.test/iocs", "manifest.json", pubkey=raw) == payload

    bad = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
    with pytest.raises(release.ReleaseSignatureError):
        release.fetch_verified_url(
            "https://example.test/iocs", "manifest.json", pubkey=bad)



def test_a_bad_asset_prefix_on_a_channel_url_is_refused():
    result = channels.pull_ioc_feed({
        "name": "Bad Name",
        "asset": "Bad Name",
        "url": f"{release.official_channel().base_url}",
    })
    assert result["status"] == "error"
    assert "invalid asset prefix" in result["error"]


# --- pull_baseline_seed ---------------------------------------------------


def test_pull_baseline_seed_verifies_and_records(monkeypatch, tmp_path):
    seen = {}

    seed = b"seed-bytes"
    manifest = json.dumps({
        "version": 1,
        "assets": [{
            "name": channels.SEED_ASSET_NAME,
            "sha256": hashlib.sha256(seed).hexdigest(),
            "size": len(seed),
        }],
    }).encode("utf-8")

    def _fetch(asset_name, **kwargs):
        if asset_name == channels.BASELINE_MANIFEST_ASSET:
            return manifest
        seen["asset_name"] = asset_name
        seen["channel"] = kwargs["channel"].repo
        return seed

    monkeypatch.setattr(release, "fetch_verified_asset", _fetch)
    imported = {}

    def _import(path):
        imported["bytes"] = path.read_bytes()
        return {"entries": 3}

    monkeypatch.setattr("trustsight.db.import_seed", _import)

    stats = channels.pull_baseline_seed(
        channel=release.official_channel(), tag="baseline-2026-01-01")

    assert seen["asset_name"] == channels.SEED_ASSET_NAME
    assert seen["channel"] == release.OFFICIAL_REPO
    assert imported["bytes"] == seed
    assert stats["entries"] == 3
    assert channel_state.pulled_tag(channel_state.BASELINE) == "baseline-2026-01-01"


# --- auto_pull ------------------------------------------------------------


def test_auto_pull_does_nothing_when_disabled():
    assert channels.auto_pull() == []


def test_auto_pull_pulls_a_newer_baseline(monkeypatch):
    monkeypatch.setattr(release, "resolve_baseline_tag",
                        lambda channel=None: "baseline-2026-02-02")
    monkeypatch.setattr(release, "clear_tag_cache", lambda: None)
    monkeypatch.setattr(release, "active_baseline_channel",
                        lambda *a, **k: release.official_channel())
    calls = []
    monkeypatch.setattr(
        channels, "pull_baseline_seed",
        lambda **kwargs: calls.append(kwargs) or {
            "tag": "baseline-2026-02-02", "channel": release.OFFICIAL_REPO})

    notes = channels.auto_pull(baselines=True)
    assert len(calls) == 1
    assert any("baseline seed pulled" in note for note in notes)


def test_auto_pull_skips_an_already_pulled_baseline(monkeypatch):
    channel_state.record_pull(channel_state.BASELINE, "baseline-2026-02-02")
    monkeypatch.setattr(release, "resolve_baseline_tag",
                        lambda channel=None: "baseline-2026-02-02")
    monkeypatch.setattr(release, "clear_tag_cache", lambda: None)
    monkeypatch.setattr(release, "active_baseline_channel",
                        lambda *a, **k: release.official_channel())
    monkeypatch.setattr(
        channels, "pull_baseline_seed",
        lambda **kwargs: pytest.fail("an already-pulled tag must not refetch"))

    assert channels.auto_pull(baselines=True) == []


# --- the pending notice ---------------------------------------------------


def test_pending_channels_reports_an_unpulled_release(monkeypatch):
    from trustsight.cli import updates

    monkeypatch.setattr(updates, "_channel_tags", lambda: {
        "baseline": "baseline-2026-03-03",
        "baseline_channel": release.OFFICIAL_REPO,
        "ioc": None,
    })
    monkeypatch.delenv("TRUSTSIGHT_NO_UPDATE_CHECK", raising=False)
    monkeypatch.delenv("TRUSTSIGHT_NO_PENDING_CHECK", raising=False)

    assert updates.pending_channels() == [
        ("baseline", "baseline-2026-03-03", release.OFFICIAL_REPO)]


def test_pending_channels_names_the_official_repo_for_iocs(monkeypatch):
    from trustsight.cli import updates

    monkeypatch.setattr(updates, "_channel_tags", lambda: {
        "baseline": None,
        "baseline_channel": release.OFFICIAL_REPO,
        "ioc": "ioc-2026-03-03",
    })
    monkeypatch.delenv("TRUSTSIGHT_NO_UPDATE_CHECK", raising=False)
    monkeypatch.delenv("TRUSTSIGHT_NO_PENDING_CHECK", raising=False)

    assert updates.pending_channels() == [
        ("ioc", "ioc-2026-03-03", release.OFFICIAL_REPO)]


def test_pending_channels_is_silent_once_pulled(monkeypatch):
    from trustsight.cli import updates

    channel_state.record_pull(channel_state.BASELINE, "baseline-2026-03-03")
    monkeypatch.setattr(updates, "_channel_tags", lambda: {
        "baseline": "baseline-2026-03-03",
        "baseline_channel": release.OFFICIAL_REPO,
        "ioc": None,
    })
    monkeypatch.delenv("TRUSTSIGHT_NO_UPDATE_CHECK", raising=False)
    monkeypatch.delenv("TRUSTSIGHT_NO_PENDING_CHECK", raising=False)

    assert updates.pending_channels() == []


def test_the_master_switch_silences_the_pending_notice(monkeypatch, capsys):
    from trustsight.cli import updates

    monkeypatch.setenv("TRUSTSIGHT_NO_UPDATE_CHECK", "1")
    monkeypatch.setattr(updates, "_channel_tags",
                        lambda: pytest.fail("disabled check must not query"))
    updates.check_and_warn_pending()
    assert capsys.readouterr().err == ""


def test_pending_notice_names_the_pull_command(monkeypatch, capsys):
    from trustsight.cli import updates

    monkeypatch.setattr(updates, "pending_channels",
                        lambda: [("ioc", "ioc-2026-03-03", release.OFFICIAL_REPO)])
    updates.check_and_warn_pending()
    err = capsys.readouterr().err
    assert "ioc-2026-03-03" in err
    assert "trustsight ioc update" in err


def test_the_channel_tags_cache_round_trips(tmp_path, monkeypatch):
    from trustsight.cli import updates

    data = {"baseline": "baseline-2026-03-03", "ioc": None,
            "baseline_channel": release.OFFICIAL_REPO}
    updates._write_json_cache(updates._pending_cache_path(), data)
    read = updates._read_json_cache(updates._pending_cache_path(),
                                    updates._TTL_SECONDS)
    assert read["baseline"] == "baseline-2026-03-03"
    assert json.loads(updates._pending_cache_path().read_text())["ioc"] is None
