"""Collecting upstream manifests into the U-series state (off by default)."""

from __future__ import annotations

import hashlib

import pytest

from trustsight.upstream_collect import collect_upstream_manifest_texts


@pytest.fixture(autouse=True)
def _online_lane(monkeypatch):
    """These tests inject their own fetcher; opt back into the online path."""
    monkeypatch.delenv("TRUSTSIGHT_OFFLINE", raising=False)

DATA = b"archive-bytes"
SHA256 = hashlib.sha256(DATA).hexdigest()

RECIPE = (
    "pkgname=demo\n"
    "pkgver=1.0\n"
    'source=("https://github.com/owner/repo/archive/refs/tags/v${pkgver}.tar.gz")\n'
    f"sha256sums=('{SHA256}')\n"
)

CONFIG = {"upstream_scan": {
    "enabled": True,
    "allowed_hosts": ["github.com"],
    "archive_fetch": True,
    "min_checksum_bits": 256,
    "deadline_seconds": 5,
}}


def _extractor(_slug, _data):
    return {"manifest_texts": [("pkg/Cargo.toml", "[package]\nname='x'\n")],
            "complete": True, "refused": False, "malformed": False}


def test_disabled_lane_collects_nothing():
    texts, notes = collect_upstream_manifest_texts(
        RECIPE, config={"upstream_scan": {"enabled": False}})
    assert texts == [] and notes == []


def test_enabled_lane_fetches_verifies_and_extracts():
    calls = []

    def fetcher(url, target):
        calls.append((url, target.slug))
        return DATA

    texts, notes = collect_upstream_manifest_texts(
        RECIPE, config=CONFIG, fetcher=fetcher, extractor=_extractor)
    assert texts == [("upstream/pkg/Cargo.toml", "[package]\nname='x'\n")]
    assert notes == []
    assert calls and calls[0][1] == "github.com/owner/repo"


def test_a_checksum_mismatch_is_a_boundary_not_a_parse():
    texts, notes = collect_upstream_manifest_texts(
        RECIPE, config=CONFIG, fetcher=lambda url, target: b"different",
        extractor=_extractor)
    assert texts == []
    assert "upstream_scan_checksum" in notes


def test_an_off_allowlist_source_is_never_fetched():
    recipe = RECIPE.replace("https://github.com", "https://evil.example")
    called = []

    def fetcher(url, target):
        called.append(url)
        return DATA

    texts, notes = collect_upstream_manifest_texts(
        recipe, config=CONFIG, fetcher=fetcher, extractor=_extractor)
    assert texts == [] and notes == []
    assert called == []


def test_archive_fetch_must_be_enabled():
    config = dict(CONFIG)
    config["upstream_scan"] = dict(CONFIG["upstream_scan"], archive_fetch=False)
    called = []
    texts, _ = collect_upstream_manifest_texts(
        RECIPE, config=config,
        fetcher=lambda url, target: called.append(url) or DATA,
        extractor=_extractor)
    assert texts == [] and called == []


def test_a_weak_checksum_is_never_an_archive_anchor():
    weak = RECIPE.replace("sha256sums", "md5sums").replace(SHA256, "0" * 32)
    called = []
    texts, _ = collect_upstream_manifest_texts(
        weak, config=CONFIG,
        fetcher=lambda url, target: called.append(url) or DATA,
        extractor=_extractor)
    assert texts == [] and called == []


def test_the_total_manifest_text_is_capped():
    def extractor(_slug, _data):
        return {"manifest_texts": [
            (f"pkg/m{i}.toml", "x" * (64 * 1024)) for i in range(80)],
            "complete": True, "refused": False, "malformed": False}

    texts, notes = collect_upstream_manifest_texts(
        RECIPE, config=CONFIG, fetcher=lambda url, target: DATA,
        extractor=extractor)
    assert sum(len(text) for _, text in texts) <= 2 * 1024 * 1024
    assert "upstream_scan_partial" in notes


def test_offline_never_opens_a_connection(monkeypatch):
    monkeypatch.setenv("TRUSTSIGHT_OFFLINE", "1")
    called = []
    texts, notes = collect_upstream_manifest_texts(
        RECIPE, config=CONFIG,
        fetcher=lambda url, target: called.append(url) or DATA,
        extractor=_extractor)
    assert texts == []
    assert notes == ["upstream_scan_offline"]
    assert called == []
