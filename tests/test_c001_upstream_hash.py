"""C001 corroboration through a signed upstream_hash baseline."""

from __future__ import annotations

import json

import pytest

from trustsight.analysis.structural import _structural_findings
from trustsight.analysis.structural._engine import (
    _upstream_hash_corroborated,
    _upstream_hash_key,
)
from trustsight.differ._sources import extract_urls_from_diff
from trustsight.ioc_baseline import import_baseline, match_upstream_hash

PKGBUILD = """\
pkgname=demo
pkgver=1.0
pkgrel=1
source=("https://example.org/demo-1.0.tar.gz")
sha256sums=('abc')
"""

KEY = "https://example.org/demo-1.0.tar.gz|1.0|abc"


@pytest.fixture
def isolated_db(tmp_path, monkeypatch):
    import trustsight.config as config
    from trustsight.db import init_db

    monkeypatch.setattr(config, "DATA_DIR", tmp_path)
    monkeypatch.setattr("trustsight.db.DATA_DIR", tmp_path)
    init_db()
    yield tmp_path


def _write_baseline(base, value=KEY):
    base.mkdir()
    manifest = {
        "version": 1,
        "source": "test-feed",
        "created_at": "2026-01-01T00:00:00+00:00",
        "expires_at": "",
        "signature": "",
        "public_key": "",
    }
    (base / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    entry = {
        "type": "upstream_hash",
        "value": value,
        "source": "test-feed",
        "confidence": "high",
        "provenance": "release-hash-feed",
    }
    (base / "iocs.jsonl").write_text(json.dumps(entry) + "\n", encoding="utf-8")


def _diff(old: str, new: str) -> str:
    import difflib

    return "".join(
        difflib.unified_diff(
            old.splitlines(True), new.splitlines(True), "a/PKGBUILD", "b/PKGBUILD"
        )
    )


def test_key_is_the_url_version_checksum_triple():
    assert _upstream_hash_key(PKGBUILD) == KEY


def test_a_signed_entry_matches_the_key(tmp_path, isolated_db):
    base = tmp_path / "baseline"
    _write_baseline(base)
    import_baseline(base, allow_unsigned=True)
    assert match_upstream_hash(KEY)
    assert _upstream_hash_corroborated(PKGBUILD)


def test_corroboration_downgrades_c001_to_info(tmp_path, isolated_db):
    base = tmp_path / "baseline"
    _write_baseline(base, "https://example.org/demo-1.0.tar.gz|1.0|def")
    import_baseline(base, allow_unsigned=True)
    new = PKGBUILD.replace("'abc'", "'def'")
    text = _diff(PKGBUILD, new)
    changes = extract_urls_from_diff(text)
    findings = _structural_findings(
        text, changes, package_name="demo", current_text=new
    )
    c001 = [item for item in findings if item["rule_id"] == "C001"]
    assert c001 and c001[0]["severity"] == "INFO"
    assert c001[0].get("weight_override") == 0


def test_an_uncorroborated_checksum_stays_high(tmp_path, isolated_db):
    new = PKGBUILD.replace("'abc'", "'def'")
    text = _diff(PKGBUILD, new)
    changes = extract_urls_from_diff(text)
    findings = _structural_findings(
        text, changes, package_name="demo", current_text=new
    )
    c001 = [item for item in findings if item["rule_id"] == "C001"]
    assert c001 and c001[0]["severity"] == "HIGH"
