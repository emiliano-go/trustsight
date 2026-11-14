"""P4: upstream observations, the upstream_manifest IOC type, and U015."""

from __future__ import annotations

import json

import pytest

from trustsight.db import (
    get_upstream_observations,
    init_db,
    save_upstream_observation,
)
from trustsight.ioc_baseline import (
    _normalize_value,
    import_baseline,
    match_upstream_manifest,
)
from trustsight.upstream_collect import persist_upstream_observation


@pytest.fixture
def isolated_db(tmp_path, monkeypatch):
    import trustsight.config as config

    monkeypatch.setattr(config, "DATA_DIR", tmp_path)
    monkeypatch.setattr("trustsight.db.DATA_DIR", tmp_path)
    init_db()
    yield tmp_path


def test_observation_roundtrip_and_upsert(isolated_db):
    save_upstream_observation("demo", "github.com/owner/repo", "1.0",
                              checksum="a" * 64, detail='{"x":1}')
    rows = get_upstream_observations(repo="github.com/owner/repo")
    assert len(rows) == 1
    assert rows[0]["version"] == "1.0"
    assert rows[0]["detail"] == '{"x":1}'

    save_upstream_observation("demo", "github.com/owner/repo", "1.0",
                              checksum="b" * 64, detail='{"x":2}')
    rows = get_upstream_observations(repo="github.com/owner/repo")
    assert len(rows) == 1
    assert rows[0]["detail"] == '{"x":2}'


def test_observation_detail_is_bounded(isolated_db):
    save_upstream_observation("demo", "github.com/owner/repo", "1.0",
                              detail="x" * (64 * 1024))
    rows = get_upstream_observations(package="demo")
    assert len(rows[0]["detail"].encode()) <= 16 * 1024


def test_manifest_value_is_normalised():
    assert _normalize_value(
        "upstream_manifest", "GitHub.com/Owner/Repo|1.0"
    ) == "github.com/owner/repo|1.0"
    assert _normalize_value("upstream_manifest", "not-a-repo") is None


def _write_baseline(base, detail='{"remote_added":["evil.example"]}'):
    base.mkdir()
    (base / "manifest.json").write_text(json.dumps({
        "version": 1, "source": "test-feed",
        "created_at": "2026-01-01T00:00:00+00:00",
        "expires_at": "", "signature": "", "public_key": "",
    }), encoding="utf-8")
    (base / "iocs.jsonl").write_text(json.dumps({
        "type": "upstream_manifest",
        "value": "github.com/owner/repo|1.0",
        "source": "test-feed",
        "confidence": "high",
        "provenance": "upstream-scan:demo",
        "detail": detail,
    }) + "\n", encoding="utf-8")


def test_a_signed_manifest_entry_matches_with_its_detail(tmp_path, isolated_db):
    base = tmp_path / "baseline"
    _write_baseline(base)
    import_baseline(base, allow_unsigned=True)
    matched = match_upstream_manifest("github.com/owner/repo|1.0")
    assert matched and "evil.example" in matched[0].detail


def test_u015_reports_a_federated_manifest_delta(tmp_path, isolated_db):
    from trustsight.analysis.upstream_release import upstream_release_findings

    base = tmp_path / "baseline"
    _write_baseline(base)
    import_baseline(base, allow_unsigned=True)

    recipe = (
        "pkgname=demo\npkgver=1.0\n"
        'url="https://github.com/owner/repo"\n'
        'source=("https://github.com/owner/repo/archive/v1.0.tar.gz")\n'
        "sha256sums=('" + "a" * 64 + "')\n"
    )
    findings: list[dict] = []
    upstream_release_findings(
        "", None, lambda *args, **extra: findings.append((args, extra)),
        {"baselines": {"ioc": {"enabled": True}}}, "demo",
        current_text=recipe,
    )
    u015 = [f for f in findings if f[0][0] == "U015"]
    assert u015
    assert "evil.example" in u015[0][1]["detail"]
    assert u015[0][1].get("weight_override") == 0


def test_persist_upstream_observation_writes_a_bounded_row(isolated_db):
    recipe = (
        "pkgname=demo\npkgver=1.0\n"
        'url="https://github.com/owner/repo"\n'
        'source=("https://github.com/owner/repo/archive/v1.0.tar.gz")\n'
        "sha256sums=('" + "a" * 64 + "')\n"
    )
    persist_upstream_observation(
        "demo", recipe,
        [("upstream/Cargo.toml", "[package]\n")],
        [{"rule_id": "U013", "file": "upstream/.github/workflows/ci.yml"}],
        ["upstream_scan_checksum"],
        frozenset({f"https://github.com/owner/repo/archive/v1.0.tar.gz|1.0|{'a' * 64}"}),
    )
    rows = get_upstream_observations(package="demo")
    assert len(rows) == 1
    assert rows[0]["repo"] == "github.com/owner/repo"
    assert rows[0]["version"] == "1.0"
    assert "U013" in rows[0]["detail"]
