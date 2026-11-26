"""The L9 acceptance corpus: every A rule has a positive and a near miss.

The diff corpus cannot reach an artifact rule, so the lane is held honest by
committed data: one positive and one near-miss negative per rule, real benign
controls produced from built packages, and a real ``makepkg`` artifact whose
extracted manifest is asserted against the producer.
"""

from __future__ import annotations

import io
import json
import shutil
import sys
import tarfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
CORPUS = ROOT / "tests" / "fixtures" / "l9-corpus"
sys.path.insert(0, str(ROOT / "scripts"))

from trustsight.analysis.artifact import inspect_manifest  # noqa: E402
from trustsight.analysis.release_asset import compare_release_asset  # noqa: E402
from trustsight.upstream_collect import _artifact_findings  # noqa: E402

EXPECTED = json.loads((CORPUS / "expected.json").read_text())


def _fired(record: dict, body: dict) -> set[str]:
    lane = record["lane"]
    if lane == "manifest":
        findings = inspect_manifest(
            body.get("manifest") or [], body.get("declared") or {})
        return {f["rule_id"] for f in findings}
    if lane == "upstream":
        findings = _artifact_findings(body.get("artifacts") or [])
        return {f["rule_id"] for f in findings}
    if lane == "release":
        finding = compare_release_asset(
            body.get("asset") or [], body.get("tag") or [])
        return {finding["rule_id"]} if finding else set()
    raise AssertionError(f"unknown lane {lane!r}")


def _body(relative: str) -> dict:
    return json.loads((CORPUS / relative).read_text())


@pytest.mark.parametrize("relative", sorted(EXPECTED))
def test_l9_corpus_fixture(relative: str) -> None:
    record = EXPECTED[relative]
    fired = _fired(record, _body(relative))
    if record["kind"] == "benign":
        unexpected = sorted(fired - set(record.get("allow") or []))
        assert not unexpected, (
            f"{relative}: benign control fired {unexpected}; "
            f"allowed {record.get('allow')}")
        return
    assert fired == set(record["expect"]), (
        f"{relative}: fired {sorted(fired)}, expected {record['expect']}")


def test_every_a_rule_has_a_pair() -> None:
    positives = {rid for rec in EXPECTED.values()
                 for rid in rec.get("expect") or ()}
    negatives = {Path(relative).name.split("-", 1)[0].upper()
                 for relative, rec in EXPECTED.items()
                 if rec["kind"] == "negative"}
    for number in range(1, 17):
        rule_id = f"A{number:03d}"
        assert rule_id in positives, f"{rule_id} has no positive fixture"
        assert rule_id in negatives, f"{rule_id} has no negative fixture"


@pytest.mark.skipif(shutil.which("zstd") is None, reason="zstd not installed")
def test_built_fixture_manifest_matches_the_producer() -> None:
    from artifact_manifest import build_manifest

    root = CORPUS / "built" / "l9-clinic"
    committed = json.loads((root / "manifest.json").read_text())
    archive = root / "l9-clinic-1.0-1-any.pkg.tar.zst"
    produced = build_manifest(archive)
    assert produced["manifest"] == committed["manifest"]
    assert produced["declared"] == committed["declared"]


def test_built_fixture_runs_through_the_production_lane(monkeypatch) -> None:
    monkeypatch.setattr(
        "trustsight.config.load_config",
        lambda: {"verify": {"enabled": True}},
    )
    from trustsight.api import TrustSight

    committed = json.loads(
        (CORPUS / "built" / "l9-clinic" / "manifest.json").read_text())
    result = TrustSight(auto_import_seed=False).verify_build(
        "l9-clinic",
        manifest=committed["manifest"],
        declared=committed["declared"],
        static_clean=True,
    )
    if result["status"] == "l9_unavailable":
        pytest.skip(result.get("reason", "L9 sandbox unavailable"))
    fired = {f["rule_id"] for f in result["findings"]}
    assert result["status"] == "l9_analyzed"
    assert fired == set(EXPECTED["built/l9-clinic/manifest.json"]["expect"])


def _verify(monkeypatch, body: dict, package: str = "l9-fixture") -> dict:
    monkeypatch.setattr(
        "trustsight.config.load_config",
        lambda: {"verify": {"enabled": True}},
    )
    from trustsight.api import TrustSight

    return TrustSight(auto_import_seed=False).verify_build(
        package,
        manifest=body.get("manifest") or [],
        declared=body.get("declared") or {},
        static_clean=True,
    )


MANIFEST_FIXTURES = sorted(
    relative for relative, record in EXPECTED.items()
    if record["lane"] == "manifest"
)


@pytest.mark.parametrize("relative", MANIFEST_FIXTURES)
def test_manifest_fixture_through_the_sandbox(monkeypatch, relative: str) -> None:
    body = _body(relative)
    result = _verify(monkeypatch, body, package="l9-fixture")
    if result["status"] == "l9_unavailable":
        pytest.skip(result.get("reason", "L9 sandbox unavailable"))
    fired = {f["rule_id"] for f in result["findings"]}
    record = EXPECTED[relative]
    if record["kind"] == "benign":
        assert not (fired - set(record.get("allow") or [])), (
            f"{relative}: benign control fired {sorted(fired)}")
    else:
        assert fired == set(record["expect"]), (
            f"{relative}: sandbox fired {sorted(fired)}, "
            f"expected {record['expect']}")


def test_lane_is_deterministic(monkeypatch) -> None:
    body = json.loads(
        (CORPUS / "built" / "l9-clinic" / "manifest.json").read_text())
    first = _verify(monkeypatch, body, package="l9-clinic")
    second = _verify(monkeypatch, body, package="l9-clinic")
    if first["status"] == "l9_unavailable":
        pytest.skip(first.get("reason", "L9 sandbox unavailable"))
    assert first["findings"] == second["findings"]


def test_cap_hit_is_partial_not_clean(monkeypatch) -> None:
    body = {"manifest": [{"path": f"/usr/share/l9/{index}"}
                         for index in range(10_001)], "declared": {}}
    result = _verify(monkeypatch, body)
    if result["status"] == "l9_unavailable":
        pytest.skip(result.get("reason", "L9 sandbox unavailable"))
    assert result["status"] == "l9_partial"
    assert result.get("truncated") is True


def test_disabled_lane_reports_a_boundary(monkeypatch) -> None:
    monkeypatch.setattr(
        "trustsight.config.load_config",
        lambda: {"verify": {"enabled": False}},
    )
    from trustsight.api import TrustSight

    result = TrustSight(auto_import_seed=False).verify_build(
        "l9-fixture", manifest=[{"path": "/usr/bin/x", "mode": 0o4755}])
    assert result["status"] == "l9_unavailable"
    assert result["findings"] == []
    assert "disabled" in result["reason"]


def test_unavailable_worker_never_reads_as_clean(monkeypatch) -> None:
    from trustsight.sandbox import manifest_client

    def down(**_kwargs):
        raise manifest_client.ManifestUnavailable("sandbox down")

    monkeypatch.setattr(manifest_client, "inspect_artifact_manifest", down)
    result = _verify(monkeypatch, {"manifest": [], "declared": {}})
    assert result["status"] == "l9_unavailable"
    assert result["findings"] == []
    assert "sandbox down" in result["reason"]


def test_producer_carries_the_capability_xattr() -> None:
    from artifact_manifest import _manifest_entry

    member = tarfile.TarInfo("usr/bin/l9-cap")
    member.mode = 0o755
    member.size = 0
    member.pax_headers = {"SCHILY.xattr.security.capability": "cap_net_raw+ep"}
    entry = _manifest_entry(member.name, member, io.BytesIO(b""))
    assert entry is not None
    assert entry["caps"].startswith("0x")
    assert "A006" in {f["rule_id"] for f in inspect_manifest([entry], {})}
