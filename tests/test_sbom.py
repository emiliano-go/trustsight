"""The CycloneDX SBOM projection: components, findings, opacity, bounds."""

import json

from typer.testing import CliRunner

from trustsight.cli.app import app
from trustsight.depth import DependencyReport
from trustsight.sbom import (
    MAX_SBOM_BYTES,
    MAX_SBOM_COMPONENTS,
    build_sbom,
    render_sbom,
)
from trustsight.schema import DiffSummary, PackageFact, ScoreEntry

GOOD_HASH = "a" * 64
GOOD_URL = "https://example.com/good.tar.gz"
RECIPE = f"""pkgname=demo
pkgver=1.2
pkgrel=1
depends=('evil>=1.2' 'glibc')
makedepends=('cmake')
optdepends=('foo: extra')
source=('{GOOD_URL}'
        'git+https://github.com/a/b.git#commit=deadbeef'
        'local.patch'
        'bad.tar.gz::https://example.com/bad.tar.gz')
sha256sums=('{GOOD_HASH}' 'SKIP' 'SKIP' 'SKIP')
"""


def _fact(**kwargs) -> PackageFact:
    defaults = dict(
        package_name="demo",
        new_version="1.2-1",
        diff_summary=DiffSummary(files_changed=["PKGBUILD"]),
        score_breakdown=[
            ScoreEntry(rule_id="R001", severity="CRITICAL", weight=40,
                       reason="curl piped to bash", file="PKGBUILD"),
            ScoreEntry(rule_id="D001", severity="MEDIUM", weight=15,
                       reason="new dependency", file="PKGBUILD",
                       evidence={"field": "depends", "dep_name": "evil"}),
            ScoreEntry(rule_id="R152", severity="LOW", weight=0,
                       reason="source URL", file="PKGBUILD",
                       evidence={"url": GOOD_URL}),
            ScoreEntry(rule_id="A014", severity="HIGH", weight=0,
                       reason="unsafe runpath", file="PKGBUILD",
                       evidence={"path": "bin/app"}),
        ],
        dependencies=[
            DependencyReport(name="evil", depth=1, score=10, risk="Low",
                             finding_count=1),
            DependencyReport(name="glibc", depth=1, failed=True,
                             error="metadata unavailable"),
        ],
        coverage_gaps=["deps_not_scanned"],
        depth_truncated=True,
    )
    defaults.update(kwargs)
    return PackageFact(**defaults)


def _by_name(bom: dict, name: str) -> dict:
    return next(c for c in bom["components"] if c["name"] == name)


def _values(component: dict, name: str) -> list[str]:
    return [p["value"] for p in component.get("properties", ())
            if p["name"] == name]


def test_sbom_describes_the_package_sources_and_dependencies():
    bom = build_sbom(_fact(), recipe_text=RECIPE)

    assert bom["bomFormat"] == "CycloneDX"
    assert bom["specVersion"] == "1.5"
    root = bom["metadata"]["component"]
    assert root["type"] == "application"
    assert root["name"] == "demo"
    assert root["version"] == "1.2-1"

    good = _by_name(bom, "good.tar.gz")
    assert good["type"] == "file"
    assert good["hashes"] == [{"alg": "SHA-256", "content": GOOD_HASH}]
    assert good["externalReferences"][0]["url"] == GOOD_URL
    assert "R152:LOW" in _values(good, "trustsight:finding")
    assert "trustsight:opaque" not in _values(good, "trustsight:opaque")

    evil = _by_name(bom, "evil")
    assert evil["type"] == "library"
    assert evil["scope"] == "required"
    assert _values(evil, "trustsight:analyzed") == ["true"]
    assert _values(evil, "trustsight:constraint") == [">=1.2"]
    assert "D001:MEDIUM" in _values(evil, "trustsight:finding")

    foo = _by_name(bom, "foo")
    assert foo["scope"] == "optional"

    root_findings = _values(root, "trustsight:finding")
    assert "R001:CRITICAL" in root_findings
    assert "A014:HIGH" in root_findings, "weight-0 evidence stays in the SBOM"

    graph = bom["dependencies"][0]
    assert graph["ref"].startswith("urn:trustsight:package:demo@")
    assert any(ref.endswith(":evil") for ref in graph["dependsOn"])


def test_sbom_marks_opaque_sources_and_incomplete_graphs():
    bom = build_sbom(_fact(), recipe_text=RECIPE)

    vcs = _by_name(bom, "b.git")
    assert "vcs_source" in _values(vcs, "trustsight:opaque-reason")
    assert "skip_checksum" in _values(vcs, "trustsight:opaque-reason")
    assert _values(vcs, "trustsight:pin") == ["commit=deadbeef"]

    assert "skip_checksum" in _values(
        _by_name(bom, "local.patch"), "trustsight:opaque-reason")
    assert "skip_checksum" in _values(
        _by_name(bom, "bad.tar.gz"), "trustsight:opaque-reason")

    glibc = _by_name(bom, "glibc")
    assert "analysis_failed" in _values(glibc, "trustsight:opaque-reason")
    cmake = _by_name(bom, "cmake")
    assert "dependency_graph_incomplete" in _values(
        cmake, "trustsight:opaque-reason")

    root = bom["metadata"]["component"]
    assert _values(root, "trustsight:opaque") == ["true"]
    assert "coverage_gap" in _values(root, "trustsight:opaque-reason")
    assert _values(root, "trustsight:coverage-gap") == ["deps_not_scanned"]


def test_sbom_is_deterministic_and_has_no_clock_or_serial():
    first = render_sbom(build_sbom(_fact(), recipe_text=RECIPE))
    second = render_sbom(build_sbom(_fact(), recipe_text=RECIPE))
    assert first == second
    assert '"timestamp"' not in first
    assert '"serialNumber"' not in first


def test_sbom_sanitizes_attacker_text():
    fact = _fact(score_breakdown=[
        ScoreEntry(rule_id="R001", severity="HIGH\x1b[31m",
                   weight=1, reason="x"),
    ])
    bom = build_sbom(fact, recipe_text="")
    root = bom["metadata"]["component"]
    joined = json.dumps(bom)
    assert "\x1b" not in joined
    assert "HIGH" in _values(root, "trustsight:finding")[0]


def test_sbom_bounds_components_and_findings():
    sources = ", ".join(f"'https://example.com/{i}.tar.gz'"
                        for i in range(MAX_SBOM_COMPONENTS + 50))
    sums = ", ".join(f"'{GOOD_HASH}'" for _ in range(MAX_SBOM_COMPONENTS + 50))
    recipe = (f"pkgname=demo\npkgver=1\nsource=({sources})\n"
              f"sha256sums=({sums})\n")
    bom = build_sbom(
        _fact(score_breakdown=[], dependencies=[]), recipe_text=recipe)
    assert len(bom["components"]) == MAX_SBOM_COMPONENTS
    root = bom["metadata"]["component"]
    assert _values(root, "trustsight:truncated") == ["true"]
    assert _values(root, "trustsight:omitted-components") == ["50"]
    assert len(render_sbom(bom).encode("utf-8")) <= MAX_SBOM_BYTES

    findings = [
        ScoreEntry(rule_id="H001", severity="HIGH", weight=1, reason="x")
        for _ in range(1100)
    ]
    capped = build_sbom(_fact(score_breakdown=findings), recipe_text="")
    root = capped["metadata"]["component"]
    assert _values(root, "trustsight:truncated") == ["true"]
    assert _values(root, "trustsight:omitted-findings") == ["76"]


def test_cli_and_api_emit_the_same_sbom(tmp_path, monkeypatch):
    bom = build_sbom(_fact(), recipe_text=RECIPE)
    monkeypatch.setattr(
        "trustsight.sbom.sbom_for_package",
        lambda package, depth=None: bom,
    )
    monkeypatch.setattr(
        "trustsight.api.client._aur_info", lambda name: {"demo": {}})
    monkeypatch.setattr(
        "trustsight.api.client._package_row", lambda name: None)

    from trustsight import TrustSight

    api_bom = TrustSight(auto_import_seed=False).sbom("demo")
    result = CliRunner().invoke(app, ["sbom", "demo"])
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout) == api_bom

    out = tmp_path / "demo.cdx.json"
    result = CliRunner().invoke(app, ["sbom", "demo", "--out", str(out)])
    assert result.exit_code == 0, result.output
    assert out.read_text(encoding="utf-8") == render_sbom(bom)


def test_cli_refuses_an_unsupported_format():
    result = CliRunner().invoke(app, ["sbom", "demo", "--format", "spdx"])
    assert result.exit_code == 2
    assert "only cyclonedx" in result.output


def test_sbom_checksum_alignment_preserves_empty_elements():
    recipe = (
        "pkgname=demo\n"
        "source=('one.tar.gz' 'two.tar.gz' 'three.tar.gz')\n"
        f"sha256sums=('' '{GOOD_HASH}' '{'b' * 64}')\n"
    )
    bom = build_sbom(_fact(score_breakdown=[], dependencies=[]),
                     recipe_text=recipe)
    by_name = {c["name"]: c for c in bom["components"]}
    assert _values(by_name["one.tar.gz"], "trustsight:opaque") == ["true"]
    assert by_name["two.tar.gz"]["hashes"][0]["content"] == GOOD_HASH
    assert by_name["three.tar.gz"]["hashes"][0]["content"] == "b" * 64


def test_sbom_dependency_refs_are_unique_after_sanitising():
    fact = _fact(score_breakdown=[], dependencies=[
        DependencyReport(name="a+b", depth=1), DependencyReport(name="a-b", depth=1),
    ])
    bom = build_sbom(fact, recipe_text="pkgname=demo\n")
    refs = [c["bom-ref"] for c in bom["components"]]
    assert len(refs) == len(set(refs))


def test_render_sbom_refuses_a_document_over_the_export_cap():
    import pytest
    from trustsight import sbom
    with pytest.raises(ValueError, match="export cap"):
        sbom.render_sbom({"x": "y" * (MAX_SBOM_BYTES + 1)})
