"""Spec §3: SARIF output and inline attribution.

Formatting only, over solved attribution: rule IDs map directly, levels
come from the severity ladder, removed-line findings anchor to the
pre-image, and no location is ever fabricated (a finding whose line does
not resolve gets no region).  Goldens pin three representative diffs.
"""

import json
import pathlib

from trustsight.analysis.pipeline import scan_diff
from trustsight.diffdoc import parse_diff
from trustsight.reporting import (
    evaluate_fact,
    finding_fingerprint,
    report_to_sarif,
)

_FIXTURES = pathlib.Path(__file__).resolve().parent / "fixtures"
_GOLD = _FIXTURES / "sarif"
_MALICIOUS = _FIXTURES / "malicious" / "synthetic"

_CLEAN_BUMP = """\
--- a/PKGBUILD
+++ b/PKGBUILD
@@ -1,4 +1,4 @@
 pkgname=demo
-pkgver=1.0
+pkgver=1.1
 pkgrel=1
 source=('https://example.invalid/demo-1.0.tar.gz')
"""

_CHECKSUM_ROTATION = """\
--- a/PKGBUILD
+++ b/PKGBUILD
@@ -1,4 +1,4 @@
 pkgname=demo
 pkgver=1.1
 pkgrel=1
-sha256sums=('aaaa')
+sha256sums=('bbbb')
"""

_REMOVED_ONLY = """\
--- a/PKGBUILD
+++ b/PKGBUILD
@@ -1,2 +1,1 @@
 pkgname=demo
-source=('https://evil.invalid/x.tar.gz')
"""


def _render(text: str, package: str = "demo"):
    fact = scan_diff(text, package_name=package)
    return report_to_sarif([evaluate_fact(fact)], {package: text})


def test_golden_sarif_for_three_representative_diffs():
    cases = {
        "clean-bump": ("demo", _CLEAN_BUMP),
        "checksum-rotation": ("demo", _CHECKSUM_ROTATION),
        "malicious": (
            "C011-prebuilt-non-upstream-bin",
            (_MALICIOUS / "C011-prebuilt-non-upstream-bin.diff").read_text(
                encoding="utf-8", errors="replace"),
        ),
    }
    for name, (package, text) in cases.items():
        golden = _GOLD / f"{name}.sarif.json"
        assert golden.exists(), f"missing golden {golden.name}"
        assert _render(text, package) == json.loads(
            golden.read_text(encoding="utf-8")), name


def test_every_emitted_location_exists_in_its_artifact():
    """No out-of-range regions: the format boundary re-checks the line the
    typed map produced."""
    for path in sorted((_FIXTURES / "benign-corpus").glob("*.diff"))[:60]:
        text = path.read_text(encoding="utf-8", errors="replace")
        package = path.stem
        document = parse_diff(text)
        sarif = report_to_sarif(
            [evaluate_fact(scan_diff(text, package_name=package))],
            {package: text},
        )
        for result in sarif["runs"][0]["results"]:
            locations = result.get("locations") or []
            if not locations:
                continue
            start = locations[0]["physicalLocation"]["region"]["startLine"]
            uri = locations[0]["physicalLocation"]["artifactLocation"]["uri"]
            side = "remove" if (
                locations[0].get("properties", {}).get("trustsight/side")
                == "removed" or
                locations[0]["physicalLocation"].get("properties", {})
                .get("trustsight/side") == "removed"
            ) else "post"
            allowed = ("remove", "context") if side == "remove" else (
                "add", "context")
            count = sum(
                1 for line in document.lines
                if line.file == uri and line.side in allowed
            )
            assert 1 <= start <= count, (path.name, uri, start, count)


def test_a_removed_line_anchors_to_the_pre_image():
    sarif = report_to_sarif(
        [{
            "package": "demo",
            "findings": [{
                "rule_id": "C003", "severity": "HIGH", "file": "PKGBUILD",
                "line": 2, "description": "source URL changed",
                "template": "source changed", "evidence": {},
            }],
        }],
        {"demo": _REMOVED_ONLY},
    )
    result = sarif["runs"][0]["results"][0]
    location = result["locations"][0]
    assert location["physicalLocation"]["region"]["startLine"] == 2
    assert location["properties"]["trustsight/side"] == "removed"


def test_an_unresolvable_line_gets_no_region_but_keeps_a_fingerprint():
    finding = {
        "rule_id": "H015", "severity": "INFO", "file": "PKGBUILD",
        "line": None, "description": "critical build function modified",
        "template": "modified {touched}", "evidence": {"touched": "build"},
    }
    sarif = report_to_sarif([{"package": "demo", "findings": [finding]}])
    result = sarif["runs"][0]["results"][0]
    assert "locations" not in result
    assert result["partialFingerprints"]["trustsight/v1"] == (
        finding_fingerprint(finding, "demo")
    )


def test_levels_follow_the_severity_ladder():
    findings = [
        {"rule_id": "A1", "severity": "FATAL", "file": "PKGBUILD", "line": 1,
         "description": "", "template": "", "evidence": {}},
        {"rule_id": "A2", "severity": "CRITICAL", "file": "PKGBUILD", "line": 1,
         "description": "", "template": "", "evidence": {}},
        {"rule_id": "A3", "severity": "HIGH", "file": "PKGBUILD", "line": 1,
         "description": "", "template": "", "evidence": {}},
        {"rule_id": "A4", "severity": "MEDIUM", "file": "PKGBUILD", "line": 1,
         "description": "", "template": "", "evidence": {}},
        {"rule_id": "A5", "severity": "LOW", "file": "PKGBUILD", "line": 1,
         "description": "", "template": "", "evidence": {}},
    ]
    sarif = report_to_sarif([{"package": "demo", "findings": findings}])
    levels = [r["level"] for r in sarif["runs"][0]["results"]]
    assert levels == ["error", "error", "warning", "warning", "note"]


def test_fingerprints_are_stable_and_evidence_sensitive():
    base = {"rule_id": "H029", "severity": "HIGH", "file": "PKGBUILD",
            "line": 3, "description": "", "template": "", "evidence": {"a": 1}}
    assert finding_fingerprint(base, "demo") == finding_fingerprint(
        dict(base), "demo")
    changed = dict(base, evidence={"a": 2})
    assert finding_fingerprint(base, "demo") != finding_fingerprint(
        changed, "demo")
