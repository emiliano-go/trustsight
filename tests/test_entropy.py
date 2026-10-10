"""Addendum 5 §6.3: the E-series entropy predicates.

Thresholds ship empty, so the series is silent until configured; the
helpers are unit-tested and the rules are exercised by setting thresholds.
"""

from trustsight.analysis.entropy import (
    added_text,
    compression_ratio,
    encoded_fraction,
    entropy_findings,
    identifier_entropy,
)


def _diff(body: str) -> str:
    added = "".join(f"+{line}\n" for line in body.splitlines())
    count = 1 + len(body.splitlines())
    return (
        f"--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,1 +1,{count} @@\n pkgname=demo\n"
        + added
    )


def _collect(diff_text, config):
    emitted: list[dict] = []

    def add(rule_id, name, severity, category, match, **extra):
        emitted.append({"rule_id": rule_id, **extra})

    entropy_findings(diff_text, config, add)
    return emitted


def test_added_text_is_the_post_side_projection():
    text = _diff("pkgver=1.0\nsource=('https://a/x')")
    assert "pkgver=1.0" in added_text(text)
    assert "pkgname=demo" not in added_text(text)


def test_compression_ratio_is_low_for_repetition():
    repetitive = ("AAAA" * 200 + "\n") * 20
    assert compression_ratio(repetitive) < 0.1
    assert compression_ratio("") == 0.0


def test_identifier_entropy_is_zero_for_no_names():
    assert identifier_entropy("echo hello") == 0.0
    assert identifier_entropy("_aa=1\n_bb=2\n_cc=3\n") > 0.0


def test_encoded_fraction_counts_long_runs():
    text = "x " + ("A" * 100) + " y"
    assert encoded_fraction(text, min_length=64) > 0.0
    assert encoded_fraction(text, min_length=200) == 0.0


def test_e_series_is_silent_with_empty_thresholds():
    assert _collect(_diff("pkgver=1.0"), {}) == []


def test_e001_fires_when_configured():
    repetitive = "\n".join("AAAA" * 100 for _ in range(20))
    emitted = _collect(_diff(repetitive), {"thresholds": {"e001": {"max_ratio": 0.2}}})
    assert [e["rule_id"] for e in emitted] == ["E001"]


def test_e002_fires_when_configured():
    body = " ".join("A" * 80 for _ in range(10)) + " short"
    emitted = _collect(_diff(body), {"thresholds": {"e002": {"min_fraction": 0.5}}})
    assert [e["rule_id"] for e in emitted] == ["E002"]


def test_e003_fires_outside_the_band():
    body = "_aa=1\n_bb=2\n_cc=3\n_d=4\n"
    emitted = _collect(_diff(body), {"thresholds": {"e003": {"min_entropy": 6.0}}})
    assert [e["rule_id"] for e in emitted] == ["E003"]
