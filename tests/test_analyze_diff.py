"""Spec §5: analyze_diff, the arbitrary-comparison entry point.

Same-difference guarantee: for a corpus diff, ``analyze_diff`` produces
the same findings as the corpus path, modulo provenance.  The text cap is
a validated error, never a silent truncation.
"""

import pathlib

import pytest

import trustsight.db as db_module
from trustsight.api import MAX_API_TEXT_BYTES, TrustSight
from trustsight.analysis.pipeline import scan_diff
from trustsight.coverage import PARTIAL_HUNK
from trustsight.db import init_db

_CORPUS = pathlib.Path(__file__).resolve().parent / "fixtures" / "benign-corpus"


@pytest.fixture
def ts(tmp_path, monkeypatch):
    monkeypatch.setattr(db_module, "DATA_DIR", tmp_path)
    monkeypatch.setattr("trustsight.config.DATA_DIR", tmp_path)
    monkeypatch.setattr("trustsight.config.CONFIG_DIR", tmp_path / ".config")
    monkeypatch.setattr("trustsight.config.CACHE_DIR", tmp_path / ".cache")
    init_db()
    client = TrustSight(auto_import_seed=False)
    client._ready = True
    return client


def _corpus_diff():
    path = sorted(_CORPUS.glob("*.diff"))[0]
    return path.stem, path.read_text(encoding="utf-8", errors="replace")


def _finding_rows(report):
    return [
        (f.rule_id, f.severity, f.file, f.line)
        for f in report.findings
    ]


def test_analyze_diff_matches_the_corpus_path(ts):
    name, text = _corpus_diff()
    direct = scan_diff(text, package_name=name)
    report = ts.analyze_diff(text, package=name)
    expected = [
        (e.rule_id, e.severity, e.file, e.line)
        for e in direct.score_breakdown
        if e.weight > 0 or e.severity in ("FATAL", "CRITICAL")
    ]
    assert _finding_rows(report) == expected
    assert report.adapter == "diff"
    assert report.package == name


def test_a_mangled_diff_reports_the_gap(ts):
    name, text = _corpus_diff()
    lines = text.splitlines()
    # Cut the diff before its last line: whatever was in flight is now a
    # partial hunk, and the pasted-diff path must say so.
    cut = "\n".join(lines[:-3])
    report = ts.analyze_diff(cut, package=name)
    assert PARTIAL_HUNK in report.coverage_gaps or report.diff_truncated


def test_an_oversized_diff_is_a_validated_error(ts):
    huge = "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1 +1 @@\n+" + (
        "x" * (MAX_API_TEXT_BYTES + 1))
    with pytest.raises(ValueError):
        ts.analyze_diff(huge)
