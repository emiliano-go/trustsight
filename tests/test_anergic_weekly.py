"""The weekly anergic calibration aggregator (scripts/anergic_weekly.py)."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))


def _fake_fetch(payload):
    def fetch(url, timeout):
        assert "rule=T008" in url
        return payload
    return fetch


def test_build_report_parses_the_feed_summary():
    import anergic_weekly

    payload = {
        "items": [],
        "summary": {
            "rules": [{"rule_id": "T008", "count": 3, "packages": 2,
                       "first": 10, "last": 20}],
            "packages": [{"package": "pkg-a", "count": 2},
                         {"package": "pkg-b", "count": 1}],
        },
    }
    report = anergic_weekly.build_report(
        ["T008"], "https://feed.example", 0, 100, fetch=_fake_fetch(payload))
    row = report["rules"][0]
    assert row["live"]["available"] is True
    assert row["live"]["count"] == 3
    assert row["live"]["packages"][0]["package"] == "pkg-a"
    text = anergic_weekly.render_markdown(report)
    assert "| T008 |" in text
    assert "pkg-a(2)" in text
    assert "Decision checklist" in text


def test_feed_failure_is_reported_not_read_as_zero():
    import anergic_weekly

    def boom(url, timeout):
        raise OSError("network down")

    report = anergic_weekly.build_report(
        ["T008"], "https://feed.example", 0, 100, fetch=boom)
    row = report["rules"][0]
    assert row["live"]["available"] is False
    assert "network down" in row["live"]["error"]
    assert "feed unavailable" in anergic_weekly.render_markdown(report)


def test_no_anergic_rules_renders_an_empty_report():
    import anergic_weekly

    report = anergic_weekly.build_report([], "https://feed.example", 0, 100)
    assert report["rules"] == []
    text = anergic_weekly.render_markdown(report)
    assert "(none)" in text
