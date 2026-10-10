"""Regression tests for historical drill-down and honest incompleteness.

Covers:
- Feature 1: ``explain --history-id`` reproduces the ORIGINAL recorded
  analysis; ``history`` surfaces the analysis id, commits and coverage.
- Feature 2: an incomplete score-zero run never renders as clean, in the
  ``history`` command or in the ``inspect --last`` panels.
- Feature 3: a global override needs an explicit confirmation, and
  suppressed rows name their scope.
"""

import io
import json

from typer.testing import CliRunner

from trustsight.cli.app import app
from trustsight.cli import inspect as inspect_cli
from trustsight.cli import display
from trustsight.coverage import SCAN_TRUNCATED
from trustsight.schema import DiffSummary, PackageFact

runner = CliRunner()

_DIFF = """\
--- a/PKGBUILD
+++ b/PKGBUILD
@@ -1,4 +1,5 @@
 pkgname=demo
 pkgver=1.0
+source=('https://evil.invalid/x.tar.gz')
 sha256sums=('aaaa')
"""


def _env(tmp_path, monkeypatch):
    monkeypatch.setattr("trustsight.config.DATA_DIR", tmp_path)
    monkeypatch.setattr("trustsight.config.CONFIG_DIR", tmp_path / ".config")
    monkeypatch.setattr("trustsight.config.CACHE_DIR", tmp_path / ".cache")
    monkeypatch.setattr("trustsight.db.DATA_DIR", tmp_path)
    # override.OVERRIDES_PATH is bound at import time from CONFIG_DIR, so it
    # must be repointed explicitly or tests would read the developer's real
    # overrides file.
    monkeypatch.setattr(
        "trustsight.override.OVERRIDES_PATH", tmp_path / ".config" / "overrides.json")
    from trustsight.config import ensure_default_configs
    ensure_default_configs()
    from trustsight.db import init_db
    init_db()


def _record(tmp_path, monkeypatch, fact_extra=None, score=0):
    """Record one analysis for 'demo' and return its history id."""
    _env(tmp_path, monkeypatch)
    from trustsight.db import insert_analysis, upsert_package
    fact = {
        "package_name": "demo",
        "risk": "Inconclusive",
        "coverage_gaps": [SCAN_TRUNCATED],
        "config_fingerprint": "deadbeef",
        "score_breakdown": [
            {
                "rule_id": "C003",
                "severity": "HIGH",
                "weight": 30,
                "reason": "source URL changed",
                "params": {},
                "template": "source {url}",
                "evidence": {"url": "https://evil.invalid/x.tar.gz"},
                "file": "PKGBUILD",
                "line": 3,
            }
        ],
        "suppressed_rules": [
            {"rule_id": "H099", "severity": "LOW",
             "override_reason": "known good", "override_package": None}
        ],
        "acknowledged_urls": [],
        "change": {"sources": {"gained": ["https://evil.invalid/x.tar.gz"]}},
    }
    fact.update(fact_extra or {})
    pkg_id = upsert_package("demo", "1.1")
    return insert_analysis(
        pkg_id, "1.0", "1.1", "aaaa1111", "bbbb2222", score,
        _DIFF, json.dumps(fact),
        [{"rule_id": "C003", "severity": "HIGH"}],
    )


# ---------------------------------------------------------------------------
# Feature 1: history output carries the stable id, commits and coverage
# ---------------------------------------------------------------------------


class TestHistoryOutput:
    def test_json_includes_id_commits_and_completeness(self, tmp_path, monkeypatch):
        hid = _record(tmp_path, monkeypatch)
        result = runner.invoke(app, ["history", "demo", "--json"])
        assert result.exit_code == 0, result.output
        data = json.loads(result.output)
        assert data[0]["id"] == hid
        assert data[0]["old_commit"] == "aaaa1111"
        assert data[0]["new_commit"] == "bbbb2222"
        assert data[0]["complete"] is False
        assert data[0]["coverage_gaps"] == [SCAN_TRUNCATED]

    def test_plain_marks_incomplete_score_zero(self, tmp_path, monkeypatch):
        _record(tmp_path, monkeypatch, score=0)
        result = runner.invoke(app, ["history", "demo"])
        assert result.exit_code == 0, result.output
        out = result.output
        assert "Score: 0/100" in out
        assert "INCOMPLETE" in out
        assert "its last lines" in out  # the scan-truncated reason text

    def test_empty_state_points_at_a_recording_command(self, tmp_path, monkeypatch):
        _env(tmp_path, monkeypatch)
        from trustsight.db import upsert_package
        upsert_package("demo", "1.0")
        result = runner.invoke(app, ["history", "demo"])
        assert result.exit_code == 0
        assert "inspect --record" in result.output

    def test_unknown_package_points_at_a_recording_command(self, tmp_path, monkeypatch):
        _env(tmp_path, monkeypatch)
        result = runner.invoke(app, ["history", "demo"])
        assert result.exit_code == 2
        assert "inspect --record" in result.output


# ---------------------------------------------------------------------------
# Feature 1: explain --history-id reproduces the ORIGINAL analysis
# ---------------------------------------------------------------------------


class TestExplainHistoryId:
    def test_reproduces_the_recorded_analysis(self, tmp_path, monkeypatch):
        hid = _record(tmp_path, monkeypatch)
        result = runner.invoke(
            app, ["explain", "demo", "--history-id", str(hid), "C003", "--json"])
        assert result.exit_code == 0, result.output
        data = json.loads(result.output)
        analysis = data["analysis"]
        assert analysis["id"] == hid
        assert analysis["old_commit"] == "aaaa1111"
        assert analysis["new_commit"] == "bbbb2222"
        assert analysis["old_version"] == "1.0"
        assert analysis["new_version"] == "1.1"
        assert analysis["config_fingerprint"] == "deadbeef"
        assert analysis["coverage_gaps"] == [SCAN_TRUNCATED]
        # The finding is the recorded one, with file/line/evidence.
        assert data["finding"]["file"] == "PKGBUILD"
        assert data["finding"]["line"] == 3
        assert data["finding"]["evidence"] == {
            "url": "https://evil.invalid/x.tar.gz"}
        # The stored diff is re-read for the line, not a fresh fetch.
        raws = [line["raw"] for line in data["lines"]]
        assert any("evil.invalid" in raw for raw in raws)

    def test_unknown_history_id_errors(self, tmp_path, monkeypatch):
        _env(tmp_path, monkeypatch)
        result = runner.invoke(app, ["explain", "demo", "--history-id", "99", "C003"])
        assert result.exit_code == 2
        assert "No recorded analysis" in result.output

    def test_rule_that_did_not_fire_in_the_recording_errors(self, tmp_path, monkeypatch):
        hid = _record(tmp_path, monkeypatch)
        result = runner.invoke(app, ["explain", "demo", "--history-id", str(hid), "H050"])
        assert result.exit_code == 2
        assert "did not fire" in result.output

    def test_old_rows_without_locations_are_marked_not_recorded(self, tmp_path, monkeypatch):
        breakdown = [{
            "rule_id": "C003", "severity": "HIGH", "weight": 30,
            "reason": "source URL changed",
        }]
        hid = _record(tmp_path, monkeypatch,
                      fact_extra={"score_breakdown": breakdown})
        result = runner.invoke(
            app, ["explain", "demo", "--history-id", str(hid), "C003"])
        assert result.exit_code == 0, result.output
        assert "not recorded for this analysis" in result.output


# ---------------------------------------------------------------------------
# Feature 2: "No findings" must not read as clean on an incomplete run
# ---------------------------------------------------------------------------


def _panel_plain(row):
    buffer = io.StringIO()
    import contextlib
    with contextlib.redirect_stdout(buffer):
        inspect_cli._render_history_panel_plain(row, show_score=True, show_risk=True)
    return buffer.getvalue()


class TestNoFindingsHonesty:
    def test_incomplete_run_is_not_shown_as_clean_plain(self):
        row = {"commit": "abcd1234", "commit_message": "bump",
               "findings": [], "coverage_gaps": [SCAN_TRUNCATED]}
        out = _panel_plain(row)
        assert "No findings (incomplete" in out
        assert "  No findings\n" not in out

    def test_complete_run_still_says_no_findings_plain(self):
        row = {"commit": "abcd1234", "commit_message": "bump",
               "findings": [], "coverage_gaps": []}
        out = _panel_plain(row)
        assert "  No findings\n" in out

    def test_incomplete_run_is_not_shown_as_clean_rich(self):
        from rich.console import Console
        row = {"commit": "abcd1234", "commit_message": "bump",
               "findings": [], "coverage_gaps": [SCAN_TRUNCATED]}
        buffer = io.StringIO()
        saved = display._console
        display._console = Console(file=buffer, force_terminal=False, width=200)
        try:
            inspect_cli._render_history_panel_rich(row, True, True, False)
        finally:
            display._console = saved
        out = buffer.getvalue()
        assert "No findings (incomplete" in out

    def test_status_text_is_inconclusive_when_gaps_exist(self):
        fact = PackageFact(
            package_name="demo",
            coverage_gaps=[SCAN_TRUNCATED],
            diff_summary=DiffSummary(),
        )
        assert inspect_cli._status_text(fact).startswith("Inconclusive")

    def test_status_text_unchanged_when_complete(self):
        fact = PackageFact(
            package_name="demo",
            diff_summary=DiffSummary(lines_added=1),
        )
        assert "Only pkgver and sha256sums changed" in inspect_cli._status_text(fact)


# ---------------------------------------------------------------------------
# Feature 3: global scope needs explicit confirmation; scope is visible
# ---------------------------------------------------------------------------


class TestOverrideScope:
    def test_global_override_requires_confirmation(self, tmp_path, monkeypatch):
        _env(tmp_path, monkeypatch)
        result = runner.invoke(
            app, ["override", "add", "H001", "--reason", "misfires"],
            input="n\n")
        assert result.exit_code == 2
        assert "Aborted" in result.output
        from trustsight.override import list_overrides
        assert list_overrides() == []

    def test_global_override_with_confirmation_applies(self, tmp_path, monkeypatch):
        _env(tmp_path, monkeypatch)
        result = runner.invoke(
            app, ["override", "add", "H001", "--reason", "misfires"],
            input="y\n")
        assert result.exit_code == 0, result.output
        from trustsight.override import list_overrides
        assert len(list_overrides()) == 1
        assert list_overrides()[0].package is None

    def test_global_override_with_yes_flag_skips_prompt(self, tmp_path, monkeypatch):
        _env(tmp_path, monkeypatch)
        result = runner.invoke(
            app, ["override", "add", "H001", "--reason", "misfires", "--yes"])
        assert result.exit_code == 0, result.output
        from trustsight.override import list_overrides
        assert len(list_overrides()) == 1

    def test_package_scope_needs_no_confirmation(self, tmp_path, monkeypatch):
        _env(tmp_path, monkeypatch)
        result = runner.invoke(
            app, ["override", "add", "H001", "--package", "demo",
                  "--reason", "misfires"])
        assert result.exit_code == 0, result.output
        from trustsight.override import list_overrides
        assert list_overrides()[0].package == "demo"

    def test_package_and_global_are_mutually_exclusive(self, tmp_path, monkeypatch):
        _env(tmp_path, monkeypatch)
        result = runner.invoke(
            app, ["override", "add", "H001", "--package", "demo",
                  "--global", "--reason", "x"])
        assert result.exit_code == 2

    def test_add_url_mentions_normalisation(self, tmp_path, monkeypatch):
        _env(tmp_path, monkeypatch)
        result = runner.invoke(
            app, ["override", "add-url", "demo",
                  "https://example.com/v1.0.0.tar.gz", "--reason", "official"])
        assert result.exit_code == 0, result.output
        assert "version bump" in result.output or "carry across" in result.output


def _suppressed_fact(*rows):
    return PackageFact(
        package_name="demo",
        suppressed_rules=rows,
        diff_summary=DiffSummary(),
    )


def _plain(fn) -> str:
    buffer = io.StringIO()
    import contextlib
    with contextlib.redirect_stdout(buffer):
        fn()
    return buffer.getvalue()


class TestSuppressedScopeVisible:
    def test_inspect_plain_shows_global_scope(self):
        fact = _suppressed_fact({"rule_id": "H001", "severity": "LOW",
                                 "override_reason": "known",
                                 "override_package": None})
        out = _plain(lambda: inspect_cli._inspect_plain(fact))
        assert "H001 (ALL packages) known" in out

    def test_inspect_plain_shows_package_scope(self):
        fact = _suppressed_fact({"rule_id": "H001", "severity": "LOW",
                                 "override_reason": "known",
                                 "override_package": "demo"})
        out = _plain(lambda: inspect_cli._inspect_plain(fact))
        assert "H001 (demo) known" in out

    def test_inspect_rich_shows_scope(self):
        from rich.console import Console
        fact = _suppressed_fact({"rule_id": "H001", "severity": "LOW",
                                 "override_reason": "known",
                                 "override_package": "demo"})
        buffer = io.StringIO()
        saved = display._console
        display._console = Console(file=buffer, force_terminal=False, width=200)
        try:
            inspect_cli._inspect_rich(fact)
        finally:
            display._console = saved
        assert "H001  (demo)  known" in buffer.getvalue()
