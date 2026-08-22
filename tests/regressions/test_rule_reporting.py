"""What a recipe does not say, and a shipped fix that never reached an install."""

import pytest

# ---------------------------------------------------------------------------
# Audit M2 - a recipe that pins says so; one that does not said nothing
#
# P005 reports a commit pin and P006 a tag pin, so a recipe tracking a branch
# produced no line at all and read the same as one that pins.  Reported at
# weight 0 rather than as a coverage gap: it is true of every VCS package by
# design, and a gap fires 20% of the benign corpus into Inconclusive.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("entry,expected", [
    ("git+https://ex.invalid/d.git#branch=main", True),
    ("git+https://ex.invalid/d.git", True),
    ("git+https://ex.invalid/d.git#tag=v1.2", True),
    ("git+https://ex.invalid/d.git#commit=" + "b" * 40, False),
    ("git+https://ex.invalid/d.git#commit=$_commit", False),
    ("https://ex.invalid/d-1.0.tar.gz", False),
])
def test_p008_reports_only_a_missing_commit_pin(entry, expected):
    from trustsight.coverage import unpinned_source_refs

    assert bool(unpinned_source_refs(f"+source=({entry})\n")) is expected


def test_p008_carries_no_weight():
    """A declared fact may not move the band; that was the whole decision."""
    from trustsight.analysis import scan_diff

    diff = (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,4 +1,6 @@\n"
        '+source=("git+https://ex.invalid/d.git#branch=main")\n'
    )
    entries = [e for e in scan_diff(diff, package_name="p").score_breakdown
               if e.rule_id == "P008"]
    assert entries, "P008 must be reachable"
    assert all(e.weight == 0 for e in entries)


# ---------------------------------------------------------------------------
# A shipped *pattern* fix never reached an existing install, and nothing said so
#
# `drifted_shipped_rules` parsed `pattern` into its field dict and then
# compared everything except it, so rules.toml - written once at install
# time - kept its original patterns forever with no report.  Both the escape
# guard and the executor list above landed that way.
# ---------------------------------------------------------------------------


def test_pattern_drift_is_reported(tmp_path, monkeypatch):
    import trustsight.config as cfg

    monkeypatch.setattr(cfg, "CONFIG_DIR", tmp_path)
    shipped = next(r for r in cfg.shipped_rules() if r["id"] == "R001")
    (tmp_path / "rules.toml").write_text(
        '[[rules]]\nid = "R001"\nname = "Curl Pipe to Shell"\n'
        "pattern = 'curl.*\\\\|\\\\s*(?:bash|sh)'\n"
        'severity = "CRITICAL"\ncategory = "network_execution"\n'
        'match_target = "resolved"\n'
    )
    cfg._rules_cache = None
    drift = {(rid, field) for rid, field, _on_disk, _shipped in
             cfg.drifted_shipped_rules()}
    cfg._rules_cache = None
    assert ("R001", "pattern") in drift
    assert "pdk" in shipped["pattern"], "the shipped pattern is the wide one"
