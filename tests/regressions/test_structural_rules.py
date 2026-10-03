"""Regression tests for operator-authored ``[[structural]]`` recipe rules.

Pins the five primitives, the changed-line anchor on partial diffs, the
first-seen degradation, and the scaffold's refusal of an unsafe pattern.
"""

from trustsight.analysis.structural_rules import apply_structural_rules
from trustsight.coverage import begin_stage_tracking, stage_failures

ADD_DIFF = """--- a/PKGBUILD
+++ b/PKGBUILD
@@ -1,3 +1,4 @@
 pkgname=foo
 source=('https://github.com/foo/foo-1.0.tar.gz')
+source+=('https://evil.example/payload.tar.gz')
"""

REMOVE_DIFF = """--- a/PKGBUILD
+++ b/PKGBUILD
@@ -1,3 +1,3 @@
 pkgname=foo
-source=('https://a.example/a.tar.gz' 'https://b.example/b.tar.gz')
+source=('https://a.example/a.tar.gz')
"""

SCALAR_DIFF = """--- a/PKGBUILD
+++ b/PKGBUILD
@@ -1,3 +1,3 @@
 pkgname=foo
-install=old.install
+install=new.install
 pkgver=1.0
"""

RENAME_DIFF = """--- a/PKGBUILD
+++ b/PKGBUILD
@@ -1,3 +1,3 @@
 pkgname=foo
-source=('oldname.tar.gz::https://example.com/foo-1.0.tar.gz')
+source=('newname.tar.gz::https://example.com/foo-1.0.tar.gz')
"""

PARTIAL_DIFF = """--- a/PKGBUILD
+++ b/PKGBUILD
@@ -1,4 +1,5 @@
 pkgname=foo
 source=(
   'https://a.example/a.tar.gz'
+  'https://c.example/c.tar.gz'
   'https://b.example/b.tar.gz'
"""

FULL_POST = """pkgname=foo
source=('https://github.com/foo/foo-1.0.tar.gz')
"""

FIRST_SEEN = """pkgname=newpkg
source=('https://evil.example/x.tar.gz')
install=hook.install
"""


def rule(field, match, pattern, **overrides):
    base = {
        "id": "R900",
        "name": "Structural test",
        "severity": "MEDIUM",
        "category": "structural",
        "enabled": True,
        "field": field,
        "match": match,
        "pattern": pattern,
    }
    base.update(overrides)
    return [base]


def _matches(diff, field, match, pattern, current=None):
    findings = apply_structural_rules(diff, current_text=current,
                                      rules=rule(field, match, pattern))
    return [(f["rule_id"], f["match"], f["file"], f["line"]) for f in findings]


def test_entry_added_fires_and_near_miss_is_silent():
    assert _matches(ADD_DIFF, "source", "entry_added", r"evil\.example")
    assert _matches(ADD_DIFF, "source", "entry_added", r"good\.example") == []


def test_entry_removed_fires_and_near_miss_is_silent():
    assert _matches(REMOVE_DIFF, "source", "entry_removed", r"b\.example")
    assert _matches(REMOVE_DIFF, "source", "entry_removed", r"c\.example") == []


def test_host_added_matches_the_extracted_host():
    findings = apply_structural_rules(
        ADD_DIFF, rules=rule("source", "host_added", r"^evil\.example$")
    )
    assert [f["match"] for f in findings] == ["evil.example"]
    assert findings[0]["params"]["entry"].endswith("payload.tar.gz")


def test_scalar_changed_fires_and_near_miss_is_silent():
    assert _matches(SCALAR_DIFF, "scalars.install", "scalar_changed", "new")
    assert _matches(SCALAR_DIFF, "scalars.install", "scalar_changed", "same") == []


def test_renamed_keeps_the_url_and_moves_the_name():
    assert _matches(RENAME_DIFF, "source", "renamed", "newname")
    assert _matches(RENAME_DIFF, "source", "renamed", "oldname") == []


def test_a_hidden_context_entry_is_not_counted_as_added():
    """The array is only partly visible; b is context, not a change."""
    assert _matches(PARTIAL_DIFF, "source", "entry_added", r"b\.example") == []


def test_a_visible_add_still_fires_on_a_partial_array():
    assert _matches(PARTIAL_DIFF, "source", "entry_added", r"c\.example")


def test_a_full_post_state_does_not_remove_the_anchor_requirement():
    """The entry is in the complete post text but never on an added line."""
    assert _matches(ADD_DIFF, "source", "entry_added", r"github",
                    current=FULL_POST) == []


def test_first_seen_added_primitives_degrade_to_presence():
    assert _matches("", "source", "entry_added", r"evil", current=FIRST_SEEN)
    assert _matches("", "source", "host_added", r"evil", current=FIRST_SEEN)
    assert _matches("", "scalars.install", "scalar_changed", "hook",
                    current=FIRST_SEEN)


def test_first_seen_removed_and_renamed_stay_silent():
    assert _matches("", "source", "entry_removed", r"evil", current=FIRST_SEEN) == []
    assert _matches("", "source", "renamed", r"evil", current=FIRST_SEEN) == []


def test_a_refused_pattern_is_skipped_and_recorded():
    begin_stage_tracking()
    findings = apply_structural_rules(
        ADD_DIFF, rules=rule("source", "entry_added", r"(a+)+")
    )
    assert findings == []
    assert "rule:R900" in stage_failures()


def test_scan_diff_runs_the_operator_rules_and_anchors_them():
    from trustsight.analysis import scan_diff

    fact = scan_diff(ADD_DIFF, package_name="pkg",
                     structural_rules=rule("source", "host_added", r"evil"))
    entries = [e for e in fact.score_breakdown if e.rule_id == "R900"]
    assert entries, "the structural rule did not reach the score breakdown"
    assert entries[0].file == "PKGBUILD"
    assert entries[0].line


def test_a_disabled_rule_does_not_fire():
    findings = apply_structural_rules(
        ADD_DIFF, rules=rule("source", "host_added", r"evil", enabled=False)
    )
    assert findings == []


def test_weight_override_reaches_the_finding():
    findings = apply_structural_rules(
        ADD_DIFF, rules=rule("source", "host_added", r"evil", weight_override=3)
    )
    assert findings[0]["weight_override"] == 3
