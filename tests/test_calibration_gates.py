"""- the calibration gates run as tests.

``scripts/calibration_gates.py`` turns each line into a number and a
comparison.  The default test run scans a sample of the benign corpus so a
full replay does not sit in every `pytest` invocation; the CI job and
``TRUSTSIGHT_FULL_CALIBRATION=1`` run it whole.

The sampled run is not a weaker gate for the corpus-independent checks -
recall, weight-0 discipline, exact-match, homograph - those see the same
data either way.  Only the fire-rate, correlation and separation numbers
move with the sample, and they move by a rounding margin, not a threshold.
"""

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import calibration_gates as gates  # noqa: E402

CORPUS = gates.FIXTURES / "benign-corpus"
MALICIOUS = gates.FIXTURES / "malicious"
SAMPLE = 1 if os.environ.get("TRUSTSIGHT_FULL_CALIBRATION") else 6

pytestmark = pytest.mark.skipif(
    not CORPUS.exists(),
    reason="benign corpus absent; rebuild with scripts/build_corpus.py",
)


@pytest.fixture(scope="module")
def results():
    # The scan dominates the suite when the locked corpus is present.  Four
    # workers keep it off the critical path without turning an xdist run
    # (which already has workers) into an oversubscribed machine.
    with gates.shipped_config():
        benign = gates.scan_corpus(CORPUS, sample=SAMPLE, jobs=4)
        malicious = gates.scan_malicious(MALICIOUS, jobs=4) if MALICIOUS.exists() else []
        yield benign, malicious


def _assert(gate: gates.Gate):
    assert gate.passed, f"{gate.name}: measured={gate.measured} {gate.detail}"


def test_no_rule_fires_on_a_third_of_the_benign_corpus(results):
    _assert(gates.gate_benign_fire_rates(results[0]))


def test_score_does_not_track_diff_size(results):
    _assert(gates.gate_score_not_size(results[0]))


def test_weight_zero_rules_score_zero(results):
    """An annotation that acquires weight double-counts another rule's evidence."""
    _assert(gates.gate_weight_zero_annotations(results[0]))


def test_h035_stays_out_of_build_and_prepare(results):
    _assert(gates.gate_h035_position(results[0]))


def test_stateful_rules_are_silent_without_state(results):
    """Class C/D cold-start gates, measured rather than asserted per-rule."""
    _assert(gates.gate_stateful_rules_stay_out(results[0]))


def test_indicators_match_only_what_they_equal(results):
    _assert(gates.gate_ioc_exact_match(results[0]))


def test_homograph_rule_ignores_single_script_domains():
    _assert(gates.gate_homograph_single_script())


def test_benign_and_attack_scores_do_not_overlap(results):
    benign, malicious = results
    if not malicious:
        pytest.skip("malicious fixtures absent")
    _assert(gates.gate_separation(benign, malicious))


def test_labelled_attacks_are_still_detected(results):
    _, malicious = results
    if not malicious:
        pytest.skip("malicious fixtures absent")
    _assert(gates.gate_malicious_recall(malicious))


def test_known_gaps_are_still_gaps(results):
    """A closed gap must lose its label, not keep passing under it."""
    _, malicious = results
    if not malicious:
        pytest.skip("malicious fixtures absent")
    _assert(gates.gate_known_gaps_unchanged(malicious))


def test_s_series_has_a_payload_and_a_lookalike_per_rule(results):
    """Every sabotage rule fires on its payload and sleeps on its near-miss."""
    benign, malicious = results
    if not malicious:
        pytest.skip("malicious fixtures absent")
    _assert(gates.gate_s_series_fixture_pairs(benign, malicious))


def test_s_series_last_fired_ledger_is_reported(results):
    """The report labels every S rule that never fired outside its fixture."""
    benign, malicious = results
    if not malicious:
        pytest.skip("malicious fixtures absent")
    gate = gates.gate_s_series_last_fired_coverage(benign, malicious)
    assert gate.passed, "the coverage ledger is reporting-only"
    assert set(gate.measured) == set(gates._S_RULES)


@pytest.mark.skipif(
    SAMPLE != 1, reason="X-rate stability is only meaningful on the whole corpus"
)
def test_x_series_rates_match_the_baseline(results):
    """A composition rate that shrinks silently fails until adjudicated."""
    _assert(gates.gate_x_series_rate_stability(results[0]))


def test_h098_cluster_stays_below_its_members(results):
    """The weight-bearing cluster never fires without the members it names."""
    _assert(gates.gate_cluster_rate_below_members(results[0]))


def test_the_runner_reports_a_gate_per_plan_line(results):
    """The script's own contract: every gate is named and exits nonzero."""
    benign, malicious = results
    all_gates = gates._evaluate(benign, malicious)
    assert len(all_gates) == 18
    assert all(g.name for g in all_gates)


def test_manifest_benign_corpus_stays_clean():
    """The scored U-rules never fire on a benign manifest edit."""
    _assert(gates.gate_manifest_benign_corpus())


def test_scan_rows_artifact_round_trips(tmp_path):
    """The H-series audit reads the gates' scan, not a second one.

    ``--rows`` writes the per-diff fired ids the audit needs; these must
    survive the round trip unchanged, or the audit silently measures
    something other than the run the gates passed.
    """
    import h_reduction_audit as audit

    benign = [
        {"entries": [{"rule_id": "H001"}, {"rule_id": "D002", "weight": 0}]},
        {"entries": [{"rule_id": "H001"}]},
    ]
    malicious = [{"fired": {"S001", "H001"}}, {"fired": set()}]
    path = tmp_path / "scan-rows.json"
    gates._write_scan_rows(path, benign, malicious)

    benign_rows, malicious_rows = audit._load_rows(path)
    assert benign_rows == [["H001", "D002"], ["H001"]]
    assert malicious_rows == [["H001", "S001"], []]
    assert audit._rule_indices(benign_rows) == {"H001": {0, 1}, "D002": {0}}
    counts, sets = audit._counts_and_sets(malicious_rows)
    assert counts == {"S001": 1, "H001": 1}
    assert sets == {"S001": {0}, "H001": {0}}
