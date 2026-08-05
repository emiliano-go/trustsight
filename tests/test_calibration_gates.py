"""Phase 8 - the §10 calibration gates run as tests.

``scripts/calibration_gates.py`` turns each §10 line into a number and a
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
    with gates.shipped_config():
        benign = gates.scan_corpus(CORPUS, sample=SAMPLE)
        malicious = gates.scan_malicious(MALICIOUS) if MALICIOUS.exists() else []
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


def test_r081_stays_out_of_build_and_prepare(results):
    _assert(gates.gate_r081_position(results[0]))


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


def test_the_runner_reports_a_gate_per_plan_line(results):
    """The script's own contract: every gate is named and exits nonzero."""
    benign, malicious = results
    all_gates = gates._evaluate(benign, malicious)
    assert len(all_gates) == 10
    assert all(g.name for g in all_gates)
