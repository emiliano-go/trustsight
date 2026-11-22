"""The ledger records when it measured the corpus."""

from calibration._ledger import build_ledger


def test_ledger_carries_measured_at():
    ledger = build_ledger([], measured_at="2026-11-02")
    assert ledger["measured_at"] == "2026-11-02"
