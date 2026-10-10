"""Addendum 5 §6.1: the T-series temporal novelty rules."""

import pytest

from trustsight.analysis.temporal import t_domain_findings, t_key_findings
from trustsight.db import (
    domain_first_seen,
    init_db,
    key_observed_before,
    observed_domain_count,
    observed_key_count,
    record_observed_domain,
    record_observed_key,
)


@pytest.fixture
def db(tmp_path, monkeypatch):
    monkeypatch.setattr("trustsight.db.DATA_DIR", tmp_path)
    init_db()
    yield
    (tmp_path / "trustsight.db").unlink(missing_ok=True)


def test_t001_cold_index_declines(db):
    assert observed_key_count() == 0
    assert t_key_findings({"pgp_keys": {"gained": ["ABCDEF"]}}, None) == []


def test_t001_fires_for_a_never_seen_key(db):
    record_observed_key("KNOWNKEY")
    assert key_observed_before("KNOWNKEY")
    got = t_key_findings({"pgp_keys": {"gained": ["NEWKEY"]}}, None)
    assert [f["rule_id"] for f in got] == ["T001"]
    assert got[0]["evidence"]["key"] == "NEWKEY"


def test_t001_silent_for_a_known_key(db):
    record_observed_key("KNOWNKEY")
    assert t_key_findings({"pgp_keys": {"gained": ["KNOWNKEY"]}}, None) == []


def test_t002_cold_index_declines(db):
    assert observed_domain_count() == 0
    assert t_domain_findings("me@new.example", None) == []


def test_t002_fires_for_a_new_domain(db):
    record_observed_domain("known.example")
    assert domain_first_seen("known.example")
    got = t_domain_findings("me@new.example", None)
    assert [f["rule_id"] for f in got] == ["T002"]


def test_t002_silent_for_a_known_domain(db):
    record_observed_domain("known.example")
    assert t_domain_findings("me@known.example", None) == []


def test_key_ledger_is_bounded(db, monkeypatch):
    import trustsight.db as dbmod

    monkeypatch.setattr(dbmod, "MAX_OBSERVED_KEYS", 5)
    for i in range(10):
        record_observed_key(f"key-{i}", observed_at=f"2026-01-01 00:00:{i:02d}")
    assert observed_key_count() <= 5
    # The newest survive; the oldest were pruned.
    assert key_observed_before("key-9")
