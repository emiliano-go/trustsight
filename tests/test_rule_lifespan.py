import datetime as dt

from scripts.rule_lifespan import check, expired


def test_expiry_and_disposition():
    rows = [
        {"rule_id": "H001", "last_measured": "2026-01-01",
         "review_horizon_days": 30, "status": "live"},
        {"rule_id": "H002", "last_measured": "2026-01-01",
         "review_horizon_days": 30, "status": "anergic"},
        {"rule_id": "H003", "last_measured": "2026-01-01",
         "review_horizon_days": 30, "status": "live",
         "disposition": "reviewed"},
    ]
    stale = check(rows, dt.date(2026, 2, 1))
    assert [row["rule_id"] for row in stale] == ["H001"]


def test_malformed_dates_fail_closed():
    import pytest

    with pytest.raises(ValueError, match="malformed"):
        expired({"rule_id": "H001", "last_measured": "not-a-date",
                 "review_horizon_days": 30}, dt.date(2026, 2, 1))
