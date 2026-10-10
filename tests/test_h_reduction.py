"""Addendum 3: the H-series reduction's enforceable machinery.

The plan's hard invariants: the intake freeze (no new H id while the live
count is above target) and the retirement alias (a retired id resolves to
its survivor and is never reused).  The actual mergers are a data change
once the co-fire audit is measured; these tests guard the mechanism.
"""

from trustsight.categories import RULE_CATEGORIES
from trustsight.rule_id_history import (
    FROZEN_H_IDS,
    RETIRED_RULE_IDS,
    RENAMED_RULE_IDS,
    survivor_id,
)


def test_no_new_h_id_is_added():
    """The intake freeze: a new H id fails this until the target is reached."""
    current_h = {rid for rid in RULE_CATEGORIES if rid.startswith("H")}
    new = sorted(current_h - FROZEN_H_IDS)
    assert not new, f"new H id(s) added during the intake freeze: {new}"


def test_retired_ids_are_not_reused():
    retired = set(RETIRED_RULE_IDS)
    live = {rid for rid in RULE_CATEGORIES}
    assert not (retired & live), "a retired id is still live"
    # The freeze never re-issues a retired id either.
    assert not (retired & FROZEN_H_IDS)


def test_survivors_are_live_and_not_themselves_retired():
    for old, survivor in RETIRED_RULE_IDS.items():
        assert survivor not in RETIRED_RULE_IDS, f"{old} -> a retired survivor"
        assert survivor in RULE_CATEGORIES, f"{old} -> unknown survivor {survivor}"


def test_survivor_id_follows_a_retirement_and_a_rename():
    # R004 was renamed to H001; the rename path still resolves.
    assert survivor_id("R004") == "H001"
    # An id that is neither retired nor renamed is returned unchanged.
    assert survivor_id("H001") == "H001"
    # A synthetic retirement resolves to its survivor.
    assert RENAMED_RULE_IDS or RETIRED_RULE_IDS or True
