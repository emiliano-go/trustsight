"""G015: a dormant multi-maintainer adoption cohort reactivates together."""

from __future__ import annotations

import time

from trustsight.analysis.correlation import sleeper_adoption_campaign
from trustsight.full_aur.pipeline import _campaign_identity

DAY = 86400


def _shape(count=4, *, maintainers=("m1", "m2"), age_days=90,
           last_modified_days=300, rules=(), routine=False):
    now = time.time()
    names = ["alpha", "beta", "gamma", "delta", "epsilon", "zeta"][:count]
    history = []
    records = []
    for i, name in enumerate(names):
        maintainer = maintainers[i % len(maintainers)]
        history.append({
            "package": name,
            "maintainer": maintainer,
            "previous_maintainer": "",
            "adoption_ts": now - age_days * DAY,
            "last_modified": now - last_modified_days * DAY,
            "current_maintainer": maintainer,
        })
        records.append({
            "package": name,
            "maintainer": maintainer,
            "routine_only": routine,
            "rules": list(rules) if i == 0 else [],
            "pkgbase": name,
            "source_repos": [],
        })
    return records, history


def test_g015_medium_on_a_delayed_multi_account_push():
    records, history = _shape()
    found = sleeper_adoption_campaign(records, history)
    assert [f["rule_id"] for f in found] == ["G015"]
    assert found[0]["severity"] == "MEDIUM"
    assert found[0]["params"]["maintainer_count"] == 2
    assert found[0]["params"]["push_share"] == 1.0
    assert found[0]["params"]["dormant_count"] == 4


def test_g015_high_with_a_payload_or_takeover_signal():
    records, history = _shape(rules=("H017",))
    found = sleeper_adoption_campaign(records, history)
    assert found[0]["severity"] == "HIGH"
    assert found[0]["params"]["signals"] == ["H017"]


def test_g015_accepts_a_multi_cycle_push_window():
    records, history = _shape()
    pushes = [
        {"package": record["package"], "maintainer": record["maintainer"],
         "score": 25, "rules": ["H017"] if i == 0 else []}
        for i, record in enumerate(records)
    ]
    found = sleeper_adoption_campaign(records, history, pushes=pushes)
    assert found[0]["rule_id"] == "G015"
    assert found[0]["severity"] == "HIGH"


def test_g015_ignores_routine_bumps():
    records, history = _shape(routine=True)
    assert sleeper_adoption_campaign(records, history) == []


def test_g015_requires_two_maintainers():
    records, history = _shape(maintainers=("m1",))
    assert sleeper_adoption_campaign(records, history) == []


def test_g015_ignores_active_packages():
    records, history = _shape(last_modified_days=10)
    assert sleeper_adoption_campaign(records, history) == []


def test_g015_ignores_recent_and_stale_adoptions():
    assert sleeper_adoption_campaign(*_shape(age_days=5)) == []
    assert sleeper_adoption_campaign(*_shape(age_days=400)) == []


def test_g015_requires_the_adoption_wave_to_be_close():
    records, history = _shape()
    history[0]["adoption_ts"] -= 200 * DAY
    assert sleeper_adoption_campaign(records, history) == []


def test_g015_requires_a_push_share_of_the_cohort():
    records, history = _shape(count=2)
    extra = {**history[0], "package": "unpushed-1"}
    history.append(extra)
    assert sleeper_adoption_campaign(records, history) == []


def test_g015_stands_down_for_a_naming_family():
    records, history = _shape(count=3)
    for i, record in enumerate(records):
        record["package"] = f"appattic{'-bin' if i else ''}{'-qt' if i == 2 else ''}"
        history[i]["package"] = record["package"]
    assert sleeper_adoption_campaign(records, history) == []


def test_g015_stands_down_for_one_pkgbase():
    records, history = _shape()
    for record in records:
        record["pkgbase"] = "one-project"
    assert sleeper_adoption_campaign(records, history) == []


def test_g015_orphan_only_can_be_relaxed():
    records, history = _shape()
    for row in history:
        row["previous_maintainer"] = "old"
    assert sleeper_adoption_campaign(records, history) == []
    cfg = {"thresholds": {"g015": {"orphan_only": False}}}
    assert sleeper_adoption_campaign(records, history, cfg)[0]["rule_id"] == "G015"


def test_g015_campaign_identity_names_the_accounts():
    finding = {
        "rule_id": "G015",
        "severity": "MEDIUM",
        "params": {
            "members": ["a", "b", "c"],
            "maintainers": ["m1", "m2"],
        },
    }
    campaign_id, scope = _campaign_identity(finding)
    assert campaign_id == "G015:sleeper-adoption"
    assert scope["maintainers"] == ["m1", "m2"]
    assert scope["package_names"] == ["a", "b", "c"]
