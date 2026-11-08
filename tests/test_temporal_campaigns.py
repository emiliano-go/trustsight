"""Positive, benign, adversarial and cold-start tests for T008--T012."""

import json
from types import SimpleNamespace

from hypothesis import given, settings, strategies as st

from trustsight.full_aur._temporal_campaigns import (
    _delayed_adoption_findings,
    _dependency_redirection_findings,
    _dormant_takeover_findings,
    _reappearance_findings,
    _trust_erosion_findings,
)

NOW = 1_800_000_000
DAY = 86_400


def snapshot(**overrides):
    values = {
        "new_meta": {},
        "old_meta": {},
        "changes": {},
        "transitions": {},
        "source_repos": {},
        "edges": {},
        "detail": {},
        "maintainer_transitions": {},
        "prior_rule_history": {},
        "package_cycle_events": {},
        "now": NOW,
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def test_t008_fires_for_delayed_payload_after_adoption():
    adopted = NOW - 20 * DAY
    finding = _delayed_adoption_findings(snapshot(
        detail={"pkg": {"rules": ["R001"]}},
        maintainer_transitions={"pkg": [{
            "id": 7, "observed_at": adopted, "old_value": "alice",
            "new_value": "mallory", "property_key": "maintainer",
        }]},
    ))[0]
    assert finding["rule_id"] == "T008"
    assert finding["severity"] == "INFO"
    assert finding["category"] == "temporal"
    assert finding["params"]["adoption_timestamp"] == adopted
    assert finding["params"]["rules"] == ["R001"]


def test_t008_ignores_recent_adoption_and_current_transition():
    history = {"pkg": [{
        "observed_at": NOW - 20 * DAY, "new_value": "mallory",
        "property_key": "maintainer",
    }]}
    recent = _delayed_adoption_findings(snapshot(
        now=NOW - 10 * DAY,
        detail={"pkg": {"rules": ["R001"]}},
        maintainer_transitions=history,
    ))
    current = _delayed_adoption_findings(snapshot(
        detail={"pkg": {"rules": ["R001"]}},
        maintainer_transitions=history,
        transitions={"pkg": ("alice", "mallory")},
    ))
    assert recent == current == []


def test_t008_cold_history_is_silent():
    assert _delayed_adoption_findings(snapshot(
        detail={"pkg": {"rules": ["R001"]}},
    )) == []


def test_t009_fires_and_reports_reverse_dependents():
    finding = _dormant_takeover_findings(snapshot(
        old_meta={"target": {"LastModified": NOW - 300 * DAY}},
        new_meta={"target": {"NumVotes": "bad", "Popularity": 0}},
        transitions={"target": ("alice", "mallory")},
        edges={f"dependent-{n}": {"target"} for n in range(10)},
    ))[0]
    assert finding["rule_id"] == "T009"
    assert finding["params"]["direct_dependents"] == 10
    assert finding["params"]["qualifying_measures"] == ["direct_dependents=10"]


def test_t009_ignores_active_or_low_value_takeovers():
    base = {
        "new_meta": {"target": {"NumVotes": 99, "Popularity": 0.5}},
        "transitions": {"target": ("alice", "mallory")},
    }
    active = _dormant_takeover_findings(snapshot(
        old_meta={"target": {"LastModified": NOW - 10 * DAY}}, **base))
    low_value = _dormant_takeover_findings(snapshot(
        old_meta={"target": {"LastModified": NOW - 300 * DAY}}, **base))
    assert active == low_value == []


def test_t009_cold_transition_history_is_silent():
    assert _dormant_takeover_findings(snapshot()) == []


def test_t010_resolves_a_unique_provider_and_groups_members():
    findings = _dependency_redirection_findings(snapshot(
        new_meta={
            "provider": {"PackageBase": "provider", "Provides": ["virtual>=1"]},
            "one": {"PackageBase": "one"},
            "two": {"PackageBase": "two"},
        },
        transitions={"provider": ("", "mallory")},
        detail={
            "one": {"dependency_changes": {"depends_added": ["virtual>=1"]}},
            "two": {"dependency_changes": {"makedepends_added": ["virtual"]}},
        },
    ))
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "T010"
    assert findings[0]["category"] == "dependency"
    assert findings[0]["params"]["members"] == ["one", "two"]
    assert findings[0]["params"]["target"] == "provider"


def test_t010_ignores_stable_related_and_ambiguous_targets():
    stable = snapshot(
        new_meta={"target": {}, "consumer": {}},
        detail={"consumer": {"dependency_changes": {"depends_added": ["target"]}}},
    )
    related = snapshot(
        new_meta={"foo-bin": {"PackageBase": "foo"}, "foo": {}},
        changes={"foo": "added"},
        detail={"foo-bin": {"dependency_changes": {"depends_added": ["foo"]}}},
    )
    ambiguous = snapshot(
        new_meta={
            "one": {"Provides": ["virtual"]},
            "two": {"Provides": ["virtual"]},
            "consumer": {},
        },
        transitions={"one": ("", "new"), "two": ("", "new")},
        detail={"consumer": {"dependency_changes": {"depends_added": ["virtual"]}}},
    )
    assert _dependency_redirection_findings(stable) == []
    assert _dependency_redirection_findings(related) == []
    assert _dependency_redirection_findings(ambiguous) == []


def test_t010_cold_dependency_detail_is_silent():
    assert _dependency_redirection_findings(snapshot()) == []


def test_t011_reports_latest_removal_without_identity_reset_claim():
    finding = _reappearance_findings(snapshot(
        changes={"pkg": "added"},
        new_meta={"pkg": {"Maintainer": "mallory", "FirstSubmitted": 123}},
        package_cycle_events={"pkg": [
            {"cycle_time": NOW - 50 * DAY, "status": "removed", "maintainer": "a"},
            {"cycle_time": NOW - 10 * DAY, "status": "removed", "maintainer": "b"},
        ]},
    ))[0]
    assert finding["rule_id"] == "T011"
    assert finding["params"]["removal_cycle"] == NOW - 10 * DAY
    assert finding["params"]["maintainer"] == "mallory"
    assert finding["params"]["first_submitted"] == 123
    assert "identity" not in finding["match"].lower()


def test_t011_ignores_modified_packages_and_other_removal_history():
    modified = _reappearance_findings(snapshot(
        changes={"pkg": "modified"},
        package_cycle_events={"pkg": [{"cycle_time": NOW - DAY, "status": "removed"}]},
    ))
    other = _reappearance_findings(snapshot(
        changes={"pkg": "added"},
        package_cycle_events={"other": [{"cycle_time": NOW - DAY, "status": "removed"}]},
    ))
    assert modified == other == []


def test_t011_cold_cycle_history_is_silent():
    assert _reappearance_findings(snapshot(changes={"pkg": "added"})) == []


def test_t012_accepts_a_provenance_only_precursor():
    finding = _trust_erosion_findings(snapshot(
        detail={"pkg": {"rules": ["S009", "R001"]}},
        prior_rule_history={"pkg": [
            {"history_id": "h1", "timestamp": 1, "rules": ["H001"]},
            {"history_id": "h2", "timestamp": 2, "rules": ["H049", "H054"]},
        ]},
    ))[0]
    assert finding["rule_id"] == "T012"
    assert finding["params"]["precursor_rules"] == ["H049", "H054"]
    assert finding["params"]["precursor_history_ids"] == ["h2"]
    assert finding["params"]["terminal_rules"] == ["R001", "S009"]


def test_t012_ignores_unrelated_or_terminal_only_history():
    unrelated = _trust_erosion_findings(snapshot(
        detail={"pkg": {"rules": ["R001"]}},
        prior_rule_history={"pkg": [{"history_id": "h1", "rules": ["H001"]}]},
    ))
    terminal_only = _trust_erosion_findings(snapshot(
        detail={"pkg": {"rules": ["H001"]}},
        prior_rule_history={"pkg": [{"history_id": "h1", "rules": ["H024"]}]},
    ))
    assert unrelated == terminal_only == []


def test_t012_cold_rule_history_is_silent():
    assert _trust_erosion_findings(snapshot(
        detail={"pkg": {"rules": ["S011"]}},
    )) == []


def test_t009_rejects_a_malformed_string_transition():
    assert _dormant_takeover_findings(snapshot(
        old_meta={"target": {"LastModified": NOW - 300 * DAY}},
        new_meta={"target": {"NumVotes": 150}},
        transitions={"target": "ab"},
    )) == []


def test_t010_provider_resolution_covers_the_full_snapshot():
    # A lexicographic package cap must not hide a valid late-sorting provider.
    new_meta = {
        **{f"filler-{n:04}": {} for n in range(4096)},
        "consumer": {},
        "zz-provider": {"Provides": ["virtual>=1"]},
    }
    findings = _dependency_redirection_findings(snapshot(
        new_meta=new_meta,
        transitions={"zz-provider": ("alice", "mallory")},
        detail={"consumer": {
            "dependency_changes": {"depends_added": ["virtual>=1"]},
        }},
    ))
    assert len(findings) == 1
    assert findings[0]["params"]["target"] == "zz-provider"


def test_t011_rejects_a_boolean_cycle_ordinal():
    assert _reappearance_findings(snapshot(
        changes={"pkg": "added"},
        package_cycle_events={"pkg": [{"cycle_time": True, "status": "removed"}]},
    )) == []


def test_transition_shapes_require_two_distinct_maintainer_names():
    dormant = snapshot(
        old_meta={"target": {"LastModified": NOW - 300 * DAY}},
        new_meta={"target": {"NumVotes": 150}},
        transitions={"target": ("alice", {"not": "a name"})},
    )
    redirection = snapshot(
        new_meta={"target": {}, "consumer": {}},
        transitions={"target": ("alice", True)},
        detail={"consumer": {
            "dependency_changes": {"depends_added": ["target"]},
        }},
    )
    assert _dormant_takeover_findings(dormant) == []
    assert _dependency_redirection_findings(redirection) == []


_JSON = st.recursive(
    st.none() | st.booleans() | st.integers() |
    st.floats(allow_nan=False, allow_infinity=False) | st.text(max_size=24),
    lambda children: st.lists(children, max_size=4) | st.dictionaries(
        st.text(max_size=16), children, max_size=4),
    max_leaves=20,
)
_EMITTERS = (
    _delayed_adoption_findings,
    _dormant_takeover_findings,
    _dependency_redirection_findings,
    _reappearance_findings,
    _trust_erosion_findings,
)


@settings(max_examples=100, deadline=None)
@given(overrides=st.fixed_dictionaries({
    "new_meta": _JSON,
    "old_meta": _JSON,
    "changes": _JSON,
    "transitions": _JSON,
    "edges": _JSON,
    "detail": _JSON,
    "maintainer_transitions": _JSON,
    "prior_rule_history": _JSON,
    "package_cycle_events": _JSON,
    "now": _JSON,
}))
def test_emitters_are_total_deterministic_and_json_safe(overrides):
    value = snapshot(**overrides)
    for emitter in _EMITTERS:
        first = emitter(value)
        assert first == emitter(value)
        json.dumps(first, allow_nan=False)
