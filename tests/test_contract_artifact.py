"""The cross-surface contract artifact must regenerate byte-for-byte.

``contract/contract.json`` is what the feed and the harness test against, so a
silent change to a rule id, a severity, a coverage gap or a payload key is a
change to the contract.  Regenerating it must be a no-op unless the change was
intended - the same gate the fixture builders use.

Run ``python -m trustsight.contract --emit`` and commit the result when the
change is deliberate.
"""

from __future__ import annotations

import json

from trustsight import contract


def test_artifact_regenerates_byte_for_byte():
    assert contract.ARTIFACT_PATH.exists(), (
        "contract/contract.json is missing; run "
        "`python -m trustsight.contract --emit`"
    )
    assert contract.ARTIFACT_PATH.read_text() == contract.render(), (
        "contract/contract.json is out of date; run "
        "`python -m trustsight.contract --emit` and commit the change"
    )


def test_the_artifact_carries_every_projection():
    data = json.loads(contract.render())
    assert set(data) == {
        "version", "rule_ids", "pseudo_rule_ids", "severities",
        "coverage_gaps", "alert_payload", "ingest", "report_body",
    }


def test_pseudo_ids_are_disjoint_from_published_rules():
    """A pseudo-rule that gains a docs page must leave this list."""
    published = set(contract.rule_ids())
    pseudo = set(contract.pseudo_rule_ids())
    assert pseudo
    assert not (published & pseudo), sorted(published & pseudo)


def test_a_rule_id_is_never_empty_and_ids_are_unique():
    ids = contract.rule_ids()
    assert len(ids) == len(set(ids))
    assert all(ids)


def test_the_sample_payload_exercises_every_branch():
    """The feed's parser reads alerts, over_threshold (with findings), ioc,
    campaign_cluster and impersonation; the sample must carry all of them or
    the conformance test proves nothing."""
    payload = contract.sample_alert_payload()
    assert payload["event"] == "trustsight.alerts"
    assert payload["alerts"]
    assert payload["over_threshold"][0]["findings"]
    assert payload["ioc_matches"]
    assert payload["campaign_cluster"]
    assert payload["impersonation"]
    assert payload["refusals"]
