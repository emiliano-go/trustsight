"""Acknowledged source URLs: one URL, one package, no SOURCE_BUCKET or NOVELTY."""

import json

import pytest
from typer.testing import CliRunner

from trustsight.analysis.pipeline import scan_diff
from trustsight.cli import app
from trustsight.override import (
    add_override,
    add_url_ack,
    list_overrides,
    list_url_acks,
    match_url_acks,
    remove_url_ack,
)


@pytest.fixture
def overrides_file(tmp_path, monkeypatch):
    """Point the override store at a per-test file."""
    import trustsight.override as override

    path = tmp_path / "overrides.json"
    monkeypatch.setattr(override, "OVERRIDES_PATH", path)
    return path


def test_add_list_remove_roundtrip(overrides_file):
    ack = add_url_ack("demo", "https://example.com/p.tar.gz", "reviewed")
    assert ack.package == "demo"
    assert [a.package for a in list_url_acks()] == ["demo"]
    assert remove_url_ack("demo", "https://example.com/p.tar.gz") is True
    assert list_url_acks() == []
    assert remove_url_ack("demo", "https://example.com/p.tar.gz") is False


def test_ack_matches_after_normalisation(overrides_file):
    """A routine version bump of the same URL stays acknowledged."""
    add_url_ack("demo", "https://example.com/v1.2.3/p.tar.gz", "reviewed")
    assert match_url_acks("demo", ["https://example.com/v9.9.9/p.tar.gz"])


def test_ack_is_scoped_to_the_package_and_the_url(overrides_file):
    add_url_ack("demo", "https://example.com/p.tar.gz", "reviewed")
    assert match_url_acks("other", ["https://example.com/p.tar.gz"]) == {}
    assert match_url_acks("demo", ["https://other.example/p.tar.gz"]) == {}


def test_ack_requires_a_reason(overrides_file):
    with pytest.raises(ValueError):
        add_url_ack("demo", "https://example.com/p.tar.gz", "   ")
    with pytest.raises(ValueError):
        add_url_ack("", "https://example.com/p.tar.gz", "reviewed")


def test_adding_twice_replaces_the_reason(overrides_file):
    add_url_ack("demo", "https://example.com/p.tar.gz", "first")
    add_url_ack("demo", "https://example.com/p.tar.gz", "second")
    acks = list_url_acks()
    assert len(acks) == 1
    assert acks[0].reason == "second"


def test_url_acks_and_rule_overrides_share_the_file(overrides_file):
    add_override("R010", "benign curl", package="demo")
    add_url_ack("demo", "https://example.com/p.tar.gz", "reviewed")
    assert len(list_overrides()) == 1
    assert len(list_url_acks()) == 1
    # Removing one must not erase the other: both keys share one file.
    remove_url_ack("demo", "https://example.com/p.tar.gz")
    assert len(list_overrides()) == 1
    add_url_ack("demo", "https://example.com/p.tar.gz", "reviewed")
    assert len(list_url_acks()) == 1


def test_acked_url_scores_nothing_but_other_urls_still_do(overrides_file):
    diff = (
        "+source=('https://known.example/p.tar.gz' "
        "'https://mystery.example/q.tar.gz')\n"
    )
    plain = scan_diff(diff, package_name="demo")
    bucket = next(e for e in plain.score_breakdown if e.rule_id == "SOURCE_BUCKET")
    assert "mystery.example" in bucket.reason or "known.example" in bucket.reason

    add_url_ack("demo", "https://mystery.example/q.tar.gz", "known mirror")
    fact = scan_diff(diff, package_name="demo")
    assert fact.acknowledged_urls == [
        {"url": "https://mystery.example/q.tar.gz", "reason": "known mirror"}
    ]
    # The unknown host was acknowledged; the remaining unknown host (the
    # first one is also unknown) keeps the prior alive.
    assert any(e.rule_id == "SOURCE_BUCKET" for e in fact.score_breakdown)


def test_ack_silences_the_bucket_when_it_is_the_only_source(overrides_file):
    diff = "+source=('https://mystery.example/q.tar.gz')\n"
    add_url_ack("demo", "https://mystery.example/q.tar.gz", "known mirror")
    fact = scan_diff(diff, package_name="demo")
    assert not any(e.rule_id == "SOURCE_BUCKET" for e in fact.score_breakdown)
    assert not any(e.rule_id == "NOVELTY" for e in fact.score_breakdown)


def test_ack_does_not_silence_structural_findings(overrides_file):
    """The ack is about the provenance prior, not about concrete rules."""
    diff = "+source=('http://mystery.example/q.tar.gz')\n"
    add_url_ack("demo", "http://mystery.example/q.tar.gz", "known mirror")
    fact = scan_diff(diff, package_name="demo")
    assert any(e.rule_id == "H003" for e in fact.score_breakdown)


def test_ack_silences_r152_on_the_same_url(overrides_file):
    """#57 side note: an acknowledged URL must not keep firing R152."""
    diff = (
        "--- /dev/null\n+++ b/demo.service\n@@ -0,0 +1,2 @@\n"
        "+[Service]\n"
        "+Documentation=https://demo.github.io/docs/\n"
    )
    assert any(e.rule_id == "R152" for e in scan_diff(
        diff, package_name="demo").score_breakdown)

    add_url_ack("demo", "https://demo.github.io/docs/", "reviewed docs link")
    fact = scan_diff(diff, package_name="demo")
    assert not any(e.rule_id == "R152" for e in fact.score_breakdown)
    # B5: removing the finding must not remove its visible acknowledgement.
    assert fact.acknowledged_urls == [{
        "url": "https://demo.github.io/docs/",
        "reason": "reviewed docs link",
    }]


def test_ack_does_not_silence_r152_on_an_unacknowledged_url(overrides_file):
    add_url_ack("demo", "https://demo.github.io/other/", "reviewed docs link")
    diff = (
        "--- /dev/null\n+++ b/demo.service\n@@ -0,0 +1,2 @@\n"
        "+[Service]\n"
        "+Documentation=https://demo.github.io/docs/\n"
    )
    assert any(e.rule_id == "R152" for e in scan_diff(
        diff, package_name="demo").score_breakdown)


# --- CLI -------------------------------------------------------------------


def test_cli_add_list_remove_url(overrides_file):
    runner = CliRunner()
    added = runner.invoke(app, [
        "override", "add-url", "demo", "https://example.com/p.tar.gz",
        "--reason", "reviewed", "--json",
    ])
    assert added.exit_code == 0, added.output
    assert json.loads(added.output)["status"] == "ok"

    listed = runner.invoke(app, ["override", "list", "--json"])
    assert listed.exit_code == 0, listed.output
    body = json.loads(listed.output)
    assert body["url_acks"] == [{
        "package": "demo",
        "url": "https://example.com/p.tar.gz",
        "reason": "reviewed",
        "created_at": body["url_acks"][0]["created_at"],
    }]

    removed = runner.invoke(app, [
        "override", "rm-url", "demo", "https://example.com/p.tar.gz", "--json",
    ])
    assert removed.exit_code == 0, removed.output
    assert json.loads(removed.output)["status"] == "ok"

    missing = runner.invoke(app, [
        "override", "rm-url", "demo", "https://example.com/p.tar.gz",
    ])
    assert missing.exit_code == 2


def test_cli_add_url_requires_a_reason(overrides_file):
    result = CliRunner().invoke(app, [
        "override", "add-url", "demo", "https://example.com/p.tar.gz",
        "--reason", "   ",
    ])
    assert result.exit_code == 2


def test_override_ttl_lapses_on_the_observation_clock(monkeypatch):
    """Peripheral tolerance: a suppression without continuous signal lapses."""
    import trustsight.override as ov
    from trustsight.override import RuleOverride, filter_triggered_rules

    override = RuleOverride(rule_id="H029", reason="noise", package="p",
                            created_at_obs=10, ttl_observations=5)
    monkeypatch.setattr(ov, "load_overrides", lambda: [override])
    rules = [{"rule_id": "H029", "severity": "HIGH"}]

    expired: list[str] = []
    kept, suppressed = filter_triggered_rules(
        rules, package="p", now_obs=14, expired_out=expired)
    assert suppressed and not expired  # still within the TTL

    kept, suppressed = filter_triggered_rules(
        rules, package="p", now_obs=15, expired_out=expired)
    assert not suppressed and expired == ["H029"]
    assert kept[0].get("override_expired") is True


def test_clear_indicator_override_is_downgraded_visible_only(monkeypatch):
    import trustsight.override as ov
    from trustsight.override import (
        RuleOverride, apply_indicator_cross_check, filter_triggered_rules,
    )

    override = RuleOverride(rule_id="C005", reason="known", package="p",
                            requires_clear_indicators=True)
    monkeypatch.setattr(ov, "load_overrides", lambda: [override])
    rules = [{"rule_id": "C005", "severity": "HIGH"}]

    kept, suppressed = filter_triggered_rules(
        rules, package="p", indicator_corroborated=True)
    assert suppressed[0]["indicator_corroborated"] is True

    # The post-hoc variant: no indicators until later.
    kept, suppressed = filter_triggered_rules(rules, package="p")
    apply_indicator_cross_check(suppressed, has_indicator_match=True)
    assert suppressed[0]["indicator_corroborated"] is True
