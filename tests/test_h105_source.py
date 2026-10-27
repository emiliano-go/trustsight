"""H105: a takeover adds a source identity and executes code from it."""

from trustsight.analysis.adoption import source_takeover_finding


def finding(**overrides):
    kwargs = dict(
        package_name="demo",
        findings=[{"rule_id": "H083"}],
        adopted=True,
        maintainer_changed=False,
        added_urls=("https://github.com/attacker/stage.sh",),
        removed_urls=("https://github.com/upstream/project.tar.gz",),
        current_text="url=https://github.com/upstream/project\n",
    )
    kwargs.update(overrides)
    return source_takeover_finding(**kwargs)


def test_h105_fires_on_takeover_new_source_and_execution():
    result = finding()
    assert result is not None
    assert result["rule_id"] == "H105"
    assert result["severity"] == "HIGH"


def test_h105_quiet_without_an_execution_sink():
    assert finding(findings=[{"rule_id": "H016"}]) is None


def test_h105_quiet_when_the_source_identity_is_the_declared_upstream():
    result = finding(
        added_urls=("https://github.com/upstream/project.tar.gz",),
        removed_urls=(),
        current_text="url=https://github.com/upstream/project\n",
    )
    assert result is None


def test_h105_quiet_without_a_takeover_signal():
    assert finding(adopted=False, maintainer_changed=False) is None


def test_h105_accepts_a_maintainer_transition_on_a_non_orphan():
    assert finding(adopted=False, maintainer_changed=True) is not None


def test_h105_uses_the_chaos_rat_historical_fixture():
    from pathlib import Path

    from trustsight.analysis.adoption import source_takeover_finding
    from trustsight.differ import extract_urls_from_diff

    diff = (Path(__file__).parent / "fixtures" / "malicious" / "historical"
            / "chaos-rat-2025-07.diff").read_text()
    changes = extract_urls_from_diff(diff)
    result = source_takeover_finding(
        package_name="firefox-patch-bin",
        findings=[{"rule_id": "H083"}],
        adopted=True,
        maintainer_changed=False,
        added_urls=changes.added_urls,
        removed_urls=changes.removed_urls,
        current_text="pkgname=firefox-patch-bin\n",
    )
    assert result is not None
    assert "github.com/danikpapas" in result["params"]["source"]
