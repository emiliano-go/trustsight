"""The G-series cross-package correlation."""

from trustsight.analysis.correlation import (
    coordinated_adoption,
    correlate,
    shared_added_literal,
    shared_gained_host,
    watchlisted_maintainer,
)


def _records():
    return [
        {"package": "a", "hosts_gained": ["new.cdn"], "maintainer": "m@x",
         "adoption": True, "added_literals": ["B" * 300]},
        {"package": "b", "hosts_gained": ["new.cdn"], "maintainer": "m@x",
         "adoption": True, "added_literals": ["B" * 300]},
        {"package": "c", "hosts_gained": ["new.cdn"], "maintainer": "m@x",
         "adoption": True, "added_literals": []},
        {"package": "d", "hosts_gained": [], "maintainer": "other@y",
         "adoption": False, "added_literals": []},
    ]


def test_shared_gained_host_fires_at_threshold():
    found = shared_gained_host(_records(), min_packages=3)
    assert [f["rule_id"] for f in found] == ["G001"]
    assert found[0]["params"]["members"] == ["a", "b", "c"]
    assert shared_gained_host(_records(), min_packages=4) == []


def test_shared_added_literal_fires_and_redacts_content():
    found = shared_added_literal(_records(), min_packages=2, min_length=64)
    assert [f["rule_id"] for f in found] == ["G002"]
    assert "B" * 300 not in found[0]["match"]
    assert found[0]["params"]["literal_length"] == 300


def test_coordinated_adoption_fires_at_threshold():
    found = coordinated_adoption(_records(), min_members=3)
    assert [f["rule_id"] for f in found] == ["G003"]
    assert coordinated_adoption(_records(), min_members=4) == []


def test_coordinated_adoption_cites_the_temporal_predicates():
    records = [
        {"package": "a", "maintainer": "m@x", "adoption": True,
         "adoption_predicates": ["H044"]},
        {"package": "b", "maintainer": "m@x", "adoption": True,
         "adoption_predicates": ["H086"]},
        {"package": "c", "maintainer": "m@x", "adoption": True,
         "adoption_predicates": ["H044"]},
    ]
    found = coordinated_adoption(records, min_members=3)
    assert found[0]["params"]["predicates"] == ["H044", "H086"]


def test_coordinated_adoption_requires_unrelated_members():
    """A maintainer adopting one variant family (all from one repo) is H052's
    shape, not a coordinated adoption."""
    related = [
        {"package": "a", "maintainer": "m", "adoption": True,
         "adoption_predicates": ["H044"], "source_repos": ["https://x/one"]},
        {"package": "b", "maintainer": "m", "adoption": True,
         "adoption_predicates": ["H044"], "source_repos": ["https://x/one"]},
        {"package": "c", "maintainer": "m", "adoption": True,
         "adoption_predicates": ["H044"], "source_repos": ["https://x/one"]},
    ]
    assert coordinated_adoption(related, min_members=3) == []

    unrelated = [dict(r, source_repos=[f"https://x/{r['package']}"])
                 for r in related]
    found = coordinated_adoption(unrelated, min_members=3)
    assert [f["rule_id"] for f in found] == ["G003"]
    assert found[0]["params"]["repos"] == [
        "https://x/a", "https://x/b", "https://x/c"]


def test_coordinated_adoption_keeps_firing_without_repo_data():
    """An unproven relationship is not evidence of one: missing repo data
    preserves the group rather than quietly dropping it."""
    records = [
        {"package": "a", "maintainer": "m", "adoption": True},
        {"package": "b", "maintainer": "m", "adoption": True},
        {"package": "c", "maintainer": "m", "adoption": True},
    ]
    assert [f["rule_id"] for f in coordinated_adoption(records, 3)] == ["G003"]


def test_coordinated_adoption_stands_down_for_a_variant_family_by_name():
    """New packages land in the window with no repo data yet, which made
    the repo relatedness test vacuous for exactly the case it exists for:
    a maintainer releasing appattic, appattic-bin and appattic-qt in one
    cycle is one project by name, not a coordinated adoption."""
    records = [
        {"package": "appattic", "maintainer": "m", "adoption": True},
        {"package": "appattic-bin", "maintainer": "m", "adoption": True},
        {"package": "appattic-qt", "maintainer": "m", "adoption": True},
    ]
    assert coordinated_adoption(records, min_members=3) == []


def test_coordinated_adoption_fires_when_one_member_is_unrelated():
    """Two variants plus one genuinely unrelated adoption stays a group:
    the unrelated member is the signal, not noise."""
    records = [
        {"package": "appattic", "maintainer": "m", "adoption": True},
        {"package": "appattic-bin", "maintainer": "m", "adoption": True},
        {"package": "unrelated-tool", "maintainer": "m", "adoption": True},
    ]
    found = coordinated_adoption(records, min_members=3)
    assert [f["rule_id"] for f in found] == ["G003"]


def test_g003_escalates_for_a_first_seen_account_adopting_dormant_packages(
        monkeypatch):
    import time

    now = time.time()
    dormant = int(now - 180 * 86400 - 86400)
    records = [
        {"package": f"pkg{i}", "maintainer": "fennekuiper", "adoption": True,
         "adoption_predicates": ["H086"], "last_modified": dormant}
        for i in range(3)
    ]
    monkeypatch.setattr(
        "trustsight.db.maintainer_first_seen",
        lambda m: "2026-10-18 12:00:00" if m == "fennekuiper" else None,
    )
    found = coordinated_adoption(records, min_members=3)
    assert found[0]["severity"] == "HIGH"
    assert found[0]["params"]["novel"] is True
    assert found[0]["params"]["dormant_count"] == 3


def test_g003_stays_medium_for_an_established_maintainer(monkeypatch):
    import time

    now = time.time()
    dormant = int(now - 180 * 86400 - 86400)
    records = [
        {"package": f"pkg{i}", "maintainer": "established", "adoption": True,
         "adoption_predicates": ["H044"], "last_modified": dormant}
        for i in range(3)
    ]
    monkeypatch.setattr(
        "trustsight.db.maintainer_first_seen",
        lambda m: "2020-01-01 00:00:00",
    )
    found = coordinated_adoption(records, min_members=3)
    assert found[0]["severity"] == "MEDIUM"
    assert found[0]["params"]["novel"] is False


def test_g003_stays_medium_when_targets_are_active(monkeypatch):
    import time

    now = time.time()
    records = [
        {"package": f"pkg{i}", "maintainer": "fennekuiper", "adoption": True,
         "adoption_predicates": ["H086"], "last_modified": int(now - 30 * 86400)}
        for i in range(3)
    ]
    monkeypatch.setattr(
        "trustsight.db.maintainer_first_seen",
        lambda m: "2026-10-18 12:00:00",
    )
    found = coordinated_adoption(records, min_members=3)
    assert found[0]["severity"] == "MEDIUM"
    assert found[0]["params"]["dormant_count"] == 0


def test_g009_reports_a_watchlisted_maintainer(monkeypatch):
    records = [{"package": "xsp", "maintainer": "fennekuiper"}]
    monkeypatch.setattr(
        "trustsight.watchlist.load_watchlist",
        lambda path=None: {"h1": "June 2026 orphan sweep"},
    )
    monkeypatch.setattr("trustsight.watchlist.load_packages",
                        lambda path=None: {})
    monkeypatch.setattr("trustsight.watchlist.local_hash_many",
                        lambda names: {n: "h1" for n in names})
    found = watchlisted_maintainer(records, None)
    assert [f["rule_id"] for f in found] == ["G009"]
    assert found[0]["severity"] == "INFO"
    assert found[0]["params"]["members"] == ["xsp"]
    assert found[0]["params"]["subject"] == "maintainer"
    assert found[0]["name"] == "Watchlisted Subject"


def test_g009_reports_a_watchlisted_package_without_hashing(monkeypatch):
    monkeypatch.setattr("trustsight.watchlist.load_watchlist",
                        lambda path=None: {})
    monkeypatch.setattr("trustsight.watchlist.load_packages",
                        lambda path=None: {"xsp": "June 2026 review"})
    monkeypatch.setattr(
        "trustsight.watchlist.local_hash_many",
        lambda names: (_ for _ in ()).throw(AssertionError("hashed a package")),
    )
    found = watchlisted_maintainer(
        [{"package": "xsp", "maintainer": "fennekuiper"}], None)
    assert len(found) == 1
    assert found[0]["params"]["subject"] == "package"
    assert found[0]["match"] == "package is on the operator watchlist (June 2026 review)"


def test_g009_prefers_the_package_when_both_match(monkeypatch):
    monkeypatch.setattr("trustsight.watchlist.load_watchlist",
                        lambda path=None: {"h1": "maintainer note"})
    monkeypatch.setattr("trustsight.watchlist.load_packages",
                        lambda path=None: {"xsp": "package note"})
    monkeypatch.setattr("trustsight.watchlist.local_hash_many",
                        lambda names: {n: "h1" for n in names})
    found = watchlisted_maintainer(
        [{"package": "xsp", "maintainer": "fennekuiper"}], None)
    assert len(found) == 1
    assert found[0]["params"]["subject"] == "package"
    assert found[0]["params"]["label"] == "package note"


def test_g009_is_silent_without_a_watchlist(monkeypatch):
    monkeypatch.setattr("trustsight.watchlist.load_watchlist",
                        lambda path=None: {})
    monkeypatch.setattr("trustsight.watchlist.load_packages",
                        lambda path=None: {})
    assert watchlisted_maintainer(
        [{"package": "x", "maintainer": "m"}], None) == []


def test_correlate_honors_configured_thresholds():
    config = {"thresholds": {
        "g_host": {"min_packages": 3},
        "g_blob": {"min_packages": 2, "min_length": 64},
        "g_adopt": {"min_members": 3},
    }}
    ids = {f["rule_id"] for f in correlate(_records(), config)}
    assert ids == {"G001", "G002", "G003"}


def test_correlate_is_empty_without_clusters():
    assert correlate([{"package": "only"}], None) == []


def test_impersonation_campaign_groups_clones_by_maintainer():
    from trustsight.analysis.correlation import impersonation_campaign

    records = [
        {"package": "yyay", "maintainer": "marchos1as",
         "impersonated_target": "yay"},
        {"package": "parru", "maintainer": "marchos1as",
         "impersonated_target": "paru"},
        {"package": "yau", "maintainer": "marchos1as",
         "impersonated_target": "yay"},
        {"package": "koboldcpp-cuda", "maintainer": "TheBill2001",
         "impersonated_target": ""},
    ]
    found = impersonation_campaign(records, min_members=3)
    assert [f["rule_id"] for f in found] == ["G005"]
    assert found[0]["severity"] == "HIGH"
    assert found[0]["params"]["members"] == ["parru", "yau", "yyay"]
    assert found[0]["params"]["targets"] == ["paru", "yay"]


def test_a_lone_clone_is_not_a_campaign():
    from trustsight.analysis.correlation import impersonation_campaign

    records = [{"package": "yyay", "maintainer": "m",
                "impersonated_target": "yay"}]
    assert impersonation_campaign(records, min_members=2) == []


def test_ownerless_clones_are_not_grouped_into_a_campaign():
    """An empty maintainer is not evidence that unrelated ownerless clones
    share an operator; they stay individual H029 findings."""
    from trustsight.analysis.correlation import impersonation_campaign

    records = [
        {"package": name, "maintainer": "", "impersonated_target": "yay"}
        for name in ("yyay", "yau", "yayy")
    ]
    assert impersonation_campaign(records, min_members=3) == []


def test_correlate_includes_the_impersonation_campaign():
    records = [
        {"package": name, "maintainer": "m", "impersonated_target": "yay"}
        for name in ("yyay", "yau", "yayy")
    ]
    ids = {f["rule_id"] for f in correlate(records, None)}
    assert "G005" in ids


def test_g008_fires_for_first_seen_account_adopting_dormant_packages(
        monkeypatch):
    import time
    from trustsight.analysis.correlation import first_seen_adoption_burst

    now = time.time()
    dormant_cutoff = now - 180 * 86400
    # Relative to the run, not a fixed calendar date: the rule's window is
    # seven days, so a hardcoded "today" silently ages out of it.
    observed = time.strftime("%Y-%m-%d %H:%M:%S",
                             time.gmtime(now - 86400))

    records = [
        {"package": f"pkg{i}", "maintainer": "fennekuiper",
         "adoption": True, "adoption_predicates": ["H086"],
         "adoption_observed_at": observed,
         "last_modified": int(dormant_cutoff - 86400)}
        for i in range(5)
    ]
    monkeypatch.setattr(
        "trustsight.db.maintainer_first_seen",
        lambda m: observed if m == "fennekuiper" else None,
    )
    found = first_seen_adoption_burst(records, None)
    assert [f["rule_id"] for f in found] == ["G008"]
    assert found[0]["params"]["maintainer"] == "fennekuiper"
    assert found[0]["params"]["dormant_count"] == 5


def test_g008_requires_first_seen_account(monkeypatch):
    from trustsight.analysis.correlation import first_seen_adoption_burst

    records = [
        {"package": f"pkg{i}", "maintainer": "established",
         "adoption": True, "adoption_predicates": ["H086"],
         "adoption_observed_at": "2026-10-18 12:00:00",
         "last_modified": 1000}
        for i in range(5)
    ]
    monkeypatch.setattr(
        "trustsight.db.maintainer_first_seen",
        lambda m: "2020-01-01 00:00:00",
    )
    assert first_seen_adoption_burst(records, None) == []


def test_g008_requires_dormant_targets(monkeypatch):
    import time
    from trustsight.analysis.correlation import first_seen_adoption_burst

    now = time.time()
    records = [
        {"package": f"pkg{i}", "maintainer": "fennekuiper",
         "adoption": True, "adoption_predicates": ["H086"],
         "adoption_observed_at": "2026-10-18 12:00:00",
         "last_modified": int(now - 30 * 86400)}
        for i in range(5)
    ]
    monkeypatch.setattr(
        "trustsight.db.maintainer_first_seen",
        lambda m: "2026-10-18 12:00:00",
    )
    assert first_seen_adoption_burst(records, None) == []


def test_g008_requires_min_packages(monkeypatch):
    from trustsight.analysis.correlation import first_seen_adoption_burst

    records = [
        {"package": "pkg0", "maintainer": "fennekuiper",
         "adoption": True, "adoption_predicates": ["H086"],
         "adoption_observed_at": "2026-10-18 12:00:00",
         "last_modified": 1000},
    ]
    monkeypatch.setattr(
        "trustsight.db.maintainer_first_seen",
        lambda m: "2026-10-18 12:00:00",
    )
    assert first_seen_adoption_burst(records, None) == []


def test_g008_survives_a_first_seen_read_failure(monkeypatch):
    """A locked or missing database is "unknown", never a cycle abort."""
    from trustsight.analysis.correlation import first_seen_adoption_burst

    records = [
        {"package": f"pkg{i}", "maintainer": "fennekuiper",
         "adoption": True,
         "adoption_observed_at": "2026-10-18 12:00:00",
         "last_modified": 1000}
        for i in range(5)
    ]
    monkeypatch.setattr(
        "trustsight.db.maintainer_first_seen",
        lambda m: (_ for _ in ()).throw(RuntimeError("database is locked")),
    )
    assert first_seen_adoption_burst(records, None) == []


def test_g008_counts_a_package_once(monkeypatch):
    """Duplicate transitions for one package do not fabricate a burst."""
    from trustsight.analysis.correlation import first_seen_adoption_burst
    import time

    now = time.time()
    records = [
        {"package": "pkg", "maintainer": "fennekuiper", "adoption": True,
         "adoption_observed_at": "2026-10-18 12:00:00",
         "last_modified": int(now - 200 * 86400)}
        for _ in range(5)
    ]
    monkeypatch.setattr(
        "trustsight.db.maintainer_first_seen",
        lambda m: "2026-10-18 12:00:00",
    )
    assert first_seen_adoption_burst(records, None) == []


def test_malformed_thresholds_do_not_abort_the_sweep():
    config = {"thresholds": {
        "g_host": "bad",
        "g_dep": "bad",
        "g_blob": {"min_packages": "2", "min_length": "64"},
        "g_adopt": {"min_members": "3"},
    }}
    found = correlate(_records(), config)
    assert {f["rule_id"] for f in found} == {"G002", "G003"}
    # A whole table that is not a table falls back to shipped defaults.
    assert {f["rule_id"] for f in correlate(_records(), {"thresholds": "bad"})} == {
        "G002", "G003"}


def test_the_relatedness_pass_is_capped(monkeypatch):
    """One maintainer controlling many adopted names must not choose an
    O(n^2) pass over the sweep."""
    from trustsight.analysis import correlation

    names = [f"pkg{i}" for i in range(correlation.MAX_RELATEDNESS_MEMBERS + 1)]
    records = [
        {"package": name, "maintainer": "m", "adoption": True,
         "adoption_predicates": ["H044"]}
        for name in names
    ]
    found = coordinated_adoption(records, min_members=3)
    assert [f["rule_id"] for f in found] == ["G003"]


def test_one_pkgbase_family_is_not_a_campaign():
    """Split outputs of one project are one release, not a shared-host or
    shared-literal campaign."""
    records = [
        {"package": name, "pkgbase": "appattic", "maintainer": "m",
         "hosts_gained": ["new.cdn"], "added_literals": ["B" * 300]}
        for name in ("appattic", "appattic-bin", "appattic-docs")
    ]
    assert shared_gained_host(records, min_packages=3) == []
    assert shared_added_literal(records, min_packages=2, min_length=256) == []


def _payload_records():
    return [
        {"package": "a", "maintainer": "a@x", "rules": ["R001"],
         "payload_urls": ["https://evil.example/x.sh"]},
        {"package": "b", "maintainer": "b@x", "rules": ["R001"],
         "payload_urls": ["https://evil.example/x.sh"]},
        {"package": "c", "maintainer": "c@x", "rules": ["R001"],
         "payload_urls": ["https://elsewhere.example/y.sh"]},
    ]


def test_shared_payload_signal_fires_across_maintainers():
    from trustsight.analysis.correlation import shared_payload_signal

    found = shared_payload_signal(_payload_records())
    assert [f["rule_id"] for f in found] == ["G012"]
    assert found[0]["params"]["signal"] == "R001"
    assert found[0]["params"]["members"] == ["a", "b", "c"]
    assert found[0]["params"]["maintainer_count"] == 3


def test_shared_payload_signal_requires_distinct_maintainers():
    from trustsight.analysis.correlation import shared_payload_signal

    records = _payload_records()
    for record in records:
        record["maintainer"] = "same@x"
    assert shared_payload_signal(records) == []


def test_shared_payload_signal_ignores_broad_rules():
    from trustsight.analysis.correlation import shared_payload_signal

    records = _payload_records()
    for record in records:
        record["rules"] = ["R010"]
    assert shared_payload_signal(records) == []


def test_shared_payload_signal_stands_down_for_one_project():
    from trustsight.analysis.correlation import shared_payload_signal

    records = _payload_records()
    for record in records:
        record["pkgbase"] = "one"
    assert shared_payload_signal(records) == []


def test_shared_payload_signal_stands_down_for_a_naming_family():
    from trustsight.analysis.correlation import shared_payload_signal

    records = [
        {"package": "appattic", "maintainer": "a@x", "rules": ["R001"]},
        {"package": "appattic-bin", "maintainer": "b@x", "rules": ["R001"]},
        {"package": "appattic-qt", "maintainer": "c@x", "rules": ["R001"]},
    ]
    assert shared_payload_signal(records) == []


def test_shared_fetch_target_fires_across_maintainers():
    from trustsight.analysis.correlation import shared_fetch_target

    found = shared_fetch_target(_payload_records())
    assert [f["rule_id"] for f in found] == ["G013"]
    assert found[0]["params"]["url"] == "https://evil.example/x.sh"
    assert found[0]["params"]["members"] == ["a", "b"]


def test_shared_fetch_target_requires_distinct_maintainers():
    from trustsight.analysis.correlation import shared_fetch_target

    records = _payload_records()
    records[1]["maintainer"] = records[0]["maintainer"]
    assert shared_fetch_target(records) == []


def test_shared_adoption_window_fires_for_several_maintainers():
    import time

    from trustsight.analysis.correlation import shared_adoption_window

    old = time.time() - 400 * 86400
    records = [
        {"package": "a", "maintainer": "a@x", "adoption": True,
         "last_modified": old},
        {"package": "b", "maintainer": "b@x", "adoption": True,
         "last_modified": old},
        {"package": "c", "maintainer": "c@x", "adoption": True,
         "last_modified": old},
    ]
    found = shared_adoption_window(records)
    assert [f["rule_id"] for f in found] == ["G014"]
    assert found[0]["params"]["dormant_count"] == 3
    assert found[0]["params"]["maintainer_count"] == 3


def test_shared_adoption_window_requires_distinct_maintainers_and_dormancy():
    import time

    from trustsight.analysis.correlation import shared_adoption_window

    old = time.time() - 400 * 86400
    ready = [
        {"package": "a", "maintainer": "a@x", "adoption": True,
         "last_modified": old},
        {"package": "b", "maintainer": "b@x", "adoption": True,
         "last_modified": old},
        {"package": "c", "maintainer": "c@x", "adoption": True,
         "last_modified": old},
    ]
    one_account = [dict(record, maintainer="same@x") for record in ready]
    assert shared_adoption_window(one_account) == []
    active = [dict(record, last_modified=time.time()) for record in ready]
    assert shared_adoption_window(active) == []


def test_correlate_includes_the_multi_maintainer_joins():
    from trustsight.analysis.correlation import correlate

    found = correlate(_payload_records())
    assert {f["rule_id"] for f in found} == {"G012", "G013"}


def test_correlation_records_carry_cycle_findings(tmp_path, monkeypatch):
    from trustsight.db import init_db
    from trustsight.full_aur.pipeline import _correlation_records

    monkeypatch.setattr("trustsight.db.DATA_DIR", tmp_path)
    init_db()
    detail = {"a": {"rules": ["R001"],
                    "payload_urls": ["https://evil.example/x.sh"]}}
    records = _correlation_records({}, None, {"a"}, detail=detail)
    assert records[0]["rules"] == ["R001"]
    assert records[0]["payload_urls"] == ["https://evil.example/x.sh"]


def test_multi_maintainer_joins_tolerate_bad_records():
    from trustsight.analysis.correlation import (
        shared_adoption_window, shared_fetch_target, shared_payload_signal,
    )

    bad = [None, "x", {}, {"package": ""},
           {"package": "a", "rules": "R001", "payload_urls": "https://e/x"}]
    assert shared_payload_signal(bad) == []
    assert shared_fetch_target(bad) == []
    assert shared_adoption_window(bad) == []


def test_shared_fetch_target_canonicalises_hand_built_urls():
    from trustsight.analysis.correlation import shared_fetch_target

    records = [
        {"package": "a", "maintainer": "a@x",
         "payload_urls": ["HTTPS://Evil.Example:443/x.sh?q=1"]},
        {"package": "b", "maintainer": "b@x",
         "payload_urls": ["https://evil.example/x.sh"]},
    ]
    found = shared_fetch_target(records)
    assert [f["rule_id"] for f in found] == ["G013"]
    assert found[0]["params"]["url"] == "https://evil.example/x.sh"


def test_new_joins_survive_malformed_thresholds():
    from trustsight.analysis.correlation import correlate

    records = _payload_records()
    config = {"thresholds": {"g012": {"min_packages": "x",
                                      "min_maintainers": None},
                             "g013": "bad", "g014": {"min_dormant": "x"}}}
    assert {f["rule_id"] for f in correlate(records, config)} >= {"G012", "G013"}


def test_correlation_records_tolerate_bad_detail(tmp_path, monkeypatch):
    from trustsight.db import init_db
    from trustsight.full_aur.pipeline import _correlation_records

    monkeypatch.setattr("trustsight.db.DATA_DIR", tmp_path)
    init_db()
    assert _correlation_records({}, None, {"a"}, detail="bad")[0]["rules"] == []
    assert _correlation_records(
        {}, None, {"a"}, detail={"a": "bad"})[0]["payload_urls"] == []


def test_shared_adoption_window_counts_a_package_once():
    import time

    from trustsight.analysis.correlation import shared_adoption_window

    old = time.time() - 400 * 86400
    records = [
        {"package": "a", "maintainer": "a@x", "adoption": True,
         "last_modified": old},
        {"package": "a", "maintainer": "b@x", "adoption": True,
         "last_modified": old},
        {"package": "b", "maintainer": "b@x", "adoption": True,
         "last_modified": old},
    ]
    assert shared_adoption_window(records) == []
