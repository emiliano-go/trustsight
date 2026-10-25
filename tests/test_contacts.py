"""The Contact Ledger (spec: contact-ledger).

The pure layers (candidate extraction, the G010 plurality join, the panel)
run without a DB; the recording and read paths run against a temp database.
The determinism check proves the ledger never touches the score.
"""

import pytest

from trustsight.contacts import (
    COLD_NOTE,
    contact_candidates,
    contact_id,
    contact_panel,
    contacts_for_fact,
    panel_lines,
    record_cycle_contacts,
    shared_first_seen_host,
)
from trustsight.db import (
    contact_entries,
    contacts_for_values,
    host_first_seen,
    init_db,
)
from trustsight.reporting import REPORT_KEYS, evaluate_fact, report_body
from trustsight.schema import PackageFact, ScoreEntry


@pytest.fixture
def db(tmp_path, monkeypatch):
    monkeypatch.setattr("trustsight.db.DATA_DIR", tmp_path)
    monkeypatch.setattr("trustsight.config.DATA_DIR", tmp_path)
    init_db()
    yield tmp_path
    (tmp_path / "trustsight.db").unlink(missing_ok=True)


def _fact(**kwargs) -> PackageFact:
    return PackageFact(package_name="demo", **kwargs)


# --- the pure layers --------------------------------------------------------


def test_contact_id_is_deterministic_and_kind_sensitive():
    a = contact_id("pkg", "host", "evil-cdn.net", 7)
    assert a == contact_id("pkg", "host", "evil-cdn.net", 7)
    assert a != contact_id("pkg", "host", "evil-cdn.net", 8)
    assert a != contact_id("pkg", "upstream", "evil-cdn.net", 7)


def test_contact_candidates_extracts_every_kind():
    record = {
        "package": "pkg",
        "hosts_gained": ["evil-cdn.net"],
        "maintainer": "throwaway",
        "added_file_kinds": ["service"],
        "upstream_dep_additions": [("libx", "files.example.com")],
    }
    kinds = {kind for kind, _ in contact_candidates(record)}
    assert kinds == {"host", "maintainer_account", "file_kind", "upstream"}


def test_shared_first_seen_host_is_g010_and_needs_a_fresh_host():
    records = [{"package": f"p{i}", "hosts_gained": ["new-cdn.net"]}
               for i in range(5)]
    findings = shared_first_seen_host(records, min_packages=5,
                                      first_seen_hosts={"new-cdn.net"})
    assert [f["rule_id"] for f in findings] == ["G010"]
    assert findings[0]["severity"] == "INFO"
    assert findings[0]["params"]["members"] == [f"p{i}" for i in range(5)]
    # A host already known is not a first-seen stranger.
    assert shared_first_seen_host(records, min_packages=5,
                                  first_seen_hosts=set()) == []
    # Below the plurality floor, strangers alone are a census, not a signal.
    assert shared_first_seen_host(records[:4], min_packages=5,
                                  first_seen_hosts={"new-cdn.net"}) == []


def test_g010_skips_trusted_forges_official_hosts_and_one_project():
    records = [
        {"package": f"p{i}", "pkgbase": f"base{i}", "maintainer": f"m{i}",
         "hosts_gained": ["github.com"]}
        for i in range(5)
    ]
    assert shared_first_seen_host(
        records, 5, first_seen_hosts={"github.com"}) == []

    split = [dict(record, pkgbase="one-project") for record in records]
    assert shared_first_seen_host(
        split, 5, first_seen_hosts={"github.com"}) == []
    for record in split:
        record["hosts_gained"] = ["cdn.example"]
    assert shared_first_seen_host(
        split, 5, first_seen_hosts={"cdn.example"}) == []


def test_g010_skips_one_maintainers_name_family_but_keeps_unrelated_members():
    records = [
        {"package": f"firefox-nightly-i18n-{lang}", "pkgbase": f"base-{lang}",
         "maintainer": "one", "hosts_gained": ["cdn.example"]}
        for lang in ("en", "de", "fr", "es", "it")
    ]
    assert shared_first_seen_host(
        records, 5, first_seen_hosts={"cdn.example"}) == []
    records[0]["maintainer"] = "other"
    assert shared_first_seen_host(
        records, 5, first_seen_hosts={"cdn.example"})


# --- the recording path -----------------------------------------------------


def test_record_cycle_contacts_basis_ledger_then_matched(db):
    record = {"package": "pkg", "hosts_gained": ["evil-cdn.net"],
              "maintainer": "throwaway"}
    first = record_cycle_contacts([record], 100, "2026-06-12T00:00:00+00:00")
    assert {r.basis for r in first["records"]} == {"ledger"}
    assert first["hosts_new"] == {"evil-cdn.net"}

    second = record_cycle_contacts([record], 101, "2026-06-13T00:00:00+00:00")
    assert {r.basis for r in second["records"]} == {"matched"}
    # Append-only: the second run added nothing.
    assert len(contact_entries()) == len(first["records"])


def test_record_contacts_is_append_only_and_hosts_first_seen_persists(db):
    record_cycle_contacts([{"package": "p", "hosts_gained": ["a.net"]}],
                          1, "2026-06-12T00:00:00+00:00")
    record_cycle_contacts([{"package": "p", "hosts_gained": ["a.net"]}],
                          2, "2026-06-13T00:00:00+00:00")
    assert host_first_seen("a.net") == "2026-06-12T00:00:00+00:00"
    assert contacts_for_values("host", ["a.net"]) == {
        "a.net": "2026-06-12T00:00:00+00:00"}


# --- the report panel -------------------------------------------------------


def test_contact_panel_is_cold_when_the_ledger_is_disabled(db, monkeypatch):
    monkeypatch.setattr("trustsight.config.load_config",
                        lambda: {"contacts": {"enabled": False}})
    panel = contact_panel(_fact())
    assert panel["available"] is False
    assert panel["note"] == COLD_NOTE
    assert panel["records"] == []


def test_contact_panel_lists_first_contacts_warm(db):
    fact = _fact(current_maintainer="throwaway",
                 diff_summary=PackageFact().diff_summary)
    fact.source_changes.added_urls.append("https://evil-cdn.net/x.tar.gz")
    rows = contacts_for_fact(fact)
    assert {r["kind"] for r in rows} == {"host", "maintainer_account"}
    assert all(r["basis"] == "ledger" for r in rows)
    panel = contact_panel(fact)
    assert panel["available"] is True
    assert len(panel["records"]) == len(rows)


def test_panel_lines_sanitise_a_hostile_contact_value():
    # A package-derived value must not carry terminal escapes into the panel;
    # brackets survive for the Rich renderers to wrap in Text (not markup).
    hostile = "\x1b[2J\x1b[H[bold red]VERDICT: CLEAN[/]\x9b31m"
    lines = panel_lines({"available": True, "note": "",
                         "records": [{"kind": "host", "value": hostile,
                                      "basis": "ledger"}]})
    out = "\n".join(lines)
    assert "\x1b" not in out and "\x9b" not in out
    assert "[bold red]VERDICT: CLEAN[/]" in out


def test_contacts_ride_the_report_body_but_never_the_score(db):
    fact = _fact(score_breakdown=[ScoreEntry(rule_id="R001", severity="HIGH",
                                             weight=25, reason="x")],
                 final_score=25, risk="Medium")
    assert "contacts" in REPORT_KEYS
    evaluated = evaluate_fact(fact)
    assert "contacts" in report_body(evaluated)
    assert "score" not in report_body(evaluated)  # withheld unless asked
    assert report_body(evaluated, include_score=True)["score"] == 25
    # The ledger is additive: it is not a score component.
    assert evaluated["score"] == fact.final_score == 25
