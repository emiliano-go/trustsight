"""All-scan export payloads and the feed-only outbox path."""


import trustsight.db as db_module
from trustsight.db import init_db, pending_alert_payloads
from trustsight.full_aur._baseline_build import _scan_records, _scan_summary


def test_scan_records_are_compact_and_cover_failures():
    detail = {
        "alpha": {
            "score": 25,
            "risk": "medium",
            "old_version": "1.0",
            "new_version": "1.1",
            "maintainer": "one",
            "findings": [
                {"rule_id": "H037", "severity": "MEDIUM"},
                {"rule_id": "H037", "severity": "MEDIUM"},
            ],
            "coverage_gaps": [],
            "diff": "@@ -1 +1 @@",
            "pkgbuild_sha256": "abc",
        },
    }
    statuses = {"alpha": "ok", "beta": "fetch_failed"}
    records = _scan_records(detail, statuses)
    assert [r["package"] for r in records] == ["alpha", "beta"]
    assert records[0]["rules"] == [{"id": "H037", "severity": "MEDIUM"}]
    assert records[0]["has_diff"] is True
    assert "diff" not in records[0]
    assert "findings" not in records[0]
    summary = _scan_summary(records, statuses)
    assert summary["attempted"] == 2
    assert summary["succeeded"] == 1
    assert summary["fetch_failed"] == 1
    assert summary["with_diff"] == 1


def test_feed_only_outbox_never_targets_ntfy(tmp_path, monkeypatch):
    monkeypatch.setattr(db_module, "DATA_DIR", tmp_path)
    init_db()
    from trustsight.db import enqueue_alert_payload

    enqueue_alert_payload(
        {"event": "trustsight.scans", "scans": []}, "webhook", 1, feed_only=True,
    )
    row = pending_alert_payloads()[0]
    assert row["feed_only"] == 1
    assert row["ntfy_delivered"] == 1


def test_export_scans_writes_compact_ndjson(tmp_path, monkeypatch):
    import json

    from typer.testing import CliRunner

    import trustsight.db as db_module
    from trustsight.cli.app import app
    from trustsight.db import init_db, insert_analysis, upsert_package

    monkeypatch.setattr(db_module, "DATA_DIR", tmp_path)
    init_db()
    package_id = upsert_package("demo", "1.0")
    insert_analysis(
        package_id, "1.0", "1.1", "", "", 25,
        "@@ -1 +1 @@",
        json.dumps({"risk": "medium", "coverage_gaps": ["tree_not_analyzed"]}),
        [{"rule_id": "H037", "severity": "MEDIUM"}],
    )
    output = tmp_path / "scans.ndjson"
    result = CliRunner().invoke(
        app, ["full-aur", "export-scans", "--output", str(output)]
    )
    assert result.exit_code == 0, result.output
    lines = output.read_text().splitlines()
    assert len(lines) == 1
    document = json.loads(lines[0])
    assert document["event"] == "trustsight.scans"
    assert document["scans"][0]["package"] == "demo"
    assert document["scans"][0]["rules"] == [{"id": "H037", "severity": "MEDIUM"}]
    assert "diff" not in document["scans"][0]


def _seed_one_history(tmp_path, monkeypatch):
    import json

    import trustsight.db as db_module
    from trustsight.db import init_db, insert_analysis, upsert_package

    monkeypatch.setattr(db_module, "DATA_DIR", tmp_path)
    init_db()
    package_id = upsert_package("demo", "1.0")
    insert_analysis(
        package_id, "1.0", "1.1", "", "", 25,
        "@@ -1 +1 @@",
        json.dumps({"risk": "medium"}),
        [{"rule_id": "H037", "severity": "MEDIUM"}],
    )


def test_export_scans_refuses_a_symlink_target(tmp_path, monkeypatch):
    from typer.testing import CliRunner

    from trustsight.cli.app import app

    _seed_one_history(tmp_path, monkeypatch)
    real = tmp_path / "real.ndjson"
    real.write_text("keep me\n", encoding="utf-8")
    link = tmp_path / "link.ndjson"
    link.symlink_to(real)
    result = CliRunner().invoke(
        app, ["full-aur", "export-scans", "--output", str(link)])
    assert result.exit_code != 0
    assert real.read_text(encoding="utf-8") == "keep me\n"


def test_export_scans_leaves_no_temporary_file(tmp_path, monkeypatch):
    from typer.testing import CliRunner

    from trustsight.cli.app import app

    _seed_one_history(tmp_path, monkeypatch)
    output = tmp_path / "scans.ndjson"
    assert CliRunner().invoke(
        app, ["full-aur", "export-scans", "--output", str(output)]
    ).exit_code == 0
    assert output.read_text(encoding="utf-8").strip()
    assert list(tmp_path.glob(".scans-*")) == []
