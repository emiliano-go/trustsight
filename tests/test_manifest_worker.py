"""Manifest parsing runs in the confined worker, not in the parent."""

from __future__ import annotations

import inspect

import pytest

from trustsight.analysis import manifests
from trustsight.analysis.manifest_syntax import ManifestSyntaxError
from trustsight.sandbox import manifest_client, manifest_worker


def test_manifest_parse_goes_through_the_sandbox_client(monkeypatch):
    calls: list[tuple[str, str]] = []

    def fake(path, text):
        calls.append((path, text))
        return None

    monkeypatch.setattr(manifest_client, "parse_manifest", fake)
    assert manifests.parse_manifest("environment.yml", "dependencies: []\n") is None
    assert calls == [("environment.yml", "dependencies: []\n")]


def test_sandbox_unavailable_is_a_named_refusal(monkeypatch):
    def fail(path, text):
        raise manifest_client.ManifestUnavailable("worker died")

    monkeypatch.setattr(manifest_client, "parse_manifest", fail)
    with pytest.raises(ManifestSyntaxError):
        manifests.parse_manifest("package.json", "{}")


def test_worker_applies_the_linux_sandbox():
    source = inspect.getsource(manifest_worker.main)
    assert '_linux_sandbox.apply("read"' in source
    assert "core_sandbox_failures(" in source


def test_worker_uses_the_local_tokenizer_engine():
    source = inspect.getsource(manifest_worker._install_local_tokenizer)
    assert "_tokenizer_engine" in source
    assert "facade.split_lines" in source


def test_the_tokenizer_runs_in_the_content_worker(monkeypatch):
    """M2: the analysis tokenizer has no second, nested child."""
    from trustsight import tokenizer

    calls: list[tuple[str, object]] = []

    def fake(op, value):
        calls.append((op, value))
        return ["resolved"]

    monkeypatch.setattr(tokenizer, "_request_tokenizer", fake)
    tokenizer._line_memo = __import__("threading").local()
    assert tokenizer.resolve_added_lines("+a=b\n") == ["resolved"]
    assert calls == [("resolve_added", "+a=b\n")]


def test_the_worker_serves_tokenizer_and_snapshot_operations():
    source = inspect.getsource(manifest_worker)
    assert '"__tokenizer__"' in source
    assert '"__snapshot__"' in source


def test_snapshot_parsing_goes_through_the_content_worker(monkeypatch):
    from trustsight.full_aur import fetch
    from trustsight.sandbox import manifest_client

    calls: list[tuple[str, bytes]] = []

    def fake(name, data, **kwargs):
        calls.append((name, data))
        return {
            "pkgbuild": "pkgname=demo\n", "manifest": [],
            "trailer": None, "install_text": None, "install_name": None,
            "manifest_texts": [], "manifest_complete": True,
            "refused": False, "malformed": False,
        }

    monkeypatch.setattr(manifest_client, "parse_snapshot", fake)
    monkeypatch.setattr(fetch, "_fetch_snapshot_tarball", lambda name: b"tar")
    text, *_rest = fetch.fetch_pkgbuild_with_tree("demo")
    assert text == "pkgname=demo\n"
    assert calls == [("demo", b"tar")]


def test_artifact_manifest_goes_through_the_worker(monkeypatch):
    import json

    from trustsight.sandbox import manifest_client

    captured = {}

    def fake(payload):
        captured.update(json.loads(payload))
        return {
            "findings": [{
                "rule_id": "A001", "name": "Setuid File In Artifact",
                "severity": "HIGH", "category": "artifact",
                "match": "/usr/bin/x has setuid",
                "file": "/usr/bin/x",
            }],
            "limits": {"truncated": False, "reasons": []},
        }

    monkeypatch.setattr(manifest_client, "_ask", fake)
    result = manifest_client.inspect_artifact_manifest(
        manifest_text='[{"path": "/usr/bin/x", "setuid": true}]')
    assert captured["path"] == "__artifact_manifest__"
    assert captured["text"].startswith("[")
    assert result["findings"][0]["rule_id"] == "A001"


def test_artifact_manifest_list_is_normalised_before_the_worker(monkeypatch):
    import json

    from trustsight.sandbox import manifest_client

    captured = {}

    def fake(payload):
        captured.update(json.loads(payload))
        return {"findings": [], "limits": {"truncated": False, "reasons": []}}

    monkeypatch.setattr(manifest_client, "_ask", fake)
    manifest_client.inspect_artifact_manifest(
        manifest=[{"path": "/usr/bin/x", "unknown": "x" * 100}],
        declared={"depends": ["glibc"], "unknown": "ignored"},
    )
    records = json.loads(captured["text"])
    assert records == [{"path": "/usr/bin/x"}]
    assert captured["declared"] == {"depends": ["glibc"]}


def test_artifact_manifest_rejects_both_forms():
    from trustsight.sandbox import manifest_client

    with pytest.raises(manifest_client.ManifestUnavailable):
        manifest_client.inspect_artifact_manifest(
            manifest=[], manifest_text="[]")


def test_artifact_manifest_rejects_a_malformed_worker_result(monkeypatch):
    from trustsight.sandbox import manifest_client

    monkeypatch.setattr(
        manifest_client, "_ask",
        lambda payload: {"findings": [{"rule_id": "X"}],
                         "limits": {"reasons": []}})
    with pytest.raises(manifest_client.ManifestUnavailable):
        manifest_client.inspect_artifact_manifest(manifest_text="[]")


def test_the_worker_parses_artifact_manifests():
    import json

    body = json.dumps({
        "path": "__artifact_manifest__",
        "text": json.dumps([{"path": "/usr/bin/x", "setuid": True}]),
    }).encode()
    response = manifest_worker._handle(body)
    assert response["result"]["findings"][0]["rule_id"] == "A001"


def test_the_worker_rejects_a_non_array_artifact_manifest():
    import json

    body = json.dumps({
        "path": "__artifact_manifest__",
        "text": json.dumps({"path": "/usr/bin/x"}),
    }).encode()
    response = manifest_worker._handle(body)
    assert "error" in response


def test_the_worker_rejects_a_pathless_artifact_record():
    import json

    body = json.dumps({
        "path": "__artifact_manifest__",
        "text": json.dumps([{}]),
    }).encode()
    response = manifest_worker._handle(body)
    assert "error" in response


def test_artifact_manifest_rejects_raw_control_text():
    from trustsight.sandbox import manifest_client

    with pytest.raises(manifest_client.ManifestUnavailable, match="control"):
        manifest_client.inspect_artifact_manifest(
            manifest_text='["\x01"]')


def test_artifact_manifest_request_over_the_frame_cap_is_refused(monkeypatch):
    from trustsight.sandbox import manifest_client, protocol

    monkeypatch.setattr(protocol, "MAX_FRAME_BYTES", 8)
    with pytest.raises(manifest_client.ManifestUnavailable, match="framed"):
        manifest_client._ask(b"x" * 9)


def test_artifact_manifest_result_requires_limits(monkeypatch):
    from trustsight.sandbox import manifest_client

    monkeypatch.setattr(
        manifest_client, "_ask",
        lambda payload: {"findings": [], "limits": {"reasons": []}})
    with pytest.raises(manifest_client.ManifestUnavailable, match="limits"):
        manifest_client.inspect_artifact_manifest(manifest_text="[]")


def test_artifact_manifest_reasons_are_bounded(monkeypatch):
    from trustsight.analysis import artifact
    from trustsight.sandbox import manifest_client

    monkeypatch.setattr(
        manifest_client, "_ask",
        lambda payload: {
            "findings": [],
            "limits": {"truncated": False,
                       "reasons": ["x" * (artifact.MAX_LIMIT_REASON_BYTES + 1)]},
        })
    with pytest.raises(manifest_client.ManifestUnavailable, match="limits"):
        manifest_client.inspect_artifact_manifest(manifest_text="[]")
