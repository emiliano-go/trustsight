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
