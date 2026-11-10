"""M2/M5 hardening: wedged workers, bounded caches and render limits."""

from __future__ import annotations

import inspect

import pytest

from trustsight.sandbox import manifest_client, render_client, render_worker


def test_manifest_client_stops_a_wedged_worker(monkeypatch):
    class Dead:
        requests = 0

        def alive(self):
            return True

        def request(self, body):
            raise manifest_client.ManifestUnavailable("timed out")

        def stop(self):
            self.stopped = True

    dead = Dead()
    monkeypatch.setattr(manifest_client, "_worker", dead)
    with pytest.raises(manifest_client.ManifestUnavailable):
        manifest_client._ask(b"{}")
    assert dead.stopped is True
    assert manifest_client._worker is None


def test_render_client_stops_a_wedged_worker(monkeypatch):
    class Dead:
        requests = 0

        def alive(self):
            return True

        def request(self, body):
            raise render_client.RenderUnavailable("timed out")

        def stop(self):
            self.stopped = True

    dead = Dead()
    monkeypatch.setattr(render_client, "_worker", dead)
    with pytest.raises(render_client.RenderUnavailable):
        render_client.render("rules_table", {"rows": []})
    assert dead.stopped is True
    assert render_client._worker is None


def test_manifest_cache_is_byte_bounded(monkeypatch):
    monkeypatch.setattr(manifest_client, "MAX_CACHE_BYTES", 64)
    monkeypatch.setattr(manifest_client, "MAX_CACHE_ENTRIES", 10)
    manifest_client._cache.clear()
    manifest_client._cache_bytes = 0
    manifest_client._remember(("a",), {"data": "x" * 100})
    assert manifest_client._cache == {}
    manifest_client._remember(("b",), {"data": "small"})
    assert ("b",) in manifest_client._cache
    manifest_client._cache.clear()
    manifest_client._cache_bytes = 0


def test_snapshot_payload_cap_is_a_refusal():
    with pytest.raises(manifest_client.ManifestUnavailable, match="input cap"):
        manifest_client.parse_snapshot(
            "demo", b"x" * (manifest_client.MAX_SNAPSHOT_PAYLOAD_BYTES + 1))


def test_render_worker_bounds_output_and_applies_limits():
    source = inspect.getsource(render_worker.main)
    assert "apply_limits(" in source
    assert "_linux_sandbox.apply(\"read\"" in source
    buffer = render_worker._BoundedOutput(limit=8)
    buffer.write("1234")
    with pytest.raises(ValueError, match="byte cap"):
        buffer.write("56789")


def test_inspect_payload_carries_config_values_without_worker_config_reads():
    from trustsight.cli.inspect._render import _inspect_payload
    from trustsight.schema import PackageFact

    payload = _inspect_payload(PackageFact(package_name="p"))
    assert "render_cap_value" in payload
    assert "policy_threshold" in payload
    source = inspect.getsource(render_worker)
    assert "load_config" not in source
