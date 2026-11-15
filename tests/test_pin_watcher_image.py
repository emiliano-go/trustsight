"""The watcher image must be deployable by digest, not a moving tag."""

from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _module():
    spec = importlib.util.spec_from_file_location(
        "pin_watcher_image", ROOT / "scripts" / "pin_watcher_image.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_repository_strips_a_tag_or_digest():
    mod = _module()
    assert mod.repository("ghcr.io/o/i:latest") == "ghcr.io/o/i"
    assert mod.repository("ghcr.io/o/i@sha256:abc") == "ghcr.io/o/i"
    assert mod.repository("localhost:5000/o/i") == "localhost:5000/o/i"


def test_resolve_digest_returns_the_index_digest():
    mod = _module()
    calls = []

    class Result:
        returncode = 0
        stdout = "sha256:abc\n"
        stderr = ""

    def runner(cmd, **kwargs):
        calls.append(cmd)
        return Result()

    assert mod.resolve_digest("ghcr.io/o/i:latest", runner=runner) == "sha256:abc"
    assert calls[0][:4] == ["docker", "buildx", "imagetools", "inspect"]


def test_pinned_compose_requires_a_digest_variable():
    text = (ROOT / "docker-compose.watcher.pinned.yml").read_text()
    assert "${TRUSTSIGHT_IMAGE:?" in text


def test_require_signature_refuses_without_a_key(monkeypatch):
    mod = _module()
    monkeypatch.setattr(mod, "resolve_digest", lambda ref: "sha256:abc")
    assert mod.main(["ghcr.io/o/i:latest", "--require-signature"]) == 2


def test_require_signature_verifies_with_a_key(monkeypatch):
    mod = _module()
    monkeypatch.setattr(mod, "resolve_digest", lambda ref: "sha256:abc")
    seen = []
    monkeypatch.setattr(
        mod, "verify", lambda ref, key: seen.append((ref, key)))
    assert mod.main([
        "ghcr.io/o/i:latest", "--require-signature", "--cosign-key", "k.pub",
    ]) == 0
    assert seen == [("ghcr.io/o/i@sha256:abc", "k.pub")]
