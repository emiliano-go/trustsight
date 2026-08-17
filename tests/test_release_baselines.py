"""Regression tests for the signed baseline-release artifact family."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from trustsight.full_aur.export import verify_artifact


ROOT = Path(__file__).resolve().parent.parent


def _release_builder():
    spec = importlib.util.spec_from_file_location(
        "build_release_baselines", ROOT / "scripts" / "build_release_baselines.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_release_builder_emits_the_runtime_ioc_name_and_signed_manifest(tmp_path, monkeypatch):
    builder = _release_builder()
    key = Ed25519PrivateKey.generate()
    key_path = tmp_path / "signing-key"
    key_path.write_bytes(key.private_bytes_raw())
    seed = tmp_path / "baseline-seed.tar.gz"
    seed.write_bytes(b"canonical seed")
    corpus = tmp_path / "baseline-corpus.tar.zst"
    corpus.write_bytes(b"corpus artifact")
    iocs = tmp_path / "incident.json"
    iocs.write_text(json.dumps([{"type": "domain", "value": "evil.example"}]))
    out = tmp_path / "dist"

    monkeypatch.setattr("sys.argv", [
        "build_release_baselines.py", "--out", str(out), "--sign-key", str(key_path),
        "--seed-archive", str(seed), "--corpus", str(corpus), "--ioc", str(iocs),
        "--ioc-source", "curator", "--ioc-incident", "incident",
    ])
    assert builder.main() == 0

    expected = {
        "baseline-seed.tar.gz",
        "baseline-corpus.tar.zst",
        "baseline-ioc-curator-incident-manifest.json",
        "baseline-ioc-curator-incident-iocs.jsonl",
        "baseline-manifest.json",
    }
    assert {path.name for path in out.iterdir() if not path.name.endswith(".sig")} == expected
    for name in expected:
        assert verify_artifact(
            (out / name).read_bytes(),
            (out / f"{name}.sig").read_bytes(),
            key.public_key().public_bytes_raw(),
        )

    manifest = json.loads((out / "baseline-manifest.json").read_text())
    assert {asset["name"] for asset in manifest["assets"]} == expected - {"baseline-manifest.json"}


def test_baseline_workflow_requires_and_signs_the_corpus_family():
    workflow = (ROOT / ".github" / "workflows" / "baselines.yml").read_text()
    assert "gh release download \"$TAG\" --pattern baseline-corpus.tar.zst" in workflow
    assert "--corpus /tmp/release-assets/baseline-corpus.tar.zst" in workflow
    assert "--seed-archive /tmp/release-assets/baseline-seed.tar.gz" in workflow
    assert "if: steps.check_seed.outputs.needs_build" not in workflow
