"""Authority and alias rules for the AUR metadata seed expansion."""

import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="module")
def generate_seed():
    spec = importlib.util.spec_from_file_location(
        "generate_seed", ROOT / "scripts" / "generate_seed.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_authoritative_maintainer_wins_and_comment_is_an_alias(generate_seed):
    records, kind = generate_seed.maintainer_records(
        "alice", "Old Name <old@example.com>", metadata_present=True)
    assert kind == "metadata"
    assert records == [
        {"name": "alice", "package_count": 1, "source": "aur-metadata"},
        {"name": "Old Name <old@example.com>", "package_count": 0,
         "source": "aur-comment-alias"},
    ]


def test_same_identity_does_not_create_an_alias(generate_seed):
    records, _ = generate_seed.maintainer_records(
        "Alice", "alice <old@example.com>", metadata_present=True)
    assert len(records) == 1
    assert records[0]["source"] == "aur-metadata"


def test_orphan_comment_is_known_but_not_active(generate_seed):
    records, kind = generate_seed.maintainer_records(
        "", "Alice <old@example.com>", metadata_present=True)
    assert kind == "orphan"
    assert records == [
        {"name": "Alice <old@example.com>", "package_count": 0,
         "source": "aur-comment-orphan"},
    ]


def test_missing_metadata_falls_back_to_the_comment(generate_seed):
    records, kind = generate_seed.maintainer_records(
        "", "alice", metadata_present=False)
    assert kind == "comment"
    assert records == [
        {"name": "alice", "package_count": 1, "source": "aur-comment"},
    ]


def test_metadata_snapshot_is_indexed_by_package_base(tmp_path, generate_seed):
    path = tmp_path / "meta.json"
    path.write_text(json.dumps([
        {"Name": "a-split", "PackageBase": "a", "Maintainer": ""},
        {"Name": "a", "PackageBase": "a", "Maintainer": "alice"},
        {"Name": "b", "PackageBase": "b", "Maintainer": "bob"},
    ]))
    index, digest = generate_seed.load_metadata(path)
    assert index["a"]["Maintainer"] == "alice"
    assert index["b"]["Maintainer"] == "bob"
    assert len(digest) == 64
