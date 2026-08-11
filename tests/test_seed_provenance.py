"""Unit tests for the seed-provenance record (scripts/generate_seed.py).

The provenance record is what lets a third party reproduce the published
seed and compare their build against the shipped one; it must be stable in
shape, so this test pins its schema.
"""

import importlib.util
import json
from datetime import datetime
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


def test_build_provenance_records_every_input(generate_seed):
    prov = generate_seed.build_provenance(
        source="/home/mirror/aur.git",
        package_count=116000,
        packages_with_sources=110000,
        maintainer_count=35587,
        observation_count=147930,
        mirror_size_bytes=2_600_000_000,
        command="python scripts/generate_seed.py --out /tmp/seed.db",
    )
    assert prov["format_version"] == "1.0.0"
    assert prov["source"] == "/home/mirror/aur.git"
    assert prov["package_count"] == 116000
    assert prov["packages_with_sources"] == 110000
    assert prov["maintainer_count"] == 35587
    assert prov["observation_count"] == 147930
    assert prov["mirror_size_bytes"] == 2_600_000_000
    assert prov["command"] == "python scripts/generate_seed.py --out /tmp/seed.db"
    datetime.fromisoformat(prov["built_at"])  # valid ISO timestamp
    assert prov["built_at"].endswith("+00:00") or prov["built_at"].endswith("Z")


def test_build_provenance_respects_explicit_timestamp(generate_seed):
    prov = generate_seed.build_provenance(
        source="x",
        package_count=1,
        packages_with_sources=1,
        maintainer_count=1,
        observation_count=1,
        mirror_size_bytes=1,
        command="c",
        built_at="2026-08-11T00:00:00+00:00",
    )
    assert prov["built_at"] == "2026-08-11T00:00:00+00:00"


def test_build_provenance_round_trips_through_json(generate_seed):
    prov = generate_seed.build_provenance(
        source="x",
        package_count=1,
        packages_with_sources=1,
        maintainer_count=1,
        observation_count=1,
        mirror_size_bytes=1,
        command="c",
    )
    json.dumps(prov)  # all values JSON-serialisable, no NaN etc.
