"""The Phase 0 seed-coverage audit reads metadata and a v3 seed."""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import seed_coverage_audit  # noqa: E402
from trustsight.seed_build import build_seed  # noqa: E402


def test_audit_counts_metadata_and_seed_rows(tmp_path):
    meta = tmp_path / "meta.json"
    meta.write_text(json.dumps([
        {"Name": "a", "PackageBase": "a", "Maintainer": "alice"},
        {"Name": "b", "PackageBase": "b", "Maintainer": ""},
    ]))
    seed_dir = tmp_path / "seed"
    build_seed([
        {"name": "alice", "package_count": 1, "source": "aur-metadata"},
        {"name": "old", "package_count": 0, "source": "aur-comment-orphan"},
    ], seed_dir)
    result = seed_coverage_audit.audit(meta, seed_dir)
    assert result["package_bases"] == 2
    assert result["with_maintainer"] == 1
    assert result["orphan"] == 1
    assert result["seed_active"] == 1
    assert result["seed_aliases"] == 1
