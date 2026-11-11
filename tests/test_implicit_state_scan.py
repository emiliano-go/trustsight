"""The implicit-state inventory scanner (scripts/implicit_state_scan.py)."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
RUNTIME = ROOT / "src" / "trustsight"


def test_scan_covers_the_runtime_source_and_is_deterministic():
    import implicit_state_scan as scan

    first = scan.scan(RUNTIME)
    second = scan.scan(RUNTIME)
    assert first == second
    assert first["files_scanned"] > 270
    paths = {row["path"] for row in first["files"]}
    assert "db/_outbox.py" in paths
    assert "cli/hook.py" in paths
    assert "anergy.json" in paths


def test_scan_finds_the_known_outbox_state_machine():
    import implicit_state_scan as scan

    report = scan.scan(RUNTIME)
    row = next(r for r in report["files"] if r["path"] == "db/_outbox.py")
    assert row["state_words"] > 10
    assert any("mark_alert" in text for _, text in row["lifecycle"])
    assert {"parked", "pending"} & set(row["states"])
