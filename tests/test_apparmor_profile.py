"""The optional watcher AppArmor profile parses and keeps the mount floor."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
PROFILE = ROOT / "docker" / "apparmor" / "trustsight-watcher"


@pytest.mark.skipif(not shutil.which("apparmor_parser"),
                    reason="apparmor_parser is not installed")
def test_the_watcher_profile_parses():
    result = subprocess.run(
        ["apparmor_parser", "-Q", str(PROFILE)],
        capture_output=True, text=True, timeout=30)
    if result.returncode != 0 and "Permission denied" in result.stderr:
        pytest.skip("apparmor_parser cannot write the policy cache")
    assert result.returncode == 0, result.stderr


def test_the_profile_allows_namespaces_and_mount():
    text = PROFILE.read_text()
    assert "mount," in text
    assert "userns," in text
    assert "profile trustsight-watcher" in text
