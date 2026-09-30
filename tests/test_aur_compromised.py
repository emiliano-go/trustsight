"""The Atomic Arch exposure list is well-formed and never enters the IOC layer."""

from __future__ import annotations

import csv
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data" / "aur-compromised" / "atomic-arch-2026-06"


def _rows(name: str) -> list[dict]:
    with open(DATA / name, newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh, delimiter="\t"))


def test_the_malware_list_is_substantial_and_deduped():
    rows = _rows("packages.tsv")
    assert len(rows) > 1000
    names = [r["package"] for r in rows]
    assert len(names) == len(set(names))
    assert set(names) == set(sorted(names))


def test_every_row_has_a_wave_and_a_confidence():
    for row in _rows("packages.tsv"):
        assert row["waves"], row
        assert row["confidence"] in ("primary-source", "single-source"), row
        assert set(row["waves"].split(",")) <= {"wave1-2", "wave3"}


def test_the_spam_campaign_is_kept_separate():
    spam = _rows("spam-packages.tsv")
    assert len(spam) > 100
    assert all(r["classification"] == "spam-rc-injection" for r in spam)
    # Never mixed: the malware file carries no spam marker of its own.
    assert "classification" not in _rows("packages.tsv")[0]


def test_the_exposure_names_were_not_imported_as_iocs():
    """The compromise list is exposure data; the IOC layer holds only the payload."""
    import json

    entries = json.loads((ROOT / "data" / "iocs" / "atomic-arch-2026-06.json").read_text())
    package_values = {e["value"] for e in entries if e["type"] == "package"}
    assert package_values == {"atomic-lockfile", "lockfile-js", "js-digest", "nextfile-js"}
    exposure = {r["package"] for r in _rows("packages.tsv")}
    assert exposure.isdisjoint(package_values)
    assert len(exposure) > 1000
