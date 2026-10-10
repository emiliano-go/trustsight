"""Sampled ChangeDelta parity gate (spec §1).

The full replay lives in ``tests/harness/change_parity.py`` and runs in the
calibration CI job; this module checks every 37th benign diff against the
same reference facts in the default suite, so a migration that makes the
delta disagree with the summary machinery fails locally.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from harness.change_parity import replay  # noqa: E402

_CORPUS = Path(__file__).resolve().parent / "fixtures" / "benign-corpus"

corpus_mark = pytest.mark.skipif(
    not _CORPUS.exists(),
    reason="benign corpus absent; rebuild with scripts/build_corpus.py",
)


@corpus_mark
def test_change_delta_parity_over_a_corpus_sample():
    mismatches = replay(sample=37)
    assert not mismatches, f"ChangeDelta parity mismatches: {mismatches[:10]}"
