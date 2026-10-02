"""Sampled projection-parity gate for the typed diff core.

The full replay lives in ``tests/harness/diffdoc_parity.py`` and runs in
the calibration CI job; this module runs every 37th benign diff plus every
labelled malicious fixture in the default suite, so a parser drift fails
locally in seconds rather than in CI.  The sample stride is coprime with
the package groupings, so every package family is visited.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from harness.diffdoc_parity import FIXTURES, check_text, iter_diff_paths  # noqa: E402

CORPUS = FIXTURES / "benign-corpus"
MALICIOUS = FIXTURES / "malicious"

corpus_mark = pytest.mark.skipif(
    not CORPUS.exists(),
    reason="benign corpus absent; rebuild with scripts/build_corpus.py",
)

BENIGN_SAMPLE = [
    path for path in iter_diff_paths(sample=37)
    if CORPUS in path.parents
]
MALICIOUS_ALL = (
    sorted(MALICIOUS.rglob("*.diff")) if MALICIOUS.exists() else []
)


@corpus_mark
@pytest.mark.parametrize("path", BENIGN_SAMPLE, ids=lambda p: p.name)
def test_benign_corpus_projection_parity(path):
    failures = check_text(path.read_text(errors="replace"))
    assert not failures, f"{path.name}: {failures}"


@pytest.mark.skipif(not MALICIOUS_ALL, reason="malicious fixtures absent")
@pytest.mark.parametrize("path", MALICIOUS_ALL, ids=lambda p: p.name)
def test_malicious_fixture_projection_parity(path):
    failures = check_text(path.read_text(errors="replace"))
    assert not failures, f"{path.name}: {failures}"
