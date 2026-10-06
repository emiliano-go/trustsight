"""Sampled projection-baseline gate for the typed diff core.

The full baseline replay lives in ``tests/harness/diffdoc_parity.py`` and
runs in the calibration CI job; this module checks every 37th benign diff
plus every labelled malicious fixture against the committed baseline in the
default suite, so parser drift fails locally in seconds.  The sample stride
is coprime with the package groupings, so every package family is visited.
"""

import gzip
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from harness.diffdoc_parity import (  # noqa: E402
    BASELINE,
    FIXTURES,
    iter_diff_paths,
    projection_digest,
)

CORPUS = FIXTURES / "benign-corpus"
MALICIOUS = FIXTURES / "malicious"

corpus_mark = pytest.mark.skipif(
    not CORPUS.exists(),
    reason="benign corpus absent; rebuild with scripts/build_corpus.py",
)
baseline_mark = pytest.mark.skipif(
    not BASELINE.exists(),
    reason="projection baseline absent; run the harness with --write",
)

BENIGN_SAMPLE = [
    path for path in iter_diff_paths(sample=37)
    if CORPUS in path.parents
]
MALICIOUS_ALL = (
    sorted(MALICIOUS.rglob("*.diff")) if MALICIOUS.exists() else []
)


@pytest.fixture(scope="module")
def projections() -> dict:
    with gzip.open(BASELINE, "rt") as handle:
        return json.load(handle)["projections"]


def _check(path: Path, projections: dict) -> None:
    key = str(path.relative_to(FIXTURES))
    expected = projections.get(key)
    assert expected is not None, f"{key}: not in the projection baseline"
    assert projection_digest(path.read_text(errors="replace")) == expected, (
        f"{key}: projection moved; re-run the harness with --write and review "
        "the change"
    )


@baseline_mark
@corpus_mark
@pytest.mark.parametrize("path", BENIGN_SAMPLE, ids=lambda p: p.name)
def test_benign_corpus_projection_baseline(path, projections):
    _check(path, projections)


@baseline_mark
@pytest.mark.skipif(not MALICIOUS_ALL, reason="malicious fixtures absent")
@pytest.mark.parametrize("path", MALICIOUS_ALL, ids=lambda p: p.name)
def test_malicious_fixture_projection_baseline(path, projections):
    _check(path, projections)
