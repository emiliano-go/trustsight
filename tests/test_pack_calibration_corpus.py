"""The calibration corpus ships as a release asset; the pack is the gate.

Reconstruction from corpus.lock is not byte-stable across git versions, so
CI downloads the packed corpus and verifies it against baseline.json.  The
pack script is what stands between a drifted local corpus and the channel:
it must refuse to pack bytes the committed hash does not describe.
"""

import json
import sys
import tarfile
import unittest.mock
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import pack_calibration_corpus as pcc


def _corpus(tmp_path):
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    (corpus / "a__1..2.diff").write_text("diff a\n")
    (corpus / "b__3..4.diff").write_text("diff b\n")
    (corpus / "c__5..6.diff").write_text("diff c\n")
    return corpus


def _baseline(tmp_path, corpus):
    baseline = tmp_path / "baseline.json"
    baseline.write_text(json.dumps(
        {"corpus_content_sha256": pcc.corpus_content_hash(corpus)}
    ))
    return baseline


def _run(argv):
    with unittest.mock.patch.object(sys, "argv", argv):
        return pcc.main()


def test_pack_is_deterministic_and_round_trips(tmp_path):
    corpus = _corpus(tmp_path)
    baseline = _baseline(tmp_path, corpus)
    out1, out2 = tmp_path / "one.tar.gz", tmp_path / "two.tar.gz"

    assert _run(["pack", "--corpus", str(corpus), "--baseline", str(baseline),
                 "--out", str(out1)]) == 0
    assert _run(["pack", "--corpus", str(corpus), "--baseline", str(baseline),
                 "--out", str(out2)]) == 0
    assert out1.read_bytes() == out2.read_bytes(), "packing must be deterministic"

    with tarfile.open(out1) as tar:
        extracted = {m.name: tar.extractfile(m).read() for m in tar.getmembers()}
    assert extracted == {p.name: p.read_bytes() for p in corpus.glob("*.diff")}


def test_pack_refuses_a_drifted_corpus(tmp_path):
    corpus = _corpus(tmp_path)
    baseline = _baseline(tmp_path, corpus)
    (corpus / "a__1..2.diff").write_text("drifted\n")
    out = tmp_path / "out.tar.gz"

    assert _run(["pack", "--corpus", str(corpus), "--baseline", str(baseline),
                 "--out", str(out)]) == 1
    assert not out.exists(), "a drifted corpus must not produce an asset"


def test_check_mode_verifies_without_writing(tmp_path):
    corpus = _corpus(tmp_path)
    baseline = _baseline(tmp_path, corpus)
    assert _run(["pack", "--check", "--corpus", str(corpus),
                 "--baseline", str(baseline)]) == 0
    (corpus / "b__3..4.diff").write_text("changed\n")
    assert _run(["pack", "--check", "--corpus", str(corpus),
                 "--baseline", str(baseline)]) == 1


def test_pack_refuses_a_missing_corpus(tmp_path):
    baseline = _baseline(tmp_path, _corpus(tmp_path))
    assert _run(["pack", "--corpus", str(tmp_path / "nope"),
                 "--baseline", str(baseline),
                 "--out", str(tmp_path / "o.tar.gz")]) == 1
