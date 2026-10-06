"""Serial vs parallel corpus runner equality.

The parallel path precomputes each package's global-URL prefix exactly and
lets each worker process its diffs serially, so it must produce the serial
rows.  A synthetic corpus makes the shared-URL case deterministic and fast.
"""

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import calibration_gates as gates  # noqa: E402

_DIFF_A = (
    "--- /dev/null\n+++ b/PKGBUILD\n@@ -0,0 +1,3 @@\n"
    "+pkgname=aaa\n"
    "+pkgver=1\n"
    "+source=('https://shared.example/x.tar.gz')\n"
)
_DIFF_B = (
    "--- /dev/null\n+++ b/PKGBUILD\n@@ -0,0 +1,3 @@\n"
    "+pkgname=bbb\n"
    "+pkgver=1\n"
    "+source=('https://shared.example/x.tar.gz')\n"
)


def _write_corpus(root: Path) -> Path:
    corpus = root / "benign-corpus"
    corpus.mkdir()
    (corpus / "aaa__1..2.diff").write_text(_DIFF_A)
    (corpus / "bbb__1..2.diff").write_text(_DIFF_B)
    return corpus


def test_the_plan_prefix_carries_a_previous_packages_urls():
    with tempfile.TemporaryDirectory() as tmp:
        corpus = _write_corpus(Path(tmp))
        with gates.shipped_config():
            config = gates.load_config()
            plan = gates._benign_plan(corpus, sample=1, config=config)
        prefixes = {pkg: prefix for pkg, _paths, prefix in plan}
        assert "https://shared.example/x.tar.gz" in prefixes["bbb"]
        assert "https://shared.example/x.tar.gz" not in prefixes["aaa"]


def test_parallel_rows_equal_serial_rows():
    with tempfile.TemporaryDirectory() as tmp:
        corpus = _write_corpus(Path(tmp))
        with gates.shipped_config():
            serial = gates.scan_corpus(corpus, sample=1, jobs=1)
            parallel = gates.scan_corpus(corpus, sample=1, jobs=2)
    assert serial == parallel
