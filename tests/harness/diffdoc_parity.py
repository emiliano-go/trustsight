"""Full projection-parity runner for the typed diff core.

For every diff in the locked benign corpus and every labelled malicious
fixture, each :class:`~trustsight.diffdoc.DiffDoc` projection is compared
against the legacy ``differ`` walker it replaces.  This is the phase-0
gate for the typed core: the layer exists, nothing consumes it yet, and
this run proves the parse is lossless with respect to every reader it
will replace.  A mismatch means the parser drifted from the walkers, and
migrating a consumer onto it would change findings.

The default test suite runs a sampled variant
(``tests/test_diffdoc_parity.py``); the calibration CI job runs this
whole, next to the §10 gates:

    uv run python tests/harness/diffdoc_parity.py
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT / "src"))

from trustsight.differ import (  # noqa: E402
    _post_diff_lines,
    _pre_diff_lines,
    map_diff_lines,
)
from trustsight.diffdoc import parse_diff  # noqa: E402

FIXTURES = ROOT / "tests" / "fixtures"


def iter_diff_paths(sample: int = 1):
    """Every corpus diff, benign first, then the labelled malicious ones.

    ``sample`` thins whole packages uniformly (every *sample*-th diff in
    the sorted walk), the same convention ``calibration_gates.scan_corpus``
    uses, so a sampled run is a subset of the full one, never a different
    one.
    """
    paths: list[Path] = []
    benign = FIXTURES / "benign-corpus"
    if benign.exists():
        paths.extend(sorted(benign.rglob("*.diff")))
    malicious = FIXTURES / "malicious"
    if malicious.exists():
        paths.extend(sorted(malicious.rglob("*.diff")))
    for index, path in enumerate(paths, start=1):
        if sample > 1 and index % sample:
            continue
        yield path


def check_text(text: str) -> list[str]:
    """The projection mismatches for one diff, empty when parity holds."""
    doc = parse_diff(text)
    failures: list[str] = []
    legacy_map = map_diff_lines(text)
    if doc.line_map() != legacy_map:
        only_new = {k: doc.line_map()[k] for k in doc.line_map().keys() - legacy_map.keys()}
        only_old = {k: legacy_map[k] for k in legacy_map.keys() - doc.line_map().keys()}
        shared_diff = {
            k: (doc.line_map()[k], legacy_map[k])
            for k in doc.line_map().keys() & legacy_map.keys()
            if doc.line_map()[k] != legacy_map[k]
        }
        failures.append(
            f"line_map: only-typed={only_new} only-legacy={only_old} "
            f"disagree={shared_diff}"
        )
    if doc.post_lines() != _post_diff_lines(text):
        failures.append("post_lines differ from _post_diff_lines")
    if doc.pre_lines() != _pre_diff_lines(text):
        failures.append("pre_lines differ from _pre_diff_lines")
    return failures


def main(argv: list[str]) -> int:
    sample = 1
    if "--sample" in argv:
        sample = int(argv[argv.index("--sample") + 1])
    checked = 0
    bad = 0
    for path in iter_diff_paths(sample=sample):
        checked += 1
        failures = check_text(path.read_text(errors="replace"))
        if failures:
            bad += 1
            print(f"PARITY FAIL {path}")
            for failure in failures:
                print(f"  {failure}")
    print(f"diffdoc parity: {checked} diffs checked, {bad} mismatched")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
