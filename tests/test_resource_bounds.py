"""Attacker-controlled input does not decide what this process consumes.

A14 says every bound on an input is a source constant. These cover the three
resources that had a cap on the *wire* and none on what the wire became:

* **RAM** - a byte ceiling on JSON is not a ceiling on the objects it parses
  into, and the amplification is about 6x.
* **Disk and network** - a deadline bounds how long a clone runs, which on a
  fast link is not a bound on how much arrives.
* **CPU** - repository history is attacker-authored, and three walks ran to
  exhaustion over it.

The last two share a shape worth naming: a cap that looks sufficient alone
but gets multiplied by a *second* cap somewhere else. `MAX_DEPTH_NODES` is
200, so a per-repo transfer ceiling is really that ceiling times 200 unless
something charges the total.
"""

import json
import tracemalloc

import pytest

from trustsight import fetcher, ioc_baseline
from trustsight.full_aur import metadata


# ---------------------------------------------------------------------------
# RAM: parsed objects, not wire bytes.
# ---------------------------------------------------------------------------


def _amplification(payload: bytes) -> float:
    """Peak Python heap while parsing *payload*, over its serialised size."""
    tracemalloc.start()
    try:
        obj = json.loads(payload)
        _peak = tracemalloc.get_traced_memory()[1]
        del obj
    finally:
        tracemalloc.stop()
    return _peak / len(payload)


def test_the_decompression_ceiling_is_set_against_parsed_size():
    """The ceiling times the amplification must stay a survivable number.

    The 1 GiB ceiling this replaced was chosen against the ~250 MB dump on
    the wire. Parsed, that ceiling permitted about 6 GiB of live objects,
    which is not a bound on memory so much as a promise to exhaust it.
    """
    worst = metadata.MAX_DECOMPRESSED_BYTES * metadata.JSON_OBJECT_AMPLIFICATION
    assert worst <= 4 * 1024**3, (
        f"the ceiling permits {worst / 1024**3:.1f} GiB of parsed objects"
    )


def test_the_documented_amplification_is_not_an_underestimate():
    """If dump-shaped JSON costs more than the constant says, re-derive it."""
    entries = [
        {"Name": f"pkg-{i}", "Version": "1.0-1", "Description": "x" * 40,
         "URL": "https://example.invalid", "Depends": ["a", "b", "c"]}
        for i in range(4000)
    ]
    payload = json.dumps(entries).encode()
    measured = _amplification(payload)
    assert measured <= metadata.JSON_OBJECT_AMPLIFICATION, (
        f"measured {measured:.1f}x against a documented "
        f"{metadata.JSON_OBJECT_AMPLIFICATION}x"
    )


def test_the_baseline_entry_cap_bounds_the_objects_not_just_the_bytes(tmp_path):
    """256 MiB of JSONL is millions of entries; a curated set is thousands."""
    overshoot = 50
    line = json.dumps({"type": "url", "value": "https://example.invalid/x",
                       "campaign": "test"})
    path = tmp_path / "iocs.jsonl"
    path.write_text(
        "\n".join([line] * (ioc_baseline.MAX_BASELINE_ENTRIES + overshoot))
    )

    entries = ioc_baseline._load_iocs(path)
    assert len(entries) <= ioc_baseline.MAX_BASELINE_ENTRIES


# ---------------------------------------------------------------------------
# Disk and network: a deadline is not a byte budget.
# ---------------------------------------------------------------------------


class _Stats:
    def __init__(self, received_bytes):
        self.received_bytes = received_bytes


@pytest.fixture(autouse=True)
def _fresh_budget():
    fetcher.reset_transfer_budget()
    yield
    fetcher.reset_transfer_budget()


def test_one_transfer_cannot_exceed_its_byte_ceiling():
    callbacks = fetcher._DeadlineCallbacks(120)
    callbacks.transfer_progress(_Stats(1024))  # well inside: no raise

    with pytest.raises(fetcher._TimeoutError):
        callbacks.transfer_progress(_Stats(fetcher.MAX_TRANSFER_BYTES + 1))


def test_many_transfers_cannot_exceed_the_run_budget():
    """The bound the per-repo ceiling does not provide.

    A dependency walk visits up to `MAX_DEPTH_NODES` repositories. Each one
    staying under its own ceiling says nothing about the total, and the
    total is what lands on the disk.
    """
    per_call = fetcher.MAX_TRANSFER_BYTES
    allowed = fetcher.MAX_TOTAL_TRANSFER_BYTES // per_call

    with pytest.raises(fetcher._TimeoutError):
        for _ in range(allowed + 2):
            callbacks = fetcher._DeadlineCallbacks(120)
            callbacks.transfer_progress(_Stats(per_call))


def test_the_run_budget_is_not_multiplied_by_the_depth_cap():
    """The two caps compose to a number, and that number is not 50 GiB."""
    from trustsight import depth

    naive = depth.MAX_DEPTH_NODES * fetcher.MAX_TRANSFER_BYTES
    assert fetcher.MAX_TOTAL_TRANSFER_BYTES < naive, (
        "the run budget does not constrain a full-depth walk at all"
    )
    assert fetcher.MAX_TOTAL_TRANSFER_BYTES <= 4 * 1024**3


def test_an_oversized_transfer_is_reported_as_an_incomplete_fetch():
    """Callers already handle `_TimeoutError`; this must not need a new path."""
    assert issubclass(fetcher._TransferTooLargeError, fetcher._TimeoutError)


def test_progress_is_charged_as_a_delta_not_a_running_total():
    """`received_bytes` is cumulative per transfer, so charging it whole
    would bill a single 10 MiB clone for the sum of its progress reports."""
    callbacks = fetcher._DeadlineCallbacks(120)
    for received in (1_000_000, 2_000_000, 3_000_000):
        callbacks.transfer_progress(_Stats(received))
    assert fetcher._transferred_bytes == 3_000_000


# ---------------------------------------------------------------------------
# CPU: history length is chosen by the package author.
# ---------------------------------------------------------------------------


class _Commit:
    def __init__(self, index):
        self.id = index
        self.parents = [index - 1] if index else []
        self.commit_time = 0


class _WalkRepo:
    """A repository whose history never ends."""

    def __init__(self):
        self.visited = 0

    def walk(self, _head, *_sort):
        index = 0
        while True:
            self.visited += 1
            yield _Commit(index)
            index += 1


def test_a_history_walk_terminates_on_an_endless_history():
    repo = _WalkRepo()
    commits = list(fetcher.walk_bounded(repo, "head"))
    assert len(commits) == fetcher.MAX_HISTORY_COMMITS
    assert repo.visited <= fetcher.MAX_HISTORY_COMMITS


def test_a_short_history_is_walked_whole():
    """The bound must not cost the ordinary case anything."""

    class _Short(_WalkRepo):
        def walk(self, _head, *_sort):
            for index in range(12):
                self.visited += 1
                yield _Commit(index)

    repo = _Short()
    assert len(list(fetcher.walk_bounded(repo, "head"))) == 12


def test_the_walk_yields_newest_first_so_the_bound_keeps_the_signal():
    """Everything reading a bounded walk wants recent commits.

    A burst inside 24h, and the most recent version bump, both live at the
    head. If the bound dropped the *newest* commits it would be silently
    changing answers rather than bounding work.
    """
    repo = _WalkRepo()
    commits = list(fetcher.walk_bounded(repo, "head", limit=3))
    assert [c.id for c in commits] == [0, 1, 2]


def test_every_history_walk_in_the_tree_goes_through_the_bounded_helper():
    """The recurring failure here is a control at one of several call sites.

    Three modules walked history and one of them bounded it. This asserts
    there is no fourth, rather than trusting that the sweep was complete.
    """
    import pathlib
    import re

    root = pathlib.Path(fetcher.__file__).parent
    offenders = []
    for path in sorted(root.rglob("*.py")):
        for lineno, line in enumerate(path.read_text().splitlines(), start=1):
            if re.search(r"\brepo\.walk\(", line) and "def walk_bounded" not in line:
                # The helper itself is the one legitimate raw call.
                if path.name == "fetcher.py":
                    continue
                offenders.append(f"{path.name}:{lineno} {line.strip()}")
    assert not offenders, "unbounded history walks: " + "; ".join(offenders)


# ---------------------------------------------------------------------------
# CPU: rule matching costs per line, and nothing counted the lines.
# ---------------------------------------------------------------------------


def _diff(line: str, count: int) -> str:
    return ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,1 +1,9 @@\n build() {\n"
            + "\n".join([line] * count) + "\n }\n")


def test_the_line_cap_clears_the_largest_real_diff_by_a_wide_margin():
    """A bound that truncates real packages is a bug, not a bound.

    The largest diff in the 3,739-diff locked benign corpus is 3,839 lines
    and p99.9 is 2,117, so the cap is set about five times above anything
    the corpus contains.
    """
    from trustsight.rules import MAX_SCANNED_LINES

    largest_observed = 3_839
    assert MAX_SCANNED_LINES >= largest_observed * 4


def test_a_diff_of_many_short_lines_is_bounded_work():
    """The byte cap is not a work bound: matching costs per line.

    5 MiB of four-byte lines is ~1.3 million lines at ~0.46 ms each, which
    is about ten minutes of CPU for one package - and `MAX_DEPTH_NODES`
    multiplies it by 200 on a full-depth walk.
    """
    from trustsight.analysis import scan_diff
    from trustsight.rules import MAX_SCANNED_LINES

    fact = scan_diff(_diff("+ x", MAX_SCANNED_LINES * 4), package_name="p")
    assert fact.scan_truncated is True


def test_an_ordinary_diff_is_not_flagged_as_truncated():
    from trustsight.analysis import scan_diff

    fact = scan_diff(_diff("+ echo hello", 200), package_name="p")
    assert fact.scan_truncated is False
    assert "scan_truncated" not in fact.coverage_gaps


def test_truncating_the_scan_is_visible_as_a_coverage_gap():
    """B2: a bound that drops content is never a silent skip."""
    from trustsight.analysis import scan_diff
    from trustsight.coverage import SCAN_TRUNCATED
    from trustsight.rules import MAX_SCANNED_LINES

    fact = scan_diff(_diff("+ x", MAX_SCANNED_LINES + 10), package_name="p")
    assert SCAN_TRUNCATED in fact.coverage_gaps


def test_the_scan_gap_is_distinct_from_the_byte_gap():
    """They point at different dials, so folding them together misleads.

    A reader who saw only `diff_truncated` would raise `max_diff_bytes` and
    find it changed nothing, because the line count was the binding cap.
    """
    from trustsight.coverage import DIFF_TRUNCATED, GAP_REASONS, SCAN_TRUNCATED

    assert SCAN_TRUNCATED != DIFF_TRUNCATED
    assert GAP_REASONS[SCAN_TRUNCATED] != GAP_REASONS[DIFF_TRUNCATED]


def test_both_analysis_entry_points_clamp_before_they_tokenize():
    """`analyze_package` and `scan_diff` are parallel implementations.

    They each tokenize and each match, and the byte cap that sits beside
    this one was originally written on the git path alone - which left
    every other caller with no ceiling at all. That is the failure this
    asserts against: a clamp in one of two equivalent paths.
    """
    import ast
    import pathlib

    import trustsight.analysis.pipeline as pipeline

    tree = ast.parse(pathlib.Path(pipeline.__file__).read_text())
    unclamped = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        calls = {
            n.func.id
            for n in ast.walk(node)
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
        }
        if "tokenize_and_resolve_indexed" in calls and "clamp_diff_lines" not in calls:
            unclamped.append(node.name)

    assert not unclamped, (
        f"these tokenize an unclamped diff: {unclamped}"
    )


# ---------------------------------------------------------------------------
# .SRCINFO: generated metadata in the ordinary case, authored in the one
# that matters. Read by scripts/generate_seed.py over a corpus checkout.
# ---------------------------------------------------------------------------


def test_srcinfo_parsing_is_linear_in_its_input():
    """The duplicate check was `value not in result[key]`, a list scan.

    Linear in the values already held, so a file repeating one key cost
    their square. Set membership makes it linear; this pins the shape by
    asserting the cost of 4x the input stays well under 4x quadratic.
    """
    import time

    from trustsight import srcinfo

    def cost(n):
        text = "\n".join(f"depends = pkg{i}" for i in range(n))
        start = time.perf_counter()
        srcinfo.parse_srcinfo(text)
        return time.perf_counter() - start

    small = cost(20_000)
    large = cost(80_000)
    # Quadratic would be ~16x. Allow generous slack for a noisy machine and
    # still fail the shape that matters.
    assert large < small * 8 + 0.5, (
        f"4x the input cost {large / max(small, 1e-6):.1f}x the time"
    )


def test_srcinfo_values_per_key_are_bounded():
    from trustsight import srcinfo

    text = "\n".join(
        f"depends = pkg{i}"
        for i in range(srcinfo.MAX_SRCINFO_VALUES_PER_KEY * 3)
    )
    parsed = srcinfo.parse_srcinfo(text)
    assert len(parsed["depends"]) == srcinfo.MAX_SRCINFO_VALUES_PER_KEY


def test_srcinfo_line_count_is_bounded():
    from trustsight import srcinfo

    text = "\n".join(
        f"key{i} = v" for i in range(srcinfo.MAX_SRCINFO_LINES + 5_000)
    )
    assert len(srcinfo.parse_srcinfo(text)) <= srcinfo.MAX_SRCINFO_LINES


def test_an_ordinary_srcinfo_parses_unchanged():
    """The bounds must cost the real case nothing."""
    from trustsight import srcinfo

    parsed = srcinfo.parse_srcinfo(
        "pkgbase = demo\n"
        "pkgver = 1.2.3\n"
        "depends = glibc\n"
        "depends = zlib\n"
        "# a comment\n"
        "source = https://example.invalid/demo-1.2.3.tar.gz\n"
    )
    assert parsed["pkgbase"] == ["demo"]
    assert parsed["depends"] == ["glibc", "zlib"]
    assert parsed["source"] == ["https://example.invalid/demo-1.2.3.tar.gz"]


def test_srcinfo_diff_does_not_cost_the_product_of_its_sides():
    """`added`/`removed` were each a list scan over the other side."""
    from trustsight import srcinfo

    old = {"depends": [f"pkg{i}" for i in range(4000)]}
    new = {"depends": [f"pkg{i}" for i in range(2000, 6000)]}
    changes = srcinfo.diff_srcinfo(old, new)
    assert len(changes["depends"]["added"]) == 2000
    assert len(changes["depends"]["removed"]) == 2000
