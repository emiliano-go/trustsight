"""Tests for the corpus replay ordering used to build baselines.

Novelty is order-dependent: "first seen" carries no meaning if diffs are
replayed in an arbitrary sequence.  The manifest records each diff as an
``old_sha -> new_sha`` pair, so true commit order can be recovered from
it without consulting the repository.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from rebaseline import _build_chain_index, _order_by_chain  # noqa: E402


def _entry(pkg, old, new):
    return {"pkg": pkg, "stratum": "s", "old_sha": old * 40, "new_sha": new * 40}


def test_chain_index_recovers_commit_order():
    # c -> d -> e, deliberately supplied out of order
    entries = [
        _entry("pkg", "d", "e"),
        _entry("pkg", "c", "d"),
    ]
    index = _build_chain_index(entries)
    assert index["pkg"] == [
        f"pkg__{'c' * 12}..{'d' * 12}",
        f"pkg__{'d' * 12}..{'e' * 12}",
    ]


def test_chain_index_skips_branched_history():
    """Two independent starts mean the chain is ambiguous."""
    entries = [_entry("pkg", "a", "b"), _entry("pkg", "c", "d")]
    assert "pkg" not in _build_chain_index(entries)


def test_chain_index_skips_incomplete_history():
    """A gap leaves entries unreachable from the single start."""
    entries = [
        _entry("pkg", "a", "b"),
        _entry("pkg", "b", "c"),
        _entry("pkg", "x", "y"),
    ]
    assert "pkg" not in _build_chain_index(entries)


def test_chain_index_handles_multiple_packages():
    entries = [_entry("one", "a", "b"), _entry("two", "m", "n")]
    index = _build_chain_index(entries)
    assert set(index) == {"one", "two"}


def test_order_by_chain_sorts_by_commit_order():
    stems = ["p__bbb..ccc", "p__aaa..bbb"]  # chain says bbb..ccc comes first
    files = [Path("p__aaa..bbb.diff"), Path("p__bbb..ccc.diff")]
    ordered, used = _order_by_chain(files, stems)
    assert used is True
    assert [p.stem for p in ordered] == stems


def test_order_by_chain_falls_back_without_a_chain():
    files = [Path("p__bbb..ccc.diff"), Path("p__aaa..bbb.diff")]
    ordered, used = _order_by_chain(files, [])
    assert used is False
    assert [p.stem for p in ordered] == ["p__aaa..bbb", "p__bbb..ccc"]


def test_order_by_chain_falls_back_on_unknown_file():
    """A diff missing from the manifest makes the chain untrustworthy."""
    files = [Path("p__aaa..bbb.diff"), Path("p__zzz..yyy.diff")]
    ordered, used = _order_by_chain(files, ["p__aaa..bbb"])
    assert used is False
    assert len(ordered) == 2
