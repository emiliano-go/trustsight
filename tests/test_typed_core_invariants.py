"""Invariants over the typed core's transition, provenance and scope surfaces.

The migration parity runner measures exact deltas against a baseline;
these assert the properties that must hold for any input, on a
deterministic fuzz set and on a slice of the locked corpus.  A future
change that breaks the array delta partition, the alignment
reconstruction, the scanner's shape or a span's bounds fails here without
needing a baseline file.
"""

import random
from collections import Counter
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
CORPUS = ROOT / "tests" / "fixtures" / "benign-corpus"


def _words(rng: random.Random, count: int | None = None) -> list[str]:
    size = rng.randint(0, 6) if count is None else count
    return [rng.choice("abcd") for _ in range(size)]


def test_array_diff_is_a_multiset_partition():
    from trustsight.recipedoc import array_diff

    rng = random.Random(0x5459)
    for _ in range(250):
        old, new = _words(rng), _words(rng)
        delta = array_diff(old, new)
        assert Counter(delta.gained) == Counter(new) - Counter(old)
        assert Counter(delta.lost) == Counter(old) - Counter(new)
        assert set(delta.gained).isdisjoint(set(delta.lost))


def test_array_alignment_reconstructs_both_sides():
    from trustsight.recipedoc import array_alignment

    rng = random.Random(0xA116)
    for _ in range(250):
        old, new = _words(rng), _words(rng)
        alignment = array_alignment(old, new)
        old_rebuilt: list[str | None] = [None] * len(old)
        for i, j, value in alignment.pairs:
            assert old[i] == new[j] == value
            old_rebuilt[i] = value
        for i, value in alignment.deleted:
            assert old[i] == value
            old_rebuilt[i] = value
        assert all(value is not None for value in old_rebuilt)

        new_rebuilt: list[str | None] = [None] * len(new)
        for _i, j, value in alignment.pairs:
            new_rebuilt[j] = value
        for j, value in alignment.inserted:
            assert new[j] == value
            new_rebuilt[j] = value
        assert all(value is not None for value in new_rebuilt)


def test_line_lex_keeps_its_shape():
    from trustsight.line_lex import lex_lines

    rng = random.Random(0x11E7)
    alphabet = "abc{}#'\"\\`$()<>= "
    for _ in range(300):
        lines = [
            "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 12)))
            for _ in range(rng.randint(0, 5))
        ]
        for lex in lex_lines(lines):
            assert len(lex.code) == len(lex.text)
            assert lex.brace_delta == lex.code.count("{") - lex.code.count("}")
            assert lex.opens_brace == ("{" in lex.code)
            assert lex.closes_line == lex.code.rstrip().endswith("}")


@pytest.mark.skipif(not CORPUS.exists(), reason="the corpus is not built")
def test_corpus_slice_keeps_span_and_scope_bounds():
    from trustsight.diffdoc import parse_diff
    from trustsight.recipedoc import recipe_states
    from trustsight.rules import (
        _classify_line_context,
        _enclosing_function_map,
        get_raw_diff_lines_indexed,
    )

    for path in sorted(CORPUS.rglob("*.diff"))[:25]:
        text = path.read_text(errors="replace")
        doc = parse_diff(text)
        pre, post = recipe_states(doc)
        for recipe in (pre, post):
            for name, entries in recipe.arrays.items():
                assert len(recipe.array_spans.get(name, ())) == len(entries)
            for span in recipe.scalar_spans.values():
                assert span.line >= 0
            for span in recipe.function_spans.values():
                assert span.line >= 0

        raw, _indices = get_raw_diff_lines_indexed(text)
        contexts = _classify_line_context(raw)
        enclosing = _enclosing_function_map(raw)
        assert all(0 <= index < len(raw) for index in contexts)
        assert all(0 <= index < len(raw) for index in enclosing)
