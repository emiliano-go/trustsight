"""Contract tests for the implicit machines that are not persisted.

These pin the shape of the lexer/diff/backfill state, not their current
outputs. The locked-corpus parity suites prove equivalence on known inputs;
these assert the invariants that must hold on arbitrary ones.
"""

from __future__ import annotations

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from trustsight.diffdoc import parse_diff_lines
from trustsight.line_lex import (
    _MAX_TOKENIZER_LINE,
    QuoteState,
    advance_quote_state,
    lex_lines,
)

_SETTINGS = settings(
    max_examples=200,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large],
)

# Deliberately excludes `<` (heredoc openers change how later lines are
# classified) and newlines (they are line boundaries, not line text).
_SHELL_TEXT = st.text(
    alphabet="abc ' \" $ ( ) ` # \\ ; { } 0",
    max_size=60,
)

_ALLOWED_FRAMES = frozenset({"'", '"', "ansi", "`", "$("})


@_SETTINGS
@given(_SHELL_TEXT)
def test_quote_state_is_well_formed(line: str) -> None:
    lexed = lex_lines([line])[0]
    assert all(frame in _ALLOWED_FRAMES for frame in lexed.quote_after.frames)
    assert lexed.quote_after == advance_quote_state(line, lexed.quote_before)


@_SETTINGS
@given(st.lists(_SHELL_TEXT, max_size=6))
def test_quote_state_carries_across_lines(lines: list[str]) -> None:
    state = QuoteState()
    for line, lexed in zip(lines, lex_lines(lines)):
        assert lexed.quote_before == state
        state = advance_quote_state(line, state)
        assert lexed.quote_after == state


def test_a_truncated_line_resets_quote_state() -> None:
    line = "x" * (_MAX_TOKENIZER_LINE + 5) + "'"
    lexed = lex_lines([line])[0]
    assert lexed.truncated
    assert not lexed.quote_after.open


def test_heredoc_openers_are_a_fifo_queue() -> None:
    lines = ["cat <<A <<B", "a-body", "A", "b-body", "B", "after"]
    lexed = lex_lines(lines)
    assert lexed[0].heredoc_openers == (("A", False), ("B", False))
    assert [item.heredoc_body for item in lexed] == [
        False, True, True, True, True, False,
    ]


@_SETTINGS
@given(st.lists(_SHELL_TEXT, max_size=40))
def test_diffdoc_classifies_every_input_line(lines: list[str]) -> None:
    doc = parse_diff_lines(lines)
    assert len(doc.lines) == len(lines)
    assert [item.index for item in doc.lines] == list(range(len(lines)))
    assert all(
        item.side in {"add", "remove", "context", "other"}
        for item in doc.lines
    )
    assert all(item.raw == lines[item.index] for item in doc.lines)


def test_backfill_skips_empty_days_and_stops_on_a_change() -> None:
    from trustsight.full_aur._baseline_build import _backfill_day

    day = 86_400
    meta = {"changed": {"LastModified": 2 * day + 5}}
    start, end, names = _backfill_day(0, 3 * day, meta, day)
    assert (start, end) == (2 * day, 3 * day)
    assert names == ["changed"]


def test_backfill_stops_at_a_future_boundary() -> None:
    from trustsight.full_aur._baseline_build import _backfill_day

    start, end, names = _backfill_day(0, 100, {}, 86_400)
    assert (start, end, names) == (0, 86_400, [])


def test_backfill_selection_is_deterministic() -> None:
    from trustsight.full_aur._baseline_build import _backfill_day

    meta = {f"p{i}": {"LastModified": i * 10} for i in range(5)}
    assert _backfill_day(0, 10_000, meta, 100) == _backfill_day(
        0, 10_000, meta, 100)
