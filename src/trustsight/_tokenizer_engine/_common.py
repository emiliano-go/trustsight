"""Extracted from _tokenizer_engine.py: _common."""

import re
import threading

__all__ = ['_ARRAY_ASSIGNMENT_RE', '_ARRAY_ELEMENT_RE', '_ASSIGNMENT_RE', '_MAX_ARRAY_ENTRIES', '_MAX_EXPANSION_PASSES', '_MAX_LINE_LEN', '_MAX_TABLE_BYTES', '_MAX_VALUE_LEN', '_MEMO_ENTRIES', '_VAR_REF_RE', '_is_diff_header', '_join_logical', '_join_side', '_memo', '_memoised', '_split_top_level', '_tail_continues']

# The bounds live with the shared resolver so the analysis and the worker
# read one value; re-exported here for the engine's own imports.
from ..expansion import (  # noqa: E402
    _MAX_EXPANSION_PASSES,
    _MAX_LINE_LEN,
    _MAX_TABLE_BYTES,
    _MAX_VALUE_LEN,
)

_memo = threading.local()

_MEMO_ENTRIES = 2

def _memoised(kind: str, key: str, compute):
    """Return ``compute()`` for *key*, reusing a recent identical object."""
    store = getattr(_memo, kind, None)
    if store is None:
        store = _memo.__dict__.setdefault(kind, [])
    for cached_key, cached_value in store:
        if cached_key is key:
            # A copy: callers receive a plain list they may treat as their
            # own, and a shared one would turn any future in-place edit
            # into a bug in an unrelated rule.
            return list(cached_value)
    value = compute()
    store.append((key, value))
    del store[:-_MEMO_ENTRIES]
    return list(value)

def _tail_continues(stripped_tail: str) -> bool:
    """True when a logical line ending in *stripped_tail* promises more.

    Bash continues without a backslash when the line ends in a pipe or a
    conditional operator: `curl url |` + newline + `bash` is one
    pipeline.  The two joiners must agree, or the rule path and the
    coverage path read different text from the same diff.

    A pipe preceded by an **odd** run of backslashes is escaped and is an
    ordinary character, so it promises nothing.  An even run is a literal
    backslash followed by a real operator, which does continue - the
    `endswith("\\|")` spelling this used to test counted `\\\\|` as
    escaped and split a live pipeline.
    """
    if stripped_tail.endswith("&&"):
        return True
    if not stripped_tail.endswith("|"):
        return False
    return _unescaped_at(stripped_tail, len(stripped_tail) - 1)


def _unescaped_at(text: str, index: int) -> bool:
    """True when ``text[index]`` is not escaped by a backslash run."""
    run = 0
    cursor = index - 1
    while cursor >= 0 and text[cursor] == "\\":
        run += 1
        cursor -= 1
    return run % 2 == 0


def _backslash_continues(tail: str) -> bool:
    """True when *tail* ends in an unescaped backslash at the physical end.

    Two details bash cares about and the previous test did not.  A backslash
    with whitespace after it escapes that whitespace, so the newline is not
    escaped and the line does **not** continue; and a run of two backslashes
    is one literal backslash, not a continuation.  Only an odd run whose
    last character is the backslash continues the line.
    """
    run = 0
    for char in reversed(tail):
        if char != "\\":
            break
        run += 1
    return bool(run) and run % 2 == 1


def _is_diff_header(line: str) -> bool:
    return line.startswith(("diff --git ", "@@ ", "--- ", "+++ ")) or line in (
        "---",
        "+++",
    )


def _opens_comment(line: str, index: int) -> bool:
    return line[index] == "#" and (
        index == 0
        or line[index - 1].isspace()
        or line[index - 1] in ";|&("
    )


def _lexical_tail_is_data(line: str) -> bool:
    """True when the end of *line* is inside a quote, backtick or comment."""
    in_single = in_double = in_backtick = False
    i = 0
    while i < len(line):
        char = line[i]
        if in_single:
            if char == "'":
                in_single = False
            i += 1
            continue
        if in_backtick:
            if char == "\\" and i + 1 < len(line):
                i += 2
                continue
            if char == "`":
                in_backtick = False
            i += 1
            continue
        if in_double:
            if char == "\\" and i + 1 < len(line):
                i += 2
                continue
            if char == '"':
                in_double = False
            elif char == "`":
                in_backtick = True
            i += 1
            continue
        if char == "\\" and i + 1 < len(line):
            i += 2
            continue
        if char == "'":
            in_single = True
        elif char == '"':
            in_double = True
        elif char == "`":
            in_backtick = True
        elif char == "#" and _opens_comment(line, i):
            return True
        i += 1
    return in_single or in_double or in_backtick


def _continuation_kind(body: str, heredoc_body: bool) -> str:
    if heredoc_body or _lexical_tail_is_data(body):
        return ""
    if _backslash_continues(body):
        return "backslash"
    if _tail_continues(body.rstrip()):
        return "operator"
    return ""


def _join_logical(lines: list[str]) -> list[tuple[int, str]]:
    """Every logical line as ``(first_raw_index, marker + joined_text)``."""
    from ..line_lex import lex_lines

    lexed = lex_lines(lines)
    out: list[tuple[int, str]] = []
    parts: list[str] | None = None
    marker = ""
    start_index = -1
    for index, line in enumerate(lines):
        if _is_diff_header(line):
            if parts is not None:
                out.append((start_index, marker + "".join(parts)))
                parts, marker, start_index = None, "", -1
            out.append((index, line))
            continue
        this_marker = line[0] if line[:1] in ("+", "-") else ""
        body = line[1:] if this_marker else line
        if parts is not None and this_marker == marker:
            parts.append(body)
        else:
            if parts is not None:
                out.append((start_index, marker + "".join(parts)))
            parts, marker, start_index = [body], this_marker, index
        kind = _continuation_kind(body, lexed[index].heredoc_body)
        if kind == "backslash":
            parts[-1] = parts[-1][:-1]
        elif kind == "operator":
            pass
        else:
            out.append((start_index, marker + "".join(parts)))
            parts, marker, start_index = None, "", -1
    if parts is not None:
        out.append((start_index, marker + "".join(parts)))
    return out


def _join_side(
    lines: list[str], marker: str
) -> list[tuple[int, str, object, object]]:
    """Logical lines for one diff side, including unchanged context.

    A context line is shared by both sides: a context line ending in a
    continuation is completed by the following added line on the new side
    (and by the following removed line on the old side).  Opposite markers
    still form a hard boundary.
    """
    from ..line_lex import lex_lines

    lexed = lex_lines(lines)
    out: list[tuple[int, str, object, object]] = []
    parts: list[str] | None = None
    first_side_index = -1
    first_state = None
    end_state = None
    for index, line in enumerate(lines):
        if _is_diff_header(line):
            if parts is not None:
                out.append((first_side_index, "".join(parts), first_state, end_state))
                parts, first_side_index, first_state = None, -1, None
            continue
        this_marker = line[0] if line[:1] in ("+", "-") else ""
        if this_marker and this_marker != marker:
            if parts is not None:
                out.append((first_side_index, "".join(parts), first_state, end_state))
                parts, first_side_index, first_state = None, -1, None
            continue
        body = line[1:] if this_marker else line
        if parts is not None:
            parts.append(body)
        else:
            parts = [body]
        if this_marker == marker and first_side_index < 0:
            first_side_index = index
            first_state = lexed[index].quote_before
        end_state = lexed[index].quote_after
        kind = _continuation_kind(body, lexed[index].heredoc_body)
        if kind == "backslash":
            parts[-1] = parts[-1][:-1]
        elif kind == "operator":
            pass
        else:
            if first_side_index >= 0:
                out.append((first_side_index, "".join(parts), first_state, end_state))
            parts, first_side_index, first_state = None, -1, None
    if parts is not None and first_side_index >= 0:
        out.append((first_side_index, "".join(parts), first_state, end_state))
    return out

_DECLARATION_OPTIONS = r"(?P<opts>(?:(?:--?|\+\+?)[A-Za-z]+\s+){0,4})"

_ASSIGNMENT_RE = re.compile(
    r"^\s*(?:(?:local|export|declare|readonly|typeset)\s+"
    + _DECLARATION_OPTIONS
    + r")?(?P<name>\w+)\s*(?P<op>\+?=)\s*(?P<value>.*)"
)

_ARRAY_ASSIGNMENT_RE = re.compile(
    r"^\s*(?:(?:local|export|declare|readonly|typeset)\s+"
    + _DECLARATION_OPTIONS
    + r")?(?P<name>\w+)\s*(?P<op>\+?=)\s*\((?P<value>.*)"
)

_ARRAY_ELEMENT_RE = re.compile(
    r"^\s*(?:(?:local|export|declare|readonly|typeset)\s+"
    + _DECLARATION_OPTIONS
    + r")?(?P<name>\w+)\[(?P<index>[^\]]{0,40})\]\s*"
    r"(?P<op>\+?=)\s*(?P<value>.*)"
)


def _declaration_options(match: re.Match) -> str:
    return match.group("opts") or ""

_VAR_REF_RE = re.compile(r"\$\{(\w+)\}(?!\[)|\$(\w+)")

def _split_top_level(body: str) -> list[str]:
    """*body* split on command separators, respecting quotes.

    Reuses the crossfire splitter rather than growing a second one here.
    Imported lazily: :mod:`analysis.crossfire` imports this module's
    public tokenizer at module level, so a top-level import would close
    the loop.
    """
    from ..analysis.crossfire import _split_commands
    return _split_commands(body)

#: An array may contribute at most this many entries to the table.  Without
#: it, one 5 MiB line of tiny words builds a multi-million-element list
#: before the table-size check is ever reached.
_MAX_ARRAY_ENTRIES = 4096
