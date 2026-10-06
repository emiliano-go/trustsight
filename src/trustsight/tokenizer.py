"""Tokenizer facade: the tokenizer runs in a sandboxed child process.

The tokenizer is the second parser eating package-controlled input (A6),
and the one with an amplification property the regex engine does not have:
a chain of ``b=$a$a`` assignments doubles per level.  The whole module now
runs in a separate process with no inherited descriptors and a hard memory
ceiling (see ``trustsight.sandbox``), so a defect in an expansion bound has
a subprocess to spend rather than the analysis process and the database,
config and filesystem permissions it holds.

This module holds no parsing code.  It delegates every call to
``trustsight.sandbox.client`` and is the only entry point the analysis
uses; ``trustsight._tokenizer_engine`` is imported by the child alone.  A
child that cannot answer raises
:class:`~trustsight.sandbox.client.TokenizerUnavailable`, which the caller
reports as a package that was NOT vetted rather than analysed with the
parser missing.

The function names are unchanged, so call sites did not move; only the
implementation behind them did.
"""

import threading

from .sandbox.client import TokenizerUnavailable, request

__all__ = [
    "TokenizerUnavailable",
    "clean_lines",
    "join_line_continuations",
    "joined_indexed",
    "reconstruct_lines",
    "reconstruct_literals",
    "resolve_added_lines",
    "split_lines",
    "strip_boms",
    "tokenize_and_resolve",
    "tokenize_and_resolve_indexed",
    "variable_table",
]


_line_memo = threading.local()
_LINE_MEMO_ENTRIES = 4


def split_lines(text: str) -> list[str]:
    """Split on shell line terminators only, in the sandbox.

    Memoised per thread on the text's identity: dozens of readers ask for
    the same diff's lines, and every call is a child round-trip.  A fresh
    list is returned, because callers are entitled to treat it as their
    own; the key is kept alive so its id cannot be reused underneath the
    memo.
    """
    store = getattr(_line_memo, "entries", None)
    if store is None:
        store = _line_memo.__dict__.setdefault("entries", [])
    for key, value in store:
        if key is text:
            return list(value)
    lines = request("lines", text)
    store.append((text, lines))
    del store[:-_LINE_MEMO_ENTRIES]
    return list(lines)


def join_line_continuations(lines: list[str]) -> list[str]:
    """Join backslash-continued logical lines, in the sandbox."""
    return request("join", lines)


def joined_indexed(lines: list[str]) -> list[tuple[int, str]]:
    """Like :func:`join_line_continuations`, each logical line paired with
    the index of the first raw line that produced it."""
    return [tuple(pair) for pair in request("joined_indexed", lines)]


def clean_lines(lines: list[str]) -> list[str]:
    """Strip a leading BOM and collapse path traversal, per line."""
    return request("clean_lines", lines)


def strip_boms(lines: list[str]) -> list[str]:
    """Strip a leading byte-order mark, per line."""
    return request("strip_boms", lines)


def reconstruct_literals(text: str) -> tuple[str, bool]:
    """Reconstruct obfuscated literals as data; returns (text, fully)."""
    return tuple(request("reconstruct_literals", text))


def reconstruct_lines(lines: list[str]) -> list[tuple[str, bool]]:
    """Reconstruct each of *lines*; one round-trip instead of one per line.

    H065 walks every added line, and routing that per line would be one
    child round-trip per line, which is the cost the sandbox exists to
    avoid paying on ordinary text.
    """
    return [tuple(pair) for pair in request("reconstruct_lines", lines)]


def resolve_added_lines(diff_text: str) -> list[str]:
    """Diff lines with each added line replaced by its resolved form."""
    return request("resolve_added", diff_text)


def tokenize_and_resolve_indexed(
    diff_text: str,
) -> tuple[list[str], list[str], list[int]]:
    """Resolve added lines and map each back to its raw diff-line index."""
    resolved, unresolved, indices = request("indexed", diff_text)
    return resolved, unresolved, indices


def tokenize_and_resolve(diff_text: str) -> tuple[list[str], list[str]]:
    """Resolve added lines, returning (resolved, unresolved)."""
    resolved, unresolved, _indices = request("indexed", diff_text)
    return resolved, unresolved


def variable_table(
    additions: list[str],
) -> tuple[dict[str, str], dict[str, list[str]]]:
    """Resolve assignments among added lines into scalar and array tables."""
    variables, arrays = request("variable_table", additions)
    return variables, arrays


def variable_table_spans(
    additions: list[str],
) -> tuple[dict[str, str], dict[str, list[str]], dict]:
    """The variable tables plus each value's source line index.

    The tables are exactly what :func:`variable_table` returns; ``spans``
    maps scalar names to their assignment line and array names to their
    opener, closer and per-entry lines, indexed into *additions*.
    """
    variables, arrays, spans = request("variable_table_spans", additions)
    return variables, arrays, spans
