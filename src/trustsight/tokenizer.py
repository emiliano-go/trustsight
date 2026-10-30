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
from collections import OrderedDict

from .sandbox.client import TokenizerUnavailable, request

__all__ = [
    "TokenizerUnavailable",
    "clean_lines",
    "join_line_continuations",
    "joined_indexed",
    "reconstruct_lines",
    "reconstruct_lines_stateful",
    "reconstruct_literals",
    "resolve_added_lines",
    "resolve_removed_lines",
    "split_lines",
    "strip_boms",
    "tokenize_and_resolve",
    "tokenize_and_resolve_indexed",
    "variable_table",
]


_line_memo = threading.local()
_LINE_MEMO_ENTRIES = 8


def _copy_value(value):
    """A caller-owned copy of a cached tokenizer result.

    Strings are immutable, so only the containers are rebuilt.  This is
    cheaper than the sandbox client's recursive ``_copy`` on a cache hit, and
    keeps the parent memo authoritative for repeated identical inputs.
    """
    if isinstance(value, dict):
        return {key: _copy_value(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_copy_value(item) for item in value]
    if isinstance(value, tuple):
        return tuple(_copy_value(item) for item in value)
    return value


def _memo(kind: str, key, compute):
    """Memoise *compute* by an immutable key, per thread.

    The tokenizer client already caches by content, but every hit still
    rebuilds a request and deep-copies the result.  Several stages ask for
    the same diff tens of times (``resolve_added_lines`` 22x/diff on the
    calibration corpus), so a small parent-side cache removes that overhead
    without changing what the child computes.
    """
    store = getattr(_line_memo, kind, None)
    if store is None:
        store = _line_memo.__dict__.setdefault(kind, OrderedDict())
    cached = store.get(key)
    if cached is not None:
        store.move_to_end(key)
        return _copy_value(cached)
    value = compute()
    store[key] = _copy_value(value)
    while len(store) > _LINE_MEMO_ENTRIES:
        store.popitem(last=False)
    return value


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
    return _memo("join", ("l", tuple(lines)),
                 lambda: request("join", lines))


def joined_indexed(lines: list[str]) -> list[tuple[int, str]]:
    """Like :func:`join_line_continuations`, each logical line paired with
    the index of the first raw line that produced it."""
    return _memo(
        "joined_indexed", ("l", tuple(lines)),
        lambda: [tuple(pair) for pair in request("joined_indexed", lines)],
    )


def clean_lines(lines: list[str]) -> list[str]:
    """Strip a leading BOM and collapse path traversal, per line."""
    return _memo("clean_lines", ("l", tuple(lines)),
                 lambda: request("clean_lines", lines))


def strip_boms(lines: list[str]) -> list[str]:
    """Strip a leading byte-order mark, per line."""
    return _memo("strip_boms", ("l", tuple(lines)),
                 lambda: request("strip_boms", lines))


def reconstruct_literals(text: str) -> tuple[str, bool]:
    """Reconstruct obfuscated literals as data; returns (text, fully)."""
    return _memo("reconstruct_literals", ("s", text),
                 lambda: tuple(request("reconstruct_literals", text)))


def reconstruct_lines_stateful(
    lines: list[str],
) -> list[tuple[str, bool, bool]]:
    """Reconstruct *lines* in sequence, carrying quote state across them.

    Returns ``(rebuilt, fully, quoted_data)`` per line.  ``quoted_data`` says
    the line is entirely inside a multi-line quote and should not be read as
    a command.
    """
    return _memo(
        "reconstruct_stateful", ("l", tuple(lines)),
        lambda: [tuple(item)
                 for item in request("reconstruct_lines_stateful", lines)],
    )


def reconstruct_lines(lines: list[str]) -> list[tuple[str, bool]]:
    """Reconstruct each of *lines*; one round-trip instead of one per line.

    H065 walks every added line, and routing that per line would be one
    child round-trip per line, which is the cost the sandbox exists to
    avoid paying on ordinary text.
    """
    return _memo(
        "reconstruct_lines", ("l", tuple(lines)),
        lambda: [tuple(pair) for pair in request("reconstruct_lines", lines)],
    )


def resolve_added_lines(diff_text: str) -> list[str]:
    """Diff lines with each added line replaced by its resolved form."""
    return _memo("resolve_added", ("s", diff_text),
                 lambda: request("resolve_added", diff_text))


def resolve_removed_lines(diff_text: str) -> list[str]:
    """Diff lines with each removed line replaced by its resolved form."""
    return _memo("resolve_removed", ("s", diff_text),
                 lambda: request("resolve_removed", diff_text))


def tokenize_and_resolve_indexed(
    diff_text: str,
) -> tuple[list[str], list[str], list[int]]:
    """Resolve added lines and map each back to its raw diff-line index."""
    return _memo(
        "indexed", ("s", diff_text),
        lambda: tuple(request("indexed", diff_text)),
    )


def tokenize_and_resolve(diff_text: str) -> tuple[list[str], list[str]]:
    """Resolve added lines, returning (resolved, unresolved)."""
    resolved, unresolved, _indices = tokenize_and_resolve_indexed(diff_text)
    return resolved, unresolved


def variable_table(
    additions: list[str],
) -> tuple[dict[str, str], dict[str, list[str]]]:
    """Resolve assignments among added lines into scalar and array tables."""
    return _memo(
        "variable_table", ("l", tuple(additions)),
        lambda: tuple(request("variable_table", additions)),
    )


def variable_table_spans(
    additions: list[str],
) -> tuple[dict[str, str], dict[str, list[str]], dict]:
    """The variable tables plus each value's source line index.

    The tables are exactly what :func:`variable_table` returns; ``spans``
    maps scalar names to their assignment line and array names to their
    opener, closer and per-entry lines, indexed into *additions*.
    """
    return _memo(
        "variable_table_spans", ("l", tuple(additions)),
        lambda: tuple(request("variable_table_spans", additions)),
    )
