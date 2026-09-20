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


def split_lines(text: str) -> list[str]:
    """Split on shell line terminators only, in the sandbox."""
    return request("lines", text)


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
