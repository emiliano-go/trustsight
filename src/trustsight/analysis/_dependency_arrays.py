"""Quote-aware tracking of dependency-array value lines.

A dependency entry is data, never a command word.  A hunk can add entries to
an array whose opener sits outside the hunk, so the whole recipe is walked
when it is available.  Parentheses are counted outside quotes because an
optdepends description may contain a paren that closes nothing.
"""

from __future__ import annotations

import re

__all__ = ["dependency_array_indices"]

_DEP_ARRAY_OPEN_RE = re.compile(
    r"^\s*(?:depends|makedepends|optdepends|checkdepends)"
    r"(?:_[a-z0-9_]+)?\s*\+?=\s*\("
)


def _unquoted_paren_delta(text: str) -> int:
    depth = 0
    quote = None
    for ch in text:
        if quote:
            if ch == quote:
                quote = None
        elif ch in "'\"":
            quote = ch
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
    return depth


def dependency_array_indices(lines: list[str]) -> set[int]:
    """Indices inside a dependency array's value."""
    from ..deps import _strip_comment

    out: set[int] = set()
    depth = 0
    for index, line in enumerate(lines):
        if line.startswith("-"):
            continue
        body = _strip_comment(line[1:] if line[:1] in "+ " else line)
        if depth > 0 or _DEP_ARRAY_OPEN_RE.match(body):
            out.add(index)
            depth = max(0, depth + _unquoted_paren_delta(body))
    return out
