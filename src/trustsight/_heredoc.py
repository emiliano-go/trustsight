"""One quote-aware heredoc opener parser, shared by both readers.

The sandboxed tokenizer engine and the typed core each carried their own
single-opener scan.  They disagreed about quoted delimiters, backslash
delimiters and - because both kept only the first opener on a line - the
order of multiple bodies, which bash reads in the order the openers appear.

This leaf has no imports, so the tokenizer worker can load it too.  It only
parses the word after ``<<``; deciding whether the ``<<`` is inside a quote
or a comment, and whether a body is data or an executed script, stays with
the caller that already tracks that state.
"""

from __future__ import annotations

__all__ = ["parse_opener"]


def _name_start(char: str) -> bool:
    return char.isascii() and (char.isalpha() or char == "_")


def _name_char(char: str) -> bool:
    return char.isascii() and (char.isalnum() or char == "_")


def parse_opener(line: str, index: int) -> tuple[str, bool, int] | None:
    """Parse a heredoc opener starting at ``line[index] == '<'``.

    Returns ``(delimiter, strip_tabs, end)``, or ``None`` when this ``<<``
    is not an opener.  A here-string (``<<<``) and an arithmetic shift
    (``1 << 2``) open nothing: the word after ``<<`` must be a shell
    delimiter, quoted or unquoted.  A quoted delimiter may hold any text up
    to its closing quote; an unquoted one is an identifier, optionally
    backslash-quoted (``<<\\EOF``).
    """
    if not line.startswith("<<", index):
        return None
    end = index + 2
    if end < len(line) and line[end] == "<":
        # <<< is a here-string and has no body.
        return None
    strip_tabs = False
    if end < len(line) and line[end] == "-":
        strip_tabs = True
        end += 1
    while end < len(line) and line[end] in " \t":
        end += 1
    if end >= len(line):
        return None
    char = line[end]
    if char in "'\"":
        close = line.find(char, end + 1)
        if close == -1:
            return None
        delimiter = line[end + 1 : close]
        return (delimiter, strip_tabs, close + 1) if delimiter else None
    if char == "\\":
        start = end + 1
        if start >= len(line) or not _name_start(line[start]):
            return None
        end = start + 1
        while end < len(line) and _name_char(line[end]):
            end += 1
        return line[start:end], strip_tabs, end
    if not _name_start(char):
        return None
    start = end
    end += 1
    while end < len(line) and _name_char(line[end]):
        end += 1
    return line[start:end], strip_tabs, end
