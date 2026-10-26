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


def _inside_arithmetic(line: str, index: int) -> bool:
    before = line[:index]
    return before.count("$((") > before.count("))") or (
        before.count("((") > before.count("))")
    )


def _delimiter_word(line: str, start: int) -> tuple[str, int] | None:
    out: list[str] = []
    quote = ""
    index = start
    while index < len(line):
        char = line[index]
        if quote:
            if char == "\\" and quote == '"' and index + 1 < len(line):
                out.append(line[index + 1])
                index += 2
                continue
            if char == quote:
                quote = ""
                index += 1
                continue
            out.append(char)
            index += 1
            continue
        if char in "'\"":
            quote = char
            index += 1
            continue
        if char == "\\" and index + 1 < len(line):
            out.append(line[index + 1])
            index += 2
            continue
        if char in " \t;|&<>()":
            break
        out.append(char)
        index += 1
    if quote or not out:
        return None
    return "".join(out), index


def parse_opener(line: str, index: int) -> tuple[str, bool, int] | None:
    """Parse a heredoc opener starting at ``line[index] == '<'``.

    Returns ``(delimiter, strip_tabs, end)``, or ``None`` when this ``<<``
    is not an opener.  A here-string (``<<<``) and an arithmetic shift
    (``1 << 2``) open nothing.
    """
    if not line.startswith("<<", index):
        return None
    end = index + 2
    if end < len(line) and line[end] == "<":
        return None
    strip_tabs = False
    if end < len(line) and line[end] == "-":
        strip_tabs = True
        end += 1
    while end < len(line) and line[end] in " \t":
        end += 1
    if end >= len(line) or _inside_arithmetic(line, index):
        return None
    word = _delimiter_word(line, end)
    if word is None:
        return None
    delimiter, close = word
    return delimiter, strip_tabs, close
