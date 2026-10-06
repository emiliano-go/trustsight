"""A bounded lexical scan of PKGBUILD-like lines.

Both the typed recipe's function-body reader and the rule engine's scope
classifier count braces, and both counted them on the raw line.  That got
``echo "}"`` wrong in one reader and ``# }`` wrong in the other.  This
module is the one place that decides which text is code, so the two
readers can no longer disagree.

It is a lexical scan, not a shell parser: it resolves nothing, follows no
command substitution, and blanks only what shell would not execute as
written.  ``$(...)`` and backticks inside double quotes stay code because
they execute; a heredoc body does not, and neither does a comment.
"""

import re
from dataclasses import dataclass
from functools import lru_cache

_HEREDOC_SHAPE_RE = re.compile(r"<<-?\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1")


@dataclass(frozen=True)
class LexedLine:
    """One line with the lexical facts both brace counters need.

    ``code`` is the line with quoted data, comments and heredoc bodies
    blanked (positions preserved).  ``brace_delta`` counts only braces in
    ``code``; ``closes_line`` says the code's last non-space character is
    an unquoted ``}``, the shape the scope classifier balances on.
    """

    text: str
    code: str
    brace_delta: int
    opens_brace: bool
    closes_line: bool
    heredoc_body: bool


def _diff_boundary(line: str) -> bool:
    """True for an outer-diff file or hunk header (never prefixed data)."""
    return line.startswith(("diff --git ", "@@ ", "--- ", "+++ ")) or line in (
        "---", "+++",
    )


def _opens_a_comment(line: str, index: int) -> bool:
    """True when ``line[index]`` is an unquoted ``#`` that starts a comment.

    The rule ``_scan`` already applies, exposed so the URL reader and the
    brace counter cannot disagree: a ``#`` opens a comment at the start of a
    line, after whitespace or ``;|&(``, or right after a diff's ``+``/``-``
    prefix.  Everything else - a ``#`` inside quotes, in a URL fragment
    (``x#sha256=``) or in ``${var#…}`` - is data.
    """
    return line[index] == "#" and (
        index == 0
        or line[index - 1].isspace()
        or line[index - 1] in ";|&("
        or (index == 1 and line[0] in "+-")
    )


def strip_comment_stateful(line: str, quote: str = "") -> tuple[str, str]:
    """Like :func:`strip_comment`, carrying quote state across lines.

    Returns ``(code, open_quote)``.  A line inside a multi-line quoted
    string is data even when it begins with ``#``, which a per-line scan
    cannot see; the URL reader passes the returned state into the next
    line.  The state is the same one :func:`lex_lines` tracks, so the two
    readers cannot disagree about what is quoted.
    """
    # Fast path for the common line: no quote open, no quote, no comment.
    # The character loop below is O(len) in Python, and a pathological
    # multi-megabyte line pays it in every reader; the C-speed scans make
    # the no-op case free.
    if not quote and "#" not in line and "'" not in line and '"' not in line:
        return line, quote
    index = 0
    while index < len(line):
        ch = line[index]
        if quote:
            if ch == "\\" and quote == '"':
                index += 2
                continue
            if ch == quote:
                quote = ""
        elif ch in "'\"":
            quote = ch
        elif _opens_a_comment(line, index):
            return line[:index], quote
        index += 1
    return line, quote


def strip_comment(line: str) -> str:
    """Return *line* up to an unquoted ``#`` comment, quotes preserved.

    Unlike :func:`lex_lines`, quoted data is kept: a URL reader needs the
    URL in ``source=("…")``, which lives inside quotes.  Only the trailing
    comment is dropped, using the same boundary :func:`_scan` recognises.
    """
    return strip_comment_stateful(line)[0]


def lex_lines(lines: list[str], fragment: bool = False) -> list[LexedLine]:
    """Lex *lines* in order; heredoc state spans lines either way.

    ``fragment=True`` says this is a partial diff: quote state resets each
    line and a heredoc ends at a diff file or hunk header.  A fragment can
    hold an unterminated quote or heredoc whose closer is outside the hunk,
    and letting either span lines blanks the rest of the file; the
    whole-file recipe read (the default) keeps the state, because a quoted
    string or heredoc there really does continue.  The result is memoised
    on the contents: several consumers lex the same lines, and a fresh
    list is returned so callers may treat it as their own.
    """
    return list(_lex_lines_cached(tuple(lines), fragment))


@lru_cache(maxsize=16)
def _lex_lines_cached(
    lines: tuple[str, ...], fragment: bool
) -> tuple[LexedLine, ...]:
    """The lexical scan, reused across readers of the same lines."""
    out: list[LexedLine] = []
    in_single = in_double = in_backtick = False
    sub_depth = 0
    heredoc: str | None = None
    heredoc_tabs = False
    for line in lines:
        if fragment:
            in_single = in_double = in_backtick = False
            sub_depth = 0
            if heredoc is not None and _diff_boundary(line):
                heredoc = None
        if heredoc is not None:
            probe = line.lstrip("\t") if heredoc_tabs else line
            # A diff line keeps its +/- prefix, which is not part of the
            # shell text: ``+EOF`` terminates the heredoc ``EOF``.
            probe = probe.lstrip("+-")
            blank = " " * len(line)
            if probe.strip() == heredoc:
                heredoc = None
            out.append(LexedLine(line, blank, 0, False, False, True))
            continue
        # Fast path for the ordinary line: nothing that could change the
        # lexical state, so the character loop is skipped.  A pathological
        # multi-megabyte line otherwise pays that loop in every scope
        # classifier that re-lexes the same diff.
        if not any(ch in line for ch in "{}#'\"\\`<"):
            out.append(LexedLine(line, line, 0, False, False, False))
            continue
        code, in_single, in_double, in_backtick, sub_depth, opener = _scan(
            line, in_single, in_double, in_backtick, sub_depth
        )
        if opener is not None:
            heredoc, heredoc_tabs = opener
        out.append(LexedLine(
            text=line,
            code=code,
            brace_delta=code.count("{") - code.count("}"),
            opens_brace="{" in code,
            closes_line=code.rstrip().endswith("}"),
            heredoc_body=False,
        ))
    return tuple(out)


def _scan(line, in_single, in_double, in_backtick, sub_depth):
    """Return ``(code, states..., heredoc)`` for one line."""
    out: list[str] = []
    i, n = 0, len(line)
    opener: tuple[str, bool] | None = None
    while i < n:
        ch = line[i]
        if in_single:
            if ch == "'":
                in_single = False
            out.append(" ")
            i += 1
            continue
        if in_backtick:
            if ch == "`":
                in_backtick = False
            out.append(ch)
            i += 1
            continue
        if in_double:
            if sub_depth > 0:
                if ch == "\\" and i + 1 < n:
                    out.append(line[i:i + 2])
                    i += 2
                    continue
                if ch == "(":
                    sub_depth += 1
                elif ch == ")":
                    sub_depth -= 1
                out.append(ch)
                i += 1
                continue
            if ch == "\\" and i + 1 < n:
                out.append("  ")
                i += 2
                continue
            if ch == '"':
                in_double = False
                out.append(" ")
                i += 1
                continue
            if ch == "$" and i + 1 < n and line[i + 1] == "(":
                sub_depth = 1
                out.append("$(")
                i += 2
                continue
            if ch == "`":
                in_backtick = True
                out.append(ch)
                i += 1
                continue
            out.append(" ")
            i += 1
            continue
        if ch == "\\" and i + 1 < n:
            out.append("  ")
            i += 2
            continue
        if ch == "'":
            in_single = True
            out.append(" ")
            i += 1
            continue
        if ch == '"':
            in_double = True
            out.append(" ")
            i += 1
            continue
        if ch == "`":
            in_backtick = True
            out.append(ch)
            i += 1
            continue
        if ch == "#" and _opens_a_comment(line, i):
            out.append(" " * (n - i))
            break
        if ch == "<" and i + 1 < n and line[i + 1] == "<" and opener is None:
            match = _HEREDOC_SHAPE_RE.match(line, i)
            if match:
                opener = (match.group(2), match.group(0).startswith("<<-"))
                out.append(" " * (match.end() - i))
                i = match.end()
                continue
        out.append(ch)
        i += 1
    return "".join(out), in_single, in_double, in_backtick, sub_depth, opener
