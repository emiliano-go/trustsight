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
from collections import deque
from dataclasses import dataclass
from functools import lru_cache

from ._heredoc import parse_opener
from .expansion import _MAX_LINE_LEN as _MAX_TOKENIZER_LINE
from .config import ANY_EXECUTOR as _ANY_EXECUTOR
from .config import SCRIPT_EXECUTOR as _SCRIPT_EXECUTOR

@dataclass(frozen=True)
class QuoteState:
    """The shell quote context at a line boundary.

    Frames are ordinary quote states (single, double, ANSI-C, backtick) and
    command-substitution frames (``$(``).  The stack is what lets a quoted
    word inside a command substitution be data while the substitution itself
    is code.
    """

    frames: tuple[str, ...] = ()

    @property
    def open(self) -> bool:
        return bool(self.frames)


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
    #: Every heredoc this line opens, in bash's body order, quote- and
    #: comment-aware: ``(delimiter, strip_tabs)``.  A ``<<`` inside a
    #: comment or a quoted string is prose, not an opener - the payload
    #: scanner downstream used to disagree with this lexer and blanked
    #: whole functions.  Bash supplies the bodies in this order, so two
    #: openers on one line are one queue, not a stack.
    heredoc_openers: tuple[tuple[str, bool], ...] = ()
    quote_before: QuoteState = QuoteState()
    quote_after: QuoteState = QuoteState()
    quoted_data: bool = False
    truncated: bool = False


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
            if quote == "ansi":
                if ch == "\\" and index + 1 < len(line):
                    index += 2
                    continue
                if ch == "'":
                    quote = ""
                index += 1
                continue
            if ch == "\\" and quote == '"':
                index += 2
                continue
            if ch == quote:
                quote = ""
        elif ch == "$" and index + 1 < len(line) and line[index + 1] == "'":
            quote = "ansi"
            index += 2
            continue
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
    state = QuoteState()
    # FIFO: bash reads heredoc bodies in the order their openers appear,
    # so `cat <<A <<B` supplies A's body before B's.
    delims: deque[tuple[str, bool]] = deque()
    diff_lines = any(_diff_boundary(line) for line in lines)
    for line in lines:
        if fragment:
            state = QuoteState()
            if delims and _diff_boundary(line):
                delims.clear()
        if delims:
            delimiter, strip_tabs = delims[0]
            # A diff line keeps its +/- prefix, which is not part of the
            # shell text: ``+EOF`` terminates the heredoc ``EOF``.
            probe = line[1:] if line[:1] in "+-" or (
                diff_lines and line[:1] == " "
            ) else line
            if strip_tabs:
                probe = probe.lstrip("\t")
            blank = " " * len(line)
            if probe == delimiter:
                delims.popleft()
            out.append(LexedLine(
                line, blank, 0, False, False, True,
                quote_before=state, quote_after=state, quoted_data=True,
            ))
            continue
        # A single line past the tokenizer bound is scanned only up to the
        # bound.  The tail is left as code and the quote state is reset, so
        # a crafted line cannot hide the rest of the recipe behind a quote
        # that opens past the ceiling.  ``truncated`` records that refusal.
        truncated = len(line) > _MAX_TOKENIZER_LINE
        scan_line = line[:_MAX_TOKENIZER_LINE] if truncated else line
        # Fast path for the ordinary line: nothing that could change the
        # lexical state, so the character loop is skipped.  A pathological
        # multi-megabyte line otherwise pays that loop in every scope
        # classifier that re-lexes the same diff.
        if not state.open and not any(ch in line for ch in "{}#'\"\\`<"):
            if truncated:
                out.append(LexedLine(
                    line, line, 0, False, False, False,
                    quote_before=state, quote_after=QuoteState(),
                    truncated=True,
                ))
            else:
                out.append(LexedLine(
                    line, line, 0, False, False, False,
                    quote_before=state, quote_after=state,
                ))
            continue
        code, after, openers, quoted = _scan(scan_line, state)
        if truncated:
            code += line[_MAX_TOKENIZER_LINE:]
            after = QuoteState()
            openers = []
            quoted = False
        delims.extend(openers)
        out.append(LexedLine(
            text=line,
            code=code,
            brace_delta=code.count("{") - code.count("}"),
            opens_brace="{" in code,
            closes_line=code.rstrip().endswith("}"),
            heredoc_body=False,
            heredoc_openers=tuple(openers),
            quote_before=state,
            quote_after=after,
            quoted_data=quoted,
            truncated=truncated,
        ))
        state = after
    return tuple(out)

def advance_quote_state(line: str, state: QuoteState | None = None) -> QuoteState:
    """Return the shell quote state after *line*, without exposing code."""
    return _scan(line, state or QuoteState())[1]


def _scan(line: str, state: QuoteState) -> tuple[str, QuoteState, list[tuple[str, bool]], bool]:
    """Scan one shell line, returning code, state, heredoc openers and data flag."""
    out: list[str] = []
    stack = list(state.frames)
    i, n = 0, len(line)
    openers: list[tuple[str, bool]] = []
    quoted = bool(stack)

    def code_context() -> bool:
        return not stack or stack[-1] in ("$(", "`")

    while i < n:
        ch = line[i]
        top = stack[-1] if stack else ""

        if top == "'":
            out.append(" ")
            if ch == "'":
                stack.pop()
            i += 1
            continue
        if top == "ansi":
            if ch == "\\" and i + 1 < n:
                out.append("  ")
                i += 2
                continue
            out.append(" ")
            if ch == "'":
                stack.pop()
            i += 1
            continue
        if top == '"':
            if ch == "\\" and i + 1 < n:
                out.append("  ")
                i += 2
                continue
            if ch == '"':
                stack.pop()
                out.append(" ")
                i += 1
                continue
            if ch == "$" and i + 1 < n and line[i + 1] == "(":
                stack.append("$(")
                out.append("$(")
                i += 2
                continue
            if ch == "`":
                stack.append("`")
                out.append("`")
                quoted = True
                i += 1
                continue
            out.append(" ")
            i += 1
            continue
        if top == "`":
            if ch == "\\" and i + 1 < n:
                out.append("  ")
                i += 2
                continue
            if ch == "`":
                stack.pop()
                out.append("`")
                i += 1
                continue
            if ch == "'":
                stack.append("'")
                out.append(" ")
                quoted = True
                i += 1
                continue
            if ch == '"':
                stack.append('"')
                out.append(" ")
                quoted = True
                i += 1
                continue
            if ch == "$" and i + 1 < n and line[i + 1] == "'":
                stack.append("ansi")
                out.append("  ")
                quoted = True
                i += 2
                continue
            if ch == "$" and i + 1 < n and line[i + 1] == "(":
                stack.append("$(")
                out.append("$(")
                i += 2
                continue
            if ch == "#" and _opens_a_comment(line, i):
                out.append(" " * (n - i))
                break
            out.append(ch)
            i += 1
            continue
        if top == "$(":
            if ch == "\\" and i + 1 < n:
                out.append("  ")
                i += 2
                continue
            if ch == ")":
                stack.pop()
                out.append(")")
                i += 1
                continue
            if ch == "'":
                stack.append("'")
                out.append(" ")
                quoted = True
                i += 1
                continue
            if ch == '"':
                stack.append('"')
                out.append(" ")
                quoted = True
                i += 1
                continue
            if ch == "$" and i + 1 < n and line[i + 1] == "'":
                stack.append("ansi")
                out.append("  ")
                quoted = True
                i += 2
                continue
            if ch == "$" and i + 1 < n and line[i + 1] == "(":
                stack.append("$(")
                out.append("$(")
                i += 2
                continue
            if ch == "`":
                stack.append("`")
                out.append("`")
                quoted = True
                i += 1
                continue
            if ch == "#" and _opens_a_comment(line, i):
                out.append(" " * (n - i))
                break
            out.append(ch)
            i += 1
            continue

        # Code context.
        if ch == "\\" and i + 1 < n:
            out.append("  ")
            i += 2
            continue
        if ch == "'":
            stack.append("'")
            quoted = True
            out.append(" ")
            i += 1
            continue
        if ch == '"':
            stack.append('"')
            quoted = True
            out.append(" ")
            i += 1
            continue
        if ch == "$" and i + 1 < n and line[i + 1] == "'":
            stack.append("ansi")
            quoted = True
            out.append("  ")
            i += 2
            continue
        if ch == "$" and i + 1 < n and line[i + 1] == "(":
            stack.append("$(")
            out.append("$(")
            i += 2
            continue
        if ch == "`":
            stack.append("`")
            quoted = True
            out.append("`")
            i += 1
            continue
        if ch == "#" and _opens_a_comment(line, i):
            out.append(" " * (n - i))
            break
        if line.startswith("<<<", i):
            out.append("<<<")
            i += 3
            continue
        if ch == "<" and i + 1 < n and line[i + 1] == "<":
            opener = parse_opener(line, i)
            if opener is not None:
                delimiter, strip_tabs, end = opener
                openers.append((delimiter, strip_tabs))
                out.append(" " * (end - i))
                i = end
                continue
        out.append(ch)
        i += 1

    return "".join(out), QuoteState(tuple(stack)), openers, quoted


# ---------------------------------------------------------------------------
# Heredoc-body classification (destination decides whether the body is data)
#
# Moved here from ``analysis.delivery``: the source-URL reader needs the same
# "is this line heredoc data" answer, and importing it from ``delivery`` would
# invert the diff -> analysis dependency.  ``line_lex`` is the one leaf both
# sides already build on.
# ---------------------------------------------------------------------------

_HEREDOC_OPEN_RE = re.compile(r"(?<!<)<<(?!<)(-)?\s*['\"]?(\w+)['\"]?")

_HEREDOC_WRAPPER = (
    r"(?:\A\s*|[;&|]\s*|"
    r"\b(?:env|exec|command|sudo|nohup|timeout|nice)\s+"
    r"(?:(?:-[ugUpChrtTDR]\s+\S+|\S+=\S*|"
    r"\d+(?:\.\d+)?[smhd]?|-\S+)\s+)*)"
)

_HEREDOC_TO_INTERPRETER_RE = re.compile(
    _HEREDOC_WRAPPER
    + r"(?:/(?:usr/)?bin/)?(?:"
    + _SCRIPT_EXECUTOR
    + r")\b(?!\s*>)"
    + r"|\|\s*(?:/(?:usr/)?bin/)?(?:"
    + _SCRIPT_EXECUTOR
    + r")\b",
    re.IGNORECASE,
)

#: A heredoc whose body is a program in another language.  The shell hands
#: the text to that interpreter; its `KEY=value`/`install=` lines are data to
#: the shell rules, not assignments or commands.
_HEREDOC_TO_NON_SHELL_RE = re.compile(
    _HEREDOC_WRAPPER
    + r"(?:/(?:usr/)?bin/)?(?:python[23]?|perl|ruby|node|php|lua(?:jit)?"
    + r"|tclsh|wish)\b(?!\s*>)",
    re.IGNORECASE,
)

_HEREDOC_TO_EXECUTING_CONFIG_RE = re.compile(
    r">\s*+[\"']?"
    r"(?=[^\"'\s;&|<>]*(?:"
    r"/(?:cron\.[a-z]+|cron\.d|systemd/(?:system|user)|xdg/autostart"
    r"|pam\.d|profile\.d|init\.d|rc\.d|xinetd\.d|logrotate\.d"
    r"|dispatcher\.d|udev/rules\.d|conf\.d|sudoers\.d)/"
    r"|\.(?:service|socket|timer|path|desktop|rules|conf)\b))",
    re.IGNORECASE,
)

_HEREDOC_PIPED_RE = re.compile(
    r"(?<!\\)\|\s*(?:" + _ANY_EXECUTOR + r")", re.IGNORECASE
)


def _heredoc_body_indices(lines: list[str]) -> set[int]:
    """Twenty rule families ask this of the same lines; the scan is cached
    on them.  A fresh ``set`` is returned so no caller can reach another's.
    """
    return set(_heredoc_body_indices_cached(tuple(lines)))


@lru_cache(maxsize=8)
def _heredoc_body_indices_cached(lines: tuple[str, ...]) -> frozenset[int]:
    """Indices of lines that are literal heredoc content, not commands.

    A heredoc's body is data being written to a file; treating it as build
    commands would let the payload's own lines fire the very rules the
    generate-then-execute rule is meant to catch once.  The opener line
    itself is a command and stays eligible.

    That reasoning holds only for a heredoc that reaches a *file*.  When the
    destination is a shell - ``bash <<'EOF'`` - the body is not data, it is
    the script being executed, and exempting it turned four rules off for
    every line inside::

        build() {
          bash <<'EOF'
          _fetch
          bash "$srcdir/x.sh"
        EOF
        }

    The exemption is therefore decided per heredoc, by where it goes.
    """
    body: set[int] = set()
    delims: deque[tuple[str, bool]] = deque()
    # The lexer owns opener detection: a `<<` inside a comment or a quoted
    # string is prose.  Scanning the raw line here disagreed with
    # line_lex._scan and turned `# upstream uses the <<EOF form` above a
    # fetch into a fake delimiter that blanked every following line - and
    # with it H069/H072/H082/H083 for the whole function.
    lexed = lex_lines(list(lines), fragment=True)
    for i, line in enumerate(lines):
        content = line[1:] if line[:1] in ("+", "-") else line
        if _diff_boundary(line):
            # A partial hunk can leave a heredoc open.  Its body cannot
            # continue into the next file or hunk; carrying the queue there
            # blanked unrelated payload lines.
            delims.clear()
        if delims:
            delimiter, strip_tabs = delims[0]
            probe = content.lstrip("\t") if strip_tabs else content
            if probe == delimiter:
                delims.popleft()
                continue
        if delims:
            if delims[0][1]:
                body.add(i)
            continue
        openers = lexed[i].heredoc_openers
        if openers:
            # The destination may be named on either side of the
            # delimiter: `bash <<EOF` puts it before, and
            # `cat <<'EOF' | sh` puts it after the redirect.  Reading
            # only the left half meant the piped form - which is how
            # the shape is usually written - stayed classified as data.
            is_data = bool(_HEREDOC_TO_NON_SHELL_RE.search(content)) or not (
                _HEREDOC_TO_INTERPRETER_RE.search(content)
                or _HEREDOC_PIPED_RE.search(content)
                or _HEREDOC_TO_EXECUTING_CONFIG_RE.search(content)
            )
            for delimiter, _strip_tabs in openers:
                delims.append((delimiter, is_data))
    return frozenset(body)


_PRINTED_HEREDOC_OPENER_RE = re.compile(
    r"^\s*(?:cat|echo|printf)\b(?![^\n]*>)"
)


def _printed_heredoc_body_indices(lines: list[str]) -> set[int]:
    """Indices of lines inside a heredoc that only prints its body.

    H017/H035/X015 read commands in install hooks; a ``cat <<'MESSAGE'``
    body that *advises* the user to run ``sudo pacman -S`` is
    documentation, and the opener is the only line that says so.  A
    redirect (``cat > out <<EOF``), a pipe into an executor
    (``cat <<EOF | sh``), or any opener that is not cat/echo/printf stays
    eligible: the body may be a script some later line runs.
    """
    return set(_printed_heredoc_body_indices_cached(tuple(lines)))


@lru_cache(maxsize=8)
def _printed_heredoc_body_indices_cached(
    lines: tuple[str, ...],
) -> frozenset[int]:
    body: set[int] = set()
    delims: deque[tuple[str, bool]] = deque()
    lexed = lex_lines(list(lines), fragment=True)
    for i, line in enumerate(lines):
        content = line[1:] if line[:1] in ("+", "-") else line
        if _diff_boundary(line):
            delims.clear()
        if delims:
            delimiter, strip_tabs = delims[0]
            probe = content.lstrip("\t") if strip_tabs else content
            if probe == delimiter:
                delims.popleft()
                continue
        if delims:
            if delims[0][1]:
                body.add(i)
            continue
        openers = lexed[i].heredoc_openers
        if not openers:
            continue
        printed = bool(
            _PRINTED_HEREDOC_OPENER_RE.match(content)
            and not _HEREDOC_PIPED_RE.search(content)
        )
        for delimiter, _strip_tabs in openers:
            delims.append((delimiter, printed))
    return frozenset(body)


#: A literal shell re-exec: ``sh -c '<script>'`` (or ``"..."``) at a
#: command position, with the option cluster carrying ``c``.  Debian
#: packaging templates wrap every hook body this way (``/bin/sh -c
#: '#!/bin/sh …'``).  Only a *literal* argument unwraps: a double-quoted
#: body carrying ``$`` or a backtick is dynamic (``sh -c "$x"``), so the
#: interpreter token stays visible and the rule fires exactly as before.
_CEXEC_LITERAL_RE = re.compile(
    r"(?P<pre>(?:^|[;&|()]|&&|\|\|)\s*)"
    r"(?:/(?:usr/)?bin/)?(?:bash|sh|dash|zsh|ksh|ash|mksh)"
    r"\s+-[A-Za-z]*c[A-Za-z]*\s+"
    r"(?:'(?P<single>[^']*)'|\"(?P<double>(?:\\.|[^\"\\$`])*)\")",
    re.DOTALL | re.MULTILINE,
)


def unwrap_shell_cexec(text: str, _depth: int = 8) -> str:
    """Replace literal ``sh -c '<lit>'`` re-exec wrappers with ``<lit>``.

    ``sh -c '<x>'`` executes ``<x>``, so the code a rule should read is the
    inner literal, not the wrapper token.  Substitution runs to a fixpoint
    (bounded by *_depth*) so nested wrappers (``sh -c 'sh -c "…"'``) are
    unwrapped too.  A non-literal argument is left untouched.
    """
    if _depth <= 0:
        return text

    def _sub(match: "re.Match[str]") -> str:
        body = match.group("single")
        if body is None:
            body = match.group("double")
        return match.group("pre") + body

    result = _CEXEC_LITERAL_RE.sub(_sub, text)
    return result if result == text else unwrap_shell_cexec(result, _depth - 1)


_CEXEC_OPEN_RE = re.compile(
    r"\A(?P<indent>[ \t]*(?:\+[ \t]*)?)(?:/(?:usr/)?bin/)?"
    r"(?:bash|sh|dash|zsh|ksh|ash|mksh)"
    r"\s+-[A-Za-z]*c[A-Za-z]*\s+(?P<q>['\"])"
)


def strip_shell_cexec_opener(line: str) -> str:
    """Drop a leading literal ``sh -c ['"]`` wrapper token from *line*.

    The re-exec body usually spans later lines (already scanned in the same
    hook scope), so only the opener token is removed here and the inner
    text on this line is kept - a one-liner payload (``sh -c 'curl x | sh'``)
    survives the strip.  A dynamic argument (``sh -c "$x"``) is left whole.
    """
    match = _CEXEC_OPEN_RE.match(line)
    if match is None:
        return line
    rest = line[match.end():]
    if match.group("q") == '"':
        close = rest.find('"')
        segment = rest if close == -1 else rest[:close]
        if "$" in segment or "`" in segment:
            return line
    return match.group("indent") + rest
