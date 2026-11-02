"""One lexical definition of shell command position.

Every rule family that asks "does this line run X?" used to answer it with
its own regex prefix.  Those prefixes drifted: some saw a brace group, some
a reserved word, some a wrapper; some matched a manager name printed inside
a quoted message, and some matched it only as an argument.  This module is
the single answer.

It is deliberately dependency-free so both ``config`` (which the rest of the
package imports) and ``analysis`` can share it without an import cycle.  It
is lexical, not a shell: it resolves nothing and never executes anything.
"""

from __future__ import annotations

import re

#: Commands whose arguments are themselves a command word.  ``sudo -u user``
#: and ``timeout 5`` are handled by the argument-skipping in
#: :func:`_first_command_start`; the reserved words (``then``, ``do``, ``!``)
#: are how the shell reaches a fresh command list.
COMMAND_WRAPPERS = frozenset({
    "env", "exec", "sudo", "doas", "run0", "nohup", "command", "builtin",
    "time", "nice", "ionice", "timeout", "xargs", "setsid", "stdbuf",
    "unbuffer", "script",
    "then", "else", "do", "elif", "if", "while", "until", "!",
})

#: Where a fresh command word can start, as an operator-only prefix that is
#: safe to match against raw text (a `;` or `(` inside quotes is still a
#: `;` or `(` character, but the rules that use this one already read code).
COMMAND_POSITION = r"(?:\A\s*|[;&|(]\s*|\$\(\s*|&&\s*|\|\|\s*)"

#: Grouping and reserved words that also begin a command list:
#: `{ pip install }`, `! pip install`, `time pip install`,
#: `if …; then pip install`, `while …; do pip install` and a `case` arm.
#: A lookbehind-style anchor that keeps the match start at the separator.  It
#: is what ``analysis.base._CMD`` uses; behaviour is the operator set it has
#: always had, now defined in one place.
COMMAND_ANCHOR = r"(?:\A|(?<=[;&|(\n])|(?<=&&)|(?<=\|\|)|^)[ \t]*"

#: The operator set plus grouping, for consumers that already mask quoted
#: text before matching.  Possessive quantifiers keep a run of separators
#: from costing an arm a scan per character.
COMMAND_START = (
    r"(?:\A\s*+|[;&|{(]\s*+(?![;&|{(])"
    r"|\b(?:do|then|else|elif)\s++|!\s++|\btime\s+(?:-p\s+)?)"
)

_ASSIGNMENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\[[^\]]{0,40}\])?\+?=")
_REDIRECT_RE = re.compile(r"^\d?[<>]")
_NUMERIC_RE = re.compile(r"^\d+$")
_EVALUATION_RE = re.compile(r"^(?:\(\(|\[\[|\[\s|test\s)")
_PRIVILEGE_WRAPPERS = frozenset({"sudo", "doas", "run0"})
_ACCOUNT_OPTION_RE = re.compile(r"^-{1,2}(?:u|user|g|group)(?:=(.*))?$")
_PLAIN_VAR_RE = re.compile(r"""^["']?\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?["']?$""")
_TOKEN_RE = re.compile(r"\S+")


def split_shell_commands(body: str) -> list[str]:
    """Split *body* on command separators, respecting quotes.

    A `|` inside a quoted argument does not start a command:
    ``sed -i 's|"$LIBS -lfoo|...|'`` is one command, and splitting naively
    on the pipe offered ``"$LIBS ...`` as a command word. That was the only
    substitution-shaped false positive the benign corpus produced.
    """
    parts, current, quote = [], [], None
    depth = 0
    index = 0
    while index < len(body):
        ch = body[index]
        if quote:
            if ch == quote:
                quote = None
            current.append(ch)
        elif ch in "'\"":
            quote = ch
            current.append(ch)
        elif ch == "[" and body[index:index + 2] == "[[":
            # `[[ -n "$a" && "$a" != "$b" ]]` is one test, not two commands.
            depth += 1
            current.append(body[index:index + 2])
            index += 2
            continue
        elif ch == "]" and body[index:index + 2] == "]]":
            depth = max(0, depth - 1)
            current.append(body[index:index + 2])
            index += 2
            continue
        elif ch == "(":
            depth += 1
            current.append(ch)
        elif ch == ")":
            depth = max(0, depth - 1)
            current.append(ch)
        elif ch in ";&|\n" and depth == 0:
            parts.append("".join(current))
            current = []
            # Consume the second character of && and ||.
            if index + 1 < len(body) and body[index + 1] == ch:
                index += 1
        elif ch in ";&|\n":
            # Inside `(( ... && ... ))` or `$( ... )` this is arithmetic or a
            # nested pipeline, not a new command.
            current.append(ch)
        else:
            current.append(ch)
        index += 1
    parts.append("".join(current))
    return parts


def _opens_a_value(token: str) -> bool:
    """True when *token* leaves a quote or a substitution unclosed.

    `FOO=1 cmd` is an environment prefix and the scan must walk past it to
    reach `cmd`. `outmsg=$(eval "$(...)" 2>&1)` is not: everything after the
    first token is the assignment's *value*, and reading on found the `$(`
    inside it and called it a command name.
    """
    return bool(
        token.count('"') % 2
        or token.count("'") % 2
        or token.count("(") > token.count(")")
    )


_CASE_LABEL_RE = re.compile(r"^\s*(?:[^()\s;&|]+(?:\|[^()\s;&|]+)*)\)\s+")


def _strip_case_label(part: str) -> str:
    """Drop a leading ``label)`` from a case arm.

    The label may carry ``|`` alternatives, so this runs before
    ``split_shell_commands`` would treat the ``|`` as a pipeline.
    """
    return _CASE_LABEL_RE.sub("", part, count=1)


def _split_case_arms(part: str) -> list[str]:
    """Split a case arm ``label) body`` at the top-level ``)``.

    ``_split_commands`` tracks parentheses for ``$(...)`` and ``( ... )``
    but leaves a case label attached to its body.  A ``)`` that is not
    closing an opened ``(`` is the arm terminator.
    """
    pieces: list[str] = []
    current: list[str] = []
    quote = None
    depth = 0
    for ch in part:
        if quote:
            if ch == quote:
                quote = None
            current.append(ch)
        elif ch in "'\"":
            quote = ch
            current.append(ch)
        elif ch == "(":
            depth += 1
            current.append(ch)
        elif ch == ")":
            if depth:
                depth -= 1
                current.append(ch)
            else:
                pieces.append("".join(current))
                current = []
        else:
            current.append(ch)
    pieces.append("".join(current))
    return pieces


#: `f() {` and `function f {` open a command list on the same line.  The
#: parser split on `;` but still saw the function token as the command word,
#: so a one-line body `f() { "$X"; }` hid the indirect command.
_FUNCTION_PREFIX_RE = re.compile(
    r"^(?:function\s+[A-Za-z_][A-Za-z0-9_]*(?:\s*\(\))?\s*\{"
    r"|[A-Za-z_][A-Za-z0-9_]*\s*\(\)\s*\{)")


def _first_command_start(part: str) -> tuple[str, str] | None:
    """The command word of *part* after prefixes, or None.

    Returns ``(word, tail)`` where *tail* is the text from the word to the
    end of the segment, so a caller can match a multi-token command
    (``python -m pip``) or read its arguments.
    """
    stripped = part.lstrip()
    prefix = _FUNCTION_PREFIX_RE.match(stripped)
    if prefix:
        stripped = stripped[prefix.end():].lstrip()
        part = stripped
    if not stripped or _EVALUATION_RE.match(stripped):
        return None
    seen_wrapper = False
    wrapper = ""
    account_option = False
    for match in _TOKEN_RE.finditer(part):
        token = match.group()
        if token.startswith("(("):
            return None
        word = token.lstrip("({")
        leading = len(token) - len(word)
        if not word:
            continue
        if _ASSIGNMENT_RE.match(word):
            if _opens_a_value(word):
                return None
            continue
        if _REDIRECT_RE.match(word) or _NUMERIC_RE.match(word):
            continue
        if word.startswith("-"):
            # A flag before any command means this line continues another
            # one; inside a wrapper's arguments it is just a flag.
            if not seen_wrapper:
                return None
            if wrapper == "command" and word in ("-v", "-V"):
                return None
            if wrapper == "type" and word in ("-p", "-P", "-a"):
                return None
            if wrapper in _PRIVILEGE_WRAPPERS:
                account_match = _ACCOUNT_OPTION_RE.match(word)
                if account_match is not None:
                    inline = account_match.group(1)
                    if inline is None:
                        account_option = True
                    elif ("$" in inline or "`" in inline) and not _PLAIN_VAR_RE.match(inline):
                        # The account slot carries the command name.
                        word = inline.strip("\"'")
                        return word, part[match.start() + leading:]
            continue
        base = word.strip("'\"").rsplit("/", 1)[-1]
        if base in COMMAND_WRAPPERS:
            seen_wrapper = True
            wrapper = base
            account_option = False
            continue
        if account_option:
            # The word right after `sudo -u`/`--user`/`-g` is the target
            # account, not the command; keep scanning after it.
            account_option = False
            continue
        return word, part[match.start() + leading:]
    return None


def _balanced_end(body: str, open_index: int) -> int | None:
    """Index of the ``)`` matching the ``(`` at *open_index*, quote-aware."""
    depth = 0
    quote = None
    index = open_index
    while index < len(body):
        ch = body[index]
        if quote:
            if ch == "\\" and quote == '"':
                index += 2
                continue
            if ch == quote:
                quote = None
        elif ch in "'\"":
            quote = ch
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return index
        index += 1
    return None


def _substitution_bodies(body: str):
    """Inner text of ``$(...)``, ``<(...)`` and ``>(...)``, quote-aware.

    A substitution inside double quotes still executes, so it is scanned; a
    single-quoted one does not.  Arithmetic ``$((...))`` and ``((...))`` are
    skipped: a word inside is an operand, not a command.  Recursion in
    :func:`command_starts` is bounded by the caller.
    """
    index = 0
    quote = None
    while index < len(body):
        ch = body[index]
        if quote == "'":
            if ch == "'":
                quote = None
            index += 1
            continue
        if quote == '"':
            if ch == "\\":
                index += 2
                continue
            if ch == '"':
                quote = None
                index += 1
                continue
            if body.startswith("$(", index) and not body.startswith("$((", index):
                end = _balanced_end(body, index + 1)
                if end is None:
                    break
                yield body[index + 2:end]
                index = end + 1
                continue
            if ch in "<>" and body.startswith(ch + "(", index):
                end = _balanced_end(body, index + 1)
                if end is None:
                    break
                yield body[index + 2:end]
                index = end + 1
                continue
            index += 1
            continue
        if ch in "'\"":
            quote = ch
            index += 1
            continue
        if body.startswith("$((", index) or body.startswith("((", index):
            open_index = index + 1 if ch == "$" else index
            end = _balanced_end(body, open_index)
            if end is None:
                break  # no closer: nothing after this can be balanced
            index = end + 1
            continue
        if body.startswith("$(", index) or (
                ch in "<>" and body.startswith(ch + "(", index)):
            end = _balanced_end(body, index + 1)
            if end is None:
                break  # unterminated substitution: stop, do not rescan
            yield body[index + 2:end]
            index = end + 1
            continue
        index += 1


def command_starts(body: str, *, recurse: bool = True,
                   _depth: int = 4):
    """Yield ``(word, tail)`` for each command position in *body*.

    A command word is not always the first token: assignments, wrappers
    (``env``, ``sudo -u root``, ``timeout 5``), redirections, group openers
    and case-arm labels all hide it one or more tokens to the right.  With
    *recurse*, command substitutions and process substitutions are scanned
    too, so ``x=$(pip install y)`` and ``echo "$(curl …)"`` are seen without
    reading a quoted argument as a command.

    ``recurse=False`` is the historical X002 scan: one word per segment,
    with the substitution token itself yielded as the word.
    """
    for part in split_shell_commands(_strip_case_label(body)):
        for piece in _split_case_arms(_strip_case_label(part)):
            start = _first_command_start(piece)
            if start is not None:
                yield start
    if recurse and _depth > 0:
        for inner in _substitution_bodies(body):
            yield from command_starts(inner, recurse=recurse,
                                      _depth=_depth - 1)
