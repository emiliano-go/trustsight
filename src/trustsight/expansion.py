"""Bash parameter-expansion resolution, shared by the tokenizer and the analysis.

Moved out of ``_tokenizer_engine`` so the parent analysis can resolve a
PKGBUILD's own variables (``pkgver=${_pkgver//-/_}``) without importing the
sandboxed engine (A6 forbids that).  The tokenizer engine re-exports these,
so the worker's surface is unchanged and there is one implementation.

Only pure string work lives here - no I/O, no execution, no state - which is
what makes it safe for both sides to share.
"""

from __future__ import annotations

import re

__all__ = [
    "_MAX_EXPANSION_PASSES",
    "_MAX_LINE_LEN",
    "_MAX_TABLE_BYTES",
    "_MAX_VALUE_LEN",
    "_INNERMOST_RE",
    "_REPLACEMENT_ESCAPE_RE",
    "_expand_one",
    "_strip_affix",
    "resolve_expansions",
    "resolve_text",
    "text_variable_table",
    "variable_table",
]

#: Bound on the resolve loop: a crafted recipe can chain substitutions, and
#: sixteen links is far past anything makepkg packaging does in practice.
_MAX_EXPANSION_PASSES = 16

#: Bound on the whole-text resolve loop.  Separate from the brace-only cap
#: because one form can expand to the other (``$a`` -> ``${b}``).
_RESOLVE_MAX_DEPTH = 8

#: A6's size bounds live here rather than only in the sandboxed engine, so
#: the parent resolver obeys the same ceilings.  The tokenizer engine
#: re-exports these; one definition means the sandboxed and in-process paths
#: cannot drift.
_MAX_VALUE_LEN = 8192

_MAX_LINE_LEN = 65536

_MAX_TABLE_BYTES = 1 << 20

#: Whole-text ceiling for :func:`resolve_text`.  A PKGBUILD is capped at
#: 5 MiB before it reaches us (``differ.MAX_PKG_BUILD_BYTES``); expansion may
#: grow it a little, never without limit.
_MAX_TEXT_LEN = 8 * 1024 * 1024

#: A glob pattern is attacker-written text.  Matching it is table-driven, so
#: the pattern length is what bounds the table, not the number of wildcards:
#: ``*a*a*a...`` is a legitimate shape that used to become a superlinear
#: regex, and a bounded matcher must still answer it (A6/A14).
_MAX_GLOB_PATTERN_LEN = 256

#: Total state visits one ``resolve_expansions`` call may spend, shared by
#: every glob match, affix strip and global substitution on that line.  A
#: single expansion is O(text x pattern), but a line can hold sixteen of
#: them, so the budget bounds the line rather than one operator: without it
#: a crafted line could multiply the per-expansion cost by the pass cap.
#: Exceeding it is a refusal, not a truncated result.
_MAX_GLOB_STEPS = 8_000_000

_INNERMOST_RE = re.compile(r"\$\{([^{}]*)\}")

_REPLACEMENT_ESCAPE_RE = re.compile(r"\\(.)")

#: A ``name=value`` assignment on a diff line, keyed by its ``-``/``+``/`` ``
#: prefix so an old-side table and a new-side table can be built separately.
_ASSIGN_LINE_RE = re.compile(
    r"^([+\- ])\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+?)\s*$"
)

#: A bare ``$NAME`` reference.  The brace form is handled by
#: :func:`resolve_expansions`; the tokenizer covers both, so the parent must
#: too or a ``$url``-built source URL stays unresolved.
_BARE_VAR_RE = re.compile(r"\$([A-Za-z_][A-Za-z0-9_]*)")

#: A ``name=value`` assignment in a whole recipe (no diff prefix).
_TEXT_ASSIGN_RE = re.compile(
    r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+?)\s*$", re.MULTILINE
)


def _glob_tokens(pat: str) -> tuple[tuple[str, object], ...]:
    """Compile a bash glob into a flat token list, or raise ``re.error``.

    ``*``, ``?`` and bracket expressions are the only operators.  Everything
    else is a literal, matching the translation this replaces: a dot is a dot,
    an unmatched ``[`` is literal, and ``**`` is one star in bash parameter
    expansion.

    Bracket bodies are compiled once as a single-character regex.  That is a
    bounded, non-backtracking operation (one character in, one decision out)
    and it preserves the old refusal of an invalid range such as ``[z-a]``.
    """
    if len(pat) > _MAX_GLOB_PATTERN_LEN:
        raise re.error("glob pattern too long")

    tokens: list[tuple[str, object]] = []
    wildcards = 0
    i = 0
    while i < len(pat):
        char = pat[i]
        if char == "\\" and i + 1 < len(pat):
            tokens.append(("lit", pat[i + 1]))
            i += 2
            continue
        if char == "*":
            # Adjacent stars are one star: ``**`` is not globstar here.
            while i + 1 < len(pat) and pat[i + 1] == "*":
                i += 1
            wildcards += 1
            tokens.append(("*", None))
        elif char == "?":
            wildcards += 1
            tokens.append(("?", None))
        elif char == "[":
            end = pat.find("]", i + 1)
            if end == -1:
                tokens.append(("lit", char))
            else:
                body = pat[i + 1 : end]
                if body.startswith("!"):
                    body = "^" + body[1:]
                try:
                    compiled = re.compile("[" + body + "]")
                except re.error:
                    # The caller's failure path is unchanged: an invalid
                    # glob leaves the expansion unresolved.
                    raise
                tokens.append(("class", compiled))
                i = end
        else:
            tokens.append(("lit", char))
        i += 1

    # A pattern with this many wildcards is still answerable in O(text x
    # pattern); the cap only rejects a token list larger than the pattern
    # bound can explain, which is a syntax error rather than a slow match.
    if wildcards > _MAX_GLOB_PATTERN_LEN:
        raise re.error("glob pattern has too many wildcards")
    return tuple(tokens)


def _glob_char_matches(token: tuple[str, object], char: str) -> bool:
    kind, value = token
    if kind == "?":
        return True
    if kind == "class":
        return value.match(char) is not None  # type: ignore[union-attr]
    return value == char


def _glob_prefix_ends(tokens: tuple[tuple[str, object], ...],
                      text: str,
                      budget: list[int] | None = None) -> list[int]:
    """End indices where *tokens* match ``text[:end]`` exactly, ascending.

    One table pass, O(len(text) x len(tokens)); a ``*`` is an epsilon edge
    plus a self-loop, never a backtracking point.  The pass spends from
    *budget* when one is given, so affix stripping is bounded like the
    substitution path rather than being the one unbudgeted matcher.
    """
    if budget is None:
        budget = [_MAX_GLOB_STEPS]
    length = len(tokens)
    start = _MAX_GLOB_STEPS + 1
    current = [start] * (length + 1)
    current[0] = 0
    for index in range(1, length + 1):
        if tokens[index - 1][0] == "*":
            current[index] = min(current[index], current[index - 1])

    ends = [0] if current[length] != start else []
    for position, char in enumerate(text):
        budget[0] -= length + 1
        if budget[0] < 0:
            raise re.error("glob match exceeded its step budget")
        following = [start] * (length + 1)
        for index in range(length + 1):
            origin = current[index]
            if origin == start:
                continue
            # A prefix that ends in a star consumes one more character and
            # stays at the same state.
            if index and tokens[index - 1][0] == "*":
                following[index] = min(following[index], origin)
            if index < length and (
                    tokens[index][0] == "*"
                    or _glob_char_matches(tokens[index], char)):
                following[index + 1] = min(following[index + 1], origin)
        for index in range(1, length + 1):
            if tokens[index - 1][0] == "*":
                following[index] = min(following[index], following[index - 1])
        current = following
        if current[length] != start:
            ends.append(position + 1)
    return ends


def _glob_fixed_find(tokens: tuple[tuple[str, object], ...], text: str,
                     start: int,
                     budget: list[int] | None = None) -> int | None:
    """Leftmost match start for a star-free token list, in O(text x tokens)."""
    width = len(tokens)
    if width == 0:
        return start if start <= len(text) else None
    if budget is None:
        budget = [_MAX_GLOB_STEPS]
    for position in range(start, len(text) - width + 1):
        budget[0] -= width
        if budget[0] < 0:
            raise re.error("glob match exceeded its step budget")
        if all(_glob_char_matches(token, text[position + offset])
               for offset, token in enumerate(tokens)):
            return position
    return None


def _glob_find(tokens: tuple[tuple[str, object], ...], text: str,
               start: int = 0, budget: list[int] | None = None) -> tuple[int, int] | None:
    """Leftmost-longest match of *tokens* in *text*, or ``None``.

    Greedy like the regex it replaces: the leftmost start wins, and at that
    start the longest end wins.  A table pass carries the earliest start for
    every pattern prefix, so a run of stars can neither branch nor backtrack.
    """
    if budget is None:
        budget = [_MAX_GLOB_STEPS]
    if not any(token[0] == "*" for token in tokens):
        found = _glob_fixed_find(tokens, text, start, budget)
        return (found, found + len(tokens)) if found is not None else None

    length = len(tokens)
    unexplored = _MAX_GLOB_STEPS + 1
    current = [unexplored] * (length + 1)
    current[0] = start
    for index in range(1, length + 1):
        if tokens[index - 1][0] == "*":
            current[index] = min(current[index], current[index - 1])

    best: tuple[int, int] | None = None
    if current[length] != unexplored:
        best = (current[length], start)

    for position in range(start, len(text)):
        budget[0] -= length + 1
        if budget[0] < 0:
            raise re.error("glob match exceeded its step budget")
        char = text[position]
        following = [unexplored] * (length + 1)
        # A new match may start after the previous character.
        following[0] = position + 1
        for index in range(length + 1):
            origin = current[index]
            if origin == unexplored:
                continue
            # A prefix that ends in a star consumes one more character and
            # stays at the same state.
            if index and tokens[index - 1][0] == "*":
                following[index] = min(following[index], origin)
            if index < length and (
                    tokens[index][0] == "*"
                    or _glob_char_matches(tokens[index], char)):
                following[index + 1] = min(following[index + 1], origin)
        for index in range(1, length + 1):
            if tokens[index - 1][0] == "*":
                following[index] = min(following[index], following[index - 1])
        current = following
        if current[length] != unexplored:
            found = (current[length], position + 1)
            if best is None or found[0] < best[0] or (
                    found[0] == best[0] and found[1] > best[1]):
                best = found
    return best


def _glob_sub(tokens: tuple[tuple[str, object], ...], text: str,
              replacement: str, count: int = 0,
              budget: list[int] | None = None) -> str:
    """Replace glob matches in *text*; mirrors ``re.sub`` for empty patterns.

    ``count=0`` replaces every non-overlapping match, ``count=1`` the first.
    The pattern is matched by :func:`_glob_find`, so a hostile glob costs a
    bounded table pass rather than an exponential backtracking search.
    """
    if not tokens:
        # ``re.sub("", "-", "abc")`` is ``-a-b-c-``.
        if count == 1:
            return replacement + text
        return replacement + replacement.join(text) + replacement

    if budget is None:
        budget = [_MAX_GLOB_STEPS]
    # ``count=0`` means every match, as in ``re.sub``.
    remaining = None if count == 0 else count
    if not any(token[0] == "*" for token in tokens):
        parts: list[str] = []
        last = 0
        position = 0
        while remaining is None or remaining > 0:
            found = _glob_fixed_find(tokens, text, position, budget)
            if found is None:
                break
            parts.append(text[last:found])
            parts.append(replacement)
            last = found + len(tokens)
            position = last
            if remaining is not None:
                remaining -= 1
        parts.append(text[last:])
        return "".join(parts)

    parts = []
    last = 0
    position = 0
    while remaining is None or remaining > 0:
        found = _glob_find(tokens, text, position, budget)
        if found is None:
            break
        begin, end = found
        parts.append(text[last:begin])
        parts.append(replacement)
        last = end
        if end == begin:
            # An empty match must advance, or ``*`` would replace forever.
            if end < len(text):
                parts.append(text[end])
                last = end + 1
            position = last
            if position > len(text):
                break
        else:
            position = end
        if remaining is not None:
            remaining -= 1
    parts.append(text[last:])
    return "".join(parts)


def _strip_affix(val: str, op: str, pat: str,
                 budget: list[int] | None = None) -> str:
    """Apply bash ## / # / %% / % stripping using glob patterns.

    The operators differ on two axes at once: ``#``/``##`` match a prefix
    of the value and ``%``/``%%`` a suffix, and the single character
    removes the SHORTEST match while the doubled removes the LONGEST.
    Anchoring is part of the contract: ``${v##foo}`` on ``barfoo`` removes
    nothing because ``foo`` is no prefix, and ``${v#*/}`` on ``a/b/c``
    leaves ``b/c`` (the shortest matching prefix), not ``c``.

    Suffix matching reverses both the value and the token list, so the same
    one-pass prefix table answers it.  Reversing tokens, rather than the
    pattern text, keeps a bracket expression intact.
    """
    tokens = _glob_tokens(pat)
    if op == "#":
        ends = _glob_prefix_ends(tokens, val, budget)
        return val[min(ends):] if ends else val
    if op == "##":
        ends = _glob_prefix_ends(tokens, val, budget)
        return val[max(ends):] if ends else val
    if op in ("%", "%%"):
        reversed_ends = _glob_prefix_ends(tokens[::-1], val[::-1], budget)
        if not reversed_ends:
            return val
        width = min(reversed_ends) if op == "%" else max(reversed_ends)
        return val[: len(val) - width]
    return val


def _split_substitution(rest: str) -> tuple[str, str]:
    """Split ``pat/rep`` at the first *unescaped* ``/``.

    Bash spells a literal slash in a pattern as ``\\/``.  The old
    ``[^/]*`` form stopped at the backslash and silently applied the wrong
    pattern: ``${p//\\//_}`` returned the value unchanged instead of
    replacing its slashes, and reported the expansion as fully resolved.
    Other backslashes are left in place, so the glob compiler sees exactly
    what it saw before.
    """
    pattern: list[str] = []
    index = 0
    while index < len(rest):
        char = rest[index]
        if char == "\\" and index + 1 < len(rest) and rest[index + 1] == "/":
            pattern.append("/")
            index += 2
            continue
        if char == "/":
            return "".join(pattern), rest[index + 1:]
        pattern.append(char)
        index += 1
    return "".join(pattern), ""


def _expand_one_unbounded(
    body: str,
    vars_: dict[str, str],
    arrays: dict[str, list[str]] | None = None,
    budget: list[int] | None = None,
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
    m = re.match(r"^(\w+)(//|/)(.*)$", body)
    if m:
        name, mode, rest = m.group(1), m.group(2), m.group(3)
        pat, rep = _split_substitution(rest)
        val = vars_.get(name)
        if val is None:
            # Bash treats an unset scalar in ${var/pat/rep} as empty.
            return ""
        # Refuse before allocating: ``regex.sub`` can emit one copy of *rep*
        # per input character, so ``${x//a/<huge>}`` is O(value x replace).
        # One substitution may not exceed a line, and a pattern may not be a
        # text-sized regex.
        if len(pat) > _MAX_GLOB_PATTERN_LEN or len(rep) > _MAX_VALUE_LEN:
            return None
        if len(val) + (len(val) + 1) * len(rep) > _MAX_LINE_LEN:
            return None
        # The replacement is bash text, not a re.sub template: a backslash
        # quotes the next character and everything else stands for itself.
        # Fed raw, a legal `${x/a/\q}` raised re.error, which the sandbox
        # escalated to TokenizerUnavailable - one odd expansion must leave
        # that expansion unresolved, not the whole package unvetted.  The
        # substitution goes through a function so the text is literal.
        rep = _REPLACEMENT_ESCAPE_RE.sub(r"\1", rep)
        try:
            tokens = _glob_tokens(pat)
            return _glob_sub(tokens, val, rep, 0 if mode == "//" else 1,
                             budget)
        except re.error:
            # A pattern we cannot compile is refused, not fatal.
            return None

    # ,, , ^^ ^ - case conversion.  `${c,,}` on `c=CURL` is `curl`, which
    # is a command name assembled out of a case operator: the payload rules
    # match `curl` and saw `${c,,}`.  X002 caught it as a *technique*, which
    # is the family's job only while the tokenizer cannot do this one.
    #
    # The optional pattern after the operator restricts which characters
    # convert, and is not resolved: `${c,,[!a]}` is refused rather than
    # guessed at, because a wrong expansion is worse than an unresolved one.
    m = re.match(r"^(\w+)(,,|,|\^\^|\^)$", body)
    if m:
        name, op = m.group(1), m.group(2)
        val = vars_.get(name)
        if val is None:
            return None
        if op == ",,":
            return val.lower()
        if op == ",":
            return val[:1].lower() + val[1:]
        if op == "^^":
            return val.upper()
        return val[:1].upper() + val[1:]

    # arr[@]:offset:length - an array slice.  `${a[@]:0:1}` on `a=(curl x)`
    # is `curl`; the slice is how the name gets past a scan that reads the
    # whole array or nothing.
    m = re.match(r"^(\w+)\[(?:\*|@)\]:(\d+)(?::(\d+))?$", body)
    if m:
        name, off, length = m.group(1), int(m.group(2)), m.group(3)
        arr = arrays.get(name)
        if arr is None:
            return None
        end = off + int(length) if length else len(arr)
        return " ".join(arr[off:end])

    # ##pat  #pat  %%pat  %pat
    m = re.match(r"^(\w+)(##|#|%%|%)(.*)$", body)
    if m:
        name, op, pat = m.group(1), m.group(2), m.group(3)
        val = vars_.get(name)
        if val is None:
            return ""
        try:
            return _strip_affix(val, op, pat, budget)
        except re.error:
            # A pattern we cannot compile is refused, not fatal.
            return None

    # :-default  /  :=default
    m = re.match(r"^(\w+):([-=])(.*)$", body)
    if m:
        name, _, default = m.group(1), m.group(2), m.group(3)
        return vars_.get(name) or default

    # :+alt  /  :?message
    #
    # ``:+`` substitutes a literal when the value is set and non-empty;
    # ``:?`` is an assertion, so when the value is unset or empty the shell
    # aborts.  A resolver must not invent a value for an abort: returning
    # None leaves the expansion unreconstructed and the caller fail-closed.
    m = re.match(r"^(\w+):([+?])(.*)$", body)
    if m:
        name, op, word = m.group(1), m.group(2), m.group(3)
        value = vars_.get(name)
        if op == "+":
            return word if value else ""
        return value if value else None

    # -default  +alternate  =default  ?message (no colon: only unset
    # triggers the operator; an empty value is a set value).
    m = re.match(r"^(\w+)([-+=?])(.*)$", body)
    if m:
        name, op, word = m.group(1), m.group(2), m.group(3)
        value = vars_.get(name)
        if op == "-":
            return value if value is not None else word
        if op == "+":
            return word if value is not None else ""
        if op == "=":
            return value if value is not None else word
        return value if value is not None else None

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


def _expand_one(
    body: str,
    vars_: dict[str, str],
    arrays: dict[str, list[str]] | None = None,
    budget: list[int] | None = None,
) -> str | None:
    """The bounded form of :func:`_expand_one_unbounded`.

    A replacement larger than a line is refused rather than returned: the
    caller inserts it into attacker-controlled text, and accepting it would
    let one expansion choose the size of the result (A6/A14).  *budget* is
    shared by every expansion on one line.
    """
    result = _expand_one_unbounded(body, vars_, arrays, budget)
    if result is not None and len(result) > _MAX_LINE_LEN:
        return None
    return result


def resolve_expansions(
    text: str,
    vars_: dict[str, str],
    arrays: dict[str, list[str]] | None = None,
    limit: int = _MAX_LINE_LEN,
) -> tuple[str, bool]:
    """Resolve nested ${...} parameter expansions innermost-first.

    Returns (resolved_text, fully_resolved).
    fully_resolved is False if any ${...} remains after the cap; the caller
    MUST treat that as unresolved, never as a literal value.  A rewrite that
    would push the text past *limit* is refused the same way: the text before
    that rewrite is returned with ``False``, never a truncated line.
    """
    arrays = arrays or {}
    all_resolved = True
    # One budget for the whole line: every affix strip and substitution in
    # this call spends from it, so `_MAX_EXPANSION_PASSES` multiplies a
    # bounded cost rather than an unbounded one.
    budget = [_MAX_GLOB_STEPS]
    for _ in range(_MAX_EXPANSION_PASSES):
        before = text
        m = _INNERMOST_RE.search(text)
        if m is None:
            return text, all_resolved and "${" not in text
        replacement = _expand_one(m.group(1), vars_, arrays, budget)
        if replacement is None:
            all_resolved = False
        else:
            grown = len(text) - (m.end() - m.start()) + len(replacement)
            if grown > limit:
                return before, False
            text = text[: m.start()] + replacement + text[m.end() :]
        if text == before:
            return text, all_resolved and "${" not in text
    return text, False


def variable_table(lines: list[str], prefixes: frozenset[str]) -> dict[str, str]:
    """Assignments visible on the diff lines carrying *prefixes*.

    Reads the same ``prefixes`` set for the old side (``-``/`` ``) and the new
    side (``+``/`` ``) so a value that is unchanged-and-in-context is present
    in both, matching how ``makepkg`` would see each end-state.
    """
    table: dict[str, str] = {}
    total = 0
    for line in lines:
        match = _ASSIGN_LINE_RE.match(line)
        if not (match and match.group(1) in prefixes):
            continue
        value = match.group(3).strip().strip("'\"")
        if len(value) > _MAX_VALUE_LEN:
            # A value past the A6 ceiling is unknown, not shortened.
            table.pop(match.group(2), None)
            continue
        total += len(value)
        if total > _MAX_TABLE_BYTES:
            break
        table[match.group(2)] = value
    return table


def text_variable_table(text: str) -> dict[str, str]:
    """``name=value`` assignments anywhere in a whole recipe.

    The post-diff counterpart of :func:`variable_table`: a source URL is
    resolved from the recipe as it now stands, so the variables need not sit
    inside a hunk.
    """
    table: dict[str, str] = {}
    total = 0
    for match in _TEXT_ASSIGN_RE.finditer(text):
        value = match.group(2).strip().strip("'\"")
        if len(value) > _MAX_VALUE_LEN:
            table.pop(match.group(1), None)
            continue
        total += len(value)
        if total > _MAX_TABLE_BYTES:
            break
        table[match.group(1)] = value
    return table


def resolve_text(value: str, table: dict[str, str]) -> str:
    """Substitute *table*'s variables into *value*, bounded, both forms.

    Brace references go through :func:`resolve_expansions`, which understands
    the parameter-expansion operators (``${_ver//-/_}``).  Bare ``$NAME``
    references, which it does not cover, are substituted in the same loop,
    because one form can expand to the other.  An unknown name is left in
    place, so the caller's own fail-closed check sees it.
    """
    original = value
    for _ in range(_RESOLVE_MAX_DEPTH):
        if "$" not in value:
            break
        before = value
        value = resolve_expansions(value, table, limit=_MAX_TEXT_LEN)[0]
        refs = _BARE_VAR_RE.findall(value)
        if refs:
            widest = max((len(table.get(name, "")) for name in refs), default=0)
            # Refuse before re.sub allocates: one reference per character is
            # enough to turn a small recipe into an arbitrary-size string.
            if len(value) + len(refs) * widest > _MAX_TEXT_LEN:
                return original
            value = _BARE_VAR_RE.sub(
                lambda m: table.get(m.group(1), m.group(0)), value
            )
        if len(value) > _MAX_TEXT_LEN:
            return original
        if value == before:
            break
    return value
