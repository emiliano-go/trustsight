"""Split resolved diff lines into executable commands and recipe text.

``ExecutionChanges.resolved_commands`` is documented as shell commands after
tokenisation and variable expansion.  The tokenizer returns every resolved
added line, including assignments, metadata, comments and function braces.
Reading that whole list as commands put ``pkgbase = ...`` under a
"Resolved commands" heading on a full recipe.

The split is lexical: ``shell_words.command_starts`` already owns command
position for every rule family, so the renderer and the report use the same
definition.
"""

from __future__ import annotations

import re

from ...line_lex import strip_comment
from ...shell_words import command_starts

__all__ = ["is_command_line", "split_resolved_lines"]

#: Shell syntax that names a position but runs nothing.
_SHELL_STRUCTURE = frozenset({"fi", "done", "esac", "}", "{", "then", "else", "elif", "do", "!"})

#: Declaration builtins whose arguments are assignments, not a command.
_DECLARATION_RE = re.compile(r"^(?:local|declare|typeset|export|readonly)$")


def _added_text(line: str) -> str:
    """The line without its diff ``+`` prefix, if it carries one."""
    if line.startswith("+") and not line.startswith("+++"):
        return line[1:]
    return line


def is_command_line(line: str) -> bool:
    """True when *line* has a command word, not only metadata or braces."""
    line = strip_comment(_added_text(line)).strip()
    if not line:
        return False
    words = [word for word, _tail in command_starts(line)]
    words = [word for word in words if word not in _SHELL_STRUCTURE]
    if not words:
        return False
    # A bare declaration (``export PATH=...``) is not a command.  A
    # declaration containing a substitution still yields the inner command,
    # so the all() test correctly leaves it in the command list.
    return not all(_DECLARATION_RE.match(word) for word in words)


def split_resolved_lines(
    resolved: list[str],
    resolved_indices: list[int],
    raw_lines: list[str] | None = None,
    raw_indices: list[int] | None = None,
) -> tuple[list[str], list[str]]:
    """Return ``(commands, recipe_lines)`` for resolved added lines.

    The raw line is used for classification because the tokenizer spaces
    out ``name = value`` on resolved metadata; the resolved text is what the
    report shows.
    """
    raw_by_index = dict(zip(raw_indices or (), raw_lines or ()))
    commands: list[str] = []
    recipe: list[str] = []
    for position, text in enumerate(resolved):
        raw_index = (
            resolved_indices[position]
            if position < len(resolved_indices) else None
        )
        raw = raw_by_index.get(raw_index, text) if raw_index is not None else text
        (commands if is_command_line(raw) else recipe).append(text)
    return commands, recipe
