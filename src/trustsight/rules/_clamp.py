"""Extracted from rules.py: _clamp."""

import re
from ..tokenizer import (
    joined_indexed,
    split_lines,
)
from ._common import MAX_RULE_LINE_BYTES, MAX_SCANNED_LINES, _log

__all__ = ['_COMMAND_CHAIN_RE', '_COMMENT_OR_DEP_RE', '_DEP_DECLARATION_RE', '_MESSAGE_LINE_RE', '_WHITESPACE_RUN_RE', '_has_unquoted_redirect', '_is_message_line', '_to_pairs', 'clamp', 'clamp_diff_lines', 'clamp_text', 'filter_raw_lines', 'get_raw_diff_lines', 'get_raw_diff_lines_indexed']

_COMMENT_OR_DEP_RE = re.compile(
    r"^(?:\+|)\s*(?:"
    r"#"
    r"|(?:depends|makedepends|optdepends|checkdepends)\s*=\s*\("
    r")"
)

_DEP_DECLARATION_RE = re.compile(
    r"^(?:\+|-|)\s*(?:depends|makedepends|optdepends|checkdepends)\s*=\s*\("
)

_MESSAGE_LINE_RE = re.compile(
    r'^(?:\+|)\s*(?:echo|printf|note|msg|warning|error|info)\s+["\']'
)

_COMMAND_CHAIN_RE = re.compile(r"[;&|]|\$\(|`")

def _has_unquoted_command_chain(line: str) -> bool:
    """True when a chain or substitution operator runs, not just printed.

    A control operator inside quotes is literal text.  ``echo "run: echo x |
    sudo tee y"`` is an instruction addressed to the reader, not a pipeline.
    The previous whole-line search saw the quoted bar, so the line stopped
    counting as a message and H004 read the printed ``sudo`` as the
    escalation itself (keymux, a CRITICAL on a hint).

    Command substitution is the one operator that still runs inside double
    quotes (``echo "$(id)"`` executes ``id``), so it stands down only inside
    single quotes; ``|``, ``;`` and ``&`` are literal inside either.
    """
    quote = ""
    i = 0
    n = len(line)
    while i < n:
        char = line[i]
        if quote == "'":
            if char == "'":
                quote = ""
        elif quote == '"':
            if char == '"':
                quote = ""
            elif char == "`" or (char == "$" and i + 1 < n and line[i + 1] == "("):
                return True
        elif char in "\"'":
            quote = char
        elif char in ";&|`" or (char == "$" and i + 1 < n and line[i + 1] == "("):
            return True
        i += 1
    return False

def _has_unquoted_redirect(line: str) -> bool:
    """True when *line* redirects outside any quoted text.

    `echo "x" > file` writes a file rather than addressing a reader, which
    is the ordinary way a recipe appends a line to a system config. A `>`
    *inside* the quotes is punctuation: `echo "==> run sudo pacman -S qemu"`
    is the exact shape whose message classification keeps H017 and H035 off
    printed instructions, and searching the whole line for `>` put that
    false positive back on two benign packages.

    Written as a scan rather than a regex on purpose. The obvious pattern -
    `(?:"[^"]*"|'[^']*'|[^"'>])*>` - is a nested alternation that backtracks
    catastrophically when there is no redirect at all: 942 ms on a
    full-length line, which the regex audit refuses.
    """
    quote = ""
    for char in line:
        if quote:
            if char == quote:
                quote = ""
        elif char in "\"'":
            quote = char
        elif char == ">":
            return True
    return False

def clamp_diff_lines(diff_text: str, package_name: str = "") -> tuple[str, bool]:
    """Cut *diff_text* to :data:`MAX_SCANNED_LINES`, reporting whether it cut.

    A function rather than four lines inlined at each analysis entry point.
    The byte cap that sits next to this one was originally written on the
    git path alone, which left every other caller unbounded, and the same
    mistake is available here: `analyze_package` and `scan_diff` are
    parallel implementations that both tokenize and both match.
    """
    lines = diff_text.split("\n")
    if len(lines) <= MAX_SCANNED_LINES:
        return diff_text, False
    # Comments and blank lines are not content, and spending the budget on
    # them is the line-count twin of padding a single line with spaces:
    # 20,000 `# c` lines pushed a `curl … | bash` past the ceiling and
    # every pattern rule went blind together.
    #
    # They are still *emitted*, because dropping them would renumber every
    # line after them and the reported line number is evidence. What
    # changes is that they no longer count against the limit - and the
    # total is held at twice it, so the cost this cap exists to bound
    # stays bounded and a padder has to supply real content for at least
    # half of what it sends.
    kept: list[str] = []
    content = 0
    for line in lines:
        body = line[1:] if line[:1] in ("+", "-", " ") else line
        stripped = body.strip()
        if stripped and not stripped.startswith("#"):
            content += 1
        kept.append(line)
        if content >= MAX_SCANNED_LINES or len(kept) >= MAX_SCANNED_LINES * 2:
            break
    if len(kept) == len(lines):
        return diff_text, False
    _log.warning(
        "diff for %s holds %d lines; matching %d (%d with content)",
        package_name or "<unnamed>", len(lines), len(kept), content,
    )
    return "\n".join(kept), True

_WHITESPACE_RUN_RE = re.compile(r"[^\S\n]{2,}")

def clamp(line: str) -> str:
    """Truncate *line* to :data:`MAX_RULE_LINE_BYTES` for matching.

    Whitespace runs are collapsed first, so the budget is spent on content
    rather than on padding chosen to exhaust it.
    """
    if len(line) <= MAX_RULE_LINE_BYTES:
        return line
    line = _WHITESPACE_RUN_RE.sub(" ", line)
    return line if len(line) <= MAX_RULE_LINE_BYTES else line[:MAX_RULE_LINE_BYTES]

def clamp_text(text: str | None) -> str | None:
    """Apply :func:`clamp` to every line of *text*, keeping the line count.

    The rules in ``analysis/`` are regexes too, and there are more of them
    than there are in ``rules.toml``, but they match against the diff text
    directly rather than through :func:`apply_rules`, so the per-line clamp
    never reached them.  One 5 MiB line cost 0.17s through ``apply_rules``
    and 15s through the code-emitted rules, which is an attacker-chosen
    multiplier on how long a review takes.

    Lines are shortened, never dropped, so every index still refers to the
    line it did before and ``map_diff_lines`` keeps pointing at the right
    place.  Callers must measure ``coverage.oversized_lines`` on the
    *original* text first: after this, the evidence of truncation is gone,
    and a bound that drops content without recording it is exactly what
    the ``line_truncated`` gap exists to prevent.
    """
    if text is None:
        return None
    if len(text) <= MAX_RULE_LINE_BYTES:
        return text
    return "\n".join(clamp(line) for line in text.split("\n"))

def _to_pairs(lines: list[str]) -> list[tuple[int, str]]:
    """pair each line with its original index"""
    return [(i, clamp(line)) for i, line in enumerate(lines)]

def filter_raw_lines(lines: list[str]) -> list[tuple[int, str]]:
    """Remove comment lines and dependency declarations from raw diff lines.

    Returns (original_index, line) pairs so callers can map back to context.
    """
    return [
        (i, clamp(line)) for i, line in enumerate(lines)
        if not _COMMENT_OR_DEP_RE.match(line)
    ]

def _is_message_line(line: str) -> bool:
    """True when *line* is a message and nothing else."""
    return (
        bool(_MESSAGE_LINE_RE.match(line))
        and not _has_unquoted_command_chain(line)
        and not _has_unquoted_redirect(line)
    )

def get_raw_diff_lines_indexed(diff_text: str) -> tuple[list[str], list[int]]:
    """Return non-empty diff lines with continuations joined, plus the
    ``split_lines(diff_text)`` index each logical line starts at.

    The index list parallels the line list and is what
    :func:`apply_rules` needs to attach a file/line to a raw-line finding:
    :func:`~trustsight.differ.map_diff_lines` is keyed on split-lines
    positions, and joining continuations and dropping blank lines makes a
    raw line's own position a different domain - off by the number of
    dropped lines above it, or onto another file's lines entirely.
    """
    lines: list[str] = []
    indices: list[int] = []
    for raw_index, line in joined_indexed(split_lines(diff_text)):
        stripped = line.strip()
        if stripped:
            lines.append(stripped)
            indices.append(raw_index)
    return lines, indices

def get_raw_diff_lines(diff_text: str) -> list[str]:
    """Return non-empty diff lines with continuations joined."""
    return get_raw_diff_lines_indexed(diff_text)[0]
