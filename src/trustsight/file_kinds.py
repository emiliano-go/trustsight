"""Which diff paths are shell.

A companion file's lines are not shell just because they look like it: a
``.desktop`` file, a patch and a JSON document all contain text that is
data to the build.  Crossfire grew this predicate first; the rule engine's
scope classifier shares it now, so a ``build() {`` inside a BUILD.gn file
cannot place the rest of that file inside a function makepkg calls.

A ``.patch`` is excluded even though it contains shell-looking text: the
text is a payload for ``patch``, and the rules that read a patch are
H018's, not the scoped ones.
"""

import re

SHELL_FILE_RE = re.compile(
    r"(?:^|/)(?:PKGBUILD|[^/]*\.(?:install|sh|bash|zsh))$", re.IGNORECASE
)

_DIFF_TARGET_RE = re.compile(r"^\+\+\+ (?:b/)?(.+?)(?:\t.*)?$")


def is_shell_file(path: str) -> bool:
    return bool(SHELL_FILE_RE.search(path or ""))


def files_at_line(lines: list[str]) -> dict[int, str]:
    """``{line_index: path}`` from the diff's own ``+++`` headers.

    Which file a hunk belongs to decides whether its lines are shell at
    all.  Lines before the first header are absent from the map, which
    reads as unknown rather than as any particular file.
    """
    files: dict[int, str] = {}
    current = None
    for index, line in enumerate(lines):
        match = _DIFF_TARGET_RE.match(line)
        if match:
            current = match.group(1).strip()
            continue
        if current is not None:
            files[index] = current
    return files


def shell_lines(lines: list[str]) -> list[str]:
    """*lines* with every line belonging to a non-shell file blanked.

    Indices, prefixes and ``+++`` headers are preserved, so a caller can
    classify and iterate the result exactly as it did the original; only
    the content of files that are not shell disappears.  A line before any
    header is treated as shell, the conservative default for fragments
    that carry no file attribution.
    """
    out: list[str] = []
    current: str | None = None
    for line in lines:
        match = _DIFF_TARGET_RE.match(line)
        if match:
            current = match.group(1).strip()
            out.append(line)
            continue
        if current is None or _may_be_shell(current):
            out.append(line)
        else:
            out.append("")
    return out


def _may_be_shell(path: str) -> bool:
    """Shell for the scope classifier: a named shell file or no extension.

    An extensionless companion may be a script the recipe executes, so it
    keeps the old treatment; only a file whose extension says it is *not*
    shell (``.json``, ``.gn``, ``.patch``, ``.fish``) is gated.  The
    execution gate in crossfire keeps the stricter allowlist, because
    there an unknown file must fail toward "this runs".
    """
    if is_shell_file(path):
        return True
    return "." not in path.rsplit("/", 1)[-1]
