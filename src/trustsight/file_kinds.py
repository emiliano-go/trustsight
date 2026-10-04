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


def is_shell_file(path: str) -> bool:
    return bool(SHELL_FILE_RE.search(path or ""))
