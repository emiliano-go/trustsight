"""File paths a recipe touches or names, for `file_path` IOC matching.

Two surfaces, both bounded:

- the files a diff **added or modified**, read from the unified diff with
  :func:`trustsight.differ.diff_summary_from_text` (a removal is not a
  compromise signal);
- the files the recipe **declares**: the `install=` scalar and the local
  (non-URL) entries of a `source=()` array, which is where a malicious
  install hook is named.

The path is normalized through the same function the indicator list uses, so
a match cannot depend on which side folded a `./` or a backslash.
"""

from __future__ import annotations

import re

from ..differ import diff_summary_from_text
from ..iocs import normalize

__all__ = ["declared_files", "touched_paths"]

_INSTALL_RE = re.compile(r"^\s*install\s*=\s*['\"]?([^'\"\s]+)", re.MULTILINE)
_SOURCE_RE = re.compile(r"^\s*(source(?:_[A-Za-z0-9_]+)?)\s*=\s*\(", re.MULTILINE)
_QUOTED_RE = re.compile(r"""(['"])(.*?)\1""")

#: A bound on declared files.  A recipe names a handful; a thousand is a
#: generator abusing the surface, and reading every one would be work an
#: attacker chose for us.
_MAX_DECLARED = 100


def _fold(value: str) -> str | None:
    return normalize("file_path", value)


def _source_body(text: str, open_index: int) -> str:
    """The body of the array whose `(` is at *open_index*, or ""."""
    depth = 0
    for index in range(open_index, len(text)):
        char = text[index]
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return text[open_index + 1:index]
    return text[open_index + 1:]


def declared_files(current_text: str | None) -> list[str]:
    """Local files the recipe names via `install=` and `source=()`."""
    if not current_text:
        return []
    found: list[str] = []
    seen: set[str] = set()

    def record(candidate: str) -> None:
        if len(found) >= _MAX_DECLARED:
            return
        candidate = candidate.strip().strip("'\"")
        if not candidate or "://" in candidate or candidate.startswith(("$", "git+")):
            return
        candidate = candidate.split("#", 1)[0]
        folded = _fold(candidate)
        if folded and folded not in seen:
            seen.add(folded)
            found.append(folded)

    install = _INSTALL_RE.search(current_text)
    if install:
        record(install.group(1))

    for match in _SOURCE_RE.finditer(current_text):
        body = _source_body(current_text, match.end() - 1)
        for quoted in _QUOTED_RE.finditer(body):
            record(quoted.group(2))
        for token in _QUOTED_RE.sub(" ", body).split():
            record(token)

    return found


def touched_paths(diff_text: str, current_text: str | None = None
                  ) -> list[tuple[str, str]]:
    """`(path, status)` for added/modified diff files and declared files."""
    out: list[tuple[str, str]] = []
    seen: set[str] = set()
    summary = diff_summary_from_text(diff_text or "")
    for entry in summary.file_changes:
        if entry.get("status") not in ("added", "modified"):
            continue
        folded = _fold(entry.get("path", ""))
        if folded and folded not in seen:
            seen.add(folded)
            out.append((folded, entry["status"]))
    for path in declared_files(current_text):
        if path not in seen:
            seen.add(path)
            out.append((path, "declared"))
    return out
