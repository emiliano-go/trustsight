"""Extracted from differ.py: _diff."""

from ..diffdoc import parse_diff_lines, strip_diff_path_prefix
from ..schema import DiffSummary
from ..tokenizer import split_lines
from ._bounds import MAX_DIFF_BYTES, MAX_DIFF_PATH_BYTES, MAX_DIFF_SUMMARY_FILES

__all__ = ['_bounded_path', '_diff_file_path', 'diff_summary_from_text', 'generate_diff', 'generate_diff_bounded', 'map_diff_lines', 'truncate_diff']

def truncate_diff(diff_text: str, max_bytes: int = MAX_DIFF_BYTES) -> tuple[str, bool]:
    """Return a deterministic UTF-8-safe prefix and truncation status."""
    if not isinstance(max_bytes, int) or isinstance(max_bytes, bool) or max_bytes < 1:
        raise ValueError("max_bytes must be a positive integer")
    max_bytes = min(max_bytes, MAX_DIFF_BYTES)
    encoded = diff_text.encode("utf-8", errors="replace")
    if len(encoded) <= max_bytes:
        return diff_text, False
    return encoded[:max_bytes].decode("utf-8", errors="ignore"), True

def map_diff_lines(diff_text: str) -> dict[int, tuple[str, int]]:
    """Map diff-line index → (file_name, new_file_line_number).

    Returns a dict keyed by the 0-based line index into *diff_text*'s
    lines, with each value being ``(file_name, line_number)``.
    Only content lines (`` `` context, ``+`` addition, ``-`` removal)
    produce entries; header lines are not mapped.

    A projection of the typed parse (:mod:`trustsight.diffdoc`): the
    file attribution, the hunk gating and the line counter are the
    parser's decisions now, made once, and the committed projection
    baseline pins the shape over the whole locked corpus.
    """
    return parse_diff_lines(split_lines(diff_text)).line_map()

def _bounded_path(path: str) -> str:
    """A path bounded and made UTF-8 safe for retention in a summary.

    Measuring with ``errors="replace"`` but returning the original string
    left a surrogate in the path (a filename git stores as arbitrary bytes),
    and the worker's JSON encoder then raised on it.  The sanitised value is
    what travels.
    """
    encoded = path.encode("utf-8", errors="replace")
    if len(encoded) <= MAX_DIFF_PATH_BYTES:
        return encoded.decode("utf-8")
    return encoded[:MAX_DIFF_PATH_BYTES].decode("utf-8", errors="ignore")

def generate_diff_bounded(
    repo, old_oid: str, new_oid: str, context_lines: int = 3,
    max_bytes: int | None = None,
) -> tuple[str, DiffSummary, bool]:
    """Generate a unified diff, and say whether anything was dropped.

    The libgit2 work lives in :mod:`trustsight.sandbox.git_project` (A16); the
    production path reaches it through a ``GitSession``, and a fixture
    repository is handled in-process for tests.
    """
    from ..sandbox.git_project import generate_diff_bounded as _core

    return _core(repo, old_oid, new_oid, context_lines, max_bytes)

def generate_diff(
    repo, old_oid: str, new_oid: str, context_lines: int = 3,
    max_bytes: int | None = None,
) -> tuple[str, DiffSummary]:
    """Two-value form, for callers that do not consume the truncation flag."""
    text, summary, _truncated = generate_diff_bounded(
        repo, old_oid, new_oid, context_lines, max_bytes
    )
    return text, summary

def diff_summary_from_text(diff_text: str) -> DiffSummary:
    """Build a ``DiffSummary`` from raw unified-diff text.

    The typed document already knows each file's status, rename metadata and
    line counts.  This projection used to walk the raw text three times,
    which missed rename-only and binary-only files entirely: a pure rename
    or a replaced binary produced an empty ``files_changed``, so
    ``is_trivial`` could call it no change at all.  Paths are bounded with
    the same helper the git producer uses, and the file list honours the
    shared summary cap.
    """
    if not diff_text:
        return DiffSummary()

    doc = parse_diff_lines(split_lines(diff_text))
    lines_added = sum(1 for line in doc.lines if line.side == "add")
    lines_removed = sum(1 for line in doc.lines if line.side == "remove")

    seen: set[str] = set()
    file_changes: list[dict] = []
    for file in doc.files:
        if len(seen) >= MAX_DIFF_SUMMARY_FILES:
            break
        if file.status == "removed":
            path = _bounded_path(_diff_file_path(file.old_path or file.path))
        else:
            path = _bounded_path(_diff_file_path(file.path))
        if not path or path == "/dev/null" or path in seen:
            continue
        seen.add(path)
        status = "renamed" if file.renamed else file.status
        if path not in (".SRCINFO", ".gitignore"):
            file_changes.append({"path": path, "status": status})

    # A binary delta has no `---`/`+++` pair and no hunk, so the typed file
    # list is empty above; git still writes the two paths on its marker line.
    from ._companions import _BINARY_DIFF_MARKER_RE

    for line in doc.lines:
        if not line.raw.startswith("Binary files "):
            continue
        match = _BINARY_DIFF_MARKER_RE.match(line.raw)
        if match is None:
            continue
        old_path, new_path = match.group(1), match.group(2)
        if new_path == "/dev/null":
            path = _bounded_path(_diff_file_path(old_path))
            status = "removed"
        elif old_path == "/dev/null":
            path = _bounded_path(_diff_file_path(new_path))
            status = "added"
        else:
            path = _bounded_path(_diff_file_path(new_path))
            status = "modified"
        if not path or path == "/dev/null" or path in seen:
            continue
        if len(seen) >= MAX_DIFF_SUMMARY_FILES:
            break
        seen.add(path)
        if path not in (".SRCINFO", ".gitignore"):
            file_changes.append({"path": path, "status": status})

    file_changes.sort(key=lambda item: (item["path"], item["status"]))
    return DiffSummary(
        lines_added=lines_added,
        lines_removed=lines_removed,
        files_changed=sorted(seen),
        file_changes=file_changes,
    )

def _diff_file_path(header: str) -> str:
    """The path from a `---`/`+++` header, git's path prefix stripped.

    The prefix may be a mnemonic one (`c/` for a commit diff) when the
    reviewer's git config sets `diff.mnemonicprefix`; `strip_diff_path_prefix`
    handles both spellings.
    """
    path = header.strip()
    if "\t" in path:
        path = path.split("\t", 1)[0]
    return strip_diff_path_prefix(path)
