r"""The typed core for diff reading: one parse, many projections.

Every analysis stage used to re-walk the raw diff text and re-decide, per
module, which lines are headers, what ``+``/``-``/context means, what file a
line belongs to, and what its new-file line number is.  Each walker made
those decisions slightly differently, and the differences were a recurring
bug class: a finding attributed to the wrong file, a post-state that
dropped a content line, an array state machine that flushed on the wrong
line.  This module parses the diff once into a :class:`DiffDoc` and every
reader becomes a projection over it, so the decisions exist exactly once.

The classification mirrors the walkers the readers replaced, and the
committed projection baseline (``tests/harness/diffdoc_parity.py``) pins it
over the locked corpus.  Two deliberate legacy behaviours are preserved,
not endorsed:

* Header recognition is prefix-based (``+++ ``/``--- ``/``@@``), not
  hunk-count-based.  A content line inside a hunk whose body starts with
  ``++ `` reads as a file header, exactly as the legacy walkers read it.
  The hunk carries ``expected_lines``/``actual_lines`` so a later phase can
  flag count mismatches as a coverage signal instead of guessing.
* A removal line's ``new_lineno`` is the number the *next* post-diff line
  will carry, matching what ``map_diff_lines`` reported for ``-`` lines.
  Readers that need the old-file position use ``old_lineno``.

The security boundary is unchanged: input text is attacker-controlled, the
parser makes no trust decision, and nothing here guesses.  A line that is
not diff content (``diff --git``, ``index``, ``Binary files``, ``\ No
newline``, junk) is classified ``side="other"``: it stays in the document
so a state machine migrating here sees exactly the lines its legacy walk
saw, but no projection feeds it anywhere as content.
"""

import hashlib
import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

from .tokenizer import split_lines

#: Bumped whenever the parse or the dataclass shape changes.  A cached
#: document written under a different version is a cache miss, never a
#: partial read (spec §4).  v2 adds the typed file metadata (mode and
#: rename headers) for Addendum 5 §7.
DIFFDOC_SCHEMA_VERSION = 2

#: The tokenizer's own critical files: a change to any of them changes
#: what a line means, so a document parsed by one version must not be
#: replayed by another.  Hashed automatically rather than bumped by hand,
#: because the failure mode of a forgotten bump is a wrong analysis.
_TOKENIZER_FILES = (
    "tokenizer.py",
    "_tokenizer_engine.py",
    "sandbox/client.py",
    "sandbox/expand_worker.py",
    "sandbox/protocol.py",
)


@lru_cache(maxsize=1)
def tokenizer_version() -> str:
    """A digest of the tokenizer's critical files, or ``"unknown"``."""
    digest = hashlib.sha256()
    root = Path(__file__).resolve().parent
    try:
        for name in _TOKENIZER_FILES:
            digest.update((root / name).read_bytes())
    except OSError:
        return "unknown"
    return digest.hexdigest()[:16]

#: Matches the legacy ``differ._HUNK_HEADER_RE`` accept set exactly, with
#: the old-side start captured as well: ``^@@ -\d+(,\d+)? \+(\d+)(,\d+)? @@``.
#: Keeping the accept set identical is what makes the line map a pure
#: projection of the legacy walk.
_HUNK_HEADER_RE = re.compile(
    r"^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@"
)

#: Git's per-file metadata headers, captured into ``DiffFile`` (Addendum 5
#: §7).  A mode change is ``old mode 100644`` / ``new mode 100755``; a
#: rename is ``rename from <path>`` / ``rename to <path>``.  These lines are
#: still classed ``side="other"`` (the parse contract keeps every line), but
#: their values are typed onto the file they precede.
_OLD_MODE_RE = re.compile(r"^old mode (\d{6})$")
_NEW_MODE_RE = re.compile(r"^new mode (\d{6})$")
_RENAME_FROM_RE = re.compile(r"^rename from (.+)$")
_RENAME_TO_RE = re.compile(r"^rename to (.+)$")
#: ``new file mode`` implies the status even when the file carries no hunk
#: (an added empty file has neither ``---``/``+++`` nor a hunk), so the file
#: is materialised from this metadata alone.  ``deleted file mode`` is
#: deliberately not interpreted: a hunk-less deletion is a binary or empty
#: removal no rule needs, and materialising it would add entries to
#: ``change.files`` for every binary deletion in the corpus.
_NEW_FILE_MODE_RE = re.compile(r"^new file mode (\d{6})$")
#: The b-side path from a ``diff --git a/x b/y`` header, used to name a
#: file section that has no ``+++`` header of its own.
_DIFF_GIT_PATH_RE = re.compile(r"^diff --git .+ b/(.+)$")

#: Same cap ``differ.map_diff_lines`` applies to a ``+++`` path, so file
#: attribution agrees byte for byte.
MAX_DIFF_PATH_BYTES = 4096

#: File assumed for content lines seen before any ``+++`` header, matching
#: ``map_diff_lines``: a headerless diff is a PKGBUILD edit.
_DEFAULT_FILE = "PKGBUILD"


@dataclass(frozen=True)
class DiffLine:
    """One line of a unified diff.

    ``side`` is ``"add"``, ``"remove"``, ``"context"`` or ``"other"`` (a
    structure or junk line: ``diff --git``, ``index``, ``Binary files``,
    ``\\ No newline``, a bare ``@@`` that fails the hunk grammar, an empty
    line).  For the three content sides, ``content`` is the line's text
    with the one-character diff prefix stripped; for ``"other"`` it is the
    whole line, which has no prefix.  ``raw`` is the line as it appeared,
    prefix included, for readers whose patterns anchor on it.  ``index``
    is the 0-based index into the diff's raw lines, which is the key
    ``map_diff_lines`` used.

    ``old_lineno``/``new_lineno`` are set only for content lines inside a
    hunk (``in_hunk``); both advance per the hunk header.  A removal
    line's ``new_lineno`` is the number the next post-diff line will
    carry, kept for parity with the legacy line map; its real position is
    ``old_lineno``.

    ``file_boundary``/``hunk_boundary`` mark the first line after a file
    header (``+++ ``/``--- ``) or a hunk header: those lines are not in
    ``DiffDoc.lines`` themselves, and a state machine migrating here needs
    to see the boundary exactly where its legacy walk saw the header.
    """

    index: int
    side: str
    content: str
    raw: str
    file: str
    old_lineno: int | None
    new_lineno: int | None
    in_hunk: bool
    file_boundary: bool = False
    hunk_boundary: bool = False

    @property
    def is_content(self) -> bool:
        """Whether the line is diff content (not structure or junk)."""
        return self.side != "other"

    def to_dict(self) -> dict:
        return {
            "index": self.index,
            "side": self.side,
            "content": self.content,
            "raw": self.raw,
            "file": self.file,
            "old_lineno": self.old_lineno,
            "new_lineno": self.new_lineno,
            "in_hunk": self.in_hunk,
            "file_boundary": self.file_boundary,
            "hunk_boundary": self.hunk_boundary,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "DiffLine":
        return cls(
            index=data["index"],
            side=data["side"],
            content=data["content"],
            raw=data["raw"],
            file=data["file"],
            old_lineno=data["old_lineno"],
            new_lineno=data["new_lineno"],
            in_hunk=data["in_hunk"],
            file_boundary=bool(data.get("file_boundary", False)),
            hunk_boundary=bool(data.get("hunk_boundary", False)),
        )


@dataclass(frozen=True)
class DiffHunk:
    """One ``@@`` hunk: its declared starts and its parsed content lines.

    ``expected_lines``/``actual_lines`` compare the header's declared
    new-side count with the number of post-side lines actually parsed.  A
    mismatch means the diff is truncated or malformed; the parser reports
    the fact and does not repair it.
    """

    old_start: int
    new_start: int
    lines: tuple[DiffLine, ...]
    expected_lines: int | None = None
    actual_lines: int = 0

    def to_dict(self) -> dict:
        return {
            "old_start": self.old_start,
            "new_start": self.new_start,
            "lines": [line.to_dict() for line in self.lines],
            "expected_lines": self.expected_lines,
            "actual_lines": self.actual_lines,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "DiffHunk":
        return cls(
            old_start=data["old_start"],
            new_start=data["new_start"],
            lines=tuple(DiffLine.from_dict(line) for line in data["lines"]),
            expected_lines=data.get("expected_lines"),
            actual_lines=int(data.get("actual_lines", 0)),
        )


@dataclass(frozen=True)
class DiffFile:
    """One file's patch: path, status, hunks, and file-level metadata.

    ``status`` is ``"added"`` when the old side is ``/dev/null``,
    ``"removed"`` when the new side is, else ``"modified"``.

    ``old_mode``/``new_mode`` are git's octal file modes (``"100644"``,
    ``"100755"``, ``"120000"`` ...) when the diff carried ``old mode``/``new
    mode`` lines; empty otherwise.  ``rename_from``/``rename_to`` are the
    paths from ``rename from``/``rename to`` (git rename headers), empty for
    an ordinary edit.  A pure rename carries no hunks and no ``+++`` header,
    so a file section is materialised here from its rename/mode metadata
    alone (Addendum 5 §7), with ``path`` naming the post-rename file.
    """

    path: str
    old_path: str
    status: str
    hunks: tuple[DiffHunk, ...] = field(default_factory=tuple)
    old_mode: str = ""
    new_mode: str = ""
    rename_from: str = ""
    rename_to: str = ""

    @property
    def renamed(self) -> bool:
        """Whether the diff declared this a rename."""
        return bool(self.rename_from or self.rename_to)

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "old_path": self.old_path,
            "status": self.status,
            "hunks": [hunk.to_dict() for hunk in self.hunks],
            "old_mode": self.old_mode,
            "new_mode": self.new_mode,
            "rename_from": self.rename_from,
            "rename_to": self.rename_to,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "DiffFile":
        return cls(
            path=data["path"],
            old_path=data["old_path"],
            status=data["status"],
            hunks=tuple(DiffHunk.from_dict(hunk) for hunk in data["hunks"]),
            old_mode=data.get("old_mode", ""),
            new_mode=data.get("new_mode", ""),
            rename_from=data.get("rename_from", ""),
            rename_to=data.get("rename_to", ""),
        )


@dataclass(frozen=True)
class DiffDoc:
    """A parsed unified diff: the files, and every line in order.

    ``lines`` flattens all hunks plus any lines seen outside a hunk,
    including structure and junk lines (``side="other"``): malformed input
    still yields data, classified, never dropped.  The projections below
    reproduce the readers they replaced byte for byte; the committed
    projection baseline pins that over the locked corpus.
    """

    files: tuple[DiffFile, ...]
    lines: tuple[DiffLine, ...]

    def line_map(self) -> dict[int, tuple[str, int]]:
        """The ``differ.map_diff_lines`` projection: raw index → (file, line).

        Only in-hunk content lines are keyed, and a removal line carries
        the next post-diff line number, exactly as the legacy walk did.
        """
        return {
            line.index: (line.file, line.new_lineno)
            for line in self.lines
            if line.in_hunk and line.is_content
        }

    def post_lines(self) -> list[str]:
        """The post-diff file text: context and addition contents.

        Projection of ``differ._post_diff_lines``: header and junk lines
        never contribute, and a content line outside any hunk still
        counts, as the legacy walk allowed.
        """
        return [
            line.content for line in self.lines
            if line.side in ("add", "context")
        ]

    def pre_lines(self) -> list[str]:
        """The pre-diff file text: context and removal contents.

        Projection of ``differ._pre_diff_lines``.
        """
        return [
            line.content for line in self.lines
            if line.side in ("remove", "context")
        ]

    def post_origins(self) -> list[tuple[str, int, str]]:
        """``(file, line, side)`` for each :meth:`post_lines` entry.

        A line the diff does not number carries 0, which reads as unknown
        rather than as line zero of a file.
        """
        return [
            (line.file, line.new_lineno or 0, line.side)
            for line in self.lines
            if line.side in ("add", "context")
        ]

    def pre_origins(self) -> list[tuple[str, int, str]]:
        """``(file, line, side)`` for each :meth:`pre_lines` entry."""
        return [
            (line.file, line.old_lineno or 0, line.side)
            for line in self.lines
            if line.side in ("remove", "context")
        ]

    def added_lines(self) -> list[DiffLine]:
        """Content lines on the ``+`` side, wherever they appeared."""
        return [line for line in self.lines if line.side == "add"]

    def removed_lines(self) -> list[DiffLine]:
        """Content lines on the ``-`` side, wherever they appeared."""
        return [line for line in self.lines if line.side == "remove"]

    def post_text(self) -> str:
        """The post-diff reconstruction as one string."""
        return "\n".join(self.post_lines())

    def pre_text(self) -> str:
        """The pre-diff reconstruction as one string."""
        return "\n".join(self.pre_lines())

    def cut_hunks(self) -> list[tuple[str, int, int, int]]:
        """``(file, hunk new-start, declared, parsed)`` for hunks whose
        parsed post-side count disagrees with the header's declaration.

        The parser reports the arithmetic and does not repair it; this is
        the coverage layer's read of that fact (the ``partial_hunk`` gap),
        and the counts are what the gap quotes back to the reader so the
        missing tail has a size.  The predicate is ``!=``, not ``<``: a hunk
        that parses *more* lines than it declares is a malformed/lying
        header too (spec §2), and a count mismatch in either direction means
        the reader cannot trust the stream's arithmetic.
        """
        return [
            (f.path, h.new_start, h.expected_lines, h.actual_lines)
            for f in self.files for h in f.hunks
            if h.expected_lines is not None and h.actual_lines != h.expected_lines
        ]

    def to_dict(self) -> dict:
        """A stable, versioned byte-format view of this document (spec §4).

        JSON only - never pickle: the document is attacker-derived and a
        deserialiser that executes is the boundary violation the sandbox
        exists to avoid.  The parser schema and the tokenizer digest ride
        the payload so a replay can refuse a document it did not parse.
        """
        return {
            "schema_version": DIFFDOC_SCHEMA_VERSION,
            "tokenizer_version": tokenizer_version(),
            "files": [file.to_dict() for file in self.files],
            "lines": [line.to_dict() for line in self.lines],
        }

    @classmethod
    def from_dict(cls, data: object) -> "DiffDoc | None":
        """Rebuild a document from :meth:`to_dict`, or ``None`` on a miss.

        A version mismatch, a tokenizer change, or a malformed payload is
        a cache miss rather than an error or a partial document: the cache
        is an optimization, never an authority (spec §4).
        """
        if not isinstance(data, dict):
            return None
        if data.get("schema_version") != DIFFDOC_SCHEMA_VERSION:
            return None
        current = tokenizer_version()
        if current == "unknown" or data.get("tokenizer_version") != current:
            return None
        try:
            files = tuple(DiffFile.from_dict(f) for f in data["files"])
            lines = tuple(DiffLine.from_dict(line) for line in data["lines"])
        except (KeyError, TypeError, ValueError):
            return None
        return cls(files=files, lines=lines)


#: Git's diff path prefixes.  ``a/`` and ``b/`` are the defaults; with
#: ``diff.mnemonicprefix = true`` libgit2 emits ``c/`` (commit), ``i/``
#: (index), ``w/`` (worktree) or ``o/`` (object) instead.  TrustSight
#: diffs commit trees, so a reviewer with that setting on saw every
#: location as ``c/PKGBUILD``.  Exactly one prefix is stripped: a real
#: path that begins with one of these letters arrives with the diff
#: prefix in front of it (``b/c/real``), so one strip is the path.
_DIFF_PATH_PREFIXES = ("a/", "b/", "c/", "i/", "w/", "o/")


def strip_diff_path_prefix(name: str) -> str:
    """*name* with one git diff path prefix removed, if it carries one."""
    for prefix in _DIFF_PATH_PREFIXES:
        if name.startswith(prefix):
            return name[len(prefix):]
    return name


def _header_path(raw: str) -> str:
    """The path from a ``+++`` header, with the legacy walk's exact steps.

    ``map_diff_lines`` strips, removes the diff path prefix, and caps at
    ``MAX_DIFF_PATH_BYTES``; it deliberately does not split a trailing tab
    (that is ``_diff_file_path``'s convention, used by the summary), and
    matching it is what keeps the line map a pure projection.
    """
    name = strip_diff_path_prefix(raw.strip())
    return name[:MAX_DIFF_PATH_BYTES]


def parse_diff_lines(lines: list[str]) -> DiffDoc:
    """Parse already-split diff lines into a :class:`DiffDoc`.

    This is the entry point for callers that already hold the split lines
    (so the text is walked exactly once); :func:`parse_diff` is the
    convenience wrapper that splits first.  The parse is memoised on the
    line contents, because the analysis re-reads the same diff dozens of
    times (69 parses per diff measured on the locked corpus) and the
    document is immutable.
    """
    return _parse_diff_lines_cached(tuple(lines))


@lru_cache(maxsize=8)
def _parse_diff_lines_cached(lines: tuple[str, ...]) -> DiffDoc:
    """The one parse, reused across every reader of the same diff.

    Content keyed rather than identity keyed: the callers rebuild the line
    list through ``split_lines``, so a fresh list (and fresh tuple) arrives
    each time while the strings compare equal.  Bounded to the analysis
    working set - the raw diff and its clamped copies - so a huge document
    cannot accumulate.
    """
    out_lines: list[DiffLine] = []
    # Files are frozen, so hunks accumulate in a parallel builder list and
    # the DiffFile objects are assembled at the end.
    file_meta: list[tuple[str, str, str, str, str, str, str]] = []
    file_hunks: list[list[DiffHunk]] = []
    current_file = _DEFAULT_FILE
    pending_old_path = ""
    in_hunk = False
    old_lineno = 0
    new_lineno = 0
    hunk_old_start = 0
    hunk_new_start = 0
    hunk_lines: list[DiffLine] = []
    hunk_expected: int | None = None
    pending_file_boundary = False
    pending_hunk_boundary = False
    # File-level metadata (Addendum 5 §7): mode changes and rename headers,
    # attached to the file they precede.  A pure rename has no ``+++``/hunk,
    # so it is materialised as a file from this metadata alone.
    pending_old_mode = ""
    pending_new_mode = ""
    pending_rename_from = ""
    pending_rename_to = ""
    pending_section_path = ""
    pending_new_file = False
    pending_binary = False
    section_has_file = False

    def reset_pending_metadata() -> None:
        nonlocal pending_old_mode, pending_new_mode
        nonlocal pending_rename_from, pending_rename_to
        nonlocal pending_section_path, pending_new_file, pending_binary
        pending_old_mode = pending_new_mode = ""
        pending_rename_from = pending_rename_to = ""
        pending_section_path = ""
        pending_new_file = pending_binary = False

    def flush_rename_section() -> None:
        """Materialise a file for a section with metadata but no ``+++``.

        Git emits no ``---``/``+++``/hunk for a pure rename, so without this
        the rename would be invisible to every reader.  Only fires when the
        section carried no header, so it never competes with a real file.
        """
        nonlocal section_has_file
        if pending_binary:
            return
        if section_has_file or not (
            pending_old_mode or pending_new_mode
            or pending_rename_from or pending_rename_to
            or pending_new_file
        ):
            return
        # Close any hunk the previous section left open *before* adding a
        # new file slot.  The legacy walk let an open hunk ride across a
        # ``diff --git`` and closed it at the next ``---``/``+++``/``@@``,
        # appending it to whatever file was last; appending here first
        # keeps that hunk on its own file and off the rename file.
        close_hunk()
        if section_has_file:
            return
        path = (pending_rename_to or pending_section_path
                or pending_rename_from or current_file)
        old_path = pending_rename_from or path
        status = "added" if pending_new_file else _status(old_path, path)
        file_meta.append((
            path, old_path, status,
            pending_old_mode, pending_new_mode,
            pending_rename_from, pending_rename_to,
        ))
        file_hunks.append([])
        section_has_file = True

    def close_hunk() -> None:
        nonlocal hunk_lines, hunk_expected, section_has_file
        if hunk_lines or hunk_expected is not None:
            actual = sum(1 for line in hunk_lines if line.side != "remove")
            hunk = DiffHunk(
                old_start=hunk_old_start,
                new_start=hunk_new_start,
                lines=tuple(hunk_lines),
                expected_lines=hunk_expected,
                actual_lines=actual,
            )
            if not file_meta:
                # A hunk before any ``+++`` header: a headerless diff is a
                # PKGBUILD edit, as the legacy map assumed.
                file_meta.append((current_file, pending_old_path,
                                  _status(pending_old_path, current_file),
                                  "", "", "", ""))
                file_hunks.append([])
                section_has_file = True
            file_hunks[-1].append(hunk)
        hunk_lines = []
        hunk_expected = None
        # ``in_hunk`` is deliberately not reset here: the legacy map leaves
        # it standing across file headers, so a content line between a
        # ``+++`` header and the next ``@@`` is still mapped, and parity
        # means keeping that (malformed-input) behaviour, not fixing it.

    for i, line in enumerate(lines):
        if line.startswith("diff --git "):
            # A new file section begins: materialise a rename-only previous
            # section, then clear its metadata.  ``close_hunk`` is
            # deliberately *not* called here - the legacy walk left a hunk
            # open across a ``diff --git`` line, and parity keeps that.
            flush_rename_section()
            reset_pending_metadata()
            section_has_file = False
            git_path = _DIFF_GIT_PATH_RE.match(line)
            if git_path:
                pending_section_path = strip_diff_path_prefix(
                    git_path.group(1).strip())[:MAX_DIFF_PATH_BYTES]
        if line.startswith("+++ "):
            close_hunk()
            current_file = _header_path(line[4:])
            file_meta.append(
                (current_file, pending_old_path,
                 _status(pending_old_path, current_file),
                 pending_old_mode, pending_new_mode,
                 pending_rename_from, pending_rename_to))
            file_hunks.append([])
            section_has_file = True
            reset_pending_metadata()
            out_lines.append(DiffLine(
                index=i, side="other", content=line, raw=line,
                file=current_file, old_lineno=None, new_lineno=None,
                in_hunk=False,
            ))
            pending_file_boundary = True
            continue
        if line.startswith("--- "):
            close_hunk()
            pending_old_path = line[4:].strip()
            out_lines.append(DiffLine(
                index=i, side="other", content=line, raw=line,
                file=current_file, old_lineno=None, new_lineno=None,
                in_hunk=False,
            ))
            pending_file_boundary = True
            continue
        m = _HUNK_HEADER_RE.match(line)
        if m:
            close_hunk()
            hunk_old_start = int(m.group(1))
            hunk_new_start = int(m.group(2))
            old_lineno = hunk_old_start
            new_lineno = hunk_new_start
            hunk_expected = _declared_new_count(line)
            in_hunk = True
            out_lines.append(DiffLine(
                index=i, side="other", content=line, raw=line,
                file=current_file, old_lineno=None, new_lineno=None,
                in_hunk=False,
            ))
            pending_hunk_boundary = True
            continue
        if line.startswith("+"):
            side = "add"
        elif line.startswith("-"):
            side = "remove"
        elif line.startswith(" "):
            side = "context"
        else:
            # ``diff --git``, ``index``, ``Binary files``, ``\ No newline``,
            # empty lines, and bare ``@@``-junk: kept, classified as
            # structure, so a migrated state machine sees the same lines
            # its legacy walk saw.  Mode and rename headers are read for
            # the typed file metadata while still emitted here.
            old_mode_m = _OLD_MODE_RE.match(line)
            if old_mode_m:
                pending_old_mode = old_mode_m.group(1)
            new_mode_m = _NEW_MODE_RE.match(line)
            if new_mode_m:
                pending_new_mode = new_mode_m.group(1)
            new_file_m = _NEW_FILE_MODE_RE.match(line)
            if new_file_m:
                pending_new_file = True
                pending_new_mode = new_file_m.group(1)
            if line.startswith("Binary files "):
                pending_binary = True
            rename_from_m = _RENAME_FROM_RE.match(line)
            if rename_from_m:
                pending_rename_from = rename_from_m.group(1).strip()
            rename_to_m = _RENAME_TO_RE.match(line)
            if rename_to_m:
                pending_rename_to = rename_to_m.group(1).strip()
            entry = DiffLine(
                index=i, side="other", content=line, raw=line,
                file=current_file, old_lineno=None, new_lineno=None,
                in_hunk=in_hunk,
                file_boundary=pending_file_boundary,
                hunk_boundary=pending_hunk_boundary,
            )
            pending_file_boundary = pending_hunk_boundary = False
            out_lines.append(entry)
            continue
        if in_hunk:
            if side == "remove":
                old_no, new_no = old_lineno, new_lineno
                old_lineno += 1
            elif side == "add":
                old_no, new_no = None, new_lineno
                new_lineno += 1
            else:
                old_no, new_no = old_lineno, new_lineno
                old_lineno += 1
                new_lineno += 1
        else:
            old_no = new_no = None
        entry = DiffLine(
            index=i, side=side, content=line[1:], raw=line,
            file=current_file, old_lineno=old_no, new_lineno=new_no,
            in_hunk=in_hunk,
            file_boundary=pending_file_boundary,
            hunk_boundary=pending_hunk_boundary,
        )
        pending_file_boundary = pending_hunk_boundary = False
        out_lines.append(entry)
        if in_hunk:
            hunk_lines.append(entry)
    close_hunk()
    flush_rename_section()
    files = tuple(
        DiffFile(path=path, old_path=old_path, status=status,
                 hunks=tuple(hunks), old_mode=old_mode, new_mode=new_mode,
                 rename_from=rename_from, rename_to=rename_to)
        for (path, old_path, status, old_mode, new_mode,
             rename_from, rename_to), hunks in zip(file_meta, file_hunks)
    )
    return DiffDoc(files=files, lines=tuple(out_lines))


def _status(old_path: str, new_path: str) -> str:
    """The file's change kind from its ``/dev/null`` markers."""
    if old_path == "/dev/null":
        return "added"
    if new_path == "/dev/null":
        return "removed"
    return "modified"


def _declared_new_count(header: str) -> int | None:
    """The hunk header's declared new-side line count, when present.

    ``@@ -1,3 +1,4 @@`` declares 4; ``@@ -1 +1 @@`` omits the count and
    means 1.  A header that does not parse to a count reports None rather
    than a guess.
    """
    try:
        plus = header.split("+", 1)[1].split(" @@", 1)[0]
        if "," in plus:
            return int(plus.split(",", 1)[1])
        return 1
    except (IndexError, ValueError):
        return None


def parse_diff(diff_text: str) -> DiffDoc:
    """Parse unified-diff text into a :class:`DiffDoc`.

    Splits with ``tokenizer.split_lines`` so the line terminators are the
    sandbox's decision, exactly as every legacy reader split them.
    """
    return parse_diff_lines(split_lines(diff_text))
