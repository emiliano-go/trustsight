r"""The typed core for diff reading: one parse, many projections.

Every analysis stage used to re-walk the raw diff text and re-decide, per
module, which lines are headers, what ``+``/``-``/context means, what file a
line belongs to, and what its new-file line number is.  Each walker made
those decisions slightly differently, and the differences were a recurring
bug class: a finding attributed to the wrong file, a post-state that
dropped a content line, an array state machine that flushed on the wrong
line.  This module parses the diff once into a :class:`DiffDoc` and every
reader becomes a projection over it, so the decisions exist exactly once.

Phase-0 contract: the classification here mirrors the legacy text walkers
*exactly*, so each legacy function is provably a projection of the same
parse (see ``tests/harness/diffdoc_parity.py``).  Two deliberate legacy
behaviours are preserved, not endorsed:

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
newline``, junk) is classified as structure and reaches no projection that
legacy code would have fed with content.
"""

import re
from dataclasses import dataclass, field

from .tokenizer import split_lines

#: Matches the legacy ``differ._HUNK_HEADER_RE`` accept set exactly, with
#: the old-side start captured as well: ``^@@ -\d+(,\d+)? \+(\d+)(,\d+)? @@``.
#: Keeping the accept set identical is what makes the line map a pure
#: projection of the legacy walk.
_HUNK_HEADER_RE = re.compile(
    r"^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@"
)

#: Same cap ``differ.map_diff_lines`` applies to a ``+++`` path, so file
#: attribution agrees byte for byte.
MAX_DIFF_PATH_BYTES = 4096

#: File assumed for content lines seen before any ``+++`` header, matching
#: ``map_diff_lines``: a headerless diff is a PKGBUILD edit.
_DEFAULT_FILE = "PKGBUILD"


@dataclass(frozen=True)
class DiffLine:
    """One content line of a unified diff.

    ``side`` is ``"add"``, ``"remove"`` or ``"context"``.  ``content`` is
    the line's text with the one-character diff prefix stripped; ``raw`` is
    the line as it appeared, prefix included, for readers whose patterns
    anchor on it.  ``index`` is the 0-based index into the diff's raw
    lines, which is the key ``map_diff_lines`` used.

    ``old_lineno``/``new_lineno`` are set only when the line sits inside a
    hunk (``in_hunk``); both advance per the hunk header.  A removal line's
    ``new_lineno`` is the number the next post-diff line will carry, kept
    for parity with the legacy line map; its real position is
    ``old_lineno``.
    """

    index: int
    side: str
    content: str
    raw: str
    file: str
    old_lineno: int | None
    new_lineno: int | None
    in_hunk: bool


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


@dataclass(frozen=True)
class DiffFile:
    """One file's patch: path, status, and hunks.

    ``status`` is ``"added"`` when the old side is ``/dev/null``,
    ``"removed"`` when the new side is, else ``"modified"``.  Rename
    headers (``rename from``/``rename to``) are not interpreted yet; the
    diff body still parses, and the paths name the post-diff file.
    """

    path: str
    old_path: str
    status: str
    hunks: tuple[DiffHunk, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class DiffDoc:
    """A parsed unified diff: the files, and every content line in order.

    ``lines`` flattens all hunks plus any content lines seen outside a
    hunk (malformed input still yields data, classified, never dropped).
    The projections below reproduce the legacy readers byte for byte; the
    parity harness proves it over the locked corpus.
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
            if line.in_hunk
        }

    def post_lines(self) -> list[str]:
        """The post-diff file text: context and addition contents.

        Projection of ``differ._post_diff_lines``: header lines never
        contribute, and a content line outside any hunk still counts, as
        the legacy walk allowed.
        """
        return [line.content for line in self.lines if line.side != "remove"]

    def pre_lines(self) -> list[str]:
        """The pre-diff file text: context and removal contents.

        Projection of ``differ._pre_diff_lines``.
        """
        return [line.content for line in self.lines if line.side != "add"]

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


def _header_path(raw: str) -> str:
    """The path from a ``+++`` header, with the legacy walk's exact steps.

    ``map_diff_lines`` strips, removes a ``b/`` prefix, and caps at
    ``MAX_DIFF_PATH_BYTES``; it deliberately does not split a trailing tab
    (that is ``_diff_file_path``'s convention, used by the summary), and
    matching it is what keeps the line map a pure projection.
    """
    name = raw.strip()
    if name.startswith("b/"):
        name = name[len("b/"):]
    return name[:MAX_DIFF_PATH_BYTES]


def parse_diff_lines(lines: list[str]) -> DiffDoc:
    """Parse already-split diff lines into a :class:`DiffDoc`.

    This is the entry point for callers that already hold the split lines
    (so the text is walked exactly once); :func:`parse_diff` is the
    convenience wrapper that splits first.
    """
    out_lines: list[DiffLine] = []
    # Files are frozen, so hunks accumulate in a parallel builder list and
    # the DiffFile objects are assembled at the end.
    file_meta: list[tuple[str, str, str]] = []
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

    def close_hunk() -> None:
        nonlocal hunk_lines, hunk_expected
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
                                  _status(pending_old_path, current_file)))
                file_hunks.append([])
            file_hunks[-1].append(hunk)
        hunk_lines = []
        hunk_expected = None
        # ``in_hunk`` is deliberately not reset here: the legacy map leaves
        # it standing across file headers, so a content line between a
        # ``+++`` header and the next ``@@`` is still mapped, and parity
        # means keeping that (malformed-input) behaviour, not fixing it.

    for i, line in enumerate(lines):
        if line.startswith("+++ "):
            close_hunk()
            current_file = _header_path(line[4:])
            file_meta.append(
                (current_file, pending_old_path,
                 _status(pending_old_path, current_file)))
            file_hunks.append([])
            continue
        if line.startswith("--- "):
            close_hunk()
            pending_old_path = line[4:].strip()
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
            continue
        if line.startswith("+"):
            side = "add"
        elif line.startswith("-"):
            side = "remove"
        elif line.startswith(" "):
            side = "context"
        else:
            # ``diff --git``, ``index``, ``Binary files``, ``\ No newline``,
            # empty lines, and bare ``@@``-junk: structure, not content.
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
        )
        out_lines.append(entry)
        if in_hunk:
            hunk_lines.append(entry)
    close_hunk()
    files = tuple(
        DiffFile(path=path, old_path=old_path, status=status,
                 hunks=tuple(hunks))
        for (path, old_path, status), hunks in zip(file_meta, file_hunks)
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
