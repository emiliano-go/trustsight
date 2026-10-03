r"""The typed core for recipe reading: a PKGBUILD as a document.

Layer 2 of the typed core.  :class:`RecipeDoc` is to a PKGBUILD what
:class:`~trustsight.diffdoc.DiffDoc` is to a diff: the text is read once,
by the sandboxed tokenizer, and every reader becomes a query over the
result - scalars, arrays, function bodies - instead of a per-module state
machine over lines.  The array state machines lived in nine modules and
each made its own opener/closer decisions; ``array_diff`` turns "did the
checksum list change" into a set question with no state machine to get
wrong.

Two rules keep this layer honest:

* ``unresolved`` is first-class.  An assignment the tokenizer refused (a
  command substitution, an expansion it will not guess at) is listed
  there, and a rule reading an unresolved field must treat it as "not
  seen", which is what the coverage gaps already report.  A typed model
  that guesses is a regression in the one place guessing is forbidden.
* Parity before migration.  A legacy reader moves here only when its
  output is a pure projection of the document; where the legacy walk
  legitimately reads the text differently (an unresolved-regex extraction
  is not a resolved-value read), the walk stays and the divergence is
  documented, not smoothed over.
"""

import re
from collections import Counter
from dataclasses import dataclass, field
from difflib import SequenceMatcher

from .diffdoc import DiffDoc
from .line_lex import lex_lines
from .tokenizer import TokenizerUnavailable, split_lines, variable_table_spans

#: An assignment line, for the unresolved list: the shape the tokenizer's
#: table builder accepts, captured here so a refusal can be named.
_ASSIGNMENT_SHAPE_RE = re.compile(
    r"^\s*(?:export\s+|local\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*(\+?=)"
)
_FUNCTION_OPEN_RE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(\s*\)")


@dataclass(frozen=True)
class Span:
    """Where a value was read.

    ``line`` is 1-based in the text the recipe was parsed from; when that
    text came from a diff, ``file`` and ``side`` name the real file and
    the ``add``/``remove``/``context`` side, and ``line`` is the file's
    line number, not the fragment's.
    """

    file: str
    line: int
    side: str = ""


@dataclass(frozen=True)
class RecipeDoc:
    """A PKGBUILD, read once.

    ``scalars``/``arrays`` are the tokenizer's tables; scalar values are
    resolved (interpolation folded), while array entries keep their
    literal text with quotes stripped.  ``functions`` maps function name
    to body text, in file order (a name defined twice keeps the last
    body, as bash does).  ``unresolved`` carries the assignment lines the
    tokenizer refused to resolve; their names must read as "not seen" to
    any rule.

    The ``*_spans`` maps answer "where did this come from": a scalar's
    assignment line, each array entry's first line, and a function's
    header line.  A value with no recorded location is absent from its
    map rather than mapped to a guess.
    """

    scalars: dict[str, str]
    arrays: dict[str, tuple[str, ...]]
    functions: dict[str, str]
    unresolved: tuple[str, ...] = field(default_factory=tuple)
    scalar_spans: dict[str, Span] = field(default_factory=dict)
    array_spans: dict[str, tuple[Span, ...]] = field(default_factory=dict)
    function_spans: dict[str, Span] = field(default_factory=dict)


@dataclass(frozen=True)
class ArrayDelta:
    """The answer to "how did this array change".

    ``gained``/``lost`` are multiset differences: the surplus occurrences,
    in the order they appear.  Adding an entry twice is two gains and
    removing one copy of a duplicate is a loss, which a set difference
    could not see.  ``reordered`` compares the matched occurrences only, so
    a multiplicity change is not a reorder.
    """

    gained: tuple[str, ...]
    lost: tuple[str, ...]
    reordered: bool


@dataclass(frozen=True)
class ArrayAlignment:
    """Positional correspondence between two arrays.

    ``pairs`` are matched occurrences as ``(old_index, new_index, value)``;
    ``inserted``/``deleted`` are unmatched occurrences as ``(index, value)``.
    Matching is by identical value, longest block first, so an entry
    inserted or removed mid-array does not mispair the entries after it.
    A move is a deletion plus an insertion, with ``reordered`` true.
    """

    pairs: tuple[tuple[int, int, str], ...]
    inserted: tuple[tuple[int, str], ...]
    deleted: tuple[tuple[int, str], ...]
    reordered: bool


def _surplus(base: tuple[str, ...], other: tuple[str, ...]) -> tuple[str, ...]:
    """The occurrences of *base* beyond what *other* holds, in base order."""
    other_counts = Counter(other)
    running: Counter = Counter()
    out: list[str] = []
    for value in base:
        running[value] += 1
        if running[value] > other_counts[value]:
            out.append(value)
    return tuple(out)


def _matched_order_moved(old_t: tuple[str, ...], new_t: tuple[str, ...]) -> bool:
    """True when the matched occurrences changed their relative order."""
    old_counts, new_counts = Counter(old_t), Counter(new_t)
    matched = {
        value: min(old_counts[value], new_counts[value])
        for value in old_counts.keys() | new_counts.keys()
    }

    def projection(values: tuple[str, ...]) -> list[str]:
        seen: Counter = Counter()
        out: list[str] = []
        for value in values:
            if seen[value] < matched[value]:
                seen[value] += 1
                out.append(value)
        return out

    return projection(old_t) != projection(new_t)


def array_diff(old: tuple[str, ...] | list[str],
               new: tuple[str, ...] | list[str]) -> ArrayDelta:
    """The change between two arrays as a multiset, plus whether order moved."""
    old_t, new_t = tuple(old), tuple(new)
    return ArrayDelta(
        gained=_surplus(new_t, old_t),
        lost=_surplus(old_t, new_t),
        reordered=_matched_order_moved(old_t, new_t),
    )


def array_alignment(old: tuple[str, ...] | list[str],
                    new: tuple[str, ...] | list[str]) -> ArrayAlignment:
    """Match array occurrences by position, reporting insertions and deletions."""
    old_t, new_t = tuple(old), tuple(new)
    matcher = SequenceMatcher(a=old_t, b=new_t, autojunk=False)
    pairs: list[tuple[int, int, str]] = []
    inserted: list[tuple[int, str]] = []
    deleted: list[tuple[int, str]] = []
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            pairs.extend(
                (i1 + k, j1 + k, old_t[i1 + k]) for k in range(i2 - i1)
            )
        elif tag == "replace":
            deleted.extend((i, old_t[i]) for i in range(i1, i2))
            inserted.extend((j, new_t[j]) for j in range(j1, j2))
        elif tag == "delete":
            deleted.extend((i, old_t[i]) for i in range(i1, i2))
        elif tag == "insert":
            inserted.extend((j, new_t[j]) for j in range(j1, j2))
    return ArrayAlignment(
        pairs=tuple(pairs),
        inserted=tuple(inserted),
        deleted=tuple(deleted),
        reordered=_matched_order_moved(old_t, new_t),
    )


def _function_segments(lines: list[str]) -> list[tuple[str, str, int]]:
    """Each body as ``(name, body, opener_line)``, in input line order.

    Redefined functions yield one segment per definition, matching the
    legacy concatenating reader exactly; callers wanting bash semantics
    (last definition wins) build a dict from the segments, as
    :func:`parse_recipe` does.

    The brace counting is the convention ``properties`` used: a one-line
    body (``build() { make; }``) is recorded and the function stays
    closed, and an opener whose brace arrives on a later line opens the
    body there.  Braces inside quotes, comments or a heredoc body are not
    code and do not move the count (``line_lex`` decides which text is
    code once for this reader and the rule scope classifier).
    """
    segments: list[tuple[str, str, int]] = []
    current: str | None = None
    current_lines: list[str] = []
    depth = 0
    opened = -1

    def close(opener: int) -> None:
        nonlocal current, current_lines
        # An empty body leaves no trace, matching the legacy reader, whose
        # joined output would otherwise gain a stray blank line.
        if current is not None and current_lines:
            segments.append((current, "\n".join(current_lines), opener))
        current = None
        current_lines = []

    for index, lex in enumerate(lex_lines(lines)):
        line = lex.text
        stripped = line.strip()
        if current is None:
            m = _FUNCTION_OPEN_RE.match(stripped)
            if not m:
                continue
            name = m.group(1)
            if not lex.opens_brace:
                # The brace arrives on a later line.
                current = name
                current_lines = []
                depth = 0
                opened = index
                continue
            depth = lex.brace_delta
            opening = stripped.split("{", 1)[1]
            if depth <= 0:
                # A one-line body: record it and stay closed, or every
                # later line is swallowed as this function's body.
                opening = opening.rsplit("}", 1)[0]
                if opening.strip():
                    segments.append((name, opening, index))
            else:
                current = name
                current_lines = [opening] if opening.strip() else []
                opened = index
            continue
        depth += lex.brace_delta
        if depth <= 0:
            close(opened)
            continue
        current_lines.append(line)
    close(opened)
    return segments


def _function_body_segments(lines: list[str]) -> list[tuple[str, str]]:
    """The ``(name, body)`` projection ``properties`` consumes."""
    return [(name, body) for name, body, _opener in _function_segments(lines)]


def parse_recipe(
    text: str,
    file: str = "",
    origins: list[tuple[str, int, str]] | None = None,
) -> RecipeDoc:
    """Read a whole PKGBUILD into a :class:`RecipeDoc`.

    The tokenizer does the resolution; this function shapes its output and
    names what it refused.  A missing tokenizer is a refusal, not an empty
    recipe: the exception propagates, as it does everywhere else.

    *origins* is parallel to ``split_lines(text)`` and maps each line to
    ``(file, line, side)``; pass the diff's origins when the text was
    rebuilt from a diff so spans name real file lines.  Without it, a span
    is ``(file, index + 1)``.
    """
    lines = split_lines(text)
    try:
        scalars, arrays, provenance = variable_table_spans(lines)
    except TokenizerUnavailable:
        raise

    def origin(index: int) -> Span:
        if origins is not None and 0 <= index < len(origins):
            origin_file, origin_line, side = origins[index]
            return Span(origin_file, origin_line, side)
        return Span(file, index + 1)

    unresolved = tuple(
        line.strip() for line in lines
        if _ASSIGNMENT_SHAPE_RE.match(line)
        and _ASSIGNMENT_SHAPE_RE.match(line).group(1) not in scalars
        and _ASSIGNMENT_SHAPE_RE.match(line).group(1) not in arrays
    )
    functions: dict[str, str] = {}
    function_spans: dict[str, Span] = {}
    for name, body, opener in _function_segments(lines):
        # bash semantics: a redefined function keeps its last body.
        functions[name] = body
        function_spans[name] = origin(opener)
    return RecipeDoc(
        scalars=dict(scalars),
        arrays={name: tuple(values) for name, values in arrays.items()},
        functions=functions,
        unresolved=unresolved,
        scalar_spans={
            name: origin(index)
            for name, index in provenance["scalars"].items()
        },
        array_spans={
            name: tuple(origin(index) for index in info["entries"])
            for name, info in provenance["arrays"].items()
        },
        function_spans=function_spans,
    )


def recipe_from_post_state(doc: DiffDoc) -> RecipeDoc:
    """The recipe as it stands after a diff, read from the typed diff.

    A diff shows hunks, not a file: the post-state is only what the diff
    shows, so recipes built this way are for change questions (what did
    this array gain), not whole-recipe questions.
    """
    return parse_recipe("\n".join(doc.post_lines()), origins=doc.post_origins())


def recipe_states(doc: DiffDoc) -> tuple[RecipeDoc, RecipeDoc]:
    """The ``(pre, post)`` RecipeDocs of what the diff shows.

    A diff shows hunks, not a file, so both states are partial: they answer
    change questions (what did this array or scalar gain) and nothing else.
    Their spans carry the real file, line and side of each value.
    """
    return (
        parse_recipe("\n".join(doc.pre_lines()), origins=doc.pre_origins()),
        parse_recipe("\n".join(doc.post_lines()), origins=doc.post_origins()),
    )
