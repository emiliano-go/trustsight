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
from dataclasses import dataclass, field

from .diffdoc import DiffDoc
from .tokenizer import TokenizerUnavailable, split_lines, variable_table

#: An assignment line, for the unresolved list: the shape the tokenizer's
#: table builder accepts, captured here so a refusal can be named.
_ASSIGNMENT_SHAPE_RE = re.compile(
    r"^\s*(?:export\s+|local\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*(\+?=)"
)
_FUNCTION_OPEN_RE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(\s*\)")


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
    """

    scalars: dict[str, str]
    arrays: dict[str, tuple[str, ...]]
    functions: dict[str, str]
    unresolved: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class ArrayDelta:
    """The answer to "how did this array change".

    ``gained``/``lost`` are set differences; ``reordered`` says the shared
    elements moved.  The checksum, source, depends and validpgpkeys rules
    are all this one question.
    """

    gained: frozenset[str]
    lost: frozenset[str]
    reordered: bool


def array_diff(old: tuple[str, ...] | list[str],
               new: tuple[str, ...] | list[str]) -> ArrayDelta:
    """The change between two arrays as sets, plus whether order moved."""
    old_t, new_t = tuple(old), tuple(new)
    gained = frozenset(new_t) - frozenset(old_t)
    lost = frozenset(old_t) - frozenset(new_t)
    shared_old = [x for x in old_t if x in frozenset(new_t)]
    shared_new = [x for x in new_t if x in frozenset(old_t)]
    return ArrayDelta(gained=gained, lost=lost,
                      reordered=shared_old != shared_new)


def _function_body_segments(lines: list[str]) -> list[tuple[str, str]]:
    """Each ``name() { ... }`` body as a ``(name, body)`` segment, in file
    order.

    Redefined functions yield one segment per definition, matching the
    legacy concatenating reader exactly; callers wanting bash semantics
    (last definition wins) build a dict from the segments, as
    :func:`parse_recipe` does.

    The brace counting is the convention ``properties`` used: a one-line
    body (``build() { make; }``) is recorded and the function stays
    closed, and an opener whose brace arrives on a later line opens the
    body there.
    """
    segments: list[tuple[str, str]] = []
    current: str | None = None
    current_lines: list[str] = []
    depth = 0

    def close() -> None:
        nonlocal current, current_lines
        # An empty body leaves no trace, matching the legacy reader, whose
        # joined output would otherwise gain a stray blank line.
        if current is not None and current_lines:
            segments.append((current, "\n".join(current_lines)))
        current = None
        current_lines = []

    for line in lines:
        stripped = line.strip()
        if current is None:
            m = _FUNCTION_OPEN_RE.match(stripped)
            if not m:
                continue
            name = m.group(1)
            if "{" not in stripped:
                # The brace arrives on a later line.
                current = name
                current_lines = []
                depth = 0
                continue
            depth = stripped.count("{") - stripped.count("}")
            opening = stripped.split("{", 1)[1]
            if depth <= 0:
                # A one-line body: record it and stay closed, or every
                # later line is swallowed as this function's body.
                opening = opening.rsplit("}", 1)[0]
                if opening.strip():
                    segments.append((name, opening))
            else:
                current = name
                current_lines = [opening] if opening.strip() else []
            continue
        depth += stripped.count("{")
        depth -= stripped.count("}")
        if depth <= 0:
            close()
            continue
        current_lines.append(line)
    close()
    return segments


def parse_recipe(text: str) -> RecipeDoc:
    """Read a whole PKGBUILD into a :class:`RecipeDoc`.

    The tokenizer does the resolution; this function shapes its output and
    names what it refused.  A missing tokenizer is a refusal, not an empty
    recipe: the exception propagates, as it does everywhere else.
    """
    lines = split_lines(text)
    try:
        scalars, arrays = variable_table(lines)
    except TokenizerUnavailable:
        raise
    unresolved = tuple(
        line.strip() for line in lines
        if _ASSIGNMENT_SHAPE_RE.match(line)
        and _ASSIGNMENT_SHAPE_RE.match(line).group(1) not in scalars
        and _ASSIGNMENT_SHAPE_RE.match(line).group(1) not in arrays
    )
    segments = _function_body_segments(lines)
    functions: dict[str, str] = {}
    for name, body in segments:
        # bash semantics: a redefined function keeps its last body.
        functions[name] = body
    return RecipeDoc(
        scalars=dict(scalars),
        arrays={name: tuple(values) for name, values in arrays.items()},
        functions=functions,
        unresolved=unresolved,
    )


def recipe_from_post_state(doc: DiffDoc) -> RecipeDoc:
    """The recipe as it stands after a diff, read from the typed diff.

    A diff shows hunks, not a file: the post-state is only what the diff
    shows, so recipes built this way are for change questions (what did
    this array gain), not whole-recipe questions.
    """
    return parse_recipe("\n".join(doc.post_lines()))


def recipe_states(doc: DiffDoc) -> tuple[RecipeDoc, RecipeDoc]:
    """The ``(pre, post)`` RecipeDocs of what the diff shows.

    A diff shows hunks, not a file, so both states are partial: they answer
    change questions (what did this array or scalar gain) and nothing else.
    """
    return (
        parse_recipe("\n".join(doc.pre_lines())),
        parse_recipe("\n".join(doc.post_lines())),
    )
