"""Dependency-free safeguards for regexes applied to hostile text."""

from __future__ import annotations

import time
import re

BACKTRACK_REPS = 22
BACKTRACK_BUDGET_S = 0.02

#: Length of the long-form probes.
#:
#: The short probes above are 22 characters, which is tuned for
#: *exponential* backtracking: 2^22 is millions of steps and shows up
#: instantly. Polynomial cost is invisible there - 22 squared is 484 steps -
#: and rules run against lines up to `rules.MAX_RULE_LINE_BYTES` (8192),
#: where the same pattern costs 67 million. Three shipped patterns were
#: quadratic and every one of them passed the short probes: a version
#: matcher took 3.2 seconds on one line, and a `sudo` matcher 1.1 seconds.
#:
#: 2048 is the compromise. Quadratic behaviour is plainly visible (4.2M
#: steps, tens of milliseconds) while a linear pattern stays in the
#: microseconds, and probing every pattern at the full 8192 would put real
#: time on the startup path for no extra signal.
LONG_PROBE_LEN = 2048

BACKTRACK_PROBES = (
    "a" * BACKTRACK_REPS + "!",
    "a" * BACKTRACK_REPS,
    " " * BACKTRACK_REPS + "!",
    "https://" + "a." * (BACKTRACK_REPS // 2) + "com",
    "curl " + "|" * BACKTRACK_REPS,
    "/" * BACKTRACK_REPS + "!",
    # A dotted name with no scheme in front of it. The URL probe above
    # cannot reach an anchored host pattern like ``^(\\w+\\.)+\\w+$``,
    # because ``https://`` fails the anchor at position 0 and the match
    # ends before any backtracking starts. Host- and module-shaped names
    # are among the most common things matched here.
    "a." * (BACKTRACK_REPS // 2) + "com",
    # Digits. Nothing above contains one, so every pattern driven by
    # ``\\d`` or ``[0-9]`` used to be probed with input it cannot match,
    # and scored a risk of exactly zero.
    "1" * BACKTRACK_REPS + "!",
    "1," * (BACKTRACK_REPS // 2) + "!",
    # Long forms. A pattern that is merely quadratic costs nothing
    # measurable at 22 characters and seconds at a full line.
    "a" * LONG_PROBE_LEN + "!",
    " " * LONG_PROBE_LEN + "!",
    "1" * LONG_PROBE_LEN + "!",
    "a." * (LONG_PROBE_LEN // 2) + "!",
    "a " * (LONG_PROBE_LEN // 2) + "!",
    "/" * LONG_PROBE_LEN + "!",
)

#: Representative characters for the classes a pattern can be built from.
#: A probe only exercises a pattern if it is drawn from that pattern's own
#: alphabet, which is why the fixed set above cannot be sufficient on its
#: own however long it grows.
_CLASS_SAMPLES = (
    (r"\d", "1"), (r"\w", "a"), (r"\s", " "), (r"\S", "a"),
    (r"0-9", "1"), (r"a-z", "a"), (r"A-Z", "A"), (r"A-Za-z", "a"),
)

_CHAR_CLASS_RE = re.compile(r"\[\^?((?:[^\]\\]|\\.){1,64})\]")
_ESCAPE_RE = re.compile(r"\\([dwsS])")

#: Distinct alphabets probed per pattern, and probe shapes per alphabet.
#: Both are capped because this runs at rule-compile time.
_MAX_DERIVED_ALPHABETS = 4



def _representatives(pattern: str) -> list[str]:
    """Characters this pattern can actually consume, longest-repeat first.

    Deriving the probe alphabet from the pattern is what makes the check
    general. A fixed probe list is a list of the attacks somebody thought
    of, and the classes it omits score zero risk rather than unknown risk.
    """
    found: list[str] = []

    def add(char: str) -> None:
        if char and char not in found:
            found.append(char)

    for escape in _ESCAPE_RE.findall(pattern):
        for token, sample in _CLASS_SAMPLES:
            if token == "\\" + escape:
                add(sample)

    for body in _CHAR_CLASS_RE.findall(pattern):
        matched = False
        for token, sample in _CLASS_SAMPLES:
            if token in body:
                add(sample)
                matched = True
        if not matched:
            # A literal set such as ``[xyz]``: any member exercises it.
            literal = next((c for c in body if c.isalnum()), "")
            add(literal)

    # Literal alphanumerics in the pattern itself, for shapes like ``(x|x)*``
    # where no class appears at all.
    for char in pattern:
        if char.isalnum():
            add(char)
            break

    return found[:_MAX_DERIVED_ALPHABETS]


def derived_probes(pattern: str) -> tuple[str, ...]:
    """Attack strings built from *pattern*'s own alphabet.

    Each alphabet is probed short and long: short finds exponential
    backtracking, long finds polynomial cost that only appears at the line
    lengths these patterns actually see.
    """
    probes: list[str] = []
    half = BACKTRACK_REPS // 2
    long_half = LONG_PROBE_LEN // 2
    for char in _representatives(pattern):
        probes.append(char * BACKTRACK_REPS + "!")
        probes.append((char + ".") * half + "!")
        probes.append((char + " ") * half + "!")
        probes.append(char * LONG_PROBE_LEN + "!")
        probes.append((char + " ") * long_half + "!")
    return tuple(probes)


# Restrict the structural check to the classic ambiguous single-atom forms.
# Broader nested-quantifier heuristics reject safe patterns whose inner and
# outer character classes are disjoint, such as ``(?:-\S+\s+)*``.
_NESTED_QUANTIFIER_RE = re.compile(
    r"\((?:\?:)?(?:[A-Za-z0-9.]|\.\*|\.\+|\\[wds])[*+]\)\s*[*+{]"
)

# A quantified character class inside a quantified group: ``([0-9]+)+``.
# The rule above only covers single atoms and escapes, so a class spelled
# out longhand went structurally unnoticed.
_NESTED_CLASS_QUANTIFIER_RE = re.compile(
    r"\((?:\?:)?\[\^?(?:[^\]\\]|\\.){1,64}\][*+]\)\s*[*+{]"
)

# An alternation whose branches match the same text, under a quantifier:
# ``(x|x)*``. Both branches are tried at every position, so the engine has
# two ways to consume each character and the search space doubles.
_AMBIGUOUS_ALTERNATION_RE = re.compile(
    r"\((?:\?:)?([^()|]{1,32})\|([^()|]{1,32})\)\s*[*+{]"
)


def _branches_overlap(left: str, right: str) -> bool:
    """Whether two alternation branches match exactly the same input.

    Identical branches only. A *prefix* relationship such as ``(a|ab)+``
    is the other textbook ambiguity, and it was rejected here until it was
    measured: under both attack shapes it is linear in CPython, so
    refusing it bought nothing. It is not a free guess either - a refused
    pattern does not raise, it returns None and the rule quietly stops
    matching, so a false refusal is a hole rather than an inconvenience.
    """
    return left == right and bool(left)


def is_superlinear(compiled: re.Pattern) -> bool:
    """Whether *compiled* costs more than linearly in its input length."""
    return growth_ratio(compiled) > SUPERLINEAR_GROWTH


def has_nested_quantifier(pattern: str) -> bool:
    """Conservatively detect nested quantified groups."""
    if _NESTED_QUANTIFIER_RE.search(pattern):
        return True
    if _NESTED_CLASS_QUANTIFIER_RE.search(pattern):
        return True
    for left, right in _AMBIGUOUS_ALTERNATION_RE.findall(pattern):
        if _branches_overlap(left, right):
            return True
    return False


#: A pattern whose cost grows faster than this multiple of its input is
#: superlinear. Four times the input costs four times the time when a
#: pattern is linear, and about sixteen when it is quadratic, so eight
#: separates the two with room for a noisy machine.
SUPERLINEAR_GROWTH = 8.0

#: Below this, a measurement is noise rather than signal and the growth
#: check is skipped. A pattern too fast to measure is fast enough.
_GROWTH_FLOOR_S = 0.001


def _time_search(compiled: re.Pattern, text: str) -> float:
    start = time.perf_counter()
    try:
        compiled.search(text)
    except (RecursionError, MemoryError):
        return BACKTRACK_BUDGET_S * 100
    return time.perf_counter() - start


def growth_ratio(compiled: re.Pattern) -> float:
    """How much slower *compiled* gets when its input grows four times.

    The absolute budget alone misses a quadratic pattern with a small
    constant: it is genuinely quadratic, and genuinely under the budget at
    the probe length, so it passes and then costs seconds at a full line.
    Shape is the more durable signal, and measuring it needs two lengths.
    """
    worst = 0.0
    alphabets = _representatives(compiled.pattern) or ["a"]
    for char in alphabets[:2]:
        short = _time_search(compiled, char * (LONG_PROBE_LEN // 4) + "!")
        long = _time_search(compiled, char * LONG_PROBE_LEN + "!")
        if long < _GROWTH_FLOOR_S:
            continue
        worst = max(worst, long / max(short, 1e-9))
    return worst


def backtracking_risk(compiled: re.Pattern) -> float:
    """Return the worst bounded-probe match time in seconds.

    Probes are the fixed set plus a set derived from the pattern, because
    a probe drawn from the wrong alphabet reports zero rather than safe.
    """
    worst = 0.0
    probes = BACKTRACK_PROBES + derived_probes(compiled.pattern)
    for probe in probes:
        start = time.perf_counter()
        try:
            compiled.search(probe)
        except (RecursionError, MemoryError):
            return BACKTRACK_BUDGET_S * 100
        elapsed = time.perf_counter() - start
        worst = max(worst, elapsed)
        # A pattern already over budget needs no further probing, and the
        # remaining probes on a catastrophic pattern are the expensive part.
        if worst > BACKTRACK_BUDGET_S:
            return worst
    return worst
