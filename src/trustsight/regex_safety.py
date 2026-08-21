"""Dependency-free safeguards for regexes applied to hostile text."""

from __future__ import annotations

import re
import time
import warnings

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

_CHAR_CLASS_RE = re.compile(r"\[(\^?)((?:[^\]\\]|\\.){1,64})\]")
_ESCAPE_RE = re.compile(r"\\([dwsS])")

#: Syntax that must not be mined for literals. A ``:`` from ``(?:``, a digit
#: from ``{1,64}`` or a ``^`` from a class body is punctuation the engine
#: consumes as grammar, and probing with it means probing with a character
#: the pattern cannot match - the same "wrong alphabet" failure the derived
#: probes exist to remove.
_SYNTAX_RE = re.compile(
    r"\[\^?(?:[^\]\\]|\\.){0,64}\]"     # class bodies: mined separately
    r"|\((?:\?(?:P?<[^>]{0,32}>|[:=!#]|<[=!]|[aiLmsux]{1,6}[:)]))?"  # group openers
    r"|\{\d{0,8}(?:,\d{0,8})?\}"        # counted quantifiers
    r"|\\[dwsSbBAZzGnrtfv0-9]"          # class escapes and non-literal escapes
)

#: Characters the engine reads as grammar rather than input.
_METACHARACTERS = frozenset(".^$*+?()[]{}|\\")

#: Probed when a pattern yields no alphabet of its own. It is a fallback,
#: not a measurement: a pattern whose alphabet cannot be derived is unknown
#: rather than safe, so the fallback is several characters wide instead of
#: one, and ``growth_ratio`` says so where it uses it.
_FALLBACK_ALPHABET = ("a", "1", " ", "/")

#: Distinct alphabets probed per pattern, and probe shapes per alphabet.
#: Both are capped because this runs at rule-compile time.
_MAX_DERIVED_ALPHABETS = 4



#: Tried in order against a character class to find one it accepts. Broad
#: enough that a negated class - which excludes a few characters and admits
#: everything else - is answered by the first or second candidate.
_CLASS_CANDIDATES = ("a", "1", " ", "/", "-", "_", ".", ":", "x")


def _class_representative(body: str, negated: bool) -> str:
    r"""One character the class ``[body]`` accepts, or "" if none is found.

    Asked of the compiled class rather than inferred from its text, because
    inference read a *negated* class as a positive one. ``[^\s]+`` derived
    ``" "`` - the single character it cannot match - and ``[^0-9]+`` derived
    ``"1"``. A pattern probed with input it cannot consume measures zero
    time, and zero is indistinguishable from fast, so every pattern driven
    by a negated class was scored safe without ever being measured.

    That is the same failure that let a quadratic ``/+$`` ship: the
    alphabet, not the timing, is what the check rests on.
    """
    try:
        with warnings.catch_warnings():
            # A body holding `[` - `[[:space:]]`, `[\[\]]` - warns about a
            # nested set when re-wrapped. The class means the same thing
            # either way for the only question asked here, which is whether
            # some character matches it.
            warnings.simplefilter("ignore", FutureWarning)
            compiled = re.compile(f"[{'^' if negated else ''}{body}]")
    except re.error:
        return ""
    for candidate in _CLASS_CANDIDATES:
        if compiled.match(candidate):
            return candidate
    # No ASCII candidate matched, so the class is non-ASCII: read a
    # character out of the class's own text. R013 is the case that matters
    # - it is FATAL, its body is `\u202A-\u202E` and friends, and every
    # fixed probe in this module is ASCII, so both its risk and its growth
    # were measured against input it cannot match. A FATAL rule whose cost
    # is unmeasured is exactly the gap this module exists to close.
    for candidate in _codepoints_in(body):
        if compiled.match(candidate):
            return candidate
    return ""


_ESCAPED_CODEPOINT_RE = re.compile(
    r"\\u([0-9a-fA-F]{4})|\\U([0-9a-fA-F]{8})|\\x([0-9a-fA-F]{2})"
)

#: Single-letter escapes, which name a character without spelling its
#: codepoint.  Without these `[\t\n\r\f\v]+` derived nothing: the scan
#: for literals sees `t`, `n`, `r` - the letters, not the controls they
#: stand for - and none of them matches the class.
_ESCAPE_LETTERS = {
    "t": "\t", "n": "\n", "r": "\r", "f": "\f", "v": "\v",
    "a": "\a", "b": "\b", "0": "\0", "e": "\x1b",
}


def _codepoints_in(body: str) -> list[str]:
    """Characters named by a class body, escapes decoded, in order.

    A range start is enough: ``[\u202A-\u202E]`` is exercised by
    ``\u202A``. Only a bounded prefix is read, because the body is
    attacker-authored text like everything else here.
    """
    out: list[str] = []
    index = 0
    while index < len(body[:512]) - 1:
        if body[index] == "\\" and body[index + 1] in _ESCAPE_LETTERS:
            char = _ESCAPE_LETTERS[body[index + 1]]
            if char not in out:
                out.append(char)
            index += 2
            continue
        index += 1
    for match in _ESCAPED_CODEPOINT_RE.finditer(body[:512]):
        digits = match.group(1) or match.group(2) or match.group(3)
        try:
            out.append(chr(int(digits, 16)))
        except (ValueError, OverflowError):
            continue
        if len(out) >= 8:
            return out
    for char in body[:512]:
        if char not in "\\-^[]" and char not in out:
            out.append(char)
            if len(out) >= 8:
                break
    return out


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

    # Class bodies are removed first: an escape *inside* a class is the
    # class's business, and reading `\s` out of `[^\s]` added a space -
    # the one character that class excludes.
    outside_classes = _CHAR_CLASS_RE.sub(" ", pattern)
    for escape in _ESCAPE_RE.findall(outside_classes):
        for token, sample in _CLASS_SAMPLES:
            if token == "\\" + escape:
                add(sample)

    for negation, body in _CHAR_CLASS_RE.findall(pattern):
        add(_class_representative(body, bool(negation)))

    # Literals in the pattern itself, for shapes like ``(x|x)*`` or ``/+$``
    # where no class appears at all.
    #
    # This used to take the first *alphanumeric* character and stop. A
    # pattern whose only consumable literal is punctuation - ``/+$`` is the
    # reported one - therefore derived no alphabet at all, fell back to
    # probing with ``a``, which ``/`` can never match, and measured zero on
    # every probe. Zero is then indistinguishable from fast, so a quadratic
    # pattern scored safe. Punctuation is input like any other character;
    # what it must not be is *syntax*, which is what ``_SYNTAX_RE`` strips
    # before this scan.
    consumable = _SYNTAX_RE.sub(" ", pattern)
    escaped = False
    for char in consumable:
        if escaped:
            # ``\.`` and friends: the escape made a metacharacter literal.
            add(char)
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if char in _METACHARACTERS or char.isspace():
            continue
        add(char)

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
    # ``or _FALLBACK_ALPHABET``: a pattern with no derivable alphabet has
    # not been measured, and an unmeasured pattern is unknown rather than
    # safe. Several characters are tried instead of one so the fallback has
    # some chance of being input the pattern can actually consume.
    alphabets = _representatives(compiled.pattern) or list(_FALLBACK_ALPHABET)
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
