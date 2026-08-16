"""The backtracking detector is measured against known-catastrophic shapes.

`regex_safety` decides whether a pattern is allowed to run against hostile
text, so its *sensitivity* is the security property, not the fact that it
exists. It ran six fixed probes, and a probe drawn from the wrong alphabet
does not report "unknown" - it reports a risk of exactly zero, which reads
identically to safe.

Half of the corpus below used to pass. Digits were the clearest case: no
fixed probe contained one, so every pattern driven by `\\d` or `[0-9]` was
tested with input it could not match.

The other half of the file is the opposite failure. A detector that flags
everything is also useless, so the linear patterns are pinned as patterns
that must keep compiling.
"""

import re
import time

import pytest

from trustsight.regex_safety import (
    BACKTRACK_BUDGET_S,
    backtracking_risk,
    derived_probes,
    has_nested_quantifier,
    is_superlinear,
)


def _flagged(pattern: str) -> bool:
    """The exact decision `rules._compiled` makes."""
    compiled = re.compile(pattern)
    return (
        has_nested_quantifier(pattern)
        or backtracking_risk(compiled) > BACKTRACK_BUDGET_S
        or is_superlinear(compiled)
    )


# Every one of these doubles its runtime for a few added repetitions, and
# each is paired with the input that makes it do so. The pairing is not
# decoration: a first draft of this file guessed the attack character from
# the pattern text, guessed " " wrong for `(\s+)+$`, and reported a
# genuinely exponential pattern as linear.
CATASTROPHIC = [
    (r"(a+)+$", "a"),
    (r"([a-z]+)+$", "a"),
    (r"([0-9]+)+$", "1"),
    (r"([0-9]+)*x", "1"),
    (r"(\d+)+$", "1"),
    (r"(\s+)+$", " "),
    (r"([A-Za-z]+\s?)+;", "a"),
    (r"(x|x)*y", "x"),
    (r"([0-9a-f]+)+g", "1"),
]

# Linear, and therefore fine. `\w+\.` and `\d+,` cannot extend past their
# terminator, so each repetition is forced and there is only one way to
# split the input.
LINEAR = [
    r"^(\w+\.)+\w+$",
    r"(?:-\S+\s+)*",
    r"https?://[\w.-]+/\S+",
    r"^\s*source=\(",
    r"curl\s+-[a-zA-Z]*s",
    r"\$\{[A-Za-z_]\w*\}",
]


@pytest.mark.parametrize("pattern,_attack", CATASTROPHIC)
def test_a_catastrophic_pattern_is_refused(pattern, _attack):
    assert _flagged(pattern), f"{pattern} would be allowed to run on hostile text"


@pytest.mark.parametrize("pattern", LINEAR)
def test_a_linear_pattern_is_allowed(pattern):
    """A detector that refuses safe patterns is not the safe direction.

    `_compiled` returns None for a refused pattern rather than raising, so
    the rule silently stops matching. A false refusal is a hole.
    """
    assert not _flagged(pattern), f"{pattern} is linear but was refused"


@pytest.mark.parametrize("pattern,attack", CATASTROPHIC)
def test_the_corpus_really_is_catastrophic(pattern, attack):
    """Guards the guard: an entry that is merely linear proves nothing."""
    compiled = re.compile(pattern)

    def cost(reps):
        start = time.perf_counter()
        compiled.search(attack * reps + "!")
        return time.perf_counter() - start

    # Exponential growth shows up long before it is slow enough to hang.
    assert cost(20) > cost(12) * 4, f"{pattern} does not blow up; it is linear"


def test_probes_are_drawn_from_the_patterns_own_alphabet():
    """The generalisation that makes the fixed list unnecessary to extend."""
    assert any("1" in probe for probe in derived_probes(r"([0-9]+)+$"))
    assert any("a" in probe for probe in derived_probes(r"([a-z]+)+$"))
    assert any("x" in probe for probe in derived_probes(r"(x|x)*y"))


def test_a_digit_driven_pattern_is_probed_with_digits():
    """The specific hole: no fixed probe contained a digit.

    A pattern that cannot match any probe scores 0.0 seconds, which is
    indistinguishable from a pattern that matched them all instantly.
    """
    assert backtracking_risk(re.compile(r"([0-9]+)+$")) > BACKTRACK_BUDGET_S


def test_an_anchored_host_pattern_is_probed_without_a_scheme():
    """`https://a.a.a.com` cannot reach a `^`-anchored host pattern.

    It fails at position 0 and the match ends before any backtracking
    begins. Host- and dotted-name shapes are everywhere in this codebase.
    """
    from trustsight.regex_safety import BACKTRACK_PROBES

    assert any(
        probe.startswith("a.") and "://" not in probe
        for probe in BACKTRACK_PROBES
    )


def test_identical_alternation_branches_are_caught_structurally():
    assert has_nested_quantifier(r"(x|x)*y")
    # Disjoint branches are unambiguous and must still compile.
    assert not has_nested_quantifier(r"(cat|dog)+x")
    # Prefix overlap is not refused *structurally* - it is caught by
    # measurement instead, which is the more honest basis for it.
    assert not has_nested_quantifier(r"(a|ab)+c")
    assert _flagged(r"(a|ab)+c")


def test_a_quantified_class_in_a_quantified_group_is_caught_structurally():
    assert has_nested_quantifier(r"([0-9]+)+$")
    assert has_nested_quantifier(r"([a-z]*)+$")


def test_probing_a_safe_pattern_stays_cheap():
    """This runs at rule-compile time, so it is on the startup path."""
    pattern = re.compile(r"https?://[\w.-]+/\S+")
    start = time.perf_counter()
    for _ in range(100):
        backtracking_risk(pattern)
    per_call = (time.perf_counter() - start) / 100
    assert per_call < 0.005, f"{per_call * 1000:.2f} ms per safe pattern"


def test_every_shipped_pattern_still_compiles():
    """The widened detector must not have refused a live rule.

    A refused pattern is not a loud failure - `_compiled` returns None and
    the rule silently stops matching - so this is asserted rather than
    left to be noticed.

    Asserted against the *shipped* set rather than ``load_rules()``, which
    reads the operator's ``rules.toml``. That file is written once at
    install time and keeps whatever pattern it was written with, so a
    developer machine holding a superseded rule made this red while CI,
    with a freshly written file, stayed green - the test would have been
    reporting the state of an untracked file outside the repository.
    What this build ships is the thing CI can actually guarantee.

    The on-disk case is not unchecked: ``trustsight lint`` reports a
    refused pattern as an ERROR, and ``trustsight config sync-rules
    --update`` replaces a superseded pattern that the operator has not
    edited. ``LEGACY_RULE_PATTERNS`` is what makes that repair possible,
    which the next test pins.
    """
    from trustsight.config import shipped_rules
    from trustsight.rules import _compiled

    refused = [
        rule.get("id")
        for rule in shipped_rules()
        if rule.get("pattern") and _compiled(rule["pattern"]) is None
    ]
    assert not refused, f"these rules no longer match anything: {refused}"


def test_a_pattern_this_detector_now_refuses_is_repairable_on_disk():
    """Widening the detector must not strand installs that already exist.

    R007 shipped as ``\\+.*\\.install.*``, which is quadratic and is now
    refused. Every install written before this release still holds that
    text, so unless the old pattern is registered as superseded, those
    installs lose the rule with no way back short of deleting the file.
    """
    import re

    from trustsight.config import LEGACY_RULE_PATTERNS, shipped_rules
    from trustsight.rules import _compiled

    legacy = LEGACY_RULE_PATTERNS["R007"]
    assert legacy, "the superseded R007 pattern must be registered"
    for pattern in legacy:
        assert _compiled(pattern) is None, (
            "a legacy entry is only needed for a pattern that no longer runs"
        )

    current = next(r for r in shipped_rules() if r["id"] == "R007")
    compiled = _compiled(current["pattern"])
    assert compiled is not None
    # The replacement still has to do the job the rule exists for.
    assert compiled.search("+  'spotify.install'")
    assert not compiled.search("+  'PKGBUILD'")
    assert re.compile(current["pattern"]).search("+source=(x.install)")


# ---------------------------------------------------------------------------
# The one pattern built at runtime rather than audited statically.
# ---------------------------------------------------------------------------


def test_a_dynamic_pattern_is_held_to_the_same_standard():
    """`scripts/regex_audit.py` reads source; it cannot see this one.

    `find_line_in_diff` takes regex syntax, so it is the single place a
    pattern reaches the engine without having been audited. It used to
    compile the argument unescaped and run whatever compiled, which cost
    5.6 seconds against one 24-character line and doubled every two
    characters after that.
    """
    from trustsight.rules import find_line_in_diff

    line = "+ " + "a" * 30 + "!"
    start = time.perf_counter()
    find_line_in_diff(line, r"(a+)+$")
    elapsed = time.perf_counter() - start
    assert elapsed < 0.5, f"a supplied pattern ran for {elapsed:.2f}s"


def test_a_refused_dynamic_pattern_is_matched_literally():
    """Refusing must not mean returning nothing.

    The argument was probably literal text somebody forgot to escape, so
    the useful fallback is to look for it as text rather than to give up.
    """
    from trustsight.rules import find_line_in_diff

    # `(a+)+$` as literal characters, present in the line.
    assert find_line_in_diff("+ value=(a+)+$", r"(a+)+$") == 1


def test_intentional_regex_arguments_still_work():
    """Most callers pass real patterns; refusing those would break rules."""
    from trustsight.rules import find_line_in_diff

    assert find_line_in_diff("+ sha256sums=('SKIP')", r"SKIP|NONE") == 1
    assert find_line_in_diff("+ source=(x)", r"source(?:_[a-z0-9_]+)?\s*=\s*\(") == 1
    assert find_line_in_diff("+ http://x/", r"http://") == 1
    assert find_line_in_diff("+ nothing here", r"SKIP|NONE") is None


def test_there_is_only_one_diff_line_finder():
    """Two copies existed, in `delivery` and `structural`.

    Identical code in two modules is the shape that lets a fix land in one
    of them, which is the recurring failure this codebase documents.
    """
    import pathlib

    import trustsight.analysis as analysis

    root = pathlib.Path(analysis.__file__).parent
    definers = [
        path.name
        for path in sorted(root.rglob("*.py"))
        if "def _find_line_in_diff" in path.read_text()
        or "def find_line_in_diff" in path.read_text()
    ]
    assert not definers, f"a local copy came back in: {definers}"


def test_a_url_is_sliced_before_it_is_escaped():
    """Cutting an escaped string can cut an escape sequence in half.

    The result is not a legal pattern, the compile fails, the fallback
    escapes the already-escaped text, and the line number is lost on
    exactly the long URLs the rule is reporting.
    """
    import re as _re

    from trustsight.rules import find_line_in_diff

    url = "https://e.invalid/" + "-" * 31
    # Escape-then-slice lands on a trailing backslash for this input.
    assert _re.escape(url)[:80].endswith("\\")

    diff = f"--- a/PKGBUILD\n+++ b/PKGBUILD\n+source=(\"{url}\")\n"
    # Slice-then-escape is what the caller now does, and it locates the line.
    assert find_line_in_diff(diff, _re.escape(url[:80])) == 3


# ---------------------------------------------------------------------------
# Polynomial cost, which the short probes are structurally unable to see.
# ---------------------------------------------------------------------------

# Each of these shipped, passed the 22-character probes, and cost hundreds
# of milliseconds to seconds against one line at `MAX_RULE_LINE_BYTES`.
QUADRATIC = [
    (r"\d+(?:\.\d+){1,}", "1"),
    (r"(?:\A\s*|[;&|]|\$\()\s*sudo(?=[\s)&|`;]|$)", " "),
    (r"/+$", "/"),
    # Both of these were classified linear from measurements at n<=26,
    # which is precisely the blind spot the long probes exist to close.
    (r"(-?\d+,)+;", "1,"),
    (r"(a|ab)+c", "a"),
]


@pytest.mark.parametrize("pattern,char", QUADRATIC)
def test_a_quadratic_pattern_is_refused(pattern, char):
    """The probes must be long enough for polynomial cost to appear.

    22 characters is tuned for exponential blowup - 2^22 is millions of
    steps. Quadratic cost at 22 characters is 484 steps, which is nothing,
    and the same pattern at the 8192-byte line ceiling is 67 million.
    """
    assert _flagged(pattern), f"{pattern} is quadratic but was allowed"


@pytest.mark.parametrize("pattern,char", QUADRATIC)
def test_the_quadratic_corpus_really_is_quadratic(pattern, char):
    """Guards the guard, as above: growth must be superlinear."""
    compiled = re.compile(pattern, re.IGNORECASE)

    def cost(n):
        start = time.perf_counter()
        compiled.search(char * n + "!")
        return time.perf_counter() - start

    # Quadratic means 4x the input costs ~16x the time; 4x proves the shape
    # while tolerating a noisy machine.
    assert cost(4096) > cost(1024) * 4, f"{pattern} is linear, not quadratic"


def test_a_punctuation_only_alphabet_is_derived():
    """The gap ``/+$`` fell through, named by its alphabet rather than itself.

    ``_representatives`` used to harvest escapes, character classes and the
    first *alphanumeric* literal. A pattern whose only consumable literal is
    punctuation therefore derived no alphabet at all, and ``growth_ratio``
    fell back to probing with ``a`` - input ``/`` can never match. Both
    measurements came back at zero, zero is below ``_GROWTH_FLOOR_S``, and a
    skipped measurement scored the same as a fast one. The pattern is
    genuinely quadratic (~16x for 4x the input on the probe pair) and was
    allowed.
    """
    from trustsight.regex_safety import _representatives

    assert _representatives(r"/+$") == ["/"]
    assert _representatives(r"-+$") == ["-"]
    # Syntax is not input: a ``:`` from ``(?:``, a digit from a counted
    # quantifier and a class body's contents must not enter the alphabet as
    # literals, or the probe is drawn from the wrong alphabet again.
    assert ":" not in _representatives(r"(?:ab)+$")
    assert _representatives(r"x{2,64}") == ["x"]


def test_an_underivable_alphabet_probes_more_than_one_character():
    """Unmeasured is unknown, not safe.

    ``or ["a"]`` was a single character standing in for every pattern whose
    alphabet could not be derived, and it silently decided the answer for
    all of them.
    """
    from trustsight.regex_safety import _FALLBACK_ALPHABET, _representatives

    assert len(_FALLBACK_ALPHABET) > 1
    assert not _representatives(r"^$")


def test_the_long_probe_is_long_enough_to_show_quadratic_cost():
    from trustsight.regex_safety import LONG_PROBE_LEN

    # n^2 at the probe length must be large enough to measure against the
    # budget: 2048^2 is 4.2M steps, comfortably tens of milliseconds.
    assert LONG_PROBE_LEN**2 > 1_000_000


def test_probes_cover_short_and_long_for_every_derived_alphabet():
    """Short finds exponential, long finds polynomial; both are needed."""
    from trustsight.regex_safety import BACKTRACK_REPS, LONG_PROBE_LEN

    probes = derived_probes(r"([0-9]+)+$")
    assert any(len(p) <= BACKTRACK_REPS + 1 for p in probes)
    assert any(len(p) >= LONG_PROBE_LEN for p in probes)


def test_a_slash_run_is_stripped_without_a_regex():
    """`/+$` was quadratic; `rstrip` is the same operation in linear time."""
    from trustsight.novelty import normalize_url

    start = time.perf_counter()
    assert normalize_url("http://x/" + "/" * 8192) == "http://x"
    assert time.perf_counter() - start < 0.05


def test_no_shipped_pattern_is_slow_on_a_full_length_line():
    """The end-to-end property: every pattern, at the real line ceiling.

    `scripts/regex_audit.py` gates this in CI against the probe set. This
    asserts the same thing directly against `MAX_RULE_LINE_BYTES`, because
    the probe set is a proxy and this is the quantity that matters.
    """
    import ast
    import pathlib

    import trustsight
    from trustsight.rules import MAX_RULE_LINE_BYTES

    root = pathlib.Path(trustsight.__file__).parent
    n = MAX_RULE_LINE_BYTES
    inputs = [
        "a" * n, " " * n, "1" * n, "/" * n, "a " * (n // 2),
        "a." * (n // 2), "$" * n, "-" * n, "curl " + "a" * (n - 5),
    ]

    slow = []
    for path in sorted(root.rglob("*.py")):
        for node in ast.walk(ast.parse(path.read_text())):
            if not (isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "compile"
                    and node.args
                    and isinstance(node.args[0], ast.Constant)
                    and isinstance(node.args[0].value, str)):
                continue
            try:
                compiled = re.compile(node.args[0].value, re.IGNORECASE)
            except re.error:
                continue
            for text in inputs:
                start = time.perf_counter()
                compiled.search(text)
                elapsed = time.perf_counter() - start
                if elapsed > 0.05:
                    slow.append(f"{path.name}:{node.lineno} {elapsed * 1000:.0f}ms")
                    break

    assert not slow, f"slow on a full-length line: {slow}"


# ---------------------------------------------------------------------------
# The audit's coverage, as distinct from its verdict.
# ---------------------------------------------------------------------------


def _live_patterns():
    """Every compiled pattern reachable from an imported module."""
    import importlib
    import pathlib

    import trustsight

    root = pathlib.Path(trustsight.__file__).parent
    found = []
    for path in sorted(root.rglob("*.py")):
        parts = [
            part for part in path.relative_to(root).with_suffix("").parts
            if part != "__init__"
        ]
        if not parts or parts[0] == "cli" or "__main__" in parts:
            continue
        name = "trustsight." + ".".join(parts)
        try:
            module = importlib.import_module(name)
        except Exception:
            continue
        for attr, value in vars(module).items():
            candidates = (
                [value] if isinstance(value, re.Pattern)
                else list(value) if isinstance(value, (list, tuple, frozenset, set))
                else []
            )
            for item in candidates:
                if isinstance(item, re.Pattern):
                    found.append((f"{name}.{attr}", item))
    return found


def test_an_assembled_pattern_is_audited():
    """The specific hole: `re.compile(PREFIX + r"...")` is not a Constant.

    The audit collected `re.compile("literal")` out of the AST, so a
    pattern built from parts was skipped in silence. That was 44 of 246
    patterns, and they cluster in `sabotage`, `persistence` and
    `crossfire`, which are built from shared command-start prefixes, so
    one bad component would have spread across many rules unchecked.
    """
    import sys

    sys.path.insert(0, "scripts")
    from regex_audit import audit_patterns

    audited = {audit.pattern for audit in audit_patterns()}

    from trustsight.analysis import persistence

    # This one is assembled, and therefore was invisible before.
    assert persistence._TEE_TARGET_RE.pattern in audited


def test_every_live_pattern_is_covered_by_the_audit():
    """A gate that passes because it never looked is the failure mode."""
    import sys

    sys.path.insert(0, "scripts")
    from regex_audit import audit_patterns

    audited = {audit.pattern for audit in audit_patterns()}
    missing = [name for name, c in _live_patterns() if c.pattern not in audited]
    assert not missing, f"not audited: {missing}"


def test_no_live_pattern_is_slow_on_a_full_length_line():
    """The end-to-end property, over assembled patterns as well as literals.

    The companion test above walks the AST and so cannot see these.
    """
    from trustsight.rules import MAX_RULE_LINE_BYTES

    n = MAX_RULE_LINE_BYTES
    inputs = [
        "a" * n, " " * n, "1" * n, "/" * n, "a " * (n // 2),
        "a." * (n // 2), "$" * n, "-" * n, "curl " + "a" * (n - 5),
    ]
    slow = []
    for name, compiled in _live_patterns():
        for text in inputs:
            start = time.perf_counter()
            compiled.search(text)
            if time.perf_counter() - start > 0.05:
                slow.append(name)
                break
    assert not slow, f"slow on a full-length line: {slow}"


# ---------------------------------------------------------------------------
# Patterns that do not exist until match time.
# ---------------------------------------------------------------------------


def _audited_patterns():
    import sys

    sys.path.insert(0, "scripts")
    from regex_audit import audit_patterns

    return {audit.pattern for audit in audit_patterns()}


def test_a_generated_rule_pattern_is_audited():
    """R013, R047 and R048 evade all three collection strategies at once.

    Their TOML entry is a placeholder, they are not `re.compile("literal")`
    in the source, and they are not module-level `re.Pattern` objects. R013
    is the FATAL homoglyph rule, and R047/R048 are built from operator
    config, so a config edit could have introduced a slow pattern with no
    gate positioned to notice.
    """
    import tomllib

    from trustsight.config import DEFAULT_RULES
    from trustsight.rules import GENERATED_PATTERN_RULES, resolve_generated_patterns

    audited = _audited_patterns()
    rules = tomllib.loads(DEFAULT_RULES).get("rules", [])
    resolve_generated_patterns(rules)

    checked = 0
    for rule in rules:
        if rule.get("id") in GENERATED_PATTERN_RULES:
            checked += 1
            assert rule["pattern"] in audited, f"{rule['id']} is not audited"
    assert checked == len(GENERATED_PATTERN_RULES)


def test_the_audit_sees_the_pattern_that_actually_runs():
    """Auditing the placeholder would audit a pattern that never executes."""
    from trustsight.unicode import R013_UNCONDITIONAL_PATTERN

    assert any(
        R013_UNCONDITIONAL_PATTERN in pattern for pattern in _audited_patterns()
    )


def test_generated_patterns_come_from_one_function():
    """`apply_rules` and the audit must not build them separately.

    Two copies would let the audit check something the engine does not run,
    which is worse than not auditing at all: it reports coverage it does
    not have.
    """
    import inspect

    from trustsight import rules

    source = inspect.getsource(rules.apply_rules)
    assert "resolve_generated_patterns" in source
    # And the generation itself lives in exactly one place.
    assert source.count("R013_UNCONDITIONAL_PATTERN") == 0


def test_generated_patterns_are_not_slow():
    """They are as much a part of the hot path as any shipped pattern."""
    import tomllib

    from trustsight.config import DEFAULT_RULES
    from trustsight.rules import (
        GENERATED_PATTERN_RULES,
        MAX_RULE_LINE_BYTES,
        resolve_generated_patterns,
    )

    rules = tomllib.loads(DEFAULT_RULES).get("rules", [])
    resolve_generated_patterns(rules)
    n = MAX_RULE_LINE_BYTES
    inputs = ["a" * n, " " * n, "1" * n, "a." * (n // 2), ":" * n, "-" * n]

    for rule in rules:
        if rule.get("id") not in GENERATED_PATTERN_RULES:
            continue
        compiled = re.compile(rule["pattern"], re.IGNORECASE)
        for text in inputs:
            start = time.perf_counter()
            compiled.search(text)
            elapsed = time.perf_counter() - start
            assert elapsed < 0.05, (
                f"{rule['id']} took {elapsed * 1000:.0f}ms on a full line"
            )
