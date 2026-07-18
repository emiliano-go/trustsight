import re

from .config import load_rules

# Lines starting with # after stripping + prefix are comments.
# Dependency declarations contain package names, not code — matching
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

# Track function body boundaries for position-aware scoring.
_FUNCTION_OPEN_RE = re.compile(r"^\s*\w+\s*\(\s*\)\s*\{")
_FUNCTION_CLOSE_RE = re.compile(r"^\s*\}")


def _to_pairs(lines: list[str]) -> list[tuple[int, str]]:
    return [(i, line) for i, line in enumerate(lines)]


def filter_raw_lines(lines: list[str]) -> list[tuple[int, str]]:
    """Remove comment lines and dependency declarations from raw diff lines.

    Returns (original_index, line) pairs so callers can map back to context.
    """
    return [(i, line) for i, line in enumerate(lines) if not _COMMENT_OR_DEP_RE.match(line)]


def _classify_line_context(lines: list[str]) -> dict[int, str]:
    """Return {line_index: context_name} for each line.

    Contexts: ``"function_body"``, ``"message"``, or ``"other"``.
    """
    contexts: dict[int, str] = {}
    depth = 0
    for i, line in enumerate(lines):
        stripped = line.lstrip("+").lstrip()
        if _MESSAGE_LINE_RE.match(line):
            contexts[i] = "message"
        elif depth > 0:
            contexts[i] = "function_body"
        else:
            contexts[i] = "other"
        if _FUNCTION_OPEN_RE.search(stripped):
            depth += 1
        if _FUNCTION_CLOSE_RE.search(stripped):
            depth = max(0, depth - 1)
    return contexts


def apply_rules(
    resolved_strings: list[str],
    raw_diff_lines: list[str],
    rules: list[dict] | None = None,
) -> list[dict]:
    if rules is None:
        rules = load_rules()

    triggered = []
    ctx_map = _classify_line_context(raw_diff_lines)

    for rule in rules:
        match_target = rule.get("match_target", "raw_line")
        if match_target == "raw_line":
            candidates = filter_raw_lines(raw_diff_lines)
        else:
            candidates = _to_pairs(resolved_strings)

        try:
            compiled = re.compile(rule["pattern"], re.IGNORECASE)
        except re.error:
            continue

        rule_scope = rule.get("scope") if match_target == "raw_line" else None

        for idx, item in candidates:
            if compiled.search(item):
                if rule_scope:
                    ctx = ctx_map.get(idx, "other")
                    if ctx not in rule_scope:
                        continue
                triggered.append(
                    {
                        "rule_id": rule["id"],
                        "name": rule["name"],
                        "severity": rule["severity"],
                        "category": rule["category"],
                        "match": item[:100],
                    }
                )
                break

    return triggered


def get_raw_diff_lines(diff_text: str) -> list[str]:
    lines = []
    for line in diff_text.splitlines():
        stripped = line.strip()
        if stripped:
            lines.append(stripped)
    return lines
