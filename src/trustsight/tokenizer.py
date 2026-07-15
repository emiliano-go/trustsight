import re


def tokenize_and_resolve(diff_text: str) -> tuple[list[str], list[str]]:
    additions = []
    for line in diff_text.splitlines():
        if line.startswith("+"):
            content = line[1:]
            if content.strip():
                additions.append(content)

    var_table: dict[str, str] = {}
    unresolved: list[str] = []
    resolved: list[str] = []

    for line in additions:
        m = re.match(r"^(\w+)\s*=\s*(.+)", line)
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
                unresolved.append(line)
        else:
            unresolved.append(line)

    for line in unresolved:

        def replacer(m: re.Match) -> str:
            var = m.group(1) or m.group(2)
            return var_table.get(var, m.group(0))

        resolved_line = re.sub(r"\$\{(\w+)\}|\$(\w+)", replacer, line)
        resolved.append(resolved_line)

    return resolved, [u for u in unresolved if u not in resolved]
