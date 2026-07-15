import re

from .config import load_rules


def apply_rules(
    resolved_strings: list[str],
    raw_diff_lines: list[str],
    rules: list[dict] | None = None,
) -> list[dict]:
    if rules is None:
        rules = load_rules()

    triggered = []

    for rule in rules:
        match_target = rule.get("match_target", "raw_line")
        target_list = resolved_strings if match_target == "resolved" else raw_diff_lines

        try:
            compiled = re.compile(rule["pattern"], re.IGNORECASE)
        except re.error:
            continue

        for item in target_list:
            if compiled.search(item):
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
