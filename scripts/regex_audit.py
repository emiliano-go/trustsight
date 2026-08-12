"""Audit shipped regex patterns against bounded adversarial probes.

This is intentionally dependency-free. It does not replace Python's ``re``
engine; it makes the current worst-case checks visible for both configured
rules and literal patterns compiled in the source tree.
"""

from __future__ import annotations

import ast
import re
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src" / "trustsight"
sys.path.insert(0, str(ROOT / "src"))

from trustsight.config import DEFAULT_RULES  # noqa: E402
from trustsight.lint import (  # noqa: E402
    _BACKTRACK_BUDGET_S,
    _backtracking_risk,
)


@dataclass(frozen=True)
class PatternAudit:
    source: str
    pattern: str
    worst_seconds: float
    error: str = ""

    @property
    def passed(self) -> bool:
        return not self.error and self.worst_seconds <= _BACKTRACK_BUDGET_S


def _literal_patterns() -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    for path in sorted(SRC.rglob("*.py")):
        tree = ast.parse(path.read_text(), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if not isinstance(func, ast.Attribute) or func.attr != "compile":
                continue
            if not isinstance(func.value, ast.Name) or func.value.id != "re":
                continue
            if not node.args or not isinstance(node.args[0], ast.Constant):
                continue
            if isinstance(node.args[0].value, str):
                found.append((f"{path.relative_to(ROOT)}:{node.lineno}", node.args[0].value))
    return found


def _configured_patterns() -> list[tuple[str, str]]:
    import tomllib

    rules = tomllib.loads(DEFAULT_RULES).get("rules", [])
    return [(f"DEFAULT_RULES:{rule.get('id', '<unknown>')}", rule["pattern"])
            for rule in rules if isinstance(rule.get("pattern"), str)]


def audit_patterns() -> list[PatternAudit]:
    audits: list[PatternAudit] = []
    seen: set[tuple[str, str]] = set()
    for source, pattern in _configured_patterns() + _literal_patterns():
        key = (source, pattern)
        if key in seen:
            continue
        seen.add(key)
        try:
            compiled = re.compile(pattern, re.IGNORECASE)
            worst = _backtracking_risk(compiled)
            audits.append(PatternAudit(source, pattern, worst))
        except re.error as exc:
            audits.append(PatternAudit(source, pattern, 0.0, f"compile: {exc}"))
    return audits


def main() -> int:
    audits = audit_patterns()
    failures = [audit for audit in audits if not audit.passed]
    for audit in audits:
        status = "PASS" if audit.passed else "FAIL"
        print(f"{status} {audit.source} {audit.worst_seconds * 1000:.2f}ms")
        if audit.error:
            print(f"  {audit.error}")
    print(f"{len(audits) - len(failures)}/{len(audits)} regex patterns passed")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
