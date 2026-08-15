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
from trustsight.regex_safety import is_superlinear  # noqa: E402


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


def _runtime_patterns() -> list[tuple[str, str]]:
    """Every compiled pattern reachable from an imported module.

    The AST scan above only sees ``re.compile("literal")``. A pattern
    assembled from parts - ``re.compile(_WRITE_CMD_START + r"tee ...")`` -
    is a ``BinOp`` rather than a ``Constant``, so it was skipped silently,
    and shared command-start prefixes are exactly the idiom the newer rule
    modules are built from. That was 44 of 246 patterns, 18%, concentrated
    in ``sabotage``, ``persistence`` and ``crossfire``.

    Importing to enumerate is the only way to see an assembled pattern,
    because its text does not exist until it is built.
    """
    import importlib

    found: list[tuple[str, str]] = []
    seen: set[int] = set()
    for path in sorted(SRC.rglob("*.py")):
        parts = [
            part
            for part in path.relative_to(SRC).with_suffix("").parts
            if part != "__init__"
        ]
        # `cli` builds a Typer app and `__main__` runs it on import.
        if not parts or parts[0] == "cli" or "__main__" in parts:
            continue
        name = "trustsight." + ".".join(parts)
        try:
            module = importlib.import_module(name)
        except Exception:
            continue
        for attr, value in vars(module).items():
            candidates = (
                [value]
                if isinstance(value, re.Pattern)
                else list(value)
                if isinstance(value, (list, tuple, frozenset, set))
                else []
            )
            for item in candidates:
                if isinstance(item, re.Pattern) and id(item) not in seen:
                    seen.add(id(item))
                    found.append((f"{name}.{attr}", item.pattern))
    return found


def _configured_patterns() -> list[tuple[str, str]]:
    """The TOML rules, with generated patterns resolved as they run.

    R013, R047 and R048 carry a placeholder in the TOML and are assembled
    at match time from Unicode data and from config. Auditing the
    placeholder audits a pattern that never executes, so this resolves them
    through the same function `rules.apply_rules` uses.
    """
    import tomllib

    from trustsight.rules import resolve_generated_patterns

    rules = tomllib.loads(DEFAULT_RULES).get("rules", [])
    resolve_generated_patterns(rules)
    return [(f"DEFAULT_RULES:{rule.get('id', '<unknown>')}", rule["pattern"])
            for rule in rules if isinstance(rule.get("pattern"), str)]


def audit_patterns() -> list[PatternAudit]:
    audits: list[PatternAudit] = []
    # Keyed on the pattern text, not on where it was found. The same
    # pattern is reached as a source literal and again as a live object,
    # and auditing it twice under two labels only inflates the count.
    seen: set[str] = set()
    for source, pattern in (
        _configured_patterns() + _literal_patterns() + _runtime_patterns()
    ):
        if pattern in seen:
            continue
        seen.add(pattern)
        try:
            compiled = re.compile(pattern, re.IGNORECASE)
            worst = _backtracking_risk(compiled)
            # Growth as well as absolute cost, matching `rules._compiled`:
            # a quadratic pattern with a small constant sits under the
            # budget at the probe length and costs seconds at a full line.
            if worst <= _BACKTRACK_BUDGET_S and is_superlinear(compiled):
                audits.append(PatternAudit(
                    source, pattern, worst,
                    "cost grows faster than input length",
                ))
            else:
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
