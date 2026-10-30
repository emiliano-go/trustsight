"""The documented rule metadata agrees with what the code emits.

``registry_meta.json`` is now the source for a rule's name and severity, and
the reference pages render from it.  These checks close the loop the other
way: for every rule whose emitters we can read statically, the documented
name and severity must be among the values the code actually emits, so the
registry cannot quietly describe a rule the analyser no longer has.

The wiring audit is exhaustive: local conditionals, loop dispatch and the
X/temporal tables are followed so every live registry rule must reach an
emitter.  Metadata checks remain conservative where one reusable local name
has several unrelated values and control flow cannot be joined safely.
"""

from __future__ import annotations

import ast
import tomllib
from pathlib import Path

from trustsight.categories import RULE_CATEGORIES
from trustsight.config._default_rules import DEFAULT_RULES
from trustsight.registry import REGISTRY, SECTION_META

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "src" / "trustsight"

#: Files that name a rule in a sample or a lint template, not as an emitter.
_NOT_EMITTERS = {"contract.py", "lint.py"}

#: Rules whose documented name is an umbrella the emitters never use
#: verbatim: H078 documents one "signing key set changed" fact, but names
#: the replacement, addition and introduction paths separately.
_UMBRELLA_NAMES = {"H078"}

_SEVERITY = {"FATAL", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}


def _strings(node: ast.AST, bindings: dict[str, set[str]]) -> set[str]:
    """Every literal string an expression can select in one scope."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return {node.value}
    if isinstance(node, ast.Name):
        return bindings.get(node.id, set())
    if isinstance(node, ast.IfExp):
        return _strings(node.body, bindings) | _strings(node.orelse, bindings)
    return set()


def _scope_bindings(scope: ast.AST) -> dict[str, set[str]]:
    """Possible string values assigned to a name, including loop dispatch."""
    bindings: dict[str, set[str]] = {}

    def bind(target: ast.AST, value: ast.AST) -> None:
        if isinstance(target, ast.Name):
            bindings.setdefault(target.id, set()).update(_strings(value, bindings))
        elif isinstance(target, (ast.Tuple, ast.List)) and isinstance(
                value, (ast.Tuple, ast.List)) and len(target.elts) == len(value.elts):
            for target_item, value_item in zip(target.elts, value.elts):
                bind(target_item, value_item)

    class ScopeVisitor(ast.NodeVisitor):
        def visit(self, node):
            # A module's bindings do not include its functions' locals.
            if node is not scope and isinstance(
                    node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                return
            super().visit(node)

        def visit_Assign(self, node):
            for target in node.targets:
                bind(target, node.value)
            self.generic_visit(node)

        def visit_AnnAssign(self, node):
            if node.value is not None:
                bind(node.target, node.value)
            self.generic_visit(node)

        def visit_For(self, node):
            values = node.iter.elts if isinstance(node.iter, (ast.Tuple, ast.List)) else []
            for value in values:
                bind(node.target, value)
            self.generic_visit(node)

    ScopeVisitor().visit(scope)
    return bindings


def _emitted() -> dict[str, set[tuple[str, str]]]:
    """rule id -> the (name, severity) pairs statically present in source.

    Besides literal emitters, follow local conditionals and loop variables.
    Table-dispatched rules are read from the tables their dispatch consumes,
    so a computed id is covered rather than silently skipped.
    """
    found: dict[str, set[tuple[str, str]]] = {}

    def record(rule_ids, names, severities) -> None:
        for rule_id in rule_ids:
            for name in names:
                for severity in severities:
                    if rule_id in RULE_CATEGORIES and name and severity in _SEVERITY:
                        found.setdefault(rule_id, set()).add((name, severity))

    for rule in tomllib.loads(DEFAULT_RULES)["rules"]:
        record({rule.get("id")}, {rule.get("name")}, {rule.get("severity")})

    for path in SOURCE.rglob("*.py"):
        if path.name in _NOT_EMITTERS:
            continue
        try:
            tree = ast.parse(path.read_text())
        except SyntaxError:  # pragma: no cover - source always parses
            continue
        module_bindings = _scope_bindings(tree)
        scopes = [tree, *(n for n in ast.walk(tree)
                          if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)))]
        for scope in scopes:
            bindings = {key: set(value) for key, value in module_bindings.items()}
            if scope is not tree:
                for key, value in _scope_bindings(scope).items():
                    bindings.setdefault(key, set()).update(value)
            for node in ast.walk(scope):
                if isinstance(node, ast.Dict):
                    fields = {}
                    for key, value in zip(node.keys, node.values):
                        if not isinstance(key, ast.Constant) or not isinstance(key.value, str):
                            continue
                        values = _strings(value, bindings)
                        # A function may reuse ``severity`` for several rules.
                        # Without control-flow analysis, unioning those values
                        # into every literal-id dict invents emissions.
                        if key.value == "severity" and isinstance(value, ast.Name) and len(values) > 1:
                            values = set()
                        fields[key.value] = values
                    rule_value = next((value for key, value in zip(node.keys, node.values)
                                       if isinstance(key, ast.Constant)
                                       and key.value == "rule_id"), None)
                    if isinstance(rule_value, ast.Constant):
                        record(fields.get("rule_id", set()), fields.get("name", set()),
                               fields.get("severity", set()))
                    # The X-series name/severity dispatch table.
                    for key, value in zip(node.keys, node.values):
                        ids = _strings(key, bindings) if key is not None else set()
                        if ids and isinstance(value, ast.Tuple) and len(value.elts) >= 2:
                            record(ids, _strings(value.elts[0], bindings),
                                   _strings(value.elts[1], bindings))
                elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                    if node.func.id in {"add", "once"} and node.args:
                        record(_strings(node.args[0], bindings),
                               _strings(node.args[1], bindings) if len(node.args) > 1 else set(),
                               _strings(node.args[2], bindings) if len(node.args) > 2 else set())
    return found


def _wired() -> set[str]:
    """Ids with an executable emitter or a row in an emitter dispatch table."""
    wired = set(_emitted())
    for path in SOURCE.rglob("*.py"):
        if path.name in _NOT_EMITTERS:
            continue
        tree = ast.parse(path.read_text())
        module_bindings = _scope_bindings(tree)
        scopes = [tree, *(n for n in ast.walk(tree)
                          if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)))]
        for scope in scopes:
            bindings = {key: set(value) for key, value in module_bindings.items()}
            if scope is not tree:
                for key, value in _scope_bindings(scope).items():
                    bindings.setdefault(key, set()).update(value)
            for node in ast.walk(scope):
                ids: set[str] = set()
                if isinstance(node, ast.Dict):
                    fields = {
                        key.value: value for key, value in zip(node.keys, node.values)
                        if isinstance(key, ast.Constant) and isinstance(key.value, str)
                    }
                    if {"rule_id", "name", "severity"} <= set(fields):
                        ids |= _strings(fields["rule_id"], bindings)
                elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                    if node.func.id in {"add", "once", "TemporalInstance"} and node.args:
                        ids |= _strings(node.args[0], bindings)
                    if node.func.id == "ScoreEntry":
                        for keyword in node.keywords:
                            if keyword.arg == "rule_id":
                                ids |= _strings(keyword.value, bindings)
                wired |= ids & set(RULE_CATEGORIES)
    return wired


def _canonical() -> dict[str, dict]:
    return {
        entry["uid"]: entry
        for entry in SECTION_META.values()
        if entry.get("canonical")
    }


def test_every_rule_has_a_documented_name():
    named = _canonical()
    missing = sorted(rule.id for rule in REGISTRY.all() if not named.get(rule.uid, {}).get("name"))
    assert missing == [], f"rules with no documented name: {missing}"


def test_the_documented_name_is_one_the_code_emits():
    emitted = _emitted()
    named = _canonical()
    wrong = []
    for rule in REGISTRY.all():
        pairs = emitted.get(rule.id)
        if not pairs:
            continue
        documented = named.get(rule.uid, {}).get("name")
        names = {name for name, _severity in pairs}
        if documented not in names and rule.id not in _UMBRELLA_NAMES:
            wrong.append((rule.id, documented, sorted(names)))
    assert wrong == [], (
        "documented name is never emitted; update registry_meta.json: " f"{wrong}"
    )


def test_the_documented_severity_covers_every_emitted_one():
    emitted = _emitted()
    named = _canonical()
    wrong = []
    for rule in REGISTRY.all():
        pairs = emitted.get(rule.id)
        if not pairs:
            continue
        text = named.get(rule.uid, {}).get("severity_text") or ""
        documented = {word for word in _SEVERITY if word in text}
        if not documented:
            continue  # no documented severity yet; skip rather than guess
        extra = {severity for _name, severity in pairs} - documented
        if extra:
            wrong.append((rule.id, sorted(extra), text))
    assert wrong == [], (
        "code emits a severity the docs do not describe; update "
        f"registry_meta.json: {wrong}"
    )


def test_every_live_rule_has_executable_wiring():
    """No live registry row is unwired, including computed-id dispatch."""
    live = {rule.id for rule in REGISTRY.all() if rule.status == "live"}
    anchors = {rule.id for rule in REGISTRY.all() if rule.status == "anchor"}
    assert len(live) == 273
    assert len(anchors) == 11
    assert not live & anchors
    missing = sorted(live - _wired())
    assert missing == [], f"live rules without an emitter or dispatch row: {missing}"
    # These were invisible to the old literal-only scanner.
    assert {"G007", "H045", "H056", "S001", "U008", "X001", "X034"} <= _wired()
