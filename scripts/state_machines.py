"""The registry and validator behind ``docs/explanation/state-and-lifecycles.md``.

The page is prose; this module is the fact layer.  It loads
``scripts/state_machines.toml``, resolves every documented anchor against the
source with ``ast`` (never by importing the package), and scans
``src/trustsight`` for modules that carry state the page has not classified.

The gate in ``scripts/gates/_state.py`` runs :func:`check_registry`; the
renderer in ``scripts/build_state_doc.py`` uses :func:`render_inventory`.

    python scripts/state_machines.py            # validate
    python scripts/state_machines.py --inventory
"""

from __future__ import annotations

import argparse
import ast
import re
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src" / "trustsight"
REGISTRY = ROOT / "scripts" / "state_machines.toml"

KIND_ORDER = ("lexical", "document", "persisted", "orchestration", "latch")

GENERATED_START = "<!-- generated: state-machines -->"
GENERATED_END = "<!-- /generated: state-machines -->"

# The scanner's vocabulary.  It is deliberately narrower than "any variable":
# these are the names that describe a mode, a carried lexical state, or a
# bounded worklist.  A miss is a documented blind spot, not a claim of
# completeness; the point of the scan is to notice a *new* module of this
# shape, not to prove every local variable harmless.
STATE_NAMES = frozenset({
    "state", "states", "mode", "phase", "status", "pending", "cursor", "seen",
    "visited", "frontier", "depth", "quote", "in_array", "in_hunk", "in_single",
    "in_double", "in_string", "in_comment", "open_quote", "message_quote",
    "in_source_array", "in_function", "opened", "closed", "array_open",
    "had_keys_before", "current_file", "truncated", "degraded", "attempts",
    "parked", "expired", "announced", "active", "carried",
})

MUTABLE_CALLS = frozenset({
    "list", "dict", "set", "defaultdict", "deque", "Counter", "OrderedDict",
})


@dataclass(frozen=True)
class Schema:
    module: str
    table: str
    columns: tuple[str, ...] = ()
    require: tuple[str, ...] = ()


@dataclass(frozen=True)
class Machine:
    id: str
    title: str
    kind: str
    status: str
    risk: str
    summary: str
    states: str
    anchors: tuple[str, ...]
    tests: tuple[str, ...]
    schema: tuple[Schema, ...] = ()


@dataclass(frozen=True)
class Registry:
    machines: tuple[Machine, ...]
    exempt: tuple[tuple[str, ...], ...] = ()

    def exempt_modules(self) -> set[str]:
        return {module for group in self.exempt for module in group}


def load_registry(path: Path = REGISTRY) -> Registry:
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    machines = []
    for raw in data.get("machine", []):
        machines.append(Machine(
            id=raw["id"],
            title=raw["title"],
            kind=raw["kind"],
            status=raw["status"],
            risk=raw["risk"],
            summary=raw["summary"],
            states=raw["states"],
            anchors=tuple(raw["anchors"]),
            tests=tuple(raw["tests"]),
            schema=tuple(
                Schema(
                    module=item["module"],
                    table=item["table"],
                    columns=tuple(item.get("columns", ())),
                    require=tuple(item.get("require", ())),
                )
                for item in raw.get("schema", ())
            ),
        ))
    exempt = tuple(tuple(group["modules"]) for group in data.get("exempt", []))
    return Registry(machines=tuple(machines), exempt=exempt)


def module_path(root: Path, module: str) -> Path | None:
    parts = module.split(".")
    if not parts or parts[0] != "trustsight":
        return None
    base = root / "src" / "trustsight"
    candidate = base.joinpath(*parts[1:]).with_suffix(".py")
    if candidate.is_file():
        return candidate
    package = base.joinpath(*parts[1:]) / "__init__.py"
    return package if package.is_file() else None


def module_relpath(module: str) -> str:
    parts = module.split(".")
    return "/".join(parts[1:]) + ".py"


def _assigned_names(node: ast.Assign | ast.AnnAssign) -> list[str]:
    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
    names: list[str] = []

    def collect(target: ast.AST) -> None:
        if isinstance(target, ast.Name):
            names.append(target.id)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for element in target.elts:
                collect(element)

    for target in targets:
        collect(target)
    return names


def _target_names(target: ast.AST) -> list[str]:
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, (ast.Tuple, ast.List)):
        names: list[str] = []
        for element in target.elts:
            names.extend(_target_names(element))
        return names
    return []


def _find_symbol(body: list[ast.stmt], name: str) -> ast.AST | None:
    for node in body:
        if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.name == name:
                return node
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            if name in _assigned_names(node):
                return node
    return None


def resolve_anchor(root: Path, anchor: str) -> str | None:
    """Resolve ``module:qualname`` to a problem string, or ``None``."""
    if ":" not in anchor:
        return f"malformed anchor {anchor!r} (expected module:qualname)"
    module, qualname = anchor.split(":", 1)
    path = module_path(root, module)
    if path is None:
        return f"missing module {module!r}"
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except SyntaxError as exc:  # pragma: no cover - source is importable
        return f"cannot parse {module!r}: {exc}"
    body = tree.body
    for part in qualname.split("."):
        node = _find_symbol(body, part)
        if node is None:
            return f"{anchor!r}: {part!r} not found in {module}"
        body = getattr(node, "body", [])
    return None


def resolve_test(root: Path, nodeid: str) -> str | None:
    """Resolve a pytest node id ``path::name[::Class...]``."""
    path_text, *qualname = nodeid.split("::")
    path = root / path_text
    if not path.is_file():
        return f"missing test file {path_text!r}"
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except SyntaxError as exc:  # pragma: no cover
        return f"cannot parse {path_text!r}: {exc}"
    body = tree.body
    for part in qualname:
        node = _find_symbol(body, part)
        if node is None:
            return f"{nodeid!r}: {part!r} not found in {path_text}"
        body = getattr(node, "body", [])
    if not qualname:
        return f"{nodeid!r}: no test name"
    return None


def _schema_source(root: Path, module: str) -> str | None:
    path = module_path(root, module)
    return path.read_text(encoding="utf-8") if path else None


def _check_schema(root: Path, machine: Machine) -> list[str]:
    problems: list[str] = []
    for schema in machine.schema:
        source = _schema_source(root, schema.module)
        if source is None:
            problems.append(f"{machine.id}: missing schema module {schema.module!r}")
            continue
        for needle, label in [(schema.table, "table"), *((c, "column") for c in schema.columns)]:
            if not re.search(rf"\b{re.escape(needle)}\b", source):
                problems.append(
                    f"{machine.id}: {label} {needle!r} not found in {schema.module}")
        for needle in schema.require:
            if needle not in source:
                problems.append(
                    f"{machine.id}: schema guarantee {needle!r} missing from {schema.module}")
    return problems


def scan_state_modules(src: Path = SRC) -> list[str]:
    """Return the modules that carry state a reader should classify."""
    hits: list[str] = []
    for path in sorted(src.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except SyntaxError:  # pragma: no cover - shipped source parses
            continue
        if _module_looks_stateful(tree):
            hits.append(path.relative_to(src).as_posix())
    return hits


def _is_state_name(name: str) -> bool:
    return name.lower() in STATE_NAMES and not name.startswith("__")


def _is_mutable_literal(node: ast.AST | None) -> bool:
    if isinstance(node, (ast.List, ast.Dict, ast.Set,
                         ast.ListComp, ast.DictComp, ast.SetComp)):
        return True
    if isinstance(node, ast.Call):
        func = node.func
        name = (func.id if isinstance(func, ast.Name)
                else func.attr if isinstance(func, ast.Attribute) else "")
        return name in MUTABLE_CALLS
    return False


def _gated_locals(function: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    params = {arg.arg for arg in function.args.args + function.args.kwonlyargs}
    assigned: set[str] = set()
    for node in ast.walk(function):
        if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                for name in _target_names(target):
                    if _is_state_name(name) and name not in params and not name.isupper():
                        assigned.add(name)
    if not assigned:
        return set()
    tested: set[str] = set()
    for node in ast.walk(function):
        if isinstance(node, (ast.If, ast.While, ast.IfExp, ast.Assert)):
            for sub in ast.walk(node.test):
                if isinstance(sub, ast.Name):
                    tested.add(sub.id)
        elif isinstance(node, (ast.For, ast.AsyncFor)):
            for sub in ast.walk(node.iter):
                if isinstance(sub, ast.Name):
                    tested.add(sub.id)
    return assigned & tested


def _module_looks_stateful(tree: ast.Module) -> bool:
    module_names: set[str] = set()
    for node in tree.body:
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        for name in _assigned_names(node):
            module_names.add(name)
            if _is_state_name(name):
                return True
            if (not name.startswith("__") and not name.isupper()
                    and _is_mutable_literal(node.value)):
                return True
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for sub in ast.walk(node):
            if isinstance(sub, ast.Global) and set(sub.names) & module_names:
                return True
        if _gated_locals(node):
            return True
    return False


def documented_modules(registry: Registry) -> set[str]:
    modules: set[str] = set()
    for machine in registry.machines:
        for anchor in machine.anchors:
            module = anchor.split(":", 1)[0]
            modules.add(module_relpath(module))
        for schema in machine.schema:
            modules.add(module_relpath(schema.module))
    return modules


def check_registry(root: Path = ROOT, registry: Registry | None = None) -> list[str]:
    """Every documented fact still exists, and no scanner hit is unclassified."""
    registry = registry or load_registry()
    problems: list[str] = []
    ids: set[str] = set()
    for machine in registry.machines:
        if machine.id in ids:
            problems.append(f"duplicate machine id {machine.id!r}")
        ids.add(machine.id)
        if machine.kind not in KIND_ORDER:
            problems.append(f"{machine.id}: unknown kind {machine.kind!r}")
        if machine.status not in ("explicit", "implicit"):
            problems.append(f"{machine.id}: unknown status {machine.status!r}")
        for anchor in machine.anchors:
            problem = resolve_anchor(root, anchor)
            if problem:
                problems.append(f"{machine.id}: {problem}")
        for nodeid in machine.tests:
            problem = resolve_test(root, nodeid)
            if problem:
                problems.append(f"{machine.id}: {problem}")
        problems.extend(_check_schema(root, machine))

    if not registry.machines:
        problems.append("registry has no machines")

    covered = documented_modules(registry) | registry.exempt_modules()
    for module in registry.exempt_modules():
        if not (root / "src" / "trustsight" / module).is_file():
            problems.append(f"exempt module {module!r} does not exist")
    for module in scan_state_modules(root / "src" / "trustsight"):
        if module not in covered:
            problems.append(
                f"unclassified stateful module {module!r}: add it to "
                f"scripts/state_machines.toml or document it on the page")
    return problems


def render_inventory(registry: Registry | None = None) -> str:
    registry = registry or load_registry()
    def order(machine: Machine) -> tuple[int, str]:
        rank = (KIND_ORDER.index(machine.kind)
                if machine.kind in KIND_ORDER else len(KIND_ORDER))
        return rank, machine.title.lower()

    machines = sorted(
        registry.machines,
        key=order,
    )
    lines = [
        f"*{len(machines)} documented machines; "
        f"{len(registry.exempt_modules())} further modules classified as "
        f"single-pass scanners, memos or one-way latches.*",
        "",
        "| Machine | Kind | Status | States | Where | Pinned by |",
        "|---|---|---|---|---|---|",
    ]
    for machine in machines:
        where = f"`{machine.anchors[0]}`" if machine.anchors else "-"
        pinned = machine.tests[0].split("::", 1)[-1] if machine.tests else "-"
        pinned = f"`{pinned}`"
        lines.append(
            f"| {machine.title} | {machine.kind} | {machine.status} | "
            f"{machine.states} | {where} | {pinned} |")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", action="store_true",
                        help="print the scanner's module list")
    args = parser.parse_args(argv)
    if args.inventory:
        for module in scan_state_modules(SRC):
            print(module)
        return 0
    problems = check_registry()
    for problem in problems:
        print(problem, file=sys.stderr)
    if problems:
        print(f"{len(problems)} problem(s)", file=sys.stderr)
        return 1
    print(f"ok: {len(load_registry().machines)} machines documented")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
