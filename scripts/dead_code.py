"""Fail when a module-level definition in ``src/trustsight`` is referenced nowhere.

The reference corpus is every Python file under ``src``, ``scripts`` and
``tests``, plus the prose that can name a public symbol (``docs``,
``docs_src``, ``pyproject.toml``, ``zensical.toml``).  A definition is live
when its identifier appears anywhere outside the line that defines it.

Deliberately conservative:

- decorated definitions are skipped (a Typer command or a callback is wired
  by its decorator, not by another reference);
- dunders, ``__init__`` and ``__main__`` are skipped;
- names listed in any ``__all__`` are public surface, not dead code;
- a small allowlist covers the few names an entry point loads as a string.

The scan is textual and therefore errs toward calling something live.  It is
a regression guard against *new* orphans, not an instrument for proving code
is dead.
"""

from __future__ import annotations

import ast
import re
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "src" / "trustsight"
REFERENCE_GLOBS = (
    "src/**/*.py",
    "scripts/**/*.py",
    "tests/**/*.py",
    "docs/**/*.md",
    "docs_src/**/*.md",
)
REFERENCE_FILES = ("pyproject.toml", "zensical.toml")

#: Loaded by string, so no static reference exists.
ALLOWLIST = {
    "makeExtension": "zensical extension factory, loaded from zensical.toml",
}

_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def _reference_corpus() -> Counter[str]:
    text = []
    for pattern in REFERENCE_GLOBS:
        text.extend(p.read_text(errors="ignore") for p in ROOT.glob(pattern))
    text.extend((ROOT / name).read_text(errors="ignore") for name in REFERENCE_FILES)
    return Counter(_IDENTIFIER.findall("\n".join(text)))


def _exports(tree: ast.AST) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        if not any(isinstance(t, ast.Name) and t.id == "__all__" for t in node.targets):
            continue
        value = node.value
        if isinstance(value, (ast.List, ast.Tuple)):
            names.update(
                element.value
                for element in value.elts
                if isinstance(element, ast.Constant) and isinstance(element.value, str)
            )
    return names


def _definitions(path: Path):
    tree = ast.parse(path.read_text(errors="ignore"))
    exported = _exports(tree)
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if node.decorator_list or node.name.startswith("__"):
                continue
            yield node.name, node.lineno, type(node).__name__, exported
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id.isupper():
                    yield target.id, node.lineno, "constant", exported


def orphans(source: Path = SOURCE, frequency: Counter[str] | None = None) -> list[tuple[str, int, str, str]]:
    """Return ``(name, line, kind, path)`` for definitions with one reference."""
    if frequency is None:
        frequency = _reference_corpus()
    found: list[tuple[str, int, str, str]] = []
    for path in sorted(source.rglob("*.py")):
        if path.name in ("__init__.py", "__main__.py"):
            continue
        try:
            definitions = list(_definitions(path))
        except (OSError, SyntaxError):
            continue
        for name, line, kind, exported in definitions:
            if name in exported or name in ALLOWLIST:
                continue
            if frequency[name] <= 1:
                found.append((name, line, kind, str(path.relative_to(ROOT))))
    return found


def main() -> int:
    dead = orphans()
    if not dead:
        print("no unreferenced module-level definitions")
        return 0
    print(f"{len(dead)} unreferenced module-level definition(s):")
    for name, line, kind, path in dead:
        print(f"  {path}:{line}  {kind} {name}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
