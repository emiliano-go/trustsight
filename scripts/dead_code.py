"""Fail when a definition is referenced nowhere.

The reference corpus is every Python file under ``src``, ``scripts`` and
``tests``, plus the prose that can name a public symbol (``docs``,
``docs_src``, ``pyproject.toml``, ``zensical.toml``).  A definition is live
when its identifier appears anywhere outside the line that defines it.

Checked:

- module-level functions, classes and uppercase constants in ``src/trustsight``;
- class methods (non-dunder, non-decorated) in ``src/trustsight``;
- module-level definitions in ``scripts/``;
- distinctive keys in ``DEFAULT_CONFIG``, which must be named outside the
  defaults module.

Deliberately conservative:

- decorated definitions are skipped (a Typer command, property or callback is
  wired by its decorator, not by another reference);
- dunders, ``__init__`` and ``__main__`` are skipped;
- names listed in any ``__all__`` are public surface, not dead code;
- a small allowlist covers names loaded by string or called by a foreign
  framework.

The scan is textual and therefore errs toward calling something live.  It is
a regression guard against *new* orphans, not an instrument for proving code
is dead.
"""

from __future__ import annotations

import ast
import re
import tomllib
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "src" / "trustsight"
SCRIPTS = ROOT / "scripts"
CONFIG_DEFAULTS = SOURCE / "config" / "_default_config.py"
REFERENCE_GLOBS = (
    "src/**/*.py",
    "scripts/**/*.py",
    "tests/**/*.py",
    "docs/**/*.md",
    "docs_src/**/*.md",
)
REFERENCE_FILES = ("pyproject.toml", "zensical.toml")

#: Names with no static reference, with the reason they are still live.
ALLOWLIST = {
    "makeExtension": "zensical extension factory, loaded from zensical.toml",
    "sideband_progress": "pygit2 RemoteCallbacks method, called by libgit2",
    "extendMarkdown": "Python-Markdown extension hook, called by the framework",
}

#: Config keys too generic to prove dead by name alone.
GENERIC_CONFIG_KEYS = frozenset({
    "enabled", "allow", "name", "names", "path", "url", "value", "values",
    "mode", "description", "tag", "limit", "rate", "weight", "severity",
    "threshold", "days", "hours", "seconds", "timeout", "interval", "max",
    "min", "count", "key", "channel", "fatal",
})

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


def _methods(node: ast.ClassDef):
    for item in node.body:
        if not isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if item.decorator_list or item.name.startswith("__"):
            continue
        yield f"{node.name}.{item.name}", item.name, item.lineno, "method"


def _definitions(path: Path):
    tree = ast.parse(path.read_text(errors="ignore"))
    exported = _exports(tree)
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if not node.decorator_list and not node.name.startswith("__"):
                yield node.name, node.name, node.lineno, type(node).__name__, exported
            if isinstance(node, ast.ClassDef):
                for display, name, line, kind in _methods(node):
                    yield display, name, line, kind, exported
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id.isupper():
                    yield target.id, target.id, node.lineno, "constant", exported


def _scan(source: Path, frequency: Counter[str]) -> list[tuple[str, int, str, str]]:
    found: list[tuple[str, int, str, str]] = []
    for path in sorted(source.rglob("*.py")):
        if path.name in ("__init__.py", "__main__.py"):
            continue
        try:
            definitions = list(_definitions(path))
        except (OSError, SyntaxError):
            continue
        for display, name, line, kind, exported in definitions:
            if name in exported or name in ALLOWLIST:
                continue
            if frequency[name] <= 1:
                found.append((display, line, kind, str(path.relative_to(ROOT))))
    return found


def _default_config_keys() -> list[str]:
    text = CONFIG_DEFAULTS.read_text(errors="ignore")
    match = re.search(r'DEFAULT_CONFIG\s*=\s*"""[\\]?\n(.*?)"""', text, re.S)
    if match is None:
        return []
    parsed = tomllib.loads(match.group(1))
    keys: list[str] = []

    def walk(mapping):
        for key, value in mapping.items():
            if isinstance(value, dict):
                walk(value)
            elif len(key) >= 5 and key not in GENERIC_CONFIG_KEYS:
                keys.append(key)

    walk(parsed)
    return keys


def config_key_orphans() -> list[tuple[str, int, str, str]]:
    """Distinctive DEFAULT_CONFIG keys never named outside the defaults module."""
    text = "\n".join(
        p.read_text(errors="ignore")
        for pattern in REFERENCE_GLOBS
        for p in ROOT.glob(pattern)
        if p != CONFIG_DEFAULTS
    )
    found: list[tuple[str, int, str, str]] = []
    for key in dict.fromkeys(_default_config_keys()):
        named = re.search(rf'["\']{re.escape(key)}["\']|\b{re.escape(key)}\b\s*=', text)
        if named is None:
            found.append((key, 0, "config-key", str(CONFIG_DEFAULTS.relative_to(ROOT))))
    return found


def orphans(
    source: Path = SOURCE,
    frequency: Counter[str] | None = None,
    *,
    include_scripts: bool = True,
    include_config: bool = True,
) -> list[tuple[str, int, str, str]]:
    """Return ``(name, line, kind, path)`` for definitions with one reference."""
    if frequency is None:
        frequency = _reference_corpus()
    found = _scan(source, frequency)
    if include_scripts:
        found.extend(_scan(SCRIPTS, frequency))
    if include_config:
        found.extend(config_key_orphans())
    return sorted(found, key=lambda item: (item[3], item[1]))


def main() -> int:
    dead = orphans()
    if not dead:
        print("no unreferenced definitions or config keys")
        return 0
    print(f"{len(dead)} unreferenced definition(s) or config key(s):")
    for name, line, kind, path in dead:
        print(f"  {path}:{line}  {kind} {name}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
