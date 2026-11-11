#!/usr/bin/env python3
"""Inventory the implicit state machines in the runtime source.

The tool has no StateMachine type, but correctness depends on status columns,
metadata keys, worker lifecycles and observation counters.  This scanner walks
every file under ``src/trustsight`` in sorted order and prints the signals that
identify such state: mutable module globals, lifecycle methods, state
vocabulary, DDL, caches and versioned state.  It is read-only and deterministic.

Usage:
    python scripts/implicit_state_scan.py
    python scripts/implicit_state_scan.py --root src/trustsight --json
"""

from __future__ import annotations

import argparse
import ast
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

STATE_WORDS = re.compile(
    r"\b(status|state|phase|stage|transition|lifecycle|stateful|"
    r"running|stopped|degraded|open|closed|active|inactive|pending|"
    r"done|failed|expired|stale|fresh|verified|unverified|promoted|"
    r"anergic|conditional|deferred|resolved|cold|warm|measured|"
    r"zero_fire|adversarial_only|cold_only|partial|complete|truncated|"
    r"refused|unavailable|analyzed|analysed|recorded|delivered|parked|"
    r"refractory|campaign|retry|backoff|reset|resume|quarantin|"
    r"watch|heartbeat|outbox|checkpoint|watermark|epoch|generation|"
    r"migrat|schema_version|user_version|fingerprint|ttl|expiry|expires|"
    r"deadline|budget|attempt|count|counter|flag|dirty|drained|armed)\b",
    re.IGNORECASE,
)
MUTABLE_GLOBAL = re.compile(
    r"^([_A-Za-z][A-Za-z0-9_]*)\s*(?::[^=]+)?=\s*(.*)$")
MUTABLE_VALUE = re.compile(
    r"(\{\}|\[\]|set\(\)|dict\(\)|list\(\)|deque\(|defaultdict\(|Counter\(|"
    r"\"\"|'')")
LIFECYCLE = re.compile(
    r"^\s+def (_?(start|stop|close|alive|advance|transition|mark_|"
    r"set_state|reset|__enter__|__exit__)\w*)\(")
LIFECYCLE_TOP = re.compile(
    r"^def (_?(start|stop|close|alive|advance|transition|mark_|"
    r"set_state|reset)\w*)\(")
CACHE = re.compile(r"(lru_cache|functools\.cache|\bcache\b|memo|@cache)", re.I)
DDL = re.compile(
    r"(CREATE TABLE|ALTER TABLE|INSERT INTO|UPDATE .* SET|user_version|"
    r"schema_version|PRAGMA|json_each)", re.I)
STATE_LITERAL = re.compile(r"^[a-z][a-z0-9_]{2,40}$")
LITERAL_KEEP = re.compile(
    r"(state|status|phase|stage|pending|done|fail|expire|stale|fresh|"
    r"verified|promot|anerg|conditional|deferred|resolved|cold|warm|"
    r"measured|zero_fire|adversarial|partial|complete|truncat|refus|"
    r"unavailable|analyz|analys|record|deliver|park|refractory|campaign|"
    r"active|inactive|lapsed|dormant|added|removed|modified|open|closed|"
    r"running|stopped|degraded|armed|drained|seen|blind|unproven|"
    r"unshaped|rearm|reset|resume|checkpoint|healthy|broken|quarantin)")


def _literal_states(tree: ast.AST) -> list[str]:
    values = set()
    for node in ast.walk(tree):
        if (isinstance(node, ast.Constant) and isinstance(node.value, str)
                and STATE_LITERAL.match(node.value)
                and LITERAL_KEEP.search(node.value)):
            values.add(node.value)
    return sorted(values)


def _py_report(path: Path, root: Path) -> dict:
    text = path.read_text(encoding="utf-8", errors="replace")
    rows = {
        "path": str(path.relative_to(root)),
        "lines": len(text.splitlines()),
        "globals": [],
        "lifecycle": [],
        "cache": [],
        "ddl": [],
        "states": [],
        "state_words": 0,
    }
    try:
        tree = ast.parse(text)
    except SyntaxError:
        tree = None
    if tree is not None:
        rows["states"] = _literal_states(tree)
    in_class = False
    for number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if stripped.startswith("class "):
            in_class = True
        if stripped.startswith("global "):
            rows["globals"].append([number, stripped])
        match = MUTABLE_GLOBAL.match(line)
        if (match and not line.startswith((" ", "\t")) and not in_class
                and not stripped.startswith(("def ", "class ", "import ",
                                              "from ", "#"))
                and not match.group(1).startswith("__")):
            name, value = match.group(1), match.group(2)
            constant = name.isupper() and not MUTABLE_VALUE.search(value)
            if not constant and (MUTABLE_VALUE.search(value)
                                 or name.startswith("_")):
                rows["globals"].append([number, f"{name} = {value[:60]}"])
        if LIFECYCLE.match(line) or LIFECYCLE_TOP.match(line):
            rows["lifecycle"].append([number, stripped])
        if CACHE.search(line):
            rows["cache"].append([number, stripped[:100]])
        if DDL.search(line):
            rows["ddl"].append([number, stripped[:100]])
        if STATE_WORDS.search(line):
            rows["state_words"] += 1
    return rows


def _other_report(path: Path, root: Path) -> dict:
    text = path.read_text(encoding="utf-8", errors="replace")
    return {
        "path": str(path.relative_to(root)),
        "lines": len(text.splitlines()),
        "kind": path.suffix or "no-extension",
    }


def scan(root: Path) -> dict:
    files = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix == ".pyc":
            continue
        if "__pycache__" in path.parts:
            continue
        if path.suffix == ".py":
            files.append(_py_report(path, root))
        else:
            files.append(_other_report(path, root))
    return {
        "root": str(root),
        "files_scanned": len(files),
        "files_with_state": sum(
            1 for row in files
            if row.get("globals") or row.get("lifecycle") or row.get("ddl")
            or row.get("states")),
        "files": files,
    }


def _render(report: dict) -> str:
    lines = [
        f"root: {report['root']}",
        f"files scanned: {report['files_scanned']}",
        f"files with state signals: {report['files_with_state']}",
        "",
    ]
    for row in report["files"]:
        if "kind" in row:
            lines.append(f"{row['path']}  lines={row['lines']}  "
                         f"kind={row['kind']}")
            continue
        summary = []
        if row["states"]:
            summary.append("states=" + ",".join(row["states"][:12]))
        if row["globals"]:
            summary.append("globals=" + str(len(row["globals"])))
        if row["lifecycle"]:
            summary.append("lifecycle=" + str(len(row["lifecycle"])))
        if row["cache"]:
            summary.append("cache=" + str(len(row["cache"])))
        if row["ddl"]:
            summary.append("ddl=" + str(len(row["ddl"])))
        if not summary:
            summary.append("no state signals")
        lines.append(f"{row['path']}  lines={row['lines']}  "
                     + "  ".join(summary))
        for number, text in row["globals"][:3]:
            lines.append(f"    G{number}: {text}")
        for number, text in row["lifecycle"][:3]:
            lines.append(f"    L{number}: {text}")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", type=Path,
                        default=ROOT / "src" / "trustsight")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    report = scan(args.root)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(_render(report), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
