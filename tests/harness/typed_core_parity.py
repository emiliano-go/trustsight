"""Migration parity runner for the typed-core hardening.

Captures, for every benign corpus diff and every labelled malicious
fixture: the scored finding entries (rule, severity, weight, file, line,
params) and the line-scanner outputs used by rule scope (line context,
enclosing function, caller closure).  Write a baseline before a change and
check against it after.

    uv run python tests/harness/typed_core_parity.py --write BASE.json.gz
    uv run python tests/harness/typed_core_parity.py --check BASE.json.gz
"""

import argparse
import gzip
import json
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

import calibration_gates as gates  # noqa: E402

from trustsight.rules import (  # noqa: E402
    _caller_closure_map,
    _classify_line_context,
    _enclosing_function_map,
    get_raw_diff_lines_indexed,
)

FIXTURES = ROOT / "tests" / "fixtures"


def _scope_for(text: str) -> dict:
    raw, _indices = get_raw_diff_lines_indexed(text)
    ctx = _classify_line_context(raw)
    fn = _enclosing_function_map(raw)
    callers = _caller_closure_map(raw)
    return {
        "ctx": [[i, ctx[i]] for i in sorted(ctx)],
        "fn": [[i, fn[i]] for i in sorted(fn)],
        "callers": {k: sorted(v) for k, v in sorted(callers.items())},
    }


def _entries(fact) -> list[dict]:
    return [
        {
            "rule_id": e.rule_id,
            "severity": e.severity,
            "weight": e.weight,
            "file": e.file,
            "line": e.line,
            "params": e.params or {},
        }
        for e in fact.score_breakdown
    ]


def replay() -> dict:
    gates.ensure_default_configs()
    config = gates.load_config()
    rules = gates.load_rules()
    findings: list[dict] = []
    scopes: list[dict] = []

    corpus = FIXTURES / "benign-corpus"
    if corpus.exists():
        by_pkg: dict[str, list[Path]] = defaultdict(list)
        for path in sorted(corpus.rglob("*.diff")):
            by_pkg[path.name.split("__")[0]].append(path)
        seen_urls: dict[str, set[str]] = {}
        for pkg in sorted(by_pkg):
            for path in sorted(by_pkg[pkg], key=lambda p: p.stem):
                text = path.read_text(errors="replace")
                fact = gates.scan_diff(
                    text, rules=rules, config=config,
                    package_name=pkg, seen_urls=seen_urls,
                )
                findings.append({
                    "kind": "benign", "package": pkg, "name": path.name,
                    "score": fact.final_score, "entries": _entries(fact),
                })
                scopes.append({
                    "kind": "benign", "package": pkg, "name": path.name,
                    "scope": _scope_for(text),
                })

    malicious = FIXTURES / "malicious"
    if malicious.exists():
        for group in sorted(p for p in malicious.iterdir() if p.is_dir()):
            for path in sorted(group.glob("*.diff")):
                text = path.read_text(errors="replace")
                fact = gates.scan_diff(
                    text, rules=rules, config=config,
                    package_name=path.stem, seen_urls={},
                )
                findings.append({
                    "kind": "malicious", "package": group.name, "name": path.name,
                    "score": fact.final_score, "entries": _entries(fact),
                })
                scopes.append({
                    "kind": "malicious", "package": group.name, "name": path.name,
                    "scope": _scope_for(text),
                })
    return {"findings": findings, "scopes": scopes}


def _key(row: dict) -> tuple:
    return (row.get("kind"), row.get("package"), row.get("name"))


def compare(old: dict, new: dict) -> list[str]:
    failures: list[str] = []
    for section in ("findings", "scopes"):
        old_rows, new_rows = old[section], new[section]
        if len(old_rows) != len(new_rows):
            failures.append(
                f"{section}: size {len(old_rows)} -> {len(new_rows)}"
            )
            continue
        for a, b in zip(old_rows, new_rows):
            if a == b:
                continue
            if section == "scopes":
                fields = [
                    f for f in ("ctx", "fn", "callers")
                    if a["scope"][f] != b["scope"][f]
                ]
                failures.append(f"scope {_key(a)}: {','.join(fields)} changed")
            else:
                ae = {json.dumps(e, sort_keys=True) for e in a["entries"]}
                be = {json.dumps(e, sort_keys=True) for e in b["entries"]}
                added = sorted(be - ae)
                removed = sorted(ae - be)
                failures.append(
                    f"finding {_key(a)}: score {a['score']} -> {b['score']}; "
                    f"added={added[:3]} removed={removed[:3]}"
                )
    return failures


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--write", metavar="PATH")
    group.add_argument("--check", metavar="PATH")
    args = parser.parse_args(argv)

    current = replay()
    if args.write:
        Path(args.write).write_bytes(
            gzip.compress(json.dumps(current, sort_keys=True).encode())
        )
        print(
            f"typed-core parity: wrote {len(current['findings'])} findings and "
            f"{len(current['scopes'])} scope records to {args.write}"
        )
        return 0

    with gzip.open(args.check, "rt") as fh:
        baseline = json.load(fh)
    failures = compare(baseline, current)
    for failure in failures[:2000]:
        print(f"PARITY FAIL {failure}")
    print(
        f"typed-core parity: {len(current['findings'])} findings, "
        f"{len(current['scopes'])} scope records, "
        f"{len(failures)} mismatched"
    )
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
