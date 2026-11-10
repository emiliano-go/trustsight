"""Static runtime-surface analysis: H009-H013.

These rules read the surface a package *runs at runtime* - committed systemd
units and other shell/script carriers - and never execute anything.  They were
the reserved ``runtime`` ids; this module gives them a static meaning that is
consistent with the project's "nothing is executed" invariant:

- H009 network client in a service's Exec* line (a unit that phones home)
- H010 write to a sensitive runtime path from a unit's Exec* line
- H011 privilege-escalating binary in a unit's Exec* line
- H012 TracerPid / ptrace / strace detection in a runtime carrier
- H013 strace log truncation or removal (tracing blinded)

They ship anergic (weight 0) until the weekly calibration assigns a weight.
"""

from __future__ import annotations

import re

from ..findings import stamp
from ..tokenizer import split_lines

__all__ = ["runtime_surface_findings"]

_UNIT_SUFFIXES = (".service", ".timer", ".socket")
_SCRIPT_SUFFIXES = (".install", ".sh", ".bash", ".py")
_EXEC_LINE_RE = re.compile(r"^\s*Exec[A-Za-z]*\s*=", re.MULTILINE)
_NETWORK_CLIENT_RE = re.compile(
    r"\b(?:curl|wget|nc|ncat|netcat|socat|telnet)\b|/dev/tcp/", re.IGNORECASE)
_SENSITIVE_WRITE_RE = re.compile(
    r"(?:>>?|\btee\b)[^\n]{0,80}(?:/etc/|/var/|/run/|\$HOME|~/|/root/)")
_ESCALATION_RE = re.compile(r"\b(?:sudo|pkexec|doas|su)\b")
_TRACE_DETECT_RE = re.compile(r"TracerPid|ptrace\s*\(\s*PTRACE_|\bstrace\s+-p\b")
_TRACE_TRUNCATE_RE = re.compile(
    r"(?:>\s*|truncate\s+-s\s*0\s+|rm\s+-f\s+)[^\n]{0,80}strace",
    re.IGNORECASE)


def _is_test(path: str) -> bool:
    lower = path.lower()
    return ("/test" in lower or lower.startswith("test")
            or lower.endswith("_test.py") or "/tests/" in lower)


def _is_unit(path: str) -> bool:
    return path.lower().endswith(_UNIT_SUFFIXES)



def _finding(rule_id: str, name: str, path: str, line: int, match: str) -> dict:
    return stamp({
        "rule_id": rule_id,
        "name": name,
        "severity": "INFO",
        "category": "runtime",
        "match": match,
        "file": path,
        "line": line,
    })


def runtime_surface_findings(files, package_name: str = "") -> list[dict]:
    """H009-H013 over committed runtime carriers.

    *files* is ``[(path, head_bytes)]``.  Units (``.service``/``.timer``/
    ``.socket``) are read for Exec* surface; install hooks and shell/python
    scripts are read for tracing evasion.  Test fixtures are skipped.
    """
    findings: list[dict] = []
    for path, head in files:
        if _is_test(path):
            continue
        is_unit = _is_unit(path)
        is_script = path.lower().endswith(_SCRIPT_SUFFIXES)
        if not (is_unit or is_script):
            continue
        text = head.decode("utf-8", errors="replace") if isinstance(
            head, (bytes, bytearray)) else str(head)
        if not text:
            continue
        for number, line in enumerate(split_lines(text)):
            if is_unit and _EXEC_LINE_RE.match(line):
                if _NETWORK_CLIENT_RE.search(line):
                    findings.append(_finding(
                        "H009", "Network connection attempt", path,
                        number, line.strip()[:160]))
                if _SENSITIVE_WRITE_RE.search(line):
                    findings.append(_finding(
                        "H010", "Suspicious file write", path,
                        number, line.strip()[:160]))
                if _ESCALATION_RE.search(line):
                    findings.append(_finding(
                        "H011", "Sensitive binary execution", path,
                        number, line.strip()[:160]))
            if _TRACE_DETECT_RE.search(line):
                findings.append(_finding(
                    "H012", "Strace detection attempt", path,
                    number, line.strip()[:160]))
            if _TRACE_TRUNCATE_RE.search(line):
                findings.append(_finding(
                    "H013", "Strace log truncated", path,
                    number, line.strip()[:160]))
    return findings
