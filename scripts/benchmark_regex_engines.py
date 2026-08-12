"""Optional comparison of Python ``re`` and third-party ``regex``.

The optional package is deliberately not a project dependency. Run this tool
in an environment where it is installed to collect comparative evidence:

    python -m pip install regex
    python scripts/benchmark_regex_engines.py
"""

from __future__ import annotations

import re
import time

from regex_audit import _configured_patterns, _literal_patterns
from trustsight.regex_safety import BACKTRACK_PROBES


def _measure(engine, pattern: str) -> float:
    compiled = engine.compile(pattern, engine.IGNORECASE)
    worst = 0.0
    for probe in BACKTRACK_PROBES:
        started = time.perf_counter()
        compiled.search(probe)
        worst = max(worst, time.perf_counter() - started)
    return worst


def main() -> int:
    try:
        import regex
    except ImportError:
        print("regex is not installed; standard re remains the runtime engine")
        print("Install it separately to run the comparison: python -m pip install regex")
        return 0

    patterns = _configured_patterns() + _literal_patterns()
    print("source\tre_ms\tregex_ms\tdelta_ms")
    for source, pattern in patterns:
        try:
            re_ms = _measure(re, pattern) * 1000
            regex_ms = _measure(regex, pattern) * 1000
        except (re.error, regex.error) as exc:
            print(f"{source}\tcompile-error\tcompile-error\t{exc}")
            continue
        print(f"{source}\t{re_ms:.3f}\t{regex_ms:.3f}\t{regex_ms - re_ms:.3f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
