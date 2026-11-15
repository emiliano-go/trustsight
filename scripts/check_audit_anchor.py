#!/usr/bin/env python3
"""Compare a published signer audit head with an off-host expected value.

The signer cannot prove its own log is unrolled back; a monitor reads the
head from the signer-audit volume and compares it with the value it anchored
last time.  Exit 0 on match, 2 on mismatch or unreadable input.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("head", help="head.json published by feed-signer")
    parser.add_argument("--expected", help="expected chain_sha256")
    parser.add_argument("--expected-file",
                        help="file holding the expected chain_sha256")
    args = parser.parse_args(argv)
    try:
        published = json.loads(Path(args.head).read_text(encoding="utf-8"))
        actual = published["chain_sha256"]
        expected = args.expected
        if args.expected_file:
            expected = Path(args.expected_file).read_text(
                encoding="utf-8").strip()
    except Exception as exc:  # noqa: BLE001 - one-line refusal
        print(f"check-audit-anchor: {type(exc).__name__}", file=sys.stderr)
        return 2
    if not isinstance(actual, str) or len(actual) != 64:
        print("check-audit-anchor: head has no valid chain", file=sys.stderr)
        return 2
    if expected is not None and actual != expected.strip():
        print("check-audit-anchor: head does not match the anchor", file=sys.stderr)
        return 2
    print(actual)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
