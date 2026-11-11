"""Fail CI when the host cannot provide the required parser sandbox.

The parser hardening design requires Linux with Landlock ABI 6, seccomp,
and unprivileged user/network namespaces.  A green suite on a host that
cannot grant that floor would certify a weaker configuration than the
security model claims, so this check is deliberately separate from the
sandbox tests (which may skip on an unsupported runner).
"""

from __future__ import annotations

import sys

from trustsight.sandbox._linux_sandbox import apply


def main() -> int:
    failures, _proxy_url = apply("read", "")
    if failures:
        for failure in failures:
            print(f"sandbox floor: {failure}", file=sys.stderr)
        return 1
    print("sandbox floor: Landlock ABI>=6, userns/netns, seccomp, no caps")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
