"""The ``trustsight-attest`` console script."""

from __future__ import annotations

import argparse
import sys

from .attest import AttestError, check_tree, write_attestation


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="trustsight-attest",
        description="Record or check a deterministic source-tree attestation.",
    )
    parser.add_argument("root", help="source tree to attest")
    parser.add_argument("--out", help="write the attestation to this file")
    parser.add_argument("--check", help="check this attestation against the tree")
    args = parser.parse_args(argv)
    if bool(args.out) == bool(args.check):
        parser.error("pass exactly one of --out or --check")
    try:
        if args.out:
            payload = write_attestation(args.root, args.out)
            print(payload["digest"])
        else:
            check_tree(args.root, args.check)
            print("attestation matches")
    except AttestError as exc:
        print(f"trustsight-attest: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
