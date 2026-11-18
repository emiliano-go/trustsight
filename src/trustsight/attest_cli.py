"""The ``trustsight-attest`` console script."""

from __future__ import annotations

import argparse
import sys

from .attest import AttestError, check_tree, unpinned_sources, write_attestation
from .safe_text import clean


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="trustsight-attest",
        description="Record or check a deterministic source-tree attestation.",
    )
    parser.add_argument("root", help="source tree to attest")
    parser.add_argument("--out", help="write the attestation to this file")
    parser.add_argument("--check", help="check this attestation against the tree")
    parser.add_argument(
        "--list-unpinned", action="store_true",
        help="list VCS, SKIP and unchecksummed declared sources",
    )
    args = parser.parse_args(argv)
    if sum((bool(args.out), bool(args.check), args.list_unpinned)) != 1:
        parser.error("pass exactly one of --out, --check or --list-unpinned")
    try:
        if args.out:
            payload = write_attestation(args.root, args.out)
            print(payload["digest"])
        elif args.check:
            check_tree(args.root, args.check)
            print("attestation matches")
        else:
            for source in unpinned_sources(args.root):
                print(
                    f"{clean(str(source['reason']), limit=32)}\t"
                    f"{clean(str(source['name']), limit=256)}\t"
                    f"{clean(str(source['url']), limit=1024)}")
    except AttestError as exc:
        print(f"trustsight-attest: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
