"""Render the inventory table in ``docs/explanation/state-and-lifecycles.md``.

The table is data; the registry is the source.  Re-run after editing
``scripts/state_machines.toml``.

    python scripts/build_state_doc.py           # regenerate in place
    python scripts/build_state_doc.py --check   # fail if the page drifted
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from state_machines import (
    GENERATED_END,
    GENERATED_START,
    REGISTRY,
    load_registry,
    render_inventory,
)

ROOT = Path(__file__).resolve().parent.parent
DOC = ROOT / "docs" / "explanation" / "state-and-lifecycles.md"


def block() -> str:
    rendered = render_inventory(load_registry(REGISTRY))
    return f"{GENERATED_START}\n{rendered}\n{GENERATED_END}"


def replace_block(text: str, rendered: str) -> str:
    pattern = re.compile(
        rf"{re.escape(GENERATED_START)}.*?{re.escape(GENERATED_END)}", re.S)
    if not pattern.search(text):
        raise SystemExit(f"markers {GENERATED_START} / {GENERATED_END} not found in {DOC}")
    return pattern.sub(lambda _: rendered, text, count=1)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true",
                        help="compare instead of writing")
    args = parser.parse_args(argv)
    text = DOC.read_text(encoding="utf-8")
    rendered = block()
    if args.check:
        if replace_block(text, rendered) != text:
            print(
                "state-machines inventory drifted; run "
                "python scripts/build_state_doc.py",
                file=sys.stderr,
            )
            return 1
        print("ok: state-machines inventory is current")
        return 0
    DOC.write_text(replace_block(text, rendered), encoding="utf-8")
    print(f"wrote {DOC}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
