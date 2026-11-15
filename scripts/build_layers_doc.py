"""Generate the series-to-category table in Part 1 from ``trustsight.layers``.

The mapping is data; this renders it into the documentation's marked block so
prose and code cannot drift.  The security gate
``docs layer mapping matches the registry`` runs the comparison.

    python scripts/build_layers_doc.py          # regenerate in place
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from trustsight.layers import RULE_LAYER_OVERRIDES, SERIES_LAYER  # noqa: E402

DOC = ROOT / "docs" / "reference" / "evidence-categories.md"
START = "<!-- generated: series-layer -->"
END = "<!-- /generated: series-layer -->"


def render() -> str:
    lines = ["| Series | Default category |", "|---|---|"]
    for series in sorted(SERIES_LAYER):
        lines.append(f"| `{series}` | {SERIES_LAYER[series].value} |")
    lines += ["", "| Rule | Category override |", "|---|---|"]
    for rule_id in sorted(RULE_LAYER_OVERRIDES):
        lines.append(f"| `{rule_id}` | {RULE_LAYER_OVERRIDES[rule_id].value} |")
    return "\n".join(lines)


def block() -> str:
    return f"{START}\n{render()}\n{END}"


def main() -> int:
    text = DOC.read_text(encoding="utf-8")
    pattern = re.compile(
        rf"{re.escape(START)}.*?{re.escape(END)}", re.S)
    if not pattern.search(text):
        print(f"marker {START} not found in {DOC}", file=sys.stderr)
        return 1
    DOC.write_text(pattern.sub(lambda _: block(), text, count=1))
    print(f"wrote {DOC}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
