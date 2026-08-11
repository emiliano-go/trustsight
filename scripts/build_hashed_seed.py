#!/usr/bin/env python3
"""CLI wrapper around trustsight.seed_build.

Builds a v2 hashed maintainer seed from raw maintainer data.  The seed
contains only salted SHA-256 hashes; no plaintext names or emails are
written.

Usage:
    python scripts/build_hashed_seed.py raw_maintainers.json --out seed-v2
    python scripts/build_hashed_seed.py raw_maintainers.jsonl --out seed-v2
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"
sys.path.insert(0, str(SRC))

from trustsight.seed_build import main  # noqa: E402

if __name__ == "__main__":
    main()
