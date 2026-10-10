"""Measure the E-series distributions and suggest thresholds (Q3).

The E-series ships its thresholds empty and is calibrated from the corpus
before it scores.  This measures the E001/E002/E003 statistics over the
locked benign corpus and prints suggested floors, using conservative
percentiles (a floor chosen so the benign fire rate stays near the tail, not
in the body):

    e001.max_ratio   ~ p05 of compression ratios (low = repetitive)
    e002.min_fraction ~ p99 of encoded-fraction (high = encoded-heavy)
    e003.min_entropy / max_entropy ~ p01 / p99 of unigram entropy
    e003.min_bigram / max_bigram    ~ p01 / p99 of bigram entropy

Print only.  A threshold a human copies into `config.toml` is a deliberate
calibration decision; the tool never rewrites the shipped defaults.

Usage:

    python scripts/entropy_calibrate.py [--corpus tests/fixtures/benign-corpus]
        [--json entropy-thresholds.json]
"""

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from trustsight.analysis.entropy import (  # noqa: E402
    added_text,
    compression_ratio,
    encoded_fraction,
    identifier_bigram_entropy,
    identifier_entropy,
)

FIXTURES = ROOT / "tests" / "fixtures"


def _percentile(values: list[float], q: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, round(q * (len(ordered) - 1))))
    return ordered[index]


def measure(corpus: Path) -> dict:
    ratios, fractions, entropies, bigrams = [], [], [], []
    for path in sorted(corpus.rglob("*.diff")):
        text = added_text(path.read_text(errors="replace"))
        if not text.strip():
            continue
        ratios.append(compression_ratio(text))
        fractions.append(encoded_fraction(text, min_length=64))
        entropies.append(identifier_entropy(text))
        bigrams.append(identifier_bigram_entropy(text))
    return {
        "n": len(ratios),
        "suggested": {
            "e001": {"max_ratio": round(_percentile(ratios, 0.05), 4)},
            "e002": {"min_fraction": round(_percentile(fractions, 0.99), 4),
                     "min_length": 64},
            "e003": {"min_entropy": round(_percentile(entropies, 0.01), 4),
                     "max_entropy": round(_percentile(entropies, 0.99), 4),
                     "min_bigram": round(_percentile(bigrams, 0.01), 4),
                     "max_bigram": round(_percentile(bigrams, 0.99), 4)},
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path,
                        default=FIXTURES / "benign-corpus")
    parser.add_argument("--json", type=Path, default=None)
    args = parser.parse_args()
    if not args.corpus.exists():
        print(f"corpus not found: {args.corpus}", file=sys.stderr)
        return 1
    result = measure(args.corpus)
    print(f"measured {result['n']} diffs; suggested thresholds:")
    print(json.dumps(result["suggested"], indent=2))
    if args.json:
        args.json.write_text(json.dumps(result, indent=2) + "\n")
        print(f"wrote {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
