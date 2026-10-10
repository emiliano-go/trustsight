"""E-series: entropy / distribution analysis (Addendum 5 §6.3).

The statistical twin of the X-series: an attacker who writes
resolvable-but-obfuscated code defeats the refusal coupling, but a
distribution does not care *why* the content is weird.  E rules read the
added text as a distribution - no patterns, no refusal semantics.

Nature-doc honesty contract: an E finding is suspicion, never a verdict.
The thresholds ship *empty* (the rules do not fire until an operator or the
calibration job sets them from the first corpus measurement), so the series
never moves the locked-corpus figures on its own; the benign fire rate is
the published number once measured.  Never FATAL.
"""

from __future__ import annotations

import gzip
import math
import re

__all__ = [
    "added_text",
    "compression_ratio",
    "encoded_fraction",
    "identifier_entropy",
    "entropy_findings",
]

_BASE64_RE = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{16,}={0,2}(?![A-Za-z0-9+/=])")
_HEX_RE = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{16,}(?![0-9A-Fa-f])")
_IDENT_RE = re.compile(r"(?:^|[\s;&|(){}])([A-Za-z_][A-Za-z0-9_]{2,})\s*=")


def _thresholds(config) -> dict:
    return (config or {}).get("thresholds", {})


def added_text(diff_text: str) -> str:
    """The added content lines of a diff, as one string (typed projection)."""
    from ..diffdoc import parse_diff_lines
    from ..tokenizer import split_lines

    return "\n".join(
        line.content for line in parse_diff_lines(split_lines(diff_text)).lines
        if line.side == "add"
    )


def compression_ratio(text: str) -> float:
    """gzip size / raw size for *text* (0.0 for empty input)."""
    raw = text.encode("utf-8", "replace")
    if not raw:
        return 0.0
    return len(gzip.compress(raw, mtime=0)) / len(raw)


def encoded_fraction(text: str, min_length: int = 64) -> float:
    """Fraction of non-whitespace tokens that look encoded above *min_length*.

    Counts base64/hex runs at least *min_length* characters long against the
    total whitespace-separated token count.
    """
    tokens = text.split()
    if not tokens:
        return 0.0
    encoded = 0
    for token in tokens:
        if len(token) < min_length:
            continue
        if _BASE64_RE.search(token) or _HEX_RE.search(token):
            encoded += 1
    return encoded / len(tokens)


def identifier_entropy(text: str) -> float:
    """Shannon entropy (bits/char) of the newly assigned identifier names."""
    names = _IDENT_RE.findall(text)
    if not names:
        return 0.0
    joined = "".join(names)
    counts: dict[str, int] = {}
    for char in joined:
        counts[char] = counts.get(char, 0) + 1
    length = len(joined)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


def entropy_findings(diff_text: str, config, add) -> None:
    """E001-E003 over the added text, gated on configured thresholds.

    Each rule is silent until its threshold key is set: the series ships
    empty and is calibrated before it scores.  A finding names the measured
    value, never the content.
    """
    thresholds = _thresholds(config)
    text = added_text(diff_text)
    if not text:
        return

    e001 = thresholds.get("e001", {})
    max_ratio = e001.get("max_ratio")
    if max_ratio is not None:
        ratio = compression_ratio(text)
        if ratio <= float(max_ratio):
            add("E001", "Added-Text Compression Ratio", "MEDIUM", "entropy",
                f"added text compresses to {ratio:.3f} "
                f"(floor {max_ratio})",
                line=None, ratio=round(ratio, 4))

    e002 = thresholds.get("e002", {})
    min_fraction = e002.get("min_fraction")
    if min_fraction is not None:
        floor = int(e002.get("min_length", 64))
        fraction = encoded_fraction(text, floor)
        if fraction >= float(min_fraction):
            add("E002", "Encoded-Alphabet Fraction", "MEDIUM", "entropy",
                f"{fraction:.2f} of added tokens are encoded runs of at "
                f"least {floor} chars (threshold {min_fraction})",
                line=None, fraction=round(fraction, 4))

    e003 = thresholds.get("e003", {})
    lo = e003.get("min_entropy")
    hi = e003.get("max_entropy")
    if lo is not None or hi is not None:
        entropy = identifier_entropy(text)
        below = lo is not None and entropy < float(lo)
        above = hi is not None and entropy > float(hi)
        if below or above:
            add("E003", "Identifier Entropy", "MEDIUM", "entropy",
                f"new identifier names have entropy {entropy:.2f} bits/char "
                f"(expected {lo}..{hi})",
                line=None, entropy=round(entropy, 4))
