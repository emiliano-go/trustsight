import json
import os
import re
import unicodedata

# ---- Character-category test for R013 ----
# Uses unicodedata.category('Cf') to cover all Unicode format-control
# characters (~170), not just a hardcoded subset.  This automatically
# catches any format-control codepoints added in future Unicode versions.

# Codepoints that require ASCII context (legitimate inside non-Latin scripts).
_CONTEXTUAL_CF = frozenset({0x200B, 0x200C, 0x200D, 0x200E, 0x200F, 0xFEFF})

# Built on first use, not at import.
#
# The scan walks all 1,114,112 code points asking `unicodedata` for each
# one's category, which costs about 360 ms. Paying that at import made every
# CLI invocation pay it - `--version` and `--help` included - because
# `cli.inspect` imports `describe_fatal_codepoints` at module level. The
# derivation is kept rather than replaced by a literal, because deriving it
# is what makes a format-control codepoint added in a future Unicode version
# covered automatically; only *when* it runs has changed.


#: Bump when the *shape* of the derived list changes, so an old on-disk
#: cache is not reused.
_CF_CACHE_SCHEMA = 1


def _unconditional_cf_cache_path():
    from .config import CACHE_DIR

    version = unicodedata.unidata_version.replace(".", "_")
    return CACHE_DIR / f"unicode_cf-{version}.json"


def _build_unconditional_cf() -> list[int]:
    """All Cf code points except the ones that need ASCII context.

    The scan walks all 1,114,112 code points.  The result is cached on disk,
    keyed by the interpreter's Unicode version and the contextual set: a
    later run reads a small file instead of paying the scan again, while a
    new Unicode version (or a changed set) derives and replaces it.  The
    derivation stays the source of truth, so a Cf codepoint added by a
    future Unicode version is still covered.
    """
    cache_path = _unconditional_cf_cache_path()
    try:
        cached = json.loads(cache_path.read_text(encoding="utf-8"))
        if (
            isinstance(cached, dict)
            and cached.get("schema") == _CF_CACHE_SCHEMA
            and cached.get("contextual") == sorted(_CONTEXTUAL_CF)
            and isinstance(cached.get("codepoints"), list)
        ):
            return [int(cp) for cp in cached["codepoints"]]
    except (OSError, ValueError, TypeError):
        pass

    found: list[int] = []
    for cp in range(0x110000):
        try:
            if unicodedata.category(chr(cp)) == "Cf" and cp not in _CONTEXTUAL_CF:
                found.append(cp)
        except ValueError:
            pass

    try:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = cache_path.with_name(cache_path.name + ".tmp")
        tmp.write_text(
            json.dumps({
                "schema": _CF_CACHE_SCHEMA,
                "contextual": sorted(_CONTEXTUAL_CF),
                "codepoints": found,
            }),
            encoding="utf-8",
        )
        os.replace(tmp, cache_path)
    except OSError:
        pass
    return found


#: Names derived from the Cf scan.  Resolved by ``__getattr__`` on first
#: access and cached in the module globals, so ``from .unicode import
#: COMBINED`` and ``unicode.COMBINED`` both keep working unchanged.
_LAZY = frozenset({
    "_UNCONDITIONAL_CF", "_COMBINED_PATTERN", "COMBINED", "UNCONDITIONAL",
    "R013_UNCONDITIONAL_PATTERN",
})


def __getattr__(name: str):
    if name not in _LAZY:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    codepoints = _build_unconditional_cf()
    pattern = "[" + "".join(f"\\U{cp:08X}" for cp in codepoints) + "]"
    values = {
        "_UNCONDITIONAL_CF": codepoints,
        "_COMBINED_PATTERN": pattern,
        "COMBINED": re.compile(pattern + r"|[\u200b-\u200f\ufeff]"),
        "UNCONDITIONAL": re.compile(pattern),
        "R013_UNCONDITIONAL_PATTERN": pattern,
    }
    globals().update(values)
    return values[name]

# Byte order mark mid-file (U+FEFF)
BOM = re.compile('\ufeff')

ANSI_ESCAPE = re.compile(r'\x1b\[[\d;]*[A-Za-z]|\x1b[\W_]')

# Codepoints that are only ever deceptive, whatever their neighbours.
# Zero-width joiners are deliberately excluded: they are mandatory in
# Malayalam, Lao and Devanagari, so R013 gates those on ASCII context.
# Zero-width and directional marks: deceptive between ASCII, legitimate
# inside non-Latin script runs.
CONTEXTUAL = re.compile('[\u200b-\u200f\ufeff]')

# Export the generated unconditional Cf pattern for use by config.py.
# This replaces the hardcoded codepoint enumeration in the R013 TOML rule.

def strip_ansi(text: str) -> str:
    """Remove ANSI escape sequences from *text*."""
    return ANSI_ESCAPE.sub("", text)


def has_fatal_codepoints(text: str) -> bool:
    """Check if text contains any fatal Unicode codepoints."""
    from . import unicode as _self

    return bool(_self.COMBINED.search(text))


def describe_fatal_codepoints(text: str) -> list[tuple[int, str]]:
    """Return a list of (position, name) pairs for each fatal codepoint."""
    matches = []
    from . import unicode as _self

    for m in _self.COMBINED.finditer(text):
        cp = ord(m.group())
        start = m.start()
        if 0x202a <= cp <= 0x202e:
            name = f"bidi-override U+{cp:04X}"
        elif 0x2066 <= cp <= 0x2069:
            name = f"bidi-isolate U+{cp:04X}"
        elif 0x200b <= cp <= 0x200f:
            name = f"zero-width U+{cp:04X}"
        elif 0x2060 <= cp <= 0x2064:
            name = f"invisible-op U+{cp:04X}"
        elif cp == 0xfeff:
            name = f"bom U+{cp:04X}"
        elif 0xe0000 <= cp <= 0xe007f:
            name = f"tag U+{cp:04X}"
        else:
            name = f"fatal-codepoint U+{cp:04X}"
        matches.append((start, name))
    return matches
