import re

# Bidirectional text overrides (U+202A–U+202E)
BIDI_OVERRIDES = re.compile(
    '[\u202a\u202b\u202c\u202d\u202e]'
)

# Bidirectional isolates (U+2066–U+2069)
BIDI_ISOLATES = re.compile(
    '[\u2066\u2067\u2068\u2069]'
)

# Zero-width characters and joiners (U+200B–U+200F)
ZERO_WIDTH = re.compile(
    '[\u200b\u200c\u200d\u200e\u200f]'
)

# Invisible operators (U+2060–U+2064)
INVISIBLE_OPS = re.compile(
    '[\u2060\u2061\u2062\u2063\u2064]'
)

# Byte order mark mid-file (U+FEFF)
BOM = re.compile('\ufeff')

# Tag characters (U+E0000–U+E007F)
TAG_CHARS = re.compile(
    '[\U000e0000\U000e0001\U000e0002\U000e0003\U000e0004\U000e0005'
    '\U000e0006\U000e0007\U000e0008\U000e0009\U000e000a\U000e000b'
    '\U000e000c\U000e000d\U000e000e\U000e000f\U000e0010\U000e0011'
    '\U000e0012\U000e0013\U000e0014\U000e0015\U000e0016\U000e0017'
    '\U000e0018\U000e0019\U000e001a\U000e001b\U000e001c\U000e001d'
    '\U000e001e\U000e001f\U000e0020\U000e0021\U000e0022\U000e0023'
    '\U000e0024\U000e0025\U000e0026\U000e0027\U000e0028\U000e0029'
    '\U000e002a\U000e002b\U000e002c\U000e002d\U000e002e\U000e002f'
    '\U000e0030\U000e0031\U000e0032\U000e0033\U000e0034\U000e0035'
    '\U000e0036\U000e0037\U000e0038\U000e0039\U000e003a\U000e003b'
    '\U000e003c\U000e003d\U000e003e\U000e003f\U000e0040\U000e0041'
    '\U000e0042\U000e0043\U000e0044\U000e0045\U000e0046\U000e0047'
    '\U000e0048\U000e0049\U000e004a\U000e004b\U000e004c\U000e004d'
    '\U000e004e\U000e004f\U000e0050\U000e0051\U000e0052\U000e0053'
    '\U000e0054\U000e0055\U000e0056\U000e0057\U000e0058\U000e0059'
    '\U000e005a\U000e005b\U000e005c\U000e005d\U000e005e\U000e005f'
    '\U000e0060\U000e0061\U000e0062\U000e0063\U000e0064\U000e0065'
    '\U000e0066\U000e0067\U000e0068\U000e0069\U000e006a\U000e006b'
    '\U000e006c\U000e006d\U000e006e\U000e006f\U000e0070\U000e0071'
    '\U000e0072\U000e0073\U000e0074\U000e0075\U000e0076\U000e0077'
    '\U000e0078\U000e0079\U000e007a\U000e007b\U000e007c\U000e007d'
    '\U000e007e\U000e007f]'
)

COMBINED = re.compile(
    '[\u202a-\u202e\u2066-\u2069\u200b-\u200f\u2060-\u2064\ufeff'
    '\U000e0000-\U000e007f]'
)


def has_fatal_codepoints(text: str) -> bool:
    return bool(COMBINED.search(text))


def describe_fatal_codepoints(text: str) -> list[tuple[int, str]]:
    matches = []
    for m in COMBINED.finditer(text):
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
