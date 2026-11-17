"""Bounded, read-only ELF metadata for the artifact and upstream lanes.

Static analysis is about *read versus execute*, not text versus binary.  This
module reads only bytes and returns a projection; it never maps the file,
never runs a loader, and never shells out to ``ldd``/``objdump``/``readelf``
(``ldd`` executes the target on glibc).  Every read is bounds-checked and a
truncated or lying file yields a partial/None result, never an exception.

The parser is deliberately partial: ELF32/ELF64, LE/BE, section headers,
``.dynstr`` and the ``.dynamic`` entries the rules need (DT_NEEDED, DT_RPATH,
DT_RUNPATH), plus packer markers.
"""

from __future__ import annotations

from dataclasses import dataclass

__all__ = ["MAX_ELF_BYTES", "ElfInfo", "parse_elf"]

#: The parse window.  A real ELF header and dynamic table live near the
#: start; a larger window buys nothing and is attacker-chosen cost.
MAX_ELF_BYTES = 1024 * 1024
MAX_SECTIONS = 256
MAX_DYNAMIC = 4096
MAX_STRINGS = 4096
MAX_NAME_BYTES = 256

_SHT_DYNAMIC = 6
_SHT_STRTAB = 3


@dataclass(frozen=True)
class ElfInfo:
    bits: int = 0
    endian: str = ""
    needed: tuple[str, ...] = ()
    rpath: tuple[str, ...] = ()
    runpath: tuple[str, ...] = ()
    packed: bool = False
    sections: tuple[str, ...] = ()
    truncated: bool = False

    def to_dict(self) -> dict:
        return {
            "bits": self.bits,
            "endian": self.endian,
            "needed": list(self.needed),
            "rpath": list(self.rpath),
            "runpath": list(self.runpath),
            "packed": self.packed,
            "sections": list(self.sections),
            "truncated": self.truncated,
        }


def _int(data: bytes, offset: int, size: int, endian: str) -> int | None:
    if offset < 0 or size <= 0 or offset + size > len(data):
        return None
    return int.from_bytes(data[offset:offset + size], endian)


def _cstr(table: bytes, offset: int) -> str:
    if not isinstance(offset, int) or offset < 0 or offset >= len(table):
        return ""
    end = table.find(b"\x00", offset)
    if end < 0:
        end = len(table)
    raw = table[offset:end][:MAX_NAME_BYTES]
    return raw.decode("utf-8", errors="replace")


def parse_elf(data, *, max_bytes: int = MAX_ELF_BYTES) -> ElfInfo | None:
    """Return the bounded projection, or ``None`` when this is not an ELF."""
    if not isinstance(data, (bytes, bytearray)) or len(data) < 52:
        return None
    data = bytes(data[: min(len(data), max(1, int(max_bytes)))])
    if data[:4] != b"\x7fELF":
        return None
    elf_class, encoding = data[4], data[5]
    if elf_class not in (1, 2) or encoding not in (1, 2):
        return None
    endian = "little" if encoding == 1 else "big"
    is32 = elf_class == 1
    truncated = False

    if is32:
        shoff = _int(data, 32, 4, endian)
        shentsize = _int(data, 46, 2, endian)
        shnum = _int(data, 48, 2, endian)
        shstrndx = _int(data, 50, 2, endian)
    else:
        shoff = _int(data, 40, 8, endian)
        shentsize = _int(data, 58, 2, endian)
        shnum = _int(data, 60, 2, endian)
        shstrndx = _int(data, 62, 2, endian)
    if shoff is None or shentsize is None or shnum is None:
        return None
    if shnum > MAX_SECTIONS:
        shnum = MAX_SECTIONS
        truncated = True
    if shstrndx is None:
        shstrndx = 0

    sections: list[tuple[int, int, int, int, int, int, int]] = []
    for index in range(shnum):
        base = shoff + index * shentsize
        if is32:
            name = _int(data, base, 4, endian)
            typ = _int(data, base + 4, 4, endian)
            off = _int(data, base + 16, 4, endian)
            size = _int(data, base + 20, 4, endian)
            link = _int(data, base + 24, 4, endian)
            entsize = _int(data, base + 36, 4, endian)
        else:
            name = _int(data, base, 4, endian)
            typ = _int(data, base + 4, 4, endian)
            off = _int(data, base + 24, 8, endian)
            size = _int(data, base + 32, 8, endian)
            link = _int(data, base + 40, 4, endian)
            entsize = _int(data, base + 56, 8, endian)
        if None in (name, typ, off, size, link, entsize):
            truncated = True
            break
        sections.append((index, name, typ, off, size, link, entsize))

    names: dict[int, str] = {}
    if 0 <= shstrndx < len(sections):
        _, _, _, str_off, str_size, _, _ = sections[shstrndx]
        strtab = data[str_off:str_off + str_size] if (
            0 <= str_off and 0 <= str_size
            and str_off + str_size <= len(data)) else b""
        for index, name_off, *_ in sections:
            names[index] = _cstr(strtab, name_off)

    needed: list[str] = []
    rpath: list[str] = []
    runpath: list[str] = []
    for _, _, typ, off, size, link, _ in sections:
        if typ != _SHT_DYNAMIC or not (0 <= link < len(sections)):
            continue
        dyn_index, _, dyn_type, dyn_off, dyn_size, _, _ = sections[link]
        if dyn_type != _SHT_STRTAB:
            continue
        dynstr = data[dyn_off:dyn_off + dyn_size] if (
            0 <= dyn_off and 0 <= dyn_size
            and dyn_off + dyn_size <= len(data)) else b""
        entry = 8 if is32 else 16
        half = 4 if is32 else 8
        count = size // entry
        if count > MAX_DYNAMIC:
            count = MAX_DYNAMIC
            truncated = True
        for item in range(count):
            base = off + item * entry
            tag = _int(data, base, half, endian)
            value = _int(data, base + half, half, endian)
            if tag is None or value is None:
                break
            if tag == 1 and len(needed) < MAX_STRINGS:
                needed.append(_cstr(dynstr, value))
            elif tag == 15 and len(rpath) < MAX_STRINGS:
                rpath.append(_cstr(dynstr, value))
            elif tag == 29 and len(runpath) < MAX_STRINGS:
                runpath.append(_cstr(dynstr, value))

    section_names = tuple(names[index] for index in sorted(names))[:MAX_SECTIONS]
    packed = (
        any(name in (".upx", "UPX0", "UPX1", ".packed") for name in section_names)
        or b"UPX!" in data[: min(len(data), 64 * 1024)]
    )
    return ElfInfo(
        bits=32 if is32 else 64,
        endian=endian,
        needed=tuple(needed),
        rpath=tuple(rpath),
        runpath=tuple(runpath),
        packed=packed,
        sections=section_names,
        truncated=truncated,
    )
