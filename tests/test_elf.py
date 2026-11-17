"""The bounded ELF reader: header/section/dynamic parsing, no execution."""

from __future__ import annotations

import struct

from trustsight.analysis.elf import parse_elf

SHSTR = b"\x00.shstrtab\x00.dynstr\x00.dynamic\x00.upx\x00"
DYNSTR = b"\x00libc.so.6\x00/tmp/lib\x00$ORIGIN/../lib\x00"


def _elf64(*, packed_name=False, rpath=True, runpath=True) -> bytes:
    shstr_off = 64
    dynstr_off = shstr_off + len(SHSTR)
    dynamic_off = dynstr_off + len(DYNSTR)
    entries = [(1, 1)]  # DT_NEEDED, libc
    if rpath:
        entries.append((15, DYNSTR.index(b"/tmp")))
    if runpath:
        entries.append((29, DYNSTR.index(b"$ORIGIN")))
    entries.append((0, 0))
    dynamic = b"".join(struct.pack("<QQ", tag, val) for tag, val in entries)
    shoff = dynamic_off + len(dynamic)
    names = [0, 1, 11, 19]  # offsets in SHSTR
    if packed_name:
        names[3] = SHSTR.index(b".upx")
    shdrs = bytearray()
    for name_off, typ, off, size, link, entsize in (
        (0, 0, 0, 0, 0, 0),
        (names[1], 3, shstr_off, len(SHSTR), 0, 0),
        (names[2], 3, dynstr_off, len(DYNSTR), 0, 0),
        (names[3], 6, dynamic_off, len(dynamic), 2, 16),
    ):
        shdrs += struct.pack("<IIQQQQIIQQ", name_off, typ, 0, 0, off, size,
                             link, 0, 0, entsize)
    header = bytearray(64)
    header[0:4] = b"\x7fELF"
    header[4] = 2  # 64-bit
    header[5] = 1  # little
    header[6] = 1
    struct.pack_into("<HHI", header, 16, 2, 0x3E, 1)
    struct.pack_into("<Q", header, 40, shoff)
    struct.pack_into("<HHHHHH", header, 52, 64, 56, 0, 64, 4, 1)
    return bytes(header) + SHSTR + DYNSTR + dynamic + bytes(shdrs)


def _elf32() -> bytes:
    shstr_off = 52
    dynstr_off = shstr_off + len(SHSTR)
    dynamic_off = dynstr_off + len(DYNSTR)
    dynamic = struct.pack("<II", 1, 1) + struct.pack("<II", 0, 0)
    shoff = dynamic_off + len(dynamic)
    shdrs = bytearray()
    for name_off, typ, off, size, link, entsize in (
        (0, 0, 0, 0, 0, 0),
        (1, 3, shstr_off, len(SHSTR), 0, 0),
        (11, 3, dynstr_off, len(DYNSTR), 0, 0),
        (19, 6, dynamic_off, len(dynamic), 2, 8),
    ):
        shdrs += struct.pack("<IIIIIIIIII", name_off, typ, 0, 0, off, size,
                             link, 0, 0, entsize)
    header = bytearray(52)
    header[0:4] = b"\x7fELF"
    header[4] = 1
    header[5] = 1
    header[6] = 1
    struct.pack_into("<HHI", header, 16, 2, 3, 1)
    struct.pack_into("<I", header, 32, shoff)
    struct.pack_into("<HHHHHH", header, 40, 52, 32, 0, 40, 4, 1)
    return bytes(header) + SHSTR + DYNSTR + dynamic + bytes(shdrs)


def test_elf64_reads_needed_rpath_and_runpath():
    info = parse_elf(_elf64())
    assert info is not None
    assert info.bits == 64 and info.endian == "little"
    assert info.needed == ("libc.so.6",)
    assert info.rpath == ("/tmp/lib",)
    assert info.runpath == ("$ORIGIN/../lib",)
    assert info.packed is False


def test_elf32_reads_needed():
    info = parse_elf(_elf32())
    assert info is not None
    assert info.bits == 32
    assert info.needed == ("libc.so.6",)


def test_packed_marker_is_reported():
    info = parse_elf(_elf64(packed_name=True))
    assert info is not None
    assert info.packed is True


def test_non_elf_and_truncated_inputs_are_refused():
    assert parse_elf(b"not an elf at all" * 10) is None
    assert parse_elf(b"\x7fELF" + b"\x00" * 10) is None
    data = _elf64()
    assert parse_elf(data[:40]) is None


def test_a_lying_section_table_is_bounded_not_a_crash():
    data = bytearray(_elf64())
    struct.pack_into("<Q", data, 40, 10**9)  # e_shoff outside the file
    assert parse_elf(bytes(data)) is not None
