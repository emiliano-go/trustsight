"""Extracted from delivery.py: _payloads."""

import base64
import binascii
import re
from ...config import (
    _SUBCOMMAND_OPTS as _SUBCOMMAND_OPTS,
)
from ...deps import _strip_comment
from ...tokenizer import resolve_added_lines, split_lines
from ._common import _ELF_MAGIC, _MACHO_MAGICS, _PE_MAGIC, _SHEBANG_MAGIC, _find_line

__all__ = ['_B64_RUN_RE', '_HEX_RUN_RE', '_PIPE_TO_SHELL_RE', '_SHELL_LEAD_TOKEN_RE', '_decode_b64', '_decode_hex', '_magic_name', '_payload_name', '_reconstructed_payload_findings', '_uu_blocks']

def _magic_name(data: bytes) -> str | None:
    """Identify executable magic at the head of *data*, or None."""
    if data.startswith(_ELF_MAGIC):
        return "ELF"
    if data.startswith(_SHEBANG_MAGIC):
        return "shebang"
    if data.startswith(_PE_MAGIC) and len(data) >= 64:
        return "PE"
    if data[:4] in _MACHO_MAGICS:
        return "Mach-O"
    return None

_SHELL_LEAD_TOKEN_RE = re.compile(
    r"(?:curl|wget|bash|sh|nc|ncat|socat|python3?|perl|ruby|chmod|chown"
    r"|eval|base64)\b",
    re.IGNORECASE,
)

_PIPE_TO_SHELL_RE = re.compile(r"(?<!\\)\|\s*(?:bash|sh)\b", re.IGNORECASE)

def _payload_name(data: bytes) -> str | None:
    """Identify a decoded payload: executable magic or shell-script text.

    The shell-text branch is deliberately narrower than "is text": the bytes
    must decode as UTF-8, be essentially all printable, and open with a
    command token or pipe into a shell.  Icons, fonts, keys and config blobs
    are binary or prose and stay silent, which is the rule's declared
    must-not-fire surface.
    """
    if magic := _magic_name(data):
        return magic
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not text.strip():
        return None
    printable = sum(1 for ch in text if ch.isprintable() or ch in "\n\r\t")
    if printable / len(text) < 0.95:
        return None
    if _PIPE_TO_SHELL_RE.search(text):
        return "shell script"
    first = next((ln.strip() for ln in split_lines(text) if ln.strip()), "")
    if _SHELL_LEAD_TOKEN_RE.match(first):
        return "shell script"
    return None

_B64_RUN_RE = re.compile(
    r"(?<![A-Za-z0-9+/])"
    r"[A-Za-z0-9+/]{32,}(?:==?)?"
    r"(?![A-Za-z0-9+/])"
)

_HEX_RUN_RE = re.compile(
    r"(?<![0-9a-fA-F])"
    r"[0-9a-fA-F]{32,}"
    r"(?![0-9a-fA-F])"
)

def _decode_b64(run: str) -> bytes | None:
    """Decode a base64 token, tolerating missing padding."""
    clean = "".join(ch for ch in run if ch in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
    clean = clean.rstrip("=")
    pad = (-len(clean)) % 4
    try:
        return base64.b64decode(clean + "=" * pad)
    except (binascii.Error, ValueError):
        return None

def _decode_hex(run: str) -> bytes | None:
    """Decode an even-length hex token."""
    if len(run) % 2:
        run = run[: len(run) - 1]
    try:
        return bytes.fromhex(run)
    except ValueError:
        return None

def _uu_blocks(added_lines: list[str]) -> list[tuple[bytes, str]]:
    """Decode ``begin``/``end`` uuencode blocks spanning added lines."""
    blocks: list[tuple[bytes, str]] = []
    i = 0
    while i < len(added_lines):
        head = added_lines[i].lstrip()
        if not head.startswith("begin "):
            i += 1
            continue
        chunks: list[bytes] = []
        j = i + 1
        while j < len(added_lines):
            line = added_lines[j].strip()
            if line.startswith("end"):
                break
            if not line:
                j += 1
                continue
            length = ord(line[0]) - 32
            if not 1 <= length <= 60:
                chunks = []
                break
            try:
                chunks.append(binascii.a2b_uu(line))
            except (binascii.Error, ValueError):
                chunks = []
                break
            j += 1
        if chunks:
            blocks.append((b"".join(chunks), added_lines[i]))
            i = j + 1
        else:
            i += 1
    return blocks

def _reconstructed_payload_findings(diff_text, config, add) -> None:
    """An encoded blob whose decoded bytes are an executable payload.

    H068 is the type check on H065's reconstruction output: one check covers
    every encoding (base64, hex, uuencode) without naming it.  The decoded
    side is executable magic (ELF, shebang, PE, Mach-O) or shell-script
    text without a shebang (a ``curl | bash`` blob carries no magic).  The
    heredoc-body skip the positional rules keep does not apply here: a long
    encoded run is data either way, and the payload's hiding place is exactly
    where the check must read.  Encoded text assets, checksums, and keys
    decode to bytes that match neither branch, so the rule's must-not-fire
    surface is structural rather than positional.
    """
    lines = resolve_added_lines(diff_text)
    added = [ln[1:] for ln in lines if ln.startswith("+")]

    for line in added:
        body = _strip_comment(line)

        for run in _HEX_RUN_RE.findall(body):
            decoded = _decode_hex(run)
            if decoded and (magic := _payload_name(decoded)):
                add("H068", "Reconstructed Executable Payload", "HIGH", "execution",
                    f"hex blob on the line decodes to {magic}: {line.strip()[:80]}",
                    line=_find_line(diff_text, run),
                    encoding="hex", magic=magic, decoded_bytes=len(decoded))
                return

        for run in _B64_RUN_RE.findall(body):
            decoded = _decode_b64(run)
            if decoded and (magic := _payload_name(decoded)):
                add("H068", "Reconstructed Executable Payload", "HIGH", "execution",
                    f"base64 blob on the line decodes to {magic}: {line.strip()[:80]}",
                    line=_find_line(diff_text, run),
                    encoding="base64", magic=magic, decoded_bytes=len(decoded))
                return

    for decoded, context in _uu_blocks(added):
        if magic := _payload_name(decoded):
            add("H068", "Reconstructed Executable Payload", "HIGH", "execution",
                f"uuencoded block decodes to {magic}: {context.strip()[:80]}",
                line=_find_line(diff_text, "begin"),
                encoding="uuencode", magic=magic, decoded_bytes=len(decoded))
            return
