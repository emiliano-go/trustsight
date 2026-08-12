"""Phase 2 - July delivery stack (Class A) rules.

R119-R124 share a threat: the PKGBUILD carries or creates the payload it
later executes.  The rules are code rather than rules.toml entries because
each needs more than a regex: R119 needs position scoping against a config
list, R120 needs actual decoding of candidate blobs, and R121/R124 need
same-function write-then-execute path tracking.

Everything here is static.  Nothing is decoded into an executed string;
``base64.b64decode`` produces bytes that are checked against executable
magic and then discarded.

R118-tree (the git-tree variant) lives here as ``scan_tree_manifest``;
R118-blob (an ELF blob embedded in the PKGBUILD) is R120's job, so the two
never double-fire on the same evidence.  R122 (archive trailer anomaly) is
a pure function in :mod:`trustsight.analysis.archives`.
"""

import base64
import binascii
import os
import re
import shlex

from ..config import (
    DEFAULT_ANTI_ANALYSIS_PROBES,
    load_patterns,
)
from ..deps import _strip_comment
from ..findings import stamp
from ..rules import _classify_enclosing_function
from ..tokenizer import resolve_added_lines
from .build import _CRITICAL_FUNCTIONS, _INSTALL_HOOKS

_SCOPE_FUNCTIONS = frozenset(_CRITICAL_FUNCTIONS) | frozenset(_INSTALL_HOOKS)

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _anti_analysis_probes(config=None) -> list[re.Pattern]:
    """Compile the R119 anti-analysis probe fragments from patterns.toml."""
    patterns = load_patterns().get("patterns", {})
    frags = patterns.get("anti_analysis_probes") or DEFAULT_ANTI_ANALYSIS_PROBES
    return [re.compile(p, re.IGNORECASE) for p in frags]


def _find_line(diff_text: str, fragment: str) -> int | None:
    """Return a 1-based diff line whose added content contains *fragment*."""
    return _find_line_in_diff(diff_text, re.escape(fragment[:60]))


def _find_line_in_diff(diff_text: str, pattern: str, prefix: str = r"\+") -> int | None:
    """Return the 1-based line number of the first ``+``/``-`` line matching *pattern*."""
    # A fragment ending in a lone backslash (an escaped URL sliced at
    # 60/80 bytes, say) is not a legal pattern.  structural.py guards the
    # same compile the same way; without it a long URL in a corpus diff
    # would crash the whole run with re.error instead of degrading the
    # line number to None.
    try:
        full = re.compile(r"^" + prefix + r".*" + pattern, re.IGNORECASE)
    except re.error:
        full = re.compile(r"^" + prefix + r".*" + re.escape(pattern), re.IGNORECASE)
    for i, line in enumerate(diff_text.splitlines()):
        if full.search(line):
            return i + 1
    return None


# ---------------------------------------------------------------------------
# R119 - anti-analysis check
# ---------------------------------------------------------------------------


def _anti_analysis_findings(diff_text, config, add) -> None:
    """A build/install line probing for debuggers, VMs, sandboxes or CI.

    The probe list is config-driven (patterns.toml ``anti_analysis_probes``).
    Legitimate arch/feature checks (`uname -m`, `getconf`) never match a
    probe fragment, which is the whole must-not-fire surface the rule has.
    """
    probes = _anti_analysis_probes(config)
    if not probes:
        return
    lines = resolve_added_lines(diff_text)
    enclosing = _classify_enclosing_function(lines)
    heredoc_body = _heredoc_body_indices(lines)
    for i, line in enumerate(lines):
        if not line.startswith("+") or enclosing.get(i) not in _SCOPE_FUNCTIONS:
            continue
        if i in heredoc_body:
            continue
        body = _strip_comment(line)
        for probe in probes:
            m = probe.search(body)
            if m:
                add("R119", "Anti-Analysis Check", "HIGH", "anti_analysis",
                    f"{enclosing[i]}() probes its environment: {body.strip()[:80]}",
                    line=_find_line(diff_text, m.group(0)),
                    position=enclosing[i],
                    probe=m.group(0)[:60])
                return


# ---------------------------------------------------------------------------
# R120 - reconstructed-executable payload
# ---------------------------------------------------------------------------

_ELF_MAGIC = b"\x7fELF"
_SHEBANG_MAGIC = b"#!"
_PE_MAGIC = b"MZ"
_MACHO_MAGICS = frozenset({
    b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe",   # 32-bit MH_MAGIC
    b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe",   # 64-bit MH_MAGIC_64
    b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca",   # fat binary
})


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


# A decoded payload that is shell-script text without a shebang: the first
# non-blank line opens with a command token, or any line pipes into a shell.
# The magic check above misses this shape because nothing marks the bytes as
# executable; makepkg never needed a marker, only a consumer.
_SHELL_LEAD_TOKEN_RE = re.compile(
    r"(?:curl|wget|bash|sh|nc|ncat|socat|python3?|perl|ruby|chmod|chown"
    r"|eval|base64)\b",
    re.IGNORECASE,
)
_PIPE_TO_SHELL_RE = re.compile(r"\|\s*(?:bash|sh)\b", re.IGNORECASE)


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
    first = next((ln.strip() for ln in text.splitlines() if ln.strip()), "")
    if _SHELL_LEAD_TOKEN_RE.match(first):
        return "shell script"
    return None


# Bounded runs: do not let an assignment prefix like ``payload=`` merge
# into the encoded token.  ``=`` is valid base64 padding only at the end, so
# it is allowed as a boundary character.
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

    R120 is the type check on R117's reconstruction output: one check covers
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

    for i, line in enumerate(added):
        body = _strip_comment(line)

        for run in _HEX_RUN_RE.findall(body):
            decoded = _decode_hex(run)
            if decoded and (magic := _payload_name(decoded)):
                add("R120", "Reconstructed Executable Payload", "HIGH", "execution",
                    f"hex blob on the line decodes to {magic}: {line.strip()[:80]}",
                    line=_find_line(diff_text, run),
                    encoding="hex", magic=magic, decoded_bytes=len(decoded))
                return

        for run in _B64_RUN_RE.findall(body):
            decoded = _decode_b64(run)
            if decoded and (magic := _payload_name(decoded)):
                add("R120", "Reconstructed Executable Payload", "HIGH", "execution",
                    f"base64 blob on the line decodes to {magic}: {line.strip()[:80]}",
                    line=_find_line(diff_text, run),
                    encoding="base64", magic=magic, decoded_bytes=len(decoded))
                return

    for decoded, context in _uu_blocks(added):
        if magic := _payload_name(decoded):
            add("R120", "Reconstructed Executable Payload", "HIGH", "execution",
                f"uuencoded block decodes to {magic}: {context.strip()[:80]}",
                line=_find_line(diff_text, "begin"),
                encoding="uuencode", magic=magic, decoded_bytes=len(decoded))
            return


# ---------------------------------------------------------------------------
# R121 / R124 - generate-then-execute and write-then-execute
# ---------------------------------------------------------------------------

# Generation writes: a heredoc or ``>`` redirect that creates the file's
# content from the recipe itself (cat/tee/printf/echo).  Pipes are allowed
# between the producer and the redirect (`echo x | base64 -d > file`).
_GENERATION_WRITE_RE = re.compile(
    r"\b(?:cat|tee)\b[^;&\n]*?<<[^;&|\n]*?"
    r"(?:>\s*(\S+))?"                       # `cat <<EOF > path` - path after >,
    r"|\b(?:cat|printf|echo)\b[^;&\n]*?>\s*(\S+)",  # ... or `> path`
    re.IGNORECASE,
)

# Copy writes: commands that move an existing file to a destination.
_COPY_WRITE_RE = re.compile(
    r"\b(?:install|cp|mv|dd)\b[^;&|\n]*?\s(\S+)$",
    re.IGNORECASE,
)

# Heredoc form ``cat > path <<EOF`` (path before the ``<<``).
_HEREDOC_PATH_BEFORE_RE = re.compile(
    r"\b(?:cat|tee)\b\s+[^;&|<]*?>\s*(\S+)\s*<<",
    re.IGNORECASE,
)

# A heredoc opener.  ``<<<`` herestrings are single-line and do not match.
_HEREDOC_OPEN_RE = re.compile(r"<<(-)?\s*['\"]?(\w+)['\"]?")


def _heredoc_body_indices(lines: list[str]) -> set[int]:
    """Indices of lines that are literal heredoc content, not commands.

    A heredoc's body is data being written to a file; treating it as build
    commands would let the payload's own lines fire the very rules the
    generate-then-execute rule is meant to catch once.  The opener line
    itself is a command and stays eligible.
    """
    body: set[int] = set()
    delims: list[str] = []
    for i, line in enumerate(lines):
        content = line[1:] if line[:1] in ("+", "-") else line
        stripped = content.strip()
        if delims and stripped == delims[-1]:
            delims.pop()
            continue
        if delims:
            body.add(i)
            continue
        for m in _HEREDOC_OPEN_RE.finditer(content):
            if m.group(2):
                delims.append(m.group(2))
                break
    return body

# An interpreter/compiler/source command must sit at a command position
# (line start or after ``;``/``&``/``|``), never inside a filename like
# ``completions/zsh`` or as a bare argument like ``cp -a . dir``.
_CMD_START = r"(?:\A\s*|[;&|]\s*)"
_EXECUTION_RE = re.compile(
    _CMD_START + r"(?:bash|sh|zsh|dash|ksh)\s+(\S+)"
    r"|" + _CMD_START + r"source\s+(\S+)"
    r"|" + _CMD_START + r"\.\s+(\S+)"
    r"|\./(\S+)"
    # An absolute path at a command position, with or without arguments:
    # requiring it to stand alone let `/tmp/.stage2 --install` past the
    # write-then-execute dataflow while `/tmp/.stage2` was caught.
    r"|^\s*(\/[^\s;&|]+)(?=\s|$)"
    r"|" + _CMD_START + r"(?:python3?|perl|ruby)\s+(\S+)"
    r"|" + _CMD_START + r"(?:gcc|g\+\+|clang|cc|rustc)\b\s+[^;&|]*?(?:-o\s+\S+\s+)?(\S+\.(?:c|cc|cpp|rs))\b",
    re.IGNORECASE,
)

# Build artifacts that are written and then run by the project's own build
# flow.  ``./configure`` after a configure script is generated by autotools
# is ordinary; these names are exempt from R124 (not from R121, where a
# heredoc-generated configure executed in-recipe is exactly the signal).
_R124_BENIGN_EXEC = frozenset({
    "configure", "make", "Makefile", "makefile", "config.status",
    "config.log", "config.cache", "config.h", "cmake", "cpack", "ctest",
    "meson", "ninja", "build.ninja", "CMakeCache.txt",
})


def _norm_path(p: str) -> str:
    """Normalise a recipe path for comparison."""
    p = p.strip().strip('"\'')
    p = re.sub(r"^\$\{(?:srcdir|pkgdir|startdir|BUILDDIR)\}/?", "", p)
    p = re.sub(r"^\$(?:srcdir|pkgdir|startdir|BUILDDIR)/?", "", p)
    p = re.sub(r"^\./", "", p)
    p = re.sub(r"/+", "/", p)
    # A destination written as ``${pkgdir}/usr/lib/foo`` becomes
    # ``usr/lib/foo``; normalise it to the absolute path it represents.
    if re.match(r"^(?:usr|etc|opt|bin|lib|lib32|lib64|sbin)/", p):
        p = "/" + p
    return p


def _source_basename(url: str) -> str:
    """Return the declared filename for a source URL, or '' when unparseable."""
    path = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", url)
    path = re.split(r"[?#]", path, maxsplit=1)[0]
    base = os.path.basename(path.rstrip("/"))
    return base


def _declared_source_basenames(diff_text: str) -> set[str]:
    """Filenames that arrive via the declared source array.

    Unlike ``extract_source_array_urls`` (scheme URLs only), this keeps bare
    filenames (`dkms.conf`, `postinst.sh`), honours ``name::url`` renames,
    and reads both the PKGBUILD ``source=(...)`` form and the per-line
    ``source = value`` form used in ``.SRCINFO``.
    """
    import shlex

    from ..differ import _SOURCE_ARRAY_START_RE

    _SCALAR_SOURCE_RE = re.compile(r"^\s*source(?:_[a-z0-9_]+)?\s*=\s*(\S.*)$")

    basenames: set[str] = set()
    in_array = False
    for line in diff_text.splitlines():
        if line.startswith(("+++", "---", "@@")):
            continue
        if line.startswith("-"):
            continue
        body = line[1:] if line[:1] in ("+", "-") else line
        if not in_array:
            scalar = _SCALAR_SOURCE_RE.match(body)
            if scalar and "(" not in scalar.group(1):
                value = scalar.group(1).strip()
                base = value.split("::", 1)[0] if "::" in value else _source_basename(value)
                if base and base != ")":
                    basenames.add(base)
                continue
            if not _SOURCE_ARRAY_START_RE.match(body):
                continue
            in_array = True
            idx = body.find("(")
            body = body[idx + 1:] if idx != -1 else ""
        try:
            entries = shlex.split(body)
        except ValueError:
            continue
        for ent in entries:
            ent = ent.strip()
            if not ent or ent in ("(", ")"):
                continue
            # shlex in POSIX mode glues a trailing `)` to the preceding quoted
            # token when the array closes on the same line: "url") becomes one
            # token.  Strip the syntactic close paren; real filenames ending in
            # `)` are rare enough that this is safe.
            ent = ent.rstrip(")")
            if not ent:
                continue
            base = ent.split("::", 1)[0] if "::" in ent else _source_basename(ent)
            if base:
                basenames.add(base)
        if ")" in body:
            in_array = False
    return basenames


def _collect_writes(body: str, fn: str) -> list[tuple[str, str]]:
    """Return ``(kind, path)`` pairs for write commands on *body*.

    kind is ``"generation"`` (content created by the recipe) or ``"copy"``
    (an existing file moved/staged to a new path).
    """
    writes: list[tuple[str, str]] = []
    m = _HEREDOC_PATH_BEFORE_RE.search(body)
    if m and m.group(1):
        writes.append(("generation", _norm_path(m.group(1))))
    for m in _GENERATION_WRITE_RE.finditer(body):
        path = m.group(1) or m.group(2)
        if path:
            writes.append(("generation", _norm_path(path)))
    for m in _COPY_WRITE_RE.finditer(body):
        path = m.group(1)
        if path.startswith("-") or ">" in path:
            continue
        writes.append(("copy", _norm_path(path)))
    return writes


def _collect_executions(body: str) -> list[str]:
    """Return normalised paths executed or compiled on *body*."""
    paths: list[str] = []
    for m in _EXECUTION_RE.finditer(body):
        for g in m.groups():
            if g:
                paths.append(_norm_path(g))
    return paths


def _write_execute_findings(diff_text, config, add) -> None:
    """Same-function write-then-execute dataflow (R121, R124).

    A path written by the recipe and later executed in the same build
    function is a delivered payload.  R121 fires on generation writes
    (heredoc/``>``) whose content the recipe itself created; R124 fires on
    any write.  Both stay silent when the executed path arrived via the
    declared source array or is one of the project's own configure/make
    artifacts (R124 only).
    """
    lines = resolve_added_lines(diff_text)
    enclosing = _classify_enclosing_function(lines)
    source_basenames = _declared_source_basenames(diff_text)
    heredoc_body = _heredoc_body_indices(lines)

    writes_by_fn: dict[str, list[tuple[str, str]]] = {}
    r121_claimed: set[tuple[str, str]] = set()

    for i, line in enumerate(lines):
        fn = enclosing.get(i)
        if not line.startswith("+") or fn not in _SCOPE_FUNCTIONS:
            continue
        if i in heredoc_body:
            continue
        body = _strip_comment(line[1:])

        for kind, path in _collect_writes(body, fn):
            writes_by_fn.setdefault(fn, []).append((kind, path))

        for path in _collect_executions(body):
            base = os.path.basename(path)
            for (kind, wpath) in list(writes_by_fn.get(fn, [])):
                if wpath != path and os.path.basename(wpath) != base:
                    continue
                if (fn, wpath) in r121_claimed:
                    continue
                r121_claimed.add((fn, wpath))
                if kind == "generation":
                    add("R121", "Build-time Generation Then Execution", "HIGH", "execution",
                        f"{fn}() generates {wpath or path} and then executes it",
                        line=_find_line(diff_text, path or base),
                        position=fn, path=path)
                    return
                if base in _R124_BENIGN_EXEC or base in source_basenames:
                    continue
                add("R124", "Write Then Execute", "HIGH", "execution",
                    f"{fn}() writes {wpath or path} and then executes it",
                    line=_find_line(diff_text, path or base),
                    position=fn, path=path)
                return


# ---------------------------------------------------------------------------
# R137 - network fetch then execute
# ---------------------------------------------------------------------------

# A downloader that writes to a file and a later execution of that file in
# the same function.  This is ``curl -o stage.sh ... ; bash stage.sh`` split
# across lines so the pipe-to-shell regex (R001/R002) never sees the ``|``.
_FETCH_CLIENT_RE = re.compile(r"\b(curl|wget|aria2c|axel)\b", re.IGNORECASE)

_FETCH_OUTPUT_RE = re.compile(
    r"\b(curl|wget|aria2c|axel)\b"
    r"[^;&|]*?"
    r"(?:\s-[oO]\s+|\s--output(?:\s+|=)|\s--output-document(?:\s+|=)|>\s*)"
    r"((?:\"[^\"]*\"|'[^']*'|\\.|[^\s;&|])+)",
    re.IGNORECASE,
)

# Build/package/check/prepare only; install hooks already have R062.
_BUILD_FUNCTIONS = frozenset(_CRITICAL_FUNCTIONS)


def _collect_fetch_outputs(body: str) -> list[str]:
    """Normalised paths a network client on *body* writes to a file."""
    paths: list[str] = []
    if not _FETCH_CLIENT_RE.search(body):
        return paths
    for m in _FETCH_OUTPUT_RE.finditer(body):
        path = _norm_path(m.group(2))
        if path:
            paths.append(path)
    return paths


def _fetch_then_execute_findings(diff_text, config, add) -> None:
    """A downloader writes a file and the same function later executes it (R137).

    R001/R002 own the single-line pipe form; R137 owns the split form.
    Files that arrived via the declared ``source=()`` array are deliberately
    excluded here - they have their own rule (R138) so checksum-bearing
    source files are not double-counted.
    """
    lines = resolve_added_lines(diff_text)
    enclosing = _classify_enclosing_function(lines)
    source_basenames = _declared_source_basenames(diff_text)
    heredoc_body = _heredoc_body_indices(lines)

    fetched_by_fn: dict[str, list[str]] = {}

    for i, line in enumerate(lines):
        fn = enclosing.get(i)
        if not line.startswith("+") or fn not in _BUILD_FUNCTIONS:
            continue
        if i in heredoc_body:
            continue
        body = _strip_comment(line[1:])

        for path in _collect_fetch_outputs(body):
            fetched_by_fn.setdefault(fn, []).append(path)

        for path in _collect_executions(body):
            base = os.path.basename(path)
            for fpath in list(fetched_by_fn.get(fn, [])):
                fbase = os.path.basename(fpath)
                if fpath != path and fbase != base:
                    continue
                if base in source_basenames or base in _R124_BENIGN_EXEC:
                    continue
                add("R137", "Fetch Then Execute", "CRITICAL", "network_execution",
                    f"{fn}() downloads {fpath or path} and then executes it",
                    line=_find_line(diff_text, path or base),
                    position=fn, path=path)
                return


# ---------------------------------------------------------------------------
# R138 - execution of a downloaded source file
# ---------------------------------------------------------------------------

# An interpreter run on a file that arrived through the declared source=()
# array.  Checksums protect integrity, not intent; a ``source=(... .sh)``
# followed by ``bash "$srcdir/that.sh"`` is remote code execution just like
# ``curl | bash``, only hidden behind the ordinary download path.
_SOURCE_EXEC_RE = re.compile(
    _CMD_START + r"(?:bash|sh|zsh|dash|ksh|python3?|perl|ruby)\s+(\S+)"
    r"|" + _CMD_START + r"source\s+(\S+)"
    r"|" + _CMD_START + r"\.\s+(\S+)"
    r"|\./(\S+)",
    re.IGNORECASE,
)


def _source_file_execution_findings(diff_text, config, add) -> None:
    """A file downloaded via ``source=()`` is executed as a script (R138).

    Build-system scripts (configure, make, meson, ninja, cmake) are common
    declared-source executables and stay silent; the rule targets interpreted
    execution of a downloaded script.
    """
    lines = resolve_added_lines(diff_text)
    enclosing = _classify_enclosing_function(lines)
    source_basenames = _declared_source_basenames(diff_text)
    heredoc_body = _heredoc_body_indices(lines)

    for i, line in enumerate(lines):
        fn = enclosing.get(i)
        if not line.startswith("+") or fn not in _BUILD_FUNCTIONS:
            continue
        if i in heredoc_body:
            continue
        body = _strip_comment(line[1:])

        for m in _SOURCE_EXEC_RE.finditer(body):
            raw = next((g for g in m.groups() if g), None)
            if not raw:
                continue
            path = _norm_path(raw)
            base = os.path.basename(path)
            if not base or base in _R124_BENIGN_EXEC:
                continue
            if base not in source_basenames:
                continue
            add("R138", "Downloaded Source File Executed", "HIGH", "execution",
                f"{fn}() executes declared source file {base}",
                line=_find_line(diff_text, raw.strip().strip('"\'')[:60] or base),
                position=fn, path=path)
            return


# ---------------------------------------------------------------------------
# R139 - systemd service running an undeclared binary
# ---------------------------------------------------------------------------

# A service unit installed by the package points at a binary the recipe
# installs, but that binary is neither declared in ``source=()`` nor present
# in the repository manifest.  Such files arrive through the unseen source
# tarball, so their content cannot be audited.
_EXECSTART_RE = re.compile(r"^ExecStart\s*=\s*(.+)$", re.IGNORECASE | re.MULTILINE)

# ``install -Dm755 src dest`` and friends that stage an executable to a
# system directory.  The source basename is what we need to attribute.
_INSTALL_CMD_RE = re.compile(r"\binstall\b", re.IGNORECASE)


def _installed_executables(diff_text: str) -> set[tuple[str, str]]:
    """Return (source_basename, normalised_dest_path) for installed executables.

    Only considers installs with explicit 7xx modes or with no ``-m`` flag
    (install defaults to 755).  Destination paths are normalised so they can
    be compared to ExecStart paths.
    """
    found: set[tuple[str, str]] = set()
    lines = resolve_added_lines(diff_text)
    enclosing = _classify_enclosing_function(lines)
    heredoc_body = _heredoc_body_indices(lines)
    for i, line in enumerate(lines):
        fn = enclosing.get(i)
        if not line.startswith("+") or fn not in _BUILD_FUNCTIONS:
            continue
        if i in heredoc_body:
            continue
        body = _strip_comment(line[1:])
        if not _INSTALL_CMD_RE.search(body):
            continue
        # Mode: explicit 7xx or no -m flag (install defaults to 755).
        mode_match = re.search(r"\s-[a-zA-Z]*[mM]\s*(\d+)", body)
        if mode_match and not mode_match.group(1).startswith("7"):
            continue
        try:
            tokens = shlex.split(body)
        except ValueError:
            continue
        # Drop the leading 'install' command and every option token.
        args = [t for t in tokens[1:] if not t.startswith("-")]
        if len(args) < 2:
            continue
        src = _norm_path(args[-2])
        dst = _norm_path(args[-1])
        if not src or not dst:
            continue
        found.add((os.path.basename(src), dst))
    return found


def _service_binary_findings(diff_text, tree_manifest, add) -> None:
    """A systemd service's ExecStart points at an undeclared binary (R139).

    Service units are read from the tree manifest when one is supplied, and
    from added diff lines otherwise.  If the ExecStart target is installed
    from a file that is neither a declared source nor part of the repository
    manifest, the binary is invisible to static review.
    """
    source_basenames = _declared_source_basenames(diff_text)
    manifest_basenames = (
        None if tree_manifest is None
        else {os.path.basename(name.rstrip("/")) for name, _ in tree_manifest}
    )
    installed = _installed_executables(diff_text)
    if not installed:
        return

    service_texts: list[str] = []
    if tree_manifest is not None:
        for name, data in tree_manifest:
            if name.endswith(".service"):
                try:
                    service_texts.append(data.decode("utf-8", errors="replace"))
                except Exception:
                    continue
    for line in resolve_added_lines(diff_text):
        if line.startswith("+") and ".service" in line:
            # Heuristic: if the diff contains the whole service file, parse it.
            # Real service files are usually committed, so the manifest branch
            # above is the normal case.
            service_texts.append(line[1:])

    exec_targets: set[str] = set()
    for text in service_texts:
        for m in _EXECSTART_RE.finditer(text):
            target = m.group(1).split(None, 1)[0].strip("\"'")
            if target.startswith("/"):
                exec_targets.add(target)

    for src_base, dst in installed:
        if dst not in exec_targets:
            continue
        if src_base in source_basenames:
            continue
        if manifest_basenames is not None and src_base in manifest_basenames:
            continue
        add("R139", "Service ExecStart Targets Undeclared Binary", "HIGH", "persistence",
            f"systemd service runs {dst}, installed from undeclared {src_base}",
            line=_find_line(diff_text, dst.split("/")[-1]),
            exec_target=dst, source_file=src_base)
        return


# ---------------------------------------------------------------------------
# R140 - PATH injection with an undeclared build-tree directory
# ---------------------------------------------------------------------------

# ``PATH=$srcdir/tools:$PATH make`` lets the recipe smuggle a binary into a
# standard command's search path.  When the added directory is not declared in
# ``source=()`` and not present in the repository manifest, its contents are
# invisible to review.
_PATH_ASSIGN_RE = re.compile(r"\bPATH\s*=\s*([^;\n]+)", re.IGNORECASE)
_PATH_BUILD_DIR_RE = re.compile(
    r"\$\{?(?:srcdir|pkgdir|startdir|BUILDDIR)\}?/([^:\s]+)",
    re.IGNORECASE,
)


def _path_injection_findings(diff_text, tree_manifest, add) -> None:
    """PATH is extended with an undeclared build-tree directory (R140).

    Only applies inside build/package/check/prepare functions.  Adding the
    plain source root is common enough that it stays silent; adding a
    subdirectory whose content cannot be attributed is the signal.
    """
    source_basenames = _declared_source_basenames(diff_text)
    manifest_basenames = (
        None if tree_manifest is None
        else {os.path.basename(name.rstrip("/")) for name, _ in tree_manifest}
    )
    lines = resolve_added_lines(diff_text)
    enclosing = _classify_enclosing_function(lines)
    heredoc_body = _heredoc_body_indices(lines)

    for i, line in enumerate(lines):
        fn = enclosing.get(i)
        if not line.startswith("+") or fn not in _BUILD_FUNCTIONS:
            continue
        if i in heredoc_body:
            continue
        body = _strip_comment(line[1:])
        for m in _PATH_ASSIGN_RE.finditer(body):
            rhs = m.group(1)
            for dirm in _PATH_BUILD_DIR_RE.finditer(rhs):
                subdir = dirm.group(1).strip('"\'').rstrip("/")
                if not subdir or "/" in subdir:
                    # Only single-level subdirectories are flagged; deeper
                    # paths are more likely to be legitimate project layouts.
                    continue
                if subdir in source_basenames:
                    continue
                if manifest_basenames is not None and subdir in manifest_basenames:
                    continue
                add("R140", "PATH Injection With Undeclared Directory", "HIGH", "build",
                    f"{fn}() adds undeclared $srcdir/{subdir} to PATH",
                    line=_find_line(diff_text, f"PATH={rhs.strip()[:40]}"),
                    position=fn, directory=subdir)
                return


# ---------------------------------------------------------------------------
# R136 - execution of a committed but undeclared repository file
# ---------------------------------------------------------------------------

# Path evidence that the execution target lives in the cloned repository,
# not in the extracted sources: makepkg sets ``$startdir`` to the directory
# the PKGBUILD was read from, and ``../`` climbs out of ``$srcdir`` the same
# way.  ``$srcdir`` is absent on purpose: a ``bash "$srcdir/run.sh"`` whose
# file rode the tarball is the ordinary build flow.
_STARTDIR_PATH_RE = re.compile(r"\$\{?startdir\}?|(?:^|/)\.\.(?:/|$)", re.IGNORECASE)


def _committed_execution_findings(diff_text, tree_manifest, add) -> None:
    """An execution whose target is a repo-committed file the recipe never
    declared (R136).

    R121/R124 own files the recipe itself writes; R118 owns committed ELF
    binaries.  Between them sat the cleartext helper script: committed to
    the AUR repository, never named in ``source=()`` (so makepkg never
    copies it into ``$srcdir`` and its bytes never reach the differ), and
    executed through ``$startdir`` or a ``../`` climb.  Two signals, either
    sufficient:

    - the executed path references ``${startdir}``/``$startdir`` or walks
      ``../`` — available even when the repository tree was not analyzed;
    - the executed basename is present in the tree manifest — only when a
      manifest was supplied; without one the rule never guesses.

    Declared ``source=()`` basenames, files the recipe wrote earlier in the
    same function, and the configure/make artifact names R124 already
    exempts stay silent.  The manifest signal requires a relative path: an
    absolute ``/usr/share/...`` target cannot be a repository file, however
    its basename collides.
    """
    lines = resolve_added_lines(diff_text)
    enclosing = _classify_enclosing_function(lines)
    source_basenames = _declared_source_basenames(diff_text)
    heredoc_body = _heredoc_body_indices(lines)
    manifest_basenames = (
        None if tree_manifest is None
        else {os.path.basename(name.rstrip("/")) for name, _ in tree_manifest}
    )

    written_by_fn: dict[str, set[str]] = {}
    for i, line in enumerate(lines):
        fn = enclosing.get(i)
        if not line.startswith("+") or fn not in _SCOPE_FUNCTIONS:
            continue
        if i in heredoc_body:
            continue
        body = _strip_comment(line[1:])

        written = written_by_fn.setdefault(fn, set())
        for _kind, wpath in _collect_writes(body, fn):
            if wpath:
                written.add(os.path.basename(wpath))

        for m in _EXECUTION_RE.finditer(body):
            raw = next((g for g in m.groups() if g), None)
            if not raw:
                continue
            path = _norm_path(raw)
            base = os.path.basename(path)
            if not base or base in source_basenames or base in _R124_BENIGN_EXEC:
                continue
            if base in written:
                continue
            committed = (
                manifest_basenames is not None
                and base in manifest_basenames
                and not raw.strip().strip('"\'').startswith("/")
            )
            if not committed and not _STARTDIR_PATH_RE.search(raw):
                continue
            add("R136", "Committed File Executed Without Declaration", "HIGH", "execution",
                f"{fn}() executes repo-committed file not declared in source=(): {base}",
                line=_find_line(diff_text, raw.strip().strip('"\'')[:60] or base),
                position=fn, path=path)
            return


# ---------------------------------------------------------------------------
# R118-tree - embedded binary in the repository manifest
# ---------------------------------------------------------------------------

_TEST_DIR_RE = re.compile(r"(?:^|/)(?:tests?|testdata|fixtures?|specs?|examples?)/")
_TEST_NAME_RE = re.compile(r"(?:^|/)(?:test|fixture|sample|mock)[^/]*$", re.IGNORECASE)


def _is_test_fixture(name: str, base: str) -> bool:
    """True for ELF files that are plausibly test fixtures, not payloads.

    Committed binaries under test/spec/fixture/example trees, or files named
    for fixtures, are the rule's declared must-not-fire surface.  This is a
    deliberate heuristic: it trades a blind spot for the false positives the
    plan names explicitly.
    """
    if _TEST_DIR_RE.search("/" + name):
        return True
    return bool(_TEST_NAME_RE.search(base))


def scan_tree_manifest(files, source_urls, package_name: str = "") -> list[dict]:
    """R118-tree findings for a repository file manifest.

    *files* is ``[(path, head_bytes)]`` from a git tree or a snapshot
    tarball.  A committed ELF file that is not a declared ``source=``
    filename and not a test fixture fires.
    """
    source_basenames = {_source_basename(u) for u in source_urls if _source_basename(u)}
    findings: list[dict] = []
    for name, head in files:
        if not head.startswith(_ELF_MAGIC):
            continue
        base = os.path.basename(name.rstrip("/"))
        if base in source_basenames:
            continue
        if _is_test_fixture(name, base):
            continue
        findings.append(stamp({
            "rule_id": "R118", "name": "Embedded Binary In Tree",
            "severity": "HIGH", "category": "obfuscation",
            "match": f"ELF file committed to the repository: {name}",
            "file": name,
            "params": {"path": name},
        }))
        break
    return findings


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------


def _delivery_findings(diff_text, config, add, tree_manifest=None) -> None:
    """Run the diff-text Phase 2 rules (R119-R121, R124, R136-R140) through *add*."""
    _anti_analysis_findings(diff_text, config, add)
    _reconstructed_payload_findings(diff_text, config, add)
    _write_execute_findings(diff_text, config, add)
    _fetch_then_execute_findings(diff_text, config, add)
    _source_file_execution_findings(diff_text, config, add)
    _service_binary_findings(diff_text, tree_manifest, add)
    _path_injection_findings(diff_text, tree_manifest, add)
    _committed_execution_findings(diff_text, tree_manifest, add)
