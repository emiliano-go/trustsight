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


_B64_RUN_RE = re.compile(r"[A-Za-z0-9+/=]{32,}")
_HEX_RUN_RE = re.compile(r"[0-9a-fA-F]{32,}")


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
    """An encoded blob whose decoded bytes carry executable magic.

    R120 is the type check on R117's reconstruction output: one check covers
    every encoding (base64, hex, uuencode) without naming it.  Encoded text
    assets, checksums, and keys decode to bytes that match no magic, so the
    rule's must-not-fire surface is structural rather than positional.
    """
    lines = resolve_added_lines(diff_text)
    added = [ln[1:] for ln in lines if ln.startswith("+")]

    for i, line in enumerate(added):
        body = _strip_comment(line)

        for run in _HEX_RUN_RE.findall(body):
            decoded = _decode_hex(run)
            if decoded and (magic := _magic_name(decoded)):
                add("R120", "Reconstructed Executable Payload", "HIGH", "execution",
                    f"hex blob on the line decodes to {magic}: {line.strip()[:80]}",
                    line=_find_line(diff_text, run),
                    encoding="hex", magic=magic, decoded_bytes=len(decoded))
                return

        for run in _B64_RUN_RE.findall(body):
            decoded = _decode_b64(run)
            if decoded and (magic := _magic_name(decoded)):
                add("R120", "Reconstructed Executable Payload", "HIGH", "execution",
                    f"base64 blob on the line decodes to {magic}: {line.strip()[:80]}",
                    line=_find_line(diff_text, run),
                    encoding="base64", magic=magic, decoded_bytes=len(decoded))
                return

    for decoded, context in _uu_blocks(added):
        if magic := _magic_name(decoded):
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
    p = re.sub(r"^\$(?:srcdir|pkgdir|startdir|BUILDDIR)/?", "", p)
    p = re.sub(r"^\./", "", p)
    p = re.sub(r"/+", "/", p)
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


def _delivery_findings(diff_text, config, add) -> None:
    """Run the diff-text Phase 2 rules (R119-R121, R124) through *add*."""
    _anti_analysis_findings(diff_text, config, add)
    _reconstructed_payload_findings(diff_text, config, add)
    _write_execute_findings(diff_text, config, add)
