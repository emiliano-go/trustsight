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
import fnmatch
import os
import re
import shlex

from ..config import (
    ANY_EXECUTOR as _ANY_EXECUTOR,
    EXEC_WRAPPER as _EXEC_WRAPPER,
    NETWORK_CLIENT as _NETWORK_CLIENT,
    PAYLOAD_PRODUCER as _PAYLOAD_PRODUCER,
    SCRIPT_EXECUTOR as _SCRIPT_EXECUTOR,
)
from ..coverage import note_stage_failure
from ..config import (
    DEFAULT_ANTI_ANALYSIS_PROBES,
    load_patterns,
)
from ..deps import _strip_comment
from ..findings import stamp
from ..rules import ScopeResolver, _classify_enclosing_function
from ..tokenizer import resolve_added_lines, split_lines
from .build import (
    _CRITICAL_FUNCTIONS,
    _INSTALL_HOOKS,
    _INTERPRETER_FETCH,
    _recipe_lines,
)
from ..rules import find_line_in_diff

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
    return find_line_in_diff(diff_text, re.escape(fragment[:60]))


# ---------------------------------------------------------------------------
# R119 - anti-analysis check
# ---------------------------------------------------------------------------


def _anti_analysis_findings(diff_text, config, add, current_text=None) -> None:
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
    scopes = ScopeResolver(lines, _recipe_lines(current_text))
    heredoc_body = _heredoc_body_indices(lines)
    for i, line in enumerate(lines):
        if not line.startswith("+") or not scopes.within(i, _SCOPE_FUNCTIONS):
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
# The bar must be an operative pipe: an escaped one is an argument and
# starts no pipeline.  Same guard as R001-R003 and R045.
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
    # Named groups, because this pattern has grown arms and positional
    # numbering is how the last two silently produced nothing: the reader
    # still asked for groups 1 and 2.
    # `tee` first: it names its destination as an argument, and the heredoc
    # arm below would otherwise consume `tee s.sh <<EOF` and yield nothing.
    r"\btee\b(?:\s+-{1,2}[A-Za-z-]*)*\s+(?![<>-])"
    r"(?P<tee>(?:\"[^\"]*\"|'[^']*'|[^\s;&|<>])+)"
    r"|\b(?:cat|tee)\b[^;&\n]*?<<[^;&|\n]*?"
    r"(?:>\s*(?P<heredoc>\S+))?"            # `cat <<EOF > path` - path after >,
    # `>>` appends; capturing from `>` alone read the second `>` as the path.
    r"|\b(?:cat|printf|echo)\b[^;&\n]*?>>?\s*(?P<simple>[^\s;&|<>]\S*)"
    # `tee` names its destination as an *argument*, which is its whole
    # purpose, and only the redirect spelling was read.
    # A pipeline that ends in a redirect writes whatever the pipeline
    # produced, whichever command produced it: `curl url | sed 's/a/b/' >
    # s.sh` and `make > s.sh` are both a file this recipe generated.  The
    # producer list above is for *payload* provenance; this is the plain
    # fact that a redirect creates a file.
    r"|(?<![0-9>])>(?!>)\s*(?P<redirect>(?:\"[^\"]*\"|'[^']*'|[^\s;&|<>])+)",
    re.IGNORECASE,
)

# The same producers, writing with an ordinary shell redirect.  The write
# tracker recognised `cat|tee|printf|echo` and nothing else, so moving the
# payload one word sideways - `gzip -dc p.gz > s.sh` instead of `cat p >
# s.sh` - left the write unseen and the later `bash s.sh` paired with
# nothing.  The producer list is the decoder alphabet, not "any command":
# `make > log` writes a file too, and it is not a payload.
_PRODUCER_REDIRECT_RE = re.compile(
    r"(?:" + _PAYLOAD_PRODUCER + r")[^;&|\n]*?>\s*"
    r"((?:\"[^\"]*\"|'[^']*'|[^\s;&|>])+)",
    re.IGNORECASE,
)

# An interpreter one-liner that writes a file.  Same reasoning as the fetch
# side: the script is a quoted argument, so nothing in it looks like a shell
# write, and `python3 -c "open('s.sh','w').write(...)"` produced no write at
# all for the execution on the next line to pair with.
_INTERPRETER_WRITE_RE = re.compile(
    r"\b(?:python[23]?|perl|ruby|node|php)\s+(?:-\S++\s++)*?-[ceE]\b[^\n]*?"
    r"(?:open|File\.(?:write|open)|writeFileSync|createWriteStream"
    r"|file_put_contents|IO\.write)\s*\(?\s*"
    # `open(F, ">s.sh")` and `open $f, ">s.sh"` name the mode and the path in
    # one string, and the bare-parenthesis form has a filehandle first.
    r"(?:[A-Za-z_$][\w$]*\s*,\s*)?"
    r"[\"']>{0,2}([^\"']{1,120})[\"']",
    re.IGNORECASE,
)

# A decoder that names its destination with a *flag* rather than a shell
# redirect.  The write tracker knew `>`, `tee`, `cp`, `install` and heredocs
# - every form the shell itself performs - so `openssl enc -d -in p.enc -out
# s.sh` followed by `bash s.sh` wrote and executed a payload that neither
# R121/R124 nor any decoder rule saw: X001's openssl arm requires the decode
# to be *piped*, and the pipe is exactly what this spelling avoids.
#
# Deliberately not a general `-o` arm.  `-o` is one of the most overloaded
# flags there is - `gcc -o`, and `install -o root` names an *owner*, not an
# output - so the commands are enumerated and they are all tools whose whole
# purpose is turning unreadable bytes into a file.
_DECODER_WRITE_RE = re.compile(
    r"\b(?:openssl|gpg2?|age|base64|base32|basenc|xxd|uudecode|certutil)\b"
    r"[^;&|\n]*?\s-(?:-?out(?:put)?|o)[=\s]+"
    r"((?:\"[^\"]*\"|'[^']*'|[^\s;&|])+)"
    r"|\bdd\b[^;&|\n]*?\bof=((?:\"[^\"]*\"|'[^']*'|[^\s;&|])+)",
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


# A heredoc whose destination is an interpreter.  `cat > x <<EOF` writes a
# file; `bash <<EOF` and `... <<EOF | sh` hand the body to a shell, and the
# body is then the script that runs.
_HEREDOC_TO_INTERPRETER_RE = re.compile(
    r"(?:\A\s*|[;&|]\s*|\b(?:env|exec|command|sudo|nohup)\s+)"
    r"(?:/(?:usr/)?bin/)?"
    r"(?:ba|z|da|k|a|mk|pdk|ya|po)?sh\b(?!\s*>)"
    r"|\|\s*(?:/(?:usr/)?bin/)?(?:ba|z|da|k|a|mk|pdk|ya|po)?sh\b"
    r"|(?:\A\s*|[;&|]\s*)(?:python[23]?|perl|ruby|node)\b(?!\s*>)",
    re.IGNORECASE,
)


#: A heredoc whose destination is a file that *executes* what it contains:
#: a systemd unit, a `.desktop` entry, a cron file, a PAM stack.  The body
#: is data in the shell's sense and a set of directives in the reader's, and
#: treating it as inert meant `cat > "$pkgdir/.../e.service" <<EOF` with an
#: `ExecStart=` payload inside was never scanned - the same distinction the
#: tokenizer draws between a shell assignment and a config directive.
#
# The destination is asserted by a lookahead rather than walked to by a
# greedy run: `[^"'\s;&|]*` followed by a large alternation backtracks
# through every branch at every position, which the adversarial audit
# refuses. The lookahead runs once per `>` on the line.
_HEREDOC_TO_EXECUTING_CONFIG_RE = re.compile(
    r">\s*[\"']?"
    r"(?=[^\n]*(?:"
    r"/(?:cron\.[a-z]+|cron\.d|systemd/(?:system|user)|xdg/autostart"
    r"|pam\.d|profile\.d|init\.d|rc\.d|xinetd\.d|logrotate\.d"
    r"|dispatcher\.d|udev/rules\.d|conf\.d|sudoers\.d)/"
    r"|\.(?:service|socket|timer|path|desktop|rules|conf)\b))",
    re.IGNORECASE,
)

#: `... <<EOF | sh` - the heredoc's destination named after the delimiter.
_HEREDOC_PIPED_RE = re.compile(
    r"(?<!\\)\|\s*(?:" + _ANY_EXECUTOR + r")", re.IGNORECASE
)


def _heredoc_body_indices(lines: list[str]) -> set[int]:
    """Indices of lines that are literal heredoc content, not commands.

    A heredoc's body is data being written to a file; treating it as build
    commands would let the payload's own lines fire the very rules the
    generate-then-execute rule is meant to catch once.  The opener line
    itself is a command and stays eligible.

    That reasoning holds only for a heredoc that reaches a *file*.  When the
    destination is a shell - ``bash <<'EOF'`` - the body is not data, it is
    the script being executed, and exempting it turned four rules off for
    every line inside::

        build() {
          bash <<'EOF'
          _fetch
          bash "$srcdir/x.sh"
        EOF
        }

    The exemption is therefore decided per heredoc, by where it goes.
    """
    body: set[int] = set()
    delims: list[tuple[str, bool]] = []
    for i, line in enumerate(lines):
        content = line[1:] if line[:1] in ("+", "-") else line
        stripped = content.strip()
        if delims and stripped == delims[-1][0]:
            delims.pop()
            continue
        if delims:
            if delims[-1][1]:
                body.add(i)
            continue
        for m in _HEREDOC_OPEN_RE.finditer(content):
            if m.group(2):
                # The destination may be named on either side of the
                # delimiter: `bash <<EOF` puts it before, and
                # `cat <<'EOF' | sh` puts it after the redirect.  Reading
                # only the left half meant the piped form - which is how
                # the shape is usually written - stayed classified as data.
                is_data = not (
                    _HEREDOC_TO_INTERPRETER_RE.search(content[:m.start()])
                    or _HEREDOC_PIPED_RE.search(content[m.end():])
                    or _HEREDOC_TO_EXECUTING_CONFIG_RE.search(content)
                )
                delims.append((m.group(2), is_data))
                break
    return body

# An interpreter/compiler/source command must sit at a command position
# (line start or after ``;``/``&``/``|``), never inside a filename like
# ``completions/zsh`` or as a bare argument like ``cp -a . dir``.
# A command may be preceded by a wrapper that changes nothing about what
# runs: `env bash s.sh`, `nohup bash s.sh &`, `timeout 5 bash s.sh`.  The
# execution patterns anchored on a bare verb at a command position, so every
# one of these forms produced no execution at all - and `env -i bash` was
# caught while plain `env bash` was not, which is the asymmetry that gives
# the game away.
# The wrapper list is the shared one.  It was a second copy here, and the
# copies drifted: `chroot`, `bwrap`, `firejail` and `unshare` were added to
# the executor vocabulary and this list kept its own shorter set, so
# `bwrap --ro-bind / / bash s.sh` executed `s.sh` and paired with nothing.
# Two lists that must agree is the defect this file has now hit three times.
_EXEC_PREFIX = r"(?:" + _EXEC_WRAPPER + r")*"

# `do`, `then`, `else`, `in` and `{` introduce a command just as a `;` does:
# in shell grammar they end the preceding construct and the next word is a
# command name.  Requiring a separator meant `for f in *.sh; do bash "$f";
# done` had no execution at all - the loop body is where the work happens,
# and it is always preceded by one of these words.
_CMD_START = (
    r"(?:\A\s*|[;&|{(]\s*|\b(?:do|then|else|elif)\s+)" + _EXEC_PREFIX
)
_EXECUTION_RE = re.compile(
    # `(?![<>])`: a redirect is not a filename argument.  Without it this
    # arm matched `bash < pipe` and captured `<`, and being first in the
    # alternation it also shadowed the redirect arm below.
    #
    # Flags sit between the verb and the script - `bash -x s.sh`, `bash --
    # s.sh` - and capturing the first token after the verb captured the
    # flag, so the write and the execution never paired.  `busybox sh` is
    # two words for one shell, and `node`/`php`/`lua` run a script file the
    # same way the shells do.
    # An absolute path is the same shell: `/usr/bin/bash s.sh` ran and
    # paired with nothing.  A quoted argument may hold spaces, and the
    # bare `\S+` stopped at the first one.
    _CMD_START + r"(?:busybox\s+)?(?:/[\w./-]*/)?(?:bash|sh|zsh|dash|ksh|ash|mksh"
    r"|node|php|lua(?:jit)?|tclsh|fish)"
    r"(?:\s+-{1,2}[A-Za-z-]*)*\s+(?![<>-])"
    # `[^\s;&|<>]+`, not `\S+`: a command may end at a separator, and
    # `bash s.sh; fi` captured `s.sh;` - a path that matches nothing.
    r"(\"[^\"]+\"|'[^']+'|[^\s;&|<>]+)"
    # A shell takes its script from a redirect just as readily as from an
    # argument, and a FIFO makes that a *fetch* it executes:
    #   mkfifo p; curl url > p & ; bash < p
    # No literal `|` for R001 to see and no filename argument for the
    # pattern above, while `curl > p` is already a fetch output R137 tracks.
    # `<(` is process substitution and `<<` a heredoc; neither is this.
    r"|" + _CMD_START + r"(?:bash|sh|zsh|dash|ksh)\s*<\s*(?!\(|<)(\S+)"
    r"|" + _CMD_START + r"source\s+(\S+)"
    r"|" + _CMD_START + r"\.\s+(\S+)"
    # `./x` only where a command starts. Unanchored, this arm matched the
    # `./` inside `sed 's|./log\.txt|…|g'` and inside `../x.patch`, and
    # captured whatever followed - harmless for R138, which discards a
    # capture that is not a declared basename, and not harmless at all for
    # a rule that reports the path to a reader.
    r"|" + _CMD_START + r"\./(\S+)"
    # A build-tree path in command position runs without any verb at all:
    # `"$srcdir/s.sh"` is an execution and was read as nothing.  The quotes
    # are optional here because the tokenizer has already removed them by
    # the time this pattern runs - requiring them matched the raw text and
    # nothing else.
    r"|(?:\A\s*|[;&|]\s*)[\"']?([$][{]?(?:srcdir|startdir|pkgdir)[}]?/[^\"'\s;&|]+)"
    # An absolute path at a command position, with or without arguments:
    # requiring it to stand alone let `/tmp/.stage2 --install` past the
    # write-then-execute dataflow while `/tmp/.stage2` was caught.
    r"|^\s*(\/[^\s;&|]+)(?=\s|$)"
    r"|" + _CMD_START + r"(?:python3?|perl|ruby)(?:\s+-{1,2}[A-Za-z-]*)*\s+(?![<>-])(\S+)"
    # Engines that run a committed record rather than a script argument.
    # `node x.js`, `dotnet run`, `go run .`, `./gradlew build` and `cargo
    # build` each execute code from a file in the tree, and R136's verb
    # list named none of them.
    r"|" + _CMD_START + r"(?:dotnet\s+(?:run|exec)|go\s+run|deno\s+run)"
    r"(?:\s+-{1,2}[A-Za-z-]*)*\s*(\S*)"
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
    # The standard entry points of an unpacked tree. A recipe running
    # `python setup.py build` or `perl Makefile.PL` is doing the one thing
    # the packaging format is for, and naming those as unaudited execution
    # would put a note on most of the ecosystem while saying nothing a
    # reader does not already assume.
    "setup.py", "Makefile.PL", "Build.PL", "autogen.sh", "bootstrap",
    "bootstrap.sh", "waf", "SConstruct", "gradlew",
})

#: Tokens that are not a path at all.
#:
#: `_SOURCE_EXEC_RE` captures the word after an interpreter, and that word
#: is not always a file: `python3 -m build` yields `-m`, a loop body yields
#: `*`, and an unresolved parameter expansion yields `${patch%%`. R138
#: discards them silently because none can equal a declared basename, so
#: the weakness was invisible - until W001 tried to *print* one.
#: `$srcdir` and its siblings are excepted: they are makepkg's own names
#: for the build tree, they are exactly where unread code lives, and
#: rejecting every `$` rejected the one case this test exists to allow.
_BUILD_ROOT_RE = re.compile(
    r"\A[\"']*\$\{?(?:srcdir|startdir|pkgdir|PWD|BUILDDIR)\}?/")
_NOT_A_PATH_RE = re.compile(r"\A-|[*?\[\]{}$%`]|\A\.{2,}\Z")


def _not_a_path(token: str) -> bool:
    """True when *token* is not a filename.

    The build-root prefix is removed before the test rather than excepted
    inside it: `${srcdir}` legitimately contains braces and a `$`, which
    are exactly the characters that mark an unresolved expansion
    everywhere else. Excepting them in the pattern meant either rejecting
    the braced spelling - `bash "${srcdir}/sync.sh"`, which is how most
    recipes write it - or letting `${patch%%...}` through.
    """
    token = _BUILD_ROOT_RE.sub("", token).strip("\"'")
    return not token or bool(_NOT_A_PATH_RE.search(token))


def _is_directory_path(p: str) -> bool:
    """True when *p* names a directory rather than a file.

    A trailing slash makes the basename empty, and two empty basenames
    compare equal - so `install -d "$pkgdir/usr/share/icons/"` paired with
    an unrelated `/opt/` and reported "writes /usr/share/icons/ and then
    executes it". A directory is neither written as a payload nor executed.
    """
    return p.endswith("/") or not os.path.basename(p.rstrip())


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
    for line in split_lines(diff_text):
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
        # A `source=(` array is routinely written one URL per line with a
        # trailing backslash.  shlex reads that dangling escape as an
        # error, which made an ordinary multi-line array look like a
        # failed stage; the loop already visits the continuation line.
        body = body.rstrip()
        # A whole-line comment inside the array is prose, and prose has
        # apostrophes: `# makepkg doesn't understand SSH signatures` is an
        # unbalanced quote to shlex.  Only a line that *starts* with `#` is
        # dropped - a bare `git+url#tag=v1` entry carries a real fragment.
        if body.lstrip().startswith("#"):
            continue
        if body.endswith("\\") and not body.endswith("\\\\"):
            body = body[:-1]
        try:
            entries = shlex.split(body)
        except ValueError:
            # What is left is a genuinely unbalanced quote, which skipped
            # the whole entry: a URL could hide behind one apostrophe.
            note_stage_failure("source-parse")
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
        path = next((v for v in m.groupdict().values() if v), None)
        # A redirect to a null or terminal device creates nothing that can
        # later be executed, and recording it only invites a spurious pair.
        if path and not path.startswith(("/dev/null", "/dev/std", "/dev/tty")):
            writes.append(("generation", _norm_path(path)))
    for m in _COPY_WRITE_RE.finditer(body):
        path = m.group(1)
        if path.startswith("-") or ">" in path:
            continue
        writes.append(("copy", _norm_path(path)))
    for m in _DECODER_WRITE_RE.finditer(body):
        path = m.group(1) or m.group(2)
        if path and not path.startswith("-"):
            writes.append(("generation", _norm_path(path)))
    for m in _PRODUCER_REDIRECT_RE.finditer(body):
        path = m.group(1)
        if path and not path.startswith("-"):
            writes.append(("generation", _norm_path(path)))
    for m in _INTERPRETER_WRITE_RE.finditer(body):
        path = m.group(1)
        if path and not path.startswith("-"):
            writes.append(("generation", _norm_path(path)))
    # One filter for every arm rather than a guard on each: a directory is
    # not a payload whichever verb created it, and its empty basename
    # compares equal to any other directory's - which is how `install -d
    # "$pkgdir/usr/share/icons/"` paired with an unrelated `/opt/`.
    return [(kind, path) for kind, path in writes
            if path and not _is_directory_path(path)]


#: Build tools and the file each one executes without being told to.
_IMPLICIT_BUILD_INPUTS = (
    # `-f` names the input explicitly and `_DRIVER_INPUT_FLAG_RE` reads it;
    # `-C` used to be excluded here for the same reason, but it names a
    # *directory* rather than a file, so the implicit input still applies -
    # relative to that directory, which is what `_DRIVER_CHDIR_RE` supplies.
    (re.compile(r"(?:\A\s*|[;&|]\s*)(?:g)?make\b(?![^;&|]*\s-f\b)",
                re.IGNORECASE),
     ("GNUmakefile", "makefile", "Makefile")),
    (re.compile(r"(?:\A\s*|[;&|]\s*)cmake\b", re.IGNORECASE),
     ("CMakeLists.txt",)),
    (re.compile(r"(?:\A\s*|[;&|]\s*)ninja\b", re.IGNORECASE),
     ("build.ninja",)),
    (re.compile(r"(?:\A\s*|[;&|]\s*)meson\b", re.IGNORECASE),
     ("meson.build",)),
)


#: `make -C dir`, `cmake -S dir`, `ninja -C dir`: the driver reads its
#: implicit input from *there*, not the current directory.
_DRIVER_CHDIR_RE = re.compile(
    r"\b(?:g?make|cmake|ninja|meson)\b[^;&|\n]*?\s-(?:C|S)\s*"
    r"((?:\"[^\"]+\"|'[^']+'|[^\s;&|]+))",
    re.IGNORECASE,
)

#: A build driver named with an explicit input file: `make -f zz.mk`,
#: `cmake -P s.cmake`, `makepkg -p x.pkg`.
_DRIVER_INPUT_FLAG_RE = re.compile(
    r"\b(?:g?make|cmake|ninja|meson|makepkg|ansible-playbook)\b"
    r"[^;&|\n]*?\s-(?:f|p|P|-file|-makefile)[=\s]+"
    r"((?:\"[^\"]*\"|'[^']*'|[^\s;&|])+)",
    re.IGNORECASE,
)


#: Drivers that take a command to run as an argument rather than running
#: one themselves.  `expect -c "spawn bash s.sh"`, `script -qfc "bash s.sh"`,
#: `tmux new-session -d "bash s.sh"` and `su -c "..."` all execute the
#: quoted text; the execution patterns saw the driver's own name and stopped.
_COMMAND_ARG_DRIVER_RE = re.compile(
    r"\b(?:expect|script|tmux|screen|su|runuser|setpriv|systemd-run|at|batch"
    r"|watch|entr|xdotool|ssh|dtach|abduco|flock|torify|torsocks)\b"
    r"[^;&|\n]*?"
    r"(?:\"(?P<dq>[^\"]{1,400})\"|'(?P<sq>[^']{1,400})')",
    re.IGNORECASE,
)

#: `find ... -exec bash {} \;` and `xargs -I{} bash {}` hand each matched
#: path to the command as `{}`.  The operand is real; it is just named by
#: the tool rather than written down.
_OPERAND_DRIVER_RE = re.compile(
    r"\bfind\b[^;&|\n]*?-(?:i?name|path)\s+[\"']?(?P<pattern>[^\"'\s;&|]+)"
    r"[^;&|\n]*?-exec(?:dir)?\s+(?P<findcmd>[^;\n]*?)(?:\\;|\+|$)"
    # The flags are captured as a run rather than matched optionally: a
    # lazy span happily skipped `-I{}` and left it inside the command,
    # which then had no command position to start from.
    r"|\bxargs\b(?P<flags>(?:\s+-\S+)*)\s+(?P<xargscmd>[^;\n|]+)",
    re.IGNORECASE,
)


def _driver_commands(body: str) -> list[str]:
    """Command text a driver on *body* will run.

    Returned as strings for the caller to re-scan, so one execution
    vocabulary answers for both the direct and the driver-invoked spelling
    rather than a second list that can drift from the first.
    """
    found: list[str] = []
    for match in _COMMAND_ARG_DRIVER_RE.finditer(body):
        inner = match.group("dq") or match.group("sq")
        if inner:
            # `spawn bash s.sh` - expect's own verb wraps the command again.
            found.append(re.sub(r"^\s*spawn\s+", "", inner))
    for match in _OPERAND_DRIVER_RE.finditer(body):
        command = match.group("findcmd") or match.group("xargscmd")
        if not command:
            continue
        flags = match.groupdict().get("flags") or ""
        replace_token = re.search(r"-I\s*(\S+)", flags)
        token = replace_token.group(1) if replace_token else "{}"
        pattern = match.group("pattern")
        if pattern is None:
            # `xargs` reads its operands from the pipeline, so the names are
            # on the *left* of the bar: `printf "s.sh" | xargs -I{} bash {}`
            # runs `bash s.sh`.  Substituting a bare `*` would name every
            # file, which is a claim about none of them.
            left = body.split("|", 1)[0]
            pattern = next(
                (w.strip("\"'") for w in reversed(left.split())
                 if "." in w and not w.startswith("-")),
                None,
            )
        if pattern is None:
            continue
        found.append(command.replace(token, pattern).replace("{}", pattern))
    return found


def _collect_executions(body: str) -> list[str]:
    """Return normalised paths executed or compiled on *body*.

    A build driver is an execution of its input file.  `curl -o Makefile
    URL` followed by `make` fetches a script and runs it, and neither half
    was paired with the other: `make` matched no execution pattern, so R137
    saw a download and nothing more.  The driver's *implicit* input is
    resolved the same way `_implicit_build_input` resolves it for committed
    files - the difference is only where the file came from.
    """
    paths: list[str] = []
    for match in _DRIVER_INPUT_FLAG_RE.finditer(body):
        path = _norm_path(match.group(1))
        if path and not _is_directory_path(path):
            paths.append(path)
    # `-C dir` moves the driver's implicit input into that directory, which
    # is how `git clone ... r` followed by `make -C r` builds the cloned
    # tree without ever naming a file in it.
    directory = _DRIVER_CHDIR_RE.search(body)
    prefix = (_norm_path(directory.group(1)).rstrip("/") + "/") if directory else ""
    for pattern, candidates in _IMPLICIT_BUILD_INPUTS:
        if pattern.search(body):
            paths.extend(prefix + name for name in candidates)
    for m in _EXECUTION_RE.finditer(body):
        for g in m.groups():
            if g and not _is_directory_path(g):
                paths.append(_norm_path(g))
    # A driver's command is scanned with the same vocabulary, once.  Bounded
    # to one level: a driver running a driver is not a shape worth the
    # recursion, and unbounded re-entry on attacker text is not a bound.
    for command in _driver_commands(body):
        for m in _EXECUTION_RE.finditer(command):
            for g in m.groups():
                if g and not _is_directory_path(g):
                    paths.append(_norm_path(g))
    return paths


def _write_execute_findings(diff_text, config, add, current_text=None) -> None:
    """Same-function write-then-execute dataflow (R121, R124).

    A path written by the recipe and later executed in the same build
    function is a delivered payload.  R121 fires on generation writes
    (heredoc/``>``) whose content the recipe itself created; R124 fires on
    any write.  Both stay silent when the executed path arrived via the
    declared source array or is one of the project's own configure/make
    artifacts (R124 only).
    """
    lines = resolve_added_lines(diff_text)
    scopes = ScopeResolver(lines, _recipe_lines(current_text))
    source_basenames = _declared_source_basenames(diff_text)
    heredoc_body = _heredoc_body_indices(lines)

    writes_by_fn: dict[str, list[tuple[str, str]]] = {}
    r121_claimed: set[tuple[str, str]] = set()

    for i, line in enumerate(lines):
        # The *resolved* scope, not the enclosing name: a write in a helper
        # and the execution in build() are one operation, and keying by the
        # spelling put them in different buckets.
        fn = scopes.within(i, _SCOPE_FUNCTIONS)
        if not line.startswith("+") or fn is None:
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
_FETCH_CLIENT_RE = re.compile(
    r"\b(?:" + _NETWORK_CLIENT + r")\b|(?:" + _INTERPRETER_FETCH + r")",
    re.IGNORECASE,
)

# Where an interpreter one-liner puts what it downloaded.  `urlretrieve(url,
# path)` and `open(path, "wb")` are the two shapes that reach a file; the
# quoted token that is not the URL is the path, which is the only part R137
# needs in order to pair the fetch with a later execution of it.
_INTERPRETER_OUTPUT_RE = re.compile(
    r"(?:urlretrieve|getstore|open|File\.write|writeFileSync|copyfileobj)"
    r"\s*\([^)]{0,200}?"
    # A path shape, not "anything between quotes": the closing quote of the
    # URL argument and the opening quote of the next one are separated by a
    # comma, which read as a one-character filename.
    r"[\"\']((?!https?://)[\w./~$@+-]{1,120})[\"\']",
    re.IGNORECASE,
)

_FETCH_OUTPUT_RE = re.compile(
    # The output-flag arm is client-specific on purpose: `-o`/`-O` mean
    # "write here" for curl and wget, and `rsync -O` is `--omit-dir-times`.
    # Sharing one client list read rsync's source URL as its destination.
    r"\b(?:curl|wget2?|aria2c|axel|lftp|ncftp(?:get)?|snarf"
    # Store clients that take an output flag too.  `ipfs get CID -o x.sh`
    # names its destination the same way curl does; the address it fetched
    # from is a content identifier rather than a URL, which is why nothing
    # else in the chain could attribute it.
    r"|ipfs|b2|swift|restic|borg)\b"
    r"[^;&|]*?"
    # `-o` is rarely alone.  `curl -Lo f` and `wget -qO f` are the forms
    # people actually type, and requiring the flag to stand by itself meant
    # the fetch never paired with the later execution of what it wrote - one
    # letter moved, and R137 went quiet.  The cluster must *end* in the
    # output letter, because that is the one whose argument follows.
    # `-O` (capital, curl) takes no argument: it means "save as the URL's
    # basename", and reading the URL after it as a destination produced a
    # path like `https:/e.x/x.sh`.  Lower-case `-o` does take one.
    r"(?:\s-[A-Za-z]*o\s+|\s-[A-Za-z]*O\s+(?![a-z][a-z0-9+.-]*://)"
    r"|\s--output(?:\s+|=)"
    r"|\s--output-document(?:\s+|=)|>\s*)"
    r"(?P<path>(?:\"[^\"]*\"|'[^']*'|\\.|[^\s;&|])+)"
    # `scp host:/x.sh s.sh` and `rsync -O URL s.sh` name the destination
    # positionally - there is no output flag to key on, and the last
    # argument is the file the next line runs.
    r"|\b(?:scp|rsync|sftp)\b(?:\s+-\S+)*\s+\S+\s+"
    r"(?P<dest>(?:\"[^\"]*\"|'[^']*'|[^\s;&|<>])+)\s*$"
    # Object stores name source and destination positionally, like scp:
    # `s3cmd get s3://b/x.sh x.sh`, `aws s3 cp s3://b/x.sh x.sh`,
    # `rclone copy remote:/x.sh .`.
    r"|\b(?:s3cmd\s+(?:get|cp|sync)|aws\s+s3\s+(?:cp|sync|mv)"
    r"|gsutil\s+(?:cp|rsync)|rclone\s+(?:copy|copyto|sync))\b"
    r"(?:\s+-\S+)*\s+\S+\s+"
    r"(?P<store_dest>(?:\"[^\"]*\"|'[^']*'|[^\s;&|<>])+)\s*$",
    re.IGNORECASE | re.MULTILINE,
)

# Build/package/check/prepare only; install hooks already have R062.
_BUILD_FUNCTIONS = frozenset(_CRITICAL_FUNCTIONS)

#: Where files are staged rather than built.
_PACKAGING_FUNCTIONS = frozenset({"package"}) | frozenset(_INSTALL_HOOKS)


#: A VCS checkout names a *directory*, and everything under it arrived from
#: the remote.  `git clone URL repo` then `bash repo/run.sh` is a fetch and
#: an execution of what it fetched, and the pair was never made because the
#: fetch produced no file path to match - only a tree.
_CLONE_DEST_RE = re.compile(
    r"\b(?:git\s+clone|hg\s+clone|bzr\s+branch|svn\s+(?:co|checkout|export)"
    r"|fossil\s+clone|darcs\s+get)\b"
    r"(?:\s+--?\S+)*"
    r"\s+(?:[a-z][a-z0-9+.-]*://\S+|\S+@\S+:\S+|\S+\.git)"
    r"\s+(?P<dir>(?:\"[^\"]+\"|'[^']+'|[^\s;&|<>-][^\s;&|<>]*))",
    re.IGNORECASE,
)


def _clone_destinations(body: str) -> list[str]:
    """Directories a VCS checkout on *body* fills from a remote."""
    return [
        _norm_path(m.group("dir")).rstrip("/")
        for m in _CLONE_DEST_RE.finditer(body)
    ]


#: A fetch that names no destination.  `wget URL` saves the URL's basename
#: into the current directory and `curl -O URL` asks for exactly that, so
#: the file the next line runs was never written down anywhere.  Plain
#: `curl` writes to stdout and is deliberately absent.
_DEFAULT_DEST_RE = re.compile(
    r"\b(?:wget2?|aria2c|axel)\b(?![^;&|\n]*\s-(?:[A-Za-z]*[oO]\s|-output))"
    r"[^;&|\n]*?([a-z][a-z0-9+.-]*://[^\s;&|'\"]+)"
    r"|\bcurl\b[^;&|\n]*?\s-[A-Za-z]*O\b"
    r"[^;&|\n]*?([a-z][a-z0-9+.-]*://[^\s;&|'\"]+)",
    re.IGNORECASE,
)


def _collect_fetch_outputs(body: str) -> list[str]:
    """Normalised paths a network client on *body* writes to a file."""
    paths: list[str] = []
    if not _FETCH_CLIENT_RE.search(body):
        return paths
    for m in _FETCH_OUTPUT_RE.finditer(body):
        raw = m.group("path") or m.group("dest") or m.group("store_dest") or ""
        # A URL is a source, not a destination.  `curl -O URL` takes no
        # argument, so whatever follows it is the address being fetched.
        if "://" in raw:
            continue
        path = _norm_path(raw)
        if path:
            paths.append(path)
    for m in _INTERPRETER_OUTPUT_RE.finditer(body):
        path = _norm_path(m.group(1))
        if path:
            paths.append(path)
    for m in _DEFAULT_DEST_RE.finditer(body):
        url = m.group(1) or m.group(2) or ""
        base = url.rstrip("/").rsplit("/", 1)[-1].split("?")[0]
        if base and "." in base:
            paths.append(_norm_path(base))
    return paths


def _fetch_then_execute_findings(diff_text, config, add, current_text=None) -> None:
    """A downloader writes a file and the same function later executes it (R137).

    R001/R002 own the single-line pipe form; R137 owns the split form.
    Files that arrived via the declared ``source=()`` array are deliberately
    excluded here - they have their own rule (R138) so checksum-bearing
    source files are not double-counted.
    """
    lines = resolve_added_lines(diff_text)
    scopes = ScopeResolver(lines, _recipe_lines(current_text))
    source_basenames = _declared_source_basenames(diff_text)
    heredoc_body = _heredoc_body_indices(lines)

    fetched_by_fn: dict[str, list[str]] = {}
    cloned_by_fn: dict[str, list[str]] = {}

    for i, line in enumerate(lines):
        fn = scopes.within(i, _BUILD_FUNCTIONS)
        if not line.startswith("+") or fn is None:
            continue
        if i in heredoc_body:
            continue
        body = _strip_comment(line[1:])

        for path in _collect_fetch_outputs(body):
            fetched_by_fn.setdefault(fn, []).append(path)
        # A clone fills a whole directory, so the pairing is by prefix
        # rather than by name: anything under it came from the remote.
        for directory in _clone_destinations(body):
            cloned_by_fn.setdefault(fn, []).append(directory)

        for path in _collect_executions(body):
            base = os.path.basename(path)
            for directory in cloned_by_fn.get(fn, []):
                if directory and path.startswith(directory.rstrip("/") + "/"):
                    add("R137", "Fetch Then Execute", "CRITICAL",
                        "network_execution",
                        f"{fn}() clones into {directory} and then executes "
                        f"{path} from it",
                        line=_find_line(diff_text, path or base),
                        position=fn, path=path)
                    return
            for fpath in list(fetched_by_fn.get(fn, [])):
                fbase = os.path.basename(fpath)
                if fpath != path and fbase != base:
                    continue
                # The benign-artifact exemption claims "this file came with
                # the project".  A `Makefile` this recipe just downloaded
                # did not, and `curl -o Makefile URL` followed by `make`
                # was reading the filename instead of the provenance - the
                # same mistake the committed-`configure` case made.
                if base in source_basenames:
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
#
# Three arms below were in R137 and not here, and the pair are meant to be
# the same question asked of a fetched file and a declared one. Feeding the
# script on stdin (`sh < "$srcdir/setup.sh"`), running it as a bare command
# (`"$srcdir/setup.sh"`), and handing a downloaded makefile to `make -f`
# are all execution of downloaded code; only the spelling differed, and the
# declared-source half of the pair could not see any of them.
_SOURCE_EXEC_RE = re.compile(
    # `(?![<>])`: a redirect is not a filename argument. Without it this
    # arm captured the `<` of `sh < file` and the redirect arm below never
    # got a turn - the same trap `_EXECUTION_RE` documents.
    _CMD_START + r"(?:bash|sh|zsh|dash|ksh|python3?|perl|ruby)\s+(?![<>])(\S+)"
    r"|" + _CMD_START + r"source\s+(\S+)"
    r"|" + _CMD_START + r"\.\s+(\S+)"
    r"|\./(\S+)"
    # `sh < file` - the interpreter reads the script from its stdin.
    # `(?!\(|<)` keeps process substitution and here-strings out: those are
    # different constructs that R127 owns.
    r"|" + _CMD_START + r"(?:bash|sh|zsh|dash|ksh|python3?|perl|ruby)"
    r"\s*<\s*(?!\(|<)(\S+)"
    # A bare `"$srcdir/x"` in command position: the file is the command.
    r"|(?:\A\s*|[;&|]\s*)[\"']?(\$\{?(?:srcdir|startdir)\}?/[^\"'\s;&|]+)"
    # `make -f downloaded.mk` runs the recipes in a downloaded file.
    r"|" + _CMD_START + r"(?:g?make|cmake)\s+(?:-\S+\s+)*-f\s+(\S+)",
    re.IGNORECASE,
)


def _source_file_execution_findings(diff_text, config, add, current_text=None) -> None:
    """A file downloaded via ``source=()`` is executed as a script (R138).

    Build-system scripts (configure, make, meson, ninja, cmake) are common
    declared-source executables and stay silent; the rule targets interpreted
    execution of a downloaded script.
    """
    lines = resolve_added_lines(diff_text)
    scopes = ScopeResolver(lines, _recipe_lines(current_text))
    source_basenames = _declared_source_basenames(diff_text)
    heredoc_body = _heredoc_body_indices(lines)
    for i, line in enumerate(lines):
        fn = scopes.within(i, _BUILD_FUNCTIONS)
        if not line.startswith("+") or fn is None:
            continue
        if i in heredoc_body:
            continue
        body = _strip_comment(line[1:])

        for m in _SOURCE_EXEC_RE.finditer(body):
            raw = next((g for g in m.groups() if g), None)
            if not raw:
                continue
            if _not_a_path(raw):
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


def _installed_executables(diff_text: str, current_text=None) -> set[tuple[str, str]]:
    """Return (source_basename, normalised_dest_path) for installed executables.

    Only considers installs with explicit 7xx modes or with no ``-m`` flag
    (install defaults to 755).  Destination paths are normalised so they can
    be compared to ExecStart paths.
    """
    found: set[tuple[str, str]] = set()
    lines = resolve_added_lines(diff_text)
    scopes = ScopeResolver(lines, _recipe_lines(current_text))
    heredoc_body = _heredoc_body_indices(lines)
    for i, line in enumerate(lines):
        fn = scopes.within(i, _BUILD_FUNCTIONS)
        if not line.startswith("+") or fn is None:
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
            note_stage_failure("install-parse")
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
                # `errors="replace"` cannot raise, so the handler that used
                # to sit here could only ever have hidden a bug.
                service_texts.append(data.decode("utf-8", errors="replace"))
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


def _path_injection_findings(diff_text, tree_manifest, add, current_text=None) -> None:
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
    scopes = ScopeResolver(lines, _recipe_lines(current_text))
    heredoc_body = _heredoc_body_indices(lines)

    for i, line in enumerate(lines):
        fn = scopes.within(i, _BUILD_FUNCTIONS)
        if not line.startswith("+") or fn is None:
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


def _implicit_build_input(body: str, manifest_basenames) -> str | None:
    """The committed file a build tool on *body* will execute, if any.

    Only answerable with a manifest: without one there is no way to tell a
    committed ``Makefile`` from the tarball's, and guessing would fire on
    every package that runs ``make``.
    """
    if not manifest_basenames:
        return None
    for pattern, candidates in _IMPLICIT_BUILD_INPUTS:
        if not pattern.search(body):
            continue
        for name in candidates:
            if name in manifest_basenames:
                return name
    return None


#: `for f in "$srcdir"/*.sh` binds `f` to every name the glob matches, and
#: the execution two words later is `bash "$f"`.  The pattern and the use are
#: on the same line but in different clauses, so neither half names a file on
#: its own.
_LOOP_BINDING_RE = re.compile(
    r"\bfor\s+(?P<var>\w+)\s+in\s+(?P<words>[^;\n]*?)(?:;|\s+do\b)",
    re.IGNORECASE,
)


#: `set -- "$srcdir"/*.sh` binds the *positional* parameters, and the
#: execution two lines later is `bash "$1"` or `bash $@`.  Same shape as a
#: `for` loop with the binding spelled differently.
_SET_POSITIONAL_RE = re.compile(
    # `\A\s*`, not `\A`: a recipe line is indented, and anchoring at the
    # very first character meant the binding was only ever found on a line
    # that began in column one.
    r"(?:\A\s*|[;&|]\s*)set\s+--\s+(?P<words>[^;\n]+)"
)

#: `mapfile -t A < <(...)` and `readarray A < ...` fill an array; `A=(*.sh)`
#: does it directly.  The cell is then executed as `bash "${A[0]}"`.
_ARRAY_BINDING_RE = re.compile(
    r"\b(?:mapfile|readarray)\b(?:\s+-\S+)*\s+(?P<mvar>\w+)"
    r"[^;\n]*?<\s*(?:<\s*\()?(?P<mwords>[^;\n)]*)"
    r"|(?:\A\s*|[;&|]\s*)(?P<avar>\w+)=\((?P<awords>[^)\n]*)\)"
)

#: Every way a shell names the positional parameters.
_POSITIONAL_NAMES = frozenset({"1", "2", "3", "4", "5", "6", "7", "8", "9",
                               "@", "*"})


def _loop_bindings(body: str) -> dict[str, list[str]]:
    """``{variable: [patterns it may hold]}`` for one line.

    A `for` loop is only the most visible binding.  `set -- "$srcdir"/*.sh`
    puts the same glob into `$1`/`$@`, `A=(*.sh)` puts it into an array
    cell, and `mapfile -t A < <(ls *.sh)` fills one from a pipeline - and
    the execution is `bash "$1"`, `bash $@` or `bash "${A[0]}"`. Each of
    those scored zero while the `for` spelling scored 85.
    """
    bindings: dict[str, list[str]] = {}

    def add(var: str, words: str) -> None:
        patterns = [os.path.basename(w.strip("\"'")) for w in words.split()]
        patterns = [p for p in patterns if p and not p.startswith("-")]
        if patterns:
            bindings.setdefault(var, []).extend(patterns)

    for match in _LOOP_BINDING_RE.finditer(body):
        add(match.group("var"), match.group("words"))
    for match in _SET_POSITIONAL_RE.finditer(body):
        # `$1` through `$9`, `$@` and `$*` all name what `set --` bound.
        for name in _POSITIONAL_NAMES:
            add(name, match.group("words"))
    for match in _ARRAY_BINDING_RE.finditer(body):
        if match.group("mvar"):
            add(match.group("mvar"), match.group("mwords"))
        elif match.group("avar"):
            add(match.group("avar"), match.group("awords"))
    return bindings


def _matches_committed(base: str, manifest_basenames) -> bool:
    """True when *base* names a committed file, literally or as a pattern.

    `bash r$i.sh` inside a loop and `bash "$f"` after `for f in *.sh` name a
    *set* of committed files rather than one, so an equality test found
    nothing.  A variable stands for an unknown run of characters exactly as
    a `*` does, and both become one wildcard here.
    """
    if base in manifest_basenames:
        return True
    if not ("$" in base or "*" in base or "?" in base):
        return False
    pattern = re.sub(r"\$\{?\w+\}?", "*", base)
    # A pattern with nothing but a wildcard names every file, which is not
    # a claim about any of them.
    if pattern.strip("*") in ("", "."):
        return False
    return any(fnmatch.fnmatchcase(name, pattern) for name in manifest_basenames)


def _committed_execution_findings(diff_text, tree_manifest, add, current_text=None) -> None:
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
    scopes = ScopeResolver(lines, _recipe_lines(current_text))
    source_basenames = _declared_source_basenames(diff_text)
    heredoc_body = _heredoc_body_indices(lines)
    manifest_basenames = (
        None if tree_manifest is None
        else {os.path.basename(name.rstrip("/")) for name, _ in tree_manifest}
    )

    written_by_fn: dict[str, set[str]] = {}
    bindings_by_fn: dict[str, dict[str, list[str]]] = {}
    for i, line in enumerate(lines):
        fn = scopes.within(i, _SCOPE_FUNCTIONS)
        if not line.startswith("+") or fn is None:
            continue
        if i in heredoc_body:
            continue
        body = _strip_comment(line[1:])

        written = written_by_fn.setdefault(fn, set())
        for _kind, wpath in _collect_writes(body, fn):
            if wpath:
                written.add(os.path.basename(wpath))

        # A build tool names no file on the command line, so no execution
        # pattern sees one - but `make` runs whatever is in the Makefile,
        # and if that Makefile was committed to the *AUR* repository rather
        # than arriving in the declared tarball, `make` is executing the
        # maintainer's code with no checksum over it and no source= entry
        # naming it.  `make` being an ordinary command is why it was exempt;
        # the question here is not the command but the file it reads.
        implicit = _implicit_build_input(body, manifest_basenames)
        if implicit and implicit not in source_basenames and implicit not in written:
            add("R136", "Committed File Executed Without Declaration", "HIGH",
                "execution",
                f"{fn}() runs a build tool over repo-committed {implicit}, "
                "which is not declared in source=()",
                line=_find_line(diff_text, body.strip()[:60]),
                position=fn, path=implicit)
            return

        # Accumulated per scope, not per line: `set -- "$srcdir"/*.sh` and
        # `bash "$1"` are two statements, and a binding computed on the
        # execution's own line can only ever see a one-liner.
        for var, patterns in _loop_bindings(body).items():
            bindings_by_fn.setdefault(fn, {}).setdefault(var, []).extend(patterns)
        bindings = bindings_by_fn.get(fn, {})
        for m in _EXECUTION_RE.finditer(body):
            raw = next((g for g in m.groups() if g), None)
            if not raw:
                continue
            path = _norm_path(raw)
            base = os.path.basename(path)
            # A bare loop variable names whatever the loop iterates.
            bare = re.fullmatch(
                r"\$\{?(\w+|[@*1-9])\}?"          # $f, ${f}, $1, $@
                r"|\$\{(\w+)\[[^\]]*\]\}",       # ${A[0]}, ${A[@]}
                base,
            )
            name = (bare.group(1) or bare.group(2)) if bare else None
            if name and name in bindings:
                candidates = bindings[name]
            else:
                candidates = [base]
            base = next(
                (c for c in candidates
                 if manifest_basenames is not None
                 and _matches_committed(c, manifest_basenames)),
                base,
            )
            if not base or base in source_basenames:
                continue
            # The benign-artifact exemption says "this is the project's own
            # build flow": a `configure` generated by autotools inside the
            # extracted tarball is ordinary.  It stops being that claim when
            # the file is committed to the *AUR* repository and named in no
            # `source=()` - then `./configure` runs the maintainer's script,
            # and the exemption was reading the filename instead of asking
            # where the file came from.
            committed_and_undeclared = (
                manifest_basenames is not None
                and _matches_committed(base, manifest_basenames)
                and not raw.strip().strip('"\'').startswith("/")
            )
            if base in _R124_BENIGN_EXEC and not committed_and_undeclared:
                continue
            if base in written:
                continue
            committed = (
                manifest_basenames is not None
                and _matches_committed(base, manifest_basenames)
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


# ---------------------------------------------------------------------------
# R146 - a committed companion file carries a fetch-execute payload
# ---------------------------------------------------------------------------
#
# A `.service` whose `ExecStart=` pipes a download into a shell, or a
# `.patch` whose added lines do, is the payload - and until now nothing read
# it. The diff shows the recipe staging or applying the file, which is
# ordinary packaging and scored as such; the bytes that matter live in a
# file the diff does not touch.
#
# That split is available to an attacker as a schedule: commit the unit in
# one push, where it is a file nobody runs, and add the `install` line in a
# later one, where the reviewer sees a single unremarkable line. Neither
# push contains an attack. Both together do.
#
# The rule reads the committed file instead of inferring from the recipe.
# What it looks for is deliberately narrow - a network fetch whose output
# reaches an executor - because that is not something a unit file, a desktop
# entry or a udev rule in a package repository does for a legitimate reason.
_COMMITTED_PAYLOAD_RE = re.compile(
    r"(?:" + _NETWORK_CLIENT + r")[^\n]{0,400}?\|\s*"
    r"(?:" + _EXEC_WRAPPER + r")?(?:/(?:usr/)?bin/)?(?:" + _SCRIPT_EXECUTOR + r")\b"
    r"|(?:" + _SCRIPT_EXECUTOR + r")\s+-c\s+[\"']?\$\([^\n]{0,200}?"
    r"(?:" + _NETWORK_CLIENT + r")",
    re.IGNORECASE,
)

#: Only the file kinds a recipe ships or applies. A payload in a committed
#: `README` is text; in a unit the machine installs, it runs.
_COMMITTED_CARRIER_RE = re.compile(
    r"\.(?:service|socket|timer|path|mount|automount|target|desktop"
    r"|rules|conf|cfg|ini|install|hook|patch|diff)\Z"
    # Build manifests belong here for the same reason unit files do: the
    # engine runs what they say, and a committed one is shipped rather
    # than generated. X020 claims the recipe *writing* a manifest and W004
    # the recipe *pointing an engine at* one; this is the third case, a
    # manifest that has been sitting in the repository all along.
    #
    # `make` spells its variables `$(srcdir)`, with parentheses, so an
    # ordinary Makefile does not look like a build-only path to
    # `_BUILD_ONLY_PATH_RE` - which wants `$srcdir` or `${srcdir}`.
    r"|(?:\A|/)(?:build\.ninja|Makefile|makefile|GNUmakefile|BUILD(?:\.bazel)?"
    r"|WORKSPACE|meson\.build|CMakeLists\.txt|SConstruct)\Z"
    r"|\.(?:mk|ninja|bazel|bzl|cmake)\Z",
    re.IGNORECASE,
)


def _committed_payload_finding(name: str, head: bytes) -> dict | None:
    """R146 for one committed companion, or ``None``."""
    if not _COMMITTED_CARRIER_RE.search(name.rstrip("/")):
        return None
    try:
        text = head.decode("utf-8", errors="replace")
    except Exception:
        return None
    # A patch is read by its *added* lines: a hunk that removes a
    # `curl … | sh` is the opposite of this rule's subject.
    if name.lower().endswith((".patch", ".diff")):
        text = "\n".join(
            ln[1:] for ln in split_lines(text)
            if ln.startswith("+") and not ln.startswith("+++")
        )
    m = _COMMITTED_PAYLOAD_RE.search(text)
    if not m:
        return None
    return stamp({
        "rule_id": "R146",
        "name": "Committed Companion Carries A Fetch-Execute Payload",
        "severity": "CRITICAL", "category": "delivery",
        "match": f"{name} downloads and runs code: {m.group(0).strip()[:80]}",
        "file": name,
        "params": {"path": name, "body": m.group(0).strip()[:120]},
    })


#: Fields that describe rather than run.
#:
#: The first version of this rule asked "is this an exec directive" and
#: carried a key list to answer it. That list cost 12 of 30 audited
#: verticals: `System(...)` in an Asterisk dialplan, `binary=` in an
#: rsyslog action, `load_module` in nginx, `NOTIFYCMD` in upsmon,
#: `DisplayCommand` in sddm, `HOOKS=()` in mkinitcpio, a bare `source` in
#: a shell rc, and a mailcap entry that has no key at all. Every one is a
#: different word for "run this", and the next daemon has another.
#:
#: So the question is inverted, the way X016 inverts the executor list. A
#: shipped file that names a build directory is broken on arrival whatever
#: field holds the path - the file points at somewhere that will not exist.
#: What genuinely does not matter is a field that only *describes*, and
#: those are few and stable: a `.desktop` `Comment=` mentioning the build
#: tree is untidy, not a command aimed at nothing.
_DESCRIPTIVE_FIELD_RE = re.compile(
    r"\A\s*(?:#|;|//)"                      # a comment
    r"|\A\s*(?:Comment|Description|Name|GenericName|Icon|Keywords|Categories"
    r"|Version|Author|Maintainer|Homepage|URL|Documentation|Summary|License"
    r"|X-[\w-]+)\s*=",
    re.IGNORECASE,
)


def _committed_build_path_finding(name: str, head: bytes) -> dict | None:
    """R149 for one committed companion, or ``None``.

    The symmetric half of R145. That rule reads content the recipe
    *generates* into `$pkgdir`; this one reads content the recipe
    *committed* and then ships. The observable is identical and so is the
    reasoning: `$srcdir`, `$startdir` and `$PWD` exist only while the
    package is being built, so a shipped file naming one is either broken
    on arrival or aimed at a directory whoever wrote it expects to control
    when it is read.

    The value has to sit in a directive that runs something. A `.desktop`
    with a `Comment=` mentioning a build path is a cosmetic mistake; an
    `Exec=` naming one is a command pointed at nothing.
    """
    if not _COMMITTED_CARRIER_RE.search(name.rstrip("/")):
        return None
    try:
        text = head.decode("utf-8", errors="replace")
    except Exception:
        return None
    if name.lower().endswith((".patch", ".diff")):
        text = "\n".join(
            ln[1:] for ln in split_lines(text)
            if ln.startswith("+") and not ln.startswith("+++")
        )
    for line in split_lines(text):
        named = _BUILD_ONLY_PATH_RE.search(line)
        if named is None:
            continue
        if _DESCRIPTIVE_FIELD_RE.search(line):
            continue
        return stamp({
            "rule_id": "R149",
            "name": "Committed Config Points At A Build-Only Path",
            "severity": "HIGH", "category": "persistence",
            "match": f"{name} runs {named.group(0)}, a directory that exists "
                     "only while the package is built",
            "file": name,
            "params": {"path": name, "named": named.group(0),
                       "body": line.strip()[:120]},
        })
    return None


def scan_tree_manifest(files, source_urls, package_name: str = "") -> list[dict]:
    """R118 and R146 findings for a repository file manifest.

    *files* is ``[(path, head_bytes)]`` from a git tree or a snapshot
    tarball.  A committed ELF file that is not a declared ``source=``
    filename and not a test fixture fires R118; a committed unit, rule,
    hook or patch whose content fetches and runs code fires R146.
    """
    source_basenames = {_source_basename(u) for u in source_urls if _source_basename(u)}
    findings: list[dict] = []
    for name, head in files:
        if _is_test_fixture(name, os.path.basename(name.rstrip("/"))):
            continue
        payload = (_committed_payload_finding(name, head)
                   or _committed_build_path_finding(name, head))
        if payload is not None:
            findings.append(payload)
            break
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
# R145 - a packaged file names a path that only exists during the build
# ---------------------------------------------------------------------------
#
# The audit's largest silent family is a configuration file the recipe
# *generates* into the package root whose exec slot names a script: an i3
# `bindsym … exec`, a polybar `exec =`, a udev `RUN+=`, an acme
# `RELOADCMD=`, a mutt `macro … !bash`. Every rule that looks for execution
# reads the recipe's own commands, and none of these lines is a command the
# recipe runs - they are text, and what runs them is the user's session,
# later, on a different machine.
#
# What separates them from the ordinary case is not the exec slot, which is
# what those files are *for*: a `.desktop` with `Exec=/usr/bin/p` and a
# `bindsym $mod+d exec dmenu_run` are exactly right. It is *which path* the
# slot names. `$srcdir`, `$startdir`, `$PWD` and `$BUILDDIR` exist only
# while the package is being built, in a directory pacman never ships and
# the user does not have. A shipped file naming one is either broken on
# arrival - it points at nothing - or it is aimed at a directory the writer
# expects to control at the moment it is read.
#
# Neither reading is packaging. The rule is therefore about the *pairing*
# of a write into `$pkgdir` with content naming a build-only path, which is
# why it cannot be a line pattern: `install -Dm755 "$srcdir/x"
# "$pkgdir/usr/bin/x"` names both on one line and is the single most common
# line in the ecosystem. The distinction is that there `$srcdir` is an
# argument to a copy, and here it is inside the bytes being written.
_BUILD_ONLY_PATH_RE = re.compile(
    r"\$\{?(?:srcdir|startdir|PWD|BUILDDIR|pkgdir)\}?",
)

#: Verbs that write their *arguments* as file content. `install`, `cp` and
#: `mv` are deliberately absent: their arguments are paths to copy from, and
#: naming the build directory there is how packaging works.
_CONTENT_WRITE_RE = re.compile(
    r"(?:\A\s*|[;&|(]\s*|&&\s*)(?:" + _EXEC_WRAPPER + r")?"
    r"(?:printf|echo|tee|cat)\b",
)

#: The write lands in the package root.
_PKGDIR_TARGET_RE = re.compile(r"\$\{?pkgdir\}?")


def _packaged_content_findings(diff_text, config, add, current_text=None) -> None:
    """Content written into ``$pkgdir`` naming a build-only path (R145)."""
    lines = resolve_added_lines(diff_text)
    scopes = ScopeResolver(lines, _recipe_lines(current_text))

    # The heredoc regions are tracked here rather than taken from
    # `_heredoc_body_indices`, which answers a different question: it says
    # whether a body should be read as *commands*, and a body bound for
    # `udev/rules.d` is deliberately read that way. This rule needs the
    # region either way, because what it reads is the text being shipped.
    open_target = ""
    delims: list[str] = []
    for i, line in enumerate(lines):
        if not line.startswith("+"):
            continue
        raw = line[1:]
        stripped = raw.strip()
        if delims and stripped == delims[-1]:
            delims.pop()
            if not delims:
                open_target = ""
            continue
        if delims:
            if open_target and _BUILD_ONLY_PATH_RE.search(raw):
                _report_packaged_path(add, diff_text, scopes, i, raw, open_target)
                return
            continue
        if scopes.within(i, _SCOPE_FUNCTIONS) is None:
            continue
        body = _strip_comment(raw)
        opener = _HEREDOC_OPEN_RE.search(body)
        if opener and opener.group(2):
            delims.append(opener.group(2))
            open_target = body if _PKGDIR_TARGET_RE.search(body) else ""
            continue
        # The single-line form: everything left of the redirect is content,
        # everything right of it is the destination. Splitting there is what
        # keeps `install "$srcdir/x" "$pkgdir/…"` out of the rule - it has
        # no redirect, so there is no content half to read.
        cut = body.rfind(">")
        if cut < 0:
            continue
        content, target = body[:cut], body[cut:]
        if not _PKGDIR_TARGET_RE.search(target):
            continue
        if not _CONTENT_WRITE_RE.search(content):
            continue
        if _BUILD_ONLY_PATH_RE.search(content):
            _report_packaged_path(add, diff_text, scopes, i, body, target)
            return


def _report_packaged_path(add, diff_text, scopes, index, body, target) -> None:
    named = _BUILD_ONLY_PATH_RE.search(body)
    add("R145", "Packaged File Names A Build-Only Path", "HIGH", "persistence",
        f"a file staged into the package names {named.group(0)}, "
        "a directory that exists only while the package is built",
        line=_find_line(diff_text, body.strip()),
        path=named.group(0),
        body=body.strip()[:120])


# ---------------------------------------------------------------------------
# W001 - code runs that this analysis never read
# ---------------------------------------------------------------------------
#
# The W series is not a risk claim. It reports something the analysis
# *could not verify*, on a surface too common to price - the same act as a
# coverage gap, attached to a line instead of to the run.
#
# This one is the E7 boundary. A recipe unpacks a declared, checksummed
# archive and runs a script from inside it. The checksum proves the bytes
# arrived unaltered; it says nothing about what they do, and this analysis
# never reads them. R138 claims the case where the executed file is itself
# a declared source, and R136 the case where it is committed. What is left
# is code that runs and that nobody looked at.
#
# It carries no weight, and it must not. Pricing it would put a finding on
# a large share of the ecosystem, because reaching into an unpacked tree is
# what building a package *is*. Silence was the other option, and silence
# is what the boundary documentation had to describe as something
# TrustSight cannot see. It can see it. It simply must not price it.
#
# The pattern is its own rather than shared with R138, because R138's
# capture is allowed to be loose: a token that is not a path cannot equal a
# declared basename, so `python3 -m build` capturing `-m` costs that rule
# nothing. A rule that *prints* the path to a reader has no such luxury,
# and reusing the loose capture produced evidence like `g` and
# `log\.txt|/var/log/ventoy.log|g` from the innards of a `sed` script.
_W001_RE = re.compile(
    # Two shapes, and no third. An interpreter naming a file, or a `./`
    # invocation - both are unambiguously "run this". A bare path-shaped
    # word at a command position is not: that reading matched the MIME
    # type in `x-scheme-handler/orcaslicer`, the `usr/bin/env` of a
    # shebang line and the innards of `sed 's/-/./g'`.
    _CMD_START
    + r"(?:"
    # `/bin/sh` and `/usr/bin/python3` are the same executors spelled by
    # path, and a sandbox wrapper almost always spells them that way:
    # `chroot "$srcdir/root" /bin/sh /x.sh` ran an unread script and
    # matched nothing, because the arm wanted a bare word.
    # The whole command may be one quoted argument: `xterm -e "bash
    # $PWD/x.sh"` puts the executor inside the quotes, not the path.
    r"[\"']?(?:/(?:usr/)?bin/)?"
    r"(?:bash|sh|zsh|dash|ksh|python[23]?|perl|ruby|node|php|lua)\s+"
        # `$PWD` is the build directory under another name, and a recipe that
    # runs `$PWD/x.sh` is running tree content exactly as `$srcdir/x.sh`
    # does.
    r"[\"']?((?:\$\{?(?:srcdir|startdir|PWD|BUILDDIR)\}?/|\./|[\w.-]+/)[\w./-]+"
    r"|[\w.-]+\.(?:sh|bash|py|pl|rb|js|lua|php))"
    r"|\./([\w.-]+(?:/[\w.-]+)*)"
    # A sandbox wrapper establishes a new root, so an *absolute* path after
    # it is a path inside that root - which is tree content, not a system
    # file. `chroot "$srcdir/root" /bin/sh /x.sh` runs a script from the
    # unpacked tree and names it `/x.sh`; without this arm the leading
    # slash made it look like `/usr/bin/foo.sh`, which is not this rule's
    # subject at all.
    r"|(?<=\s)(/[\w.-]+(?:/[\w.-]+)*\.(?:sh|bash|py|pl|rb|js|lua|php))"
    r")[\"']?(?:\s|;|$)",
    re.IGNORECASE,
)


#: Wrappers that give the command a different filesystem root.
_SANDBOX_WRAPPER_RE = re.compile(
    r"\b(?:chroot|bwrap|firejail|nsjail|unshare|proot|fakechroot"
    r"|systemd-nspawn|toolbox|distrobox-enter)\b",
    re.IGNORECASE,
)


def _unread_execution_findings(diff_text, config, add, tree_manifest=None,
                               current_text=None) -> None:
    """Code from the unpacked tree runs and nobody read it (W001)."""
    lines = resolve_added_lines(diff_text)
    scopes = ScopeResolver(lines, _recipe_lines(current_text))
    source_basenames = _declared_source_basenames(diff_text)
    committed = {os.path.basename(name.rstrip("/"))
                 for name, _head in (tree_manifest or ())}
    heredoc_body = _heredoc_body_indices(lines)

    for i, line in enumerate(lines):
        fn = scopes.within(i, _BUILD_FUNCTIONS)
        if not line.startswith("+") or fn is None or i in heredoc_body:
            continue
        body = _strip_comment(line[1:])
        m = _W001_RE.search(body)
        if not m:
            continue
        raw = m.group(1) or m.group(2) or m.group(3)
        if not raw:
            continue
        # The absolute-path arm is only meaningful under a new root.
        if raw.startswith("/") and not _SANDBOX_WRAPPER_RE.search(body):
            continue
        if _not_a_path(raw):
            continue
        base = os.path.basename(_norm_path(raw))
        if not base or base in _R124_BENIGN_EXEC:
            continue
        # Anything already claimed by a scoring rule is not this rule's
        # subject: W001 is what is left when nothing else could speak.
        if base in source_basenames or base in committed:
            continue
        # R150 - the same act, in the one function where it is not
        # ordinary. `package()` stages files into `$pkgdir`; it is not
        # where software gets built, and its output *is* the package.
        # Running an unaudited script there is a different act from
        # running one in `build()`, and the corpus agrees: of the three
        # benign diffs that reach this line, two are in `build()` and one
        # in `prepare()`, and none is in `package()`.
        #
        # That is the split the W series needs. W001 keeps weight 0 over
        # the surface where the behaviour is ordinary, and the subset that
        # is not ordinary is scored rather than merely reported.
        if fn in _PACKAGING_FUNCTIONS:
            add("R150", "Unread Script Executed During Packaging", "HIGH",
                "execution",
                f"{fn}() runs {raw}, whose content was never read, while "
                "staging the files that become the package",
                line=_find_line(diff_text, raw[:60]), position=fn, path=raw)
            return
        add("W001", "Executes Code This Analysis Did Not Read", "INFO",
            "unverifiable",
            f"{fn}() runs {raw}, which is neither declared in source=() nor "
            f"committed to this repository, so its content was never read",
            line=_find_line(diff_text, raw[:60]), position=fn, path=raw)
        return


# ---------------------------------------------------------------------------
# W002 - a registry chooses what the build runs
# ---------------------------------------------------------------------------
#
# `npm install`, `pip install -r`, `cargo fetch`, `go mod download`: the
# recipe names a *set* of packages and a registry decides which bytes
# satisfy it, at build time, after review. No checksum in the recipe covers
# them, and the resolved versions are not in the analysed text.
#
# The run already says this once, as the `unpinned_build_deps` coverage
# gap. What the gap cannot say is *where*: a reader told the recipe
# resolves dependencies still has to find the line. This is the same fact
# with a line number on it, which is the whole difference between a
# property of the analysis and a property of the recipe.
#
# It scores nothing for the same reason the gap does not: resolving
# dependencies is how most language ecosystems build, and B10 forbids a gap
# adding points.


# ---------------------------------------------------------------------------
# W003 - a patch this analysis did not read
# ---------------------------------------------------------------------------
#
# `patch -Np1 -i "$srcdir/fix.patch"` edits the source before it is built,
# and the edit is whatever the patch says. When the patch is *committed*,
# R146 reads it and claims a fetch-execute payload in its added lines. When
# it is a declared remote source, the bytes are behind a checksum this tool
# never downloads - the same sealed tin as the tarball, applied to code
# that was about to be compiled.
#
# The distinction from the tarball case is worth stating: a tarball is
# upstream's own code, and a patch is a *change to it* that the packager
# chose. That makes it more interesting to a reader, not less - and still
# unreadable here.
_PATCH_APPLY_RE = re.compile(
    _CMD_START + r"(?:patch|git\s+apply)\b[^\n;&|]*?[\"']?"
    r"((?:\$\{?(?:srcdir|startdir)\}?/|\./)?[\w./-]+"
    r"\.(?:patch|diff))[\"']?",
    re.IGNORECASE,
)


#: A build engine pointed at a manifest the recipe names explicitly.
#:
#: Anchored on an *explicit* `-f`/`--file` argument on purpose. A bare
#: `make` or `ninja -C build` also runs a manifest nobody read, and that is
#: most of the ecosystem - reporting it would say nothing at all. Naming a
#: particular file is a choice, and the choice is the observable.
_MANIFEST_ARG_RE = re.compile(
    r"(?:\A\s*|[;&|(]\s*|&&\s*)(?:" + _EXEC_WRAPPER + r")?"
    r"(?:g?make|ninja|samu|bazel|buck2?|pants|scons|waf|just|task)\b"
    r"[^\n;&|]*?\s-(?:f|-file|-makefile)[=\s]+[\"']?"
    r"([^\"'\s;&|]+)",
    re.IGNORECASE,
)


def _unread_manifest_findings(diff_text, add, tree_manifest=None,
                              current_text=None) -> None:
    """A build engine run against steps nobody read (W004).

    The counterpart to X020. That rule claims the recipe *writing* a
    manifest; this one reports the recipe *pointing an engine at* one whose
    content is neither declared nor committed. R138 already claims the case
    where the named file is a declared source - there the bytes are at
    least checksum-pinned - so what is left is a manifest that arrived
    inside an archive, and whose build steps are therefore chosen by
    something this analysis never saw.
    """
    lines = resolve_added_lines(diff_text)
    scopes = ScopeResolver(lines, _recipe_lines(current_text))
    source_basenames = _declared_source_basenames(diff_text)
    committed = {os.path.basename(name.rstrip("/"))
                 for name, _head in (tree_manifest or ())}
    heredoc_body = _heredoc_body_indices(lines)

    for i, line in enumerate(lines):
        fn = scopes.within(i, _BUILD_FUNCTIONS)
        if not line.startswith("+") or fn is None or i in heredoc_body:
            continue
        body = _strip_comment(line[1:])
        m = _MANIFEST_ARG_RE.search(body)
        if not m:
            continue
        raw = m.group(1)
        if _not_a_path(raw):
            continue
        base = os.path.basename(_norm_path(raw))
        if not base or base in source_basenames or base in committed:
            continue
        add("W004", "Build Engine Runs A Manifest This Analysis Did Not Read",
            "INFO", "unverifiable",
            f"{fn}() points a build engine at {raw}, whose steps are neither "
            "declared in source=() nor committed to this repository",
            line=_find_line(diff_text, raw[:60]), position=fn, path=raw)
        return


#: Targets whose recipe every build system defines the same way.
#:
#: `make install` says what it does. `make dist-hooks` names a recipe that
#: exists only in this project's Makefile - a file that arrived inside the
#: archive and that this analysis never read.
_STANDARD_TARGETS = frozenset({
    "all", "install", "install-strip", "clean", "distclean", "mostlyclean",
    "check", "test", "tests", "dist", "world", "modules", "modules_install",
    "defconfig", "menuconfig", "oldconfig", "prepare", "build", "docs",
    "doc", "man", "html", "info", "uninstall", "release", "debug",
})

_MAKE_TARGET_RE = re.compile(
    r"(?:\A\s*|[;&|(]\s*|&&\s*)(?:" + _EXEC_WRAPPER + r")?"
    r"(?:g?make|ninja|samu)\b([^\n;&|#]*)",
    re.IGNORECASE,
)


def _unread_target_findings(diff_text, add, tree_manifest=None,
                            current_text=None) -> None:
    """A build target whose recipe nobody read (W005).

    The third of the manifest trio. X020 claims the recipe *writing* the
    steps, W004 the recipe naming a manifest file, and this one the recipe
    naming a *target* inside a manifest it did not name - the implicit
    `Makefile` that came with the archive.

    Standard targets stand down. `make install` is a contract every build
    system honours and says what it does; `make dist-hooks` names a recipe
    that exists only in this project's Makefile.
    """
    lines = resolve_added_lines(diff_text)
    scopes = ScopeResolver(lines, _recipe_lines(current_text))
    committed = {os.path.basename(name.rstrip("/"))
                 for name, _head in (tree_manifest or ())}
    if committed & {"Makefile", "makefile", "GNUmakefile", "build.ninja"}:
        return
    heredoc_body = _heredoc_body_indices(lines)

    for i, line in enumerate(lines):
        fn = scopes.within(i, _BUILD_FUNCTIONS)
        if not line.startswith("+") or fn is None or i in heredoc_body:
            continue
        body = _strip_comment(line[1:])
        m = _MAKE_TARGET_RE.search(body)
        if not m:
            continue
        for token in m.group(1).split():
            # Flags and variable assignments are not targets.
            if token.startswith("-") or "=" in token:
                continue
            if token.lower() in _STANDARD_TARGETS:
                continue
            if _not_a_path(token) or "/" in token:
                continue
            add("W005", "Build Runs A Target Whose Recipe Was Not Read",
                "INFO", "unverifiable",
                f"{fn}() runs the {token!r} target, whose recipe is in a "
                "build file that arrived with the source and was never read",
                line=_find_line(diff_text, body.strip()[:50]),
                position=fn, target=token)
            return


#: Tools that build what the machine boots, or the contents of an image.
#:
#: `dracut --include "$srcdir/x" /x` injects a path from the build tree
#: into the initramfs, which runs before userspace exists and before any
#: filesystem the user can inspect is mounted. `grub-mkconfig` writes the
#: boot menu. `guestfish`/`virt-customize` edit a disk image's contents.
#:
#: A package may legitimately ship kernel modules or a bootloader, and
#: those are `install`ed like any other file. *Generating* boot material
#: during a build is different: the result captures the builder's machine,
#: and any path from the source tree that goes into it is code that will
#: run at the earliest moment there is.
#:
#: None of these appear in the benign corpus at all.
_BOOT_ARTIFACT_RE = re.compile(
    r"(?:\A\s*|[;&|(]\s*|&&\s*)(?:" + _EXEC_WRAPPER + r")?"
    r"(?:dracut|mkinitcpio|update-initramfs|grub2?-mkconfig|grub2?-install"
    r"|guestfish|virt-customize|virt-sysprep|bootctl)\b([^\n;&|]*)",
    re.IGNORECASE,
)


def _boot_artifact_findings(diff_text, add, current_text=None) -> None:
    """Boot or image material built from the source tree (R151)."""
    lines = resolve_added_lines(diff_text)
    scopes = ScopeResolver(lines, _recipe_lines(current_text))
    heredoc_body = _heredoc_body_indices(lines)

    for i, line in enumerate(lines):
        fn = scopes.within(i, _SCOPE_FUNCTIONS)
        if not line.startswith("+") or fn is None or i in heredoc_body:
            continue
        body = _strip_comment(line[1:])
        m = _BOOT_ARTIFACT_RE.search(body)
        if not m:
            continue
        named = _BUILD_ONLY_PATH_RE.search(m.group(1))
        if named is None:
            continue
        add("R151", "Boot Or Image Artifact Built From The Source Tree",
            "HIGH", "persistence",
            f"{fn}() builds boot or image material naming {named.group(0)}, "
            "so content from the build tree runs before userspace",
            line=_find_line(diff_text, body.strip()[:50]),
            position=fn, body=body.strip()[:120])
        return


#: A redirect to a file descriptor, not a file. `>&2` is how a recipe
#: writes a diagnostic, and two of this rule's three benign matches were
#: exactly that - an error message that happens to mention `$srcdir`.
_FD_REDIRECT_RE = re.compile(r"\A&\d")

#: The quoted arguments of a write - the text that becomes the file.
_QUOTED_SEGMENT_RE = re.compile(r"\"([^\"]*)\"|'([^']*)'")

#: `cat "$srcdir/a" | tee "$srcdir/b"` copies a file. The build path is an
#: argument naming what to read, not content the recipe authored - the
#: same distinction X020 draws between authoring and transforming.
_COPY_SOURCE_RE = re.compile(
    r"(?:\A\s*|[;&|(]\s*|&&\s*)cat\s+[\"']?\$\{?(?:srcdir|startdir)\}?/")


def _generated_config_findings(diff_text, add, current_text=None) -> None:
    """A generated file whose body names a build-tree path (W006).

    X022 claims this when the recipe goes on to hand the file to a tool.
    Without that second line there is no evidence anything reads it - the
    file may be a build input, a generated `.pc`, a note. What can be said
    is narrower and still worth saying: the recipe wrote a file whose
    content names a directory that exists only during the build, and
    whether anything runs it is not visible here.

    That is a W and not a rule with weight, because the claim stops at
    "unreadable", and the same predicate R149 uses decides it: a line that
    names a build-only path and is not a field that merely describes.
    """
    lines = resolve_added_lines(diff_text)
    scopes = ScopeResolver(lines, _recipe_lines(current_text))
    heredoc_body = _heredoc_body_indices(lines)

    for i, line in enumerate(lines):
        fn = scopes.within(i, _SCOPE_FUNCTIONS)
        if not line.startswith("+") or fn is None or i in heredoc_body:
            continue
        body = _strip_comment(line[1:])
        if not _CONTENT_WRITE_RE.search(body) or _COPY_SOURCE_RE.search(body):
            continue
        cut = body.rfind(">")
        if cut < 0 or _FD_REDIRECT_RE.match(body[cut + 1:]):
            continue
        content, target = body[:cut], body[cut + 1:]
        if _PKGDIR_TARGET_RE.search(target):
            continue          # R145 owns anything staged into the package.
        named = _BUILD_ONLY_PATH_RE.search(content)
        if named is None:
            continue
        # The descriptive test reads the *written text*, not the shell
        # line. `printf "Comment=built in $srcdir\n" > f` starts with
        # `printf`, so anchoring on the line missed the field entirely and
        # claimed a tidy-up note as a config directive.
        if any(_DESCRIPTIVE_FIELD_RE.search(a or b)
               for a, b in _QUOTED_SEGMENT_RE.findall(content)):
            continue
        add("W006", "Generated File Names A Build-Only Path", "INFO",
            "unverifiable",
            f"{fn}() writes a file whose content names {named.group(0)}; "
            "whether anything reads it is not visible here",
            line=_find_line(diff_text, body.strip()[:50]),
            position=fn, path=named.group(0))
        return


def _unverifiable_findings(diff_text, config, add, tree_manifest=None,
                           current_text=None) -> None:
    """The W series: what ran, or will run, that nobody here read."""
    _unread_execution_findings(diff_text, config, add,
                               tree_manifest=tree_manifest,
                               current_text=current_text)

    from .buildfetch import registry_resolutions

    resolutions = registry_resolutions(diff_text)
    if resolutions:
        function, command = resolutions[0]
        others = len(resolutions) - 1
        suffix = f" (and {others} more)" if others else ""
        add("W002", "Build Resolves Dependencies From A Registry", "INFO",
            "unverifiable",
            f"{function or 'the recipe'} runs {command.strip()[:60]}, so a "
            "registry chooses at build time which code runs; no checksum "
            f"here covers it{suffix}",
            line=_find_line(diff_text, command.strip()[:50]),
            position=function, command=command.strip()[:80],
            count=len(resolutions))

    _unread_patch_findings(diff_text, add, tree_manifest=tree_manifest,
                           current_text=current_text)
    _unread_manifest_findings(diff_text, add, tree_manifest=tree_manifest,
                              current_text=current_text)
    _unread_target_findings(diff_text, add, tree_manifest=tree_manifest,
                            current_text=current_text)
    _generated_config_findings(diff_text, add, current_text=current_text)


def _unread_patch_findings(diff_text, add, tree_manifest=None,
                           current_text=None) -> None:
    """A patch applied from bytes this analysis never read (W003)."""
    lines = resolve_added_lines(diff_text)
    scopes = ScopeResolver(lines, _recipe_lines(current_text))
    committed = {os.path.basename(name.rstrip("/"))
                 for name, _head in (tree_manifest or ())}
    heredoc_body = _heredoc_body_indices(lines)

    for i, line in enumerate(lines):
        fn = scopes.within(i, _BUILD_FUNCTIONS)
        if not line.startswith("+") or fn is None or i in heredoc_body:
            continue
        body = _strip_comment(line[1:])
        m = _PATCH_APPLY_RE.search(body)
        if not m:
            continue
        raw = m.group(1)
        if _not_a_path(raw):
            continue
        base = os.path.basename(_norm_path(raw))
        # A committed patch is one R146 has already read.
        if not base or base in committed:
            continue
        add("W003", "Applies A Patch This Analysis Did Not Read", "INFO",
            "unverifiable",
            f"{fn}() applies {base}, whose content is not in this repository "
            "and was never read",
            line=_find_line(diff_text, raw[:60]), position=fn, path=raw)
        return


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------


def _delivery_findings(
    diff_text, config, add, tree_manifest=None, current_text=None
) -> None:
    """Run the diff-text Phase 2 rules (R119-R121, R124, R136-R140) through *add*.

    *current_text* is the PKGBUILD as it now stands, used only to build the
    call graph: a helper added by this diff may be called from a ``build()``
    that the hunk does not show.
    """
    _anti_analysis_findings(diff_text, config, add, current_text=current_text)
    _reconstructed_payload_findings(diff_text, config, add)
    _write_execute_findings(diff_text, config, add, current_text=current_text)
    _fetch_then_execute_findings(diff_text, config, add, current_text=current_text)
    _source_file_execution_findings(diff_text, config, add, current_text=current_text)
    _service_binary_findings(diff_text, tree_manifest, add)
    _path_injection_findings(diff_text, tree_manifest, add, current_text=current_text)
    _committed_execution_findings(
        diff_text, tree_manifest, add, current_text=current_text,
    )
    _packaged_content_findings(diff_text, config, add, current_text=current_text)
    _boot_artifact_findings(diff_text, add, current_text=current_text)
    _unverifiable_findings(diff_text, config, add,
                           tree_manifest=tree_manifest,
                           current_text=current_text)
