"""Extracted from delivery.py: _common."""

import fnmatch
import os
import re
import shlex
from ...config import (
    EXEC_WRAPPER as _EXEC_WRAPPER,
    PAYLOAD_PRODUCER as _PAYLOAD_PRODUCER,
    _SUBCOMMAND_OPTS as _SUBCOMMAND_OPTS,
)
from ...coverage import note_stage_failure
from ...diffdoc import parse_diff_lines
from ...expansion import resolve_text
from ...line_lex import (
    _HEREDOC_OPEN_RE,
    _HEREDOC_PIPED_RE,
    _HEREDOC_TO_EXECUTING_CONFIG_RE,
    _HEREDOC_TO_INTERPRETER_RE,
    _PRINTED_HEREDOC_OPENER_RE,
    _heredoc_body_indices,
    _heredoc_body_indices_cached,
    _printed_heredoc_body_indices,
    _printed_heredoc_body_indices_cached,
)
from ...tokenizer import split_lines
from ..build import _CRITICAL_FUNCTIONS, _SCOPE_FUNCTIONS
from ...rules import find_line_in_diff

__all__ = ['_BUILD_FUNCTIONS', '_BUILD_ONLY_PATH_RE', '_BUILD_ROOT_RE', '_CMD_START', '_COPY_WRITE_RE', '_DECODER_WRITE_RE', '_DESCRIPTIVE_FIELD_RE', '_ELF_MAGIC', '_EXECUTION_RE', '_EXEC_PREFIX', '_GENERATION_WRITE_RE', '_H072_BENIGN_EXEC', '_HEREDOC_OPEN_RE', '_HEREDOC_PATH_BEFORE_RE', '_HEREDOC_PIPED_RE', '_HEREDOC_TO_EXECUTING_CONFIG_RE', '_HEREDOC_TO_INTERPRETER_RE', '_IMPLICIT_BUILD_INPUTS', '_INTERPRETER_WRITE_RE', '_MACHO_MAGICS', '_NOT_A_PATH_RE', '_PATCH_APPLY_RE', '_PE_MAGIC', '_PRINTED_HEREDOC_OPENER_RE', '_PRODUCER_REDIRECT_RE', '_SCOPE_FUNCTIONS', '_SHEBANG_MAGIC', '_SRCINFO_SOURCE_RE', '_VCS_SOURCE_RE', '_collect_writes', '_declared_extraction_dirs', '_declared_extraction_dirs_cached', '_declared_source_basenames', '_declared_source_basenames_cached', '_declared_source_entries_cached', '_find_line', '_heredoc_body_indices', '_heredoc_body_indices_cached', '_is_directory_path', '_norm_path', '_not_a_path', '_printed_heredoc_body_indices', '_printed_heredoc_body_indices_cached', '_source_basename']

def _find_line(diff_text: str, fragment: str) -> int | None:
    """Return a 1-based diff line whose added content contains *fragment*."""
    return find_line_in_diff(diff_text, re.escape(fragment[:60]))

def _subst(ent: str, table: dict[str, str]) -> str:
    """Resolve one source entry against the recipe's own variable table."""
    return resolve_text(ent, table)

_ELF_MAGIC = b"\x7fELF"

_SHEBANG_MAGIC = b"#!"

_PE_MAGIC = b"MZ"

_MACHO_MAGICS = frozenset({
    b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe",   # 32-bit MH_MAGIC
    b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe",   # 64-bit MH_MAGIC_64
    b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca",   # fat binary
})

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

_PRODUCER_REDIRECT_RE = re.compile(
    r"(?:" + _PAYLOAD_PRODUCER + r")[^;&|\n]*?>\s*"
    r"((?:\"[^\"]*\"|'[^']*'|[^\s;&|>])+)",
    re.IGNORECASE,
)

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

_DECODER_WRITE_RE = re.compile(
    r"\b(?:openssl|gpg2?|age|base64|base32|basenc|xxd|uudecode|certutil)\b"
    r"[^;&|\n]*?\s-(?:-?out(?:put)?|o)[=\s]+"
    r"((?:\"[^\"]*\"|'[^']*'|[^\s;&|])+)"
    r"|\bdd\b[^;&|\n]*?\bof=((?:\"[^\"]*\"|'[^']*'|[^\s;&|])+)",
    re.IGNORECASE,
)

_COPY_WRITE_RE = re.compile(
    r"\b(?:install|cp|mv|dd)\b[^;&|\n]*?\s(\S+)$",
    re.IGNORECASE,
)

_HEREDOC_PATH_BEFORE_RE = re.compile(
    r"\b(?:cat|tee)\b\s+[^;&|<]*?>\s*(\S+)\s*<<",
    re.IGNORECASE,
)

_EXEC_PREFIX = r"(?:" + _EXEC_WRAPPER + r")*"

_CMD_START = (
    # `(?![;&|{(])` after the separator: a command word cannot begin with
    # another separator, so a run of `;` fails here instead of carrying the
    # whole arm alternation to the next character.  Without it the audit's
    # `;` probe cost every arm a scan per position, which is what leaves
    # `_SOURCE_EXEC_RE` over budget on a slow machine.
    r"(?:\A\s*+|[;&|{(]\s*+(?![;&|{(])|\b(?:do|then|else|elif)\s++)"
    + _EXEC_PREFIX
)

_EXECUTION_RE = re.compile(
    # `_CMD_START` is factored out of the arms that share it rather than
    # repeated per arm.  Repeated, the engine re-matched the separator, the
    # indentation and the whole wrapper alternation once per arm at every
    # position on the line; on a line of `;` that is eight scans per
    # character, and the adversarial audit measured it over budget.  The
    # arms keep their order and their capture numbering, so the match a
    # given line produces is unchanged.
    _CMD_START + r"(?:"
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
    #
    # The interpreter list carries the sinks the harness proved missing:
    # `escript`, `fennel`, `zx`, `guile`, `racket`, `pwsh`, `julia`,
    # `Rscript`, `deno`, `bun`, `elixir`, `ts-node` and the rest run a
    # script file exactly as `bash` does, and H082's pairing saw none of
    # them.  `pwsh -File f` rides the flag run like every other verb.
    r"(?:busybox\s+)?(?:/[\w./-]*/)?(?:bash|sh|zsh|dash|ksh|ash|mksh"
    r"|node|php|lua(?:jit)?|tclsh|fish"
    # `python3 setup.py build` runs the script file exactly as `bash s.sh`
    # does; the flag run already absorbs `-c`/`-m`, and a captured code
    # string only pairs if its basename equals a fetched name.
    r"|python[23]?|perl|ruby"
    r"|escript|fennel|zx|guile|racket|pwsh|julia|Rscript|deno|bun|elixir"
    r"|ts-node|gjs|csi|bb|babashka|clj|janet)"
    r"(?:\s+-{1,2}[A-Za-z-]*)*\s+(?![<>-])"
    # `[^\s;&|<>]+`, not `\S+`: a command may end at a separator, and
    # `bash s.sh; fi` captured `s.sh;` - a path that matches nothing.
    r"(\"[^\"]+\"|'[^']+'|[^\s;&|<>]+)"
    # A shell takes its script from a redirect just as readily as from an
    # argument, and a FIFO makes that a *fetch* it executes:
    #   mkfifo p; curl url > p & ; bash < p
    # No literal `|` for R001 to see and no filename argument for the
    # pattern above, while `curl > p` is already a fetch output H082 tracks.
    # `<(` is process substitution and `<<` a heredoc; neither is this.
    # `-s < f` is the same stdin read with the shell's flag in between; the
    # flag run sits before the redirect so the capture still lands on the
    # file, and the interpreter family reads a script from stdin too.
    r"|(?:bash|sh|zsh|dash|ksh|ash|mksh)"
    r"(?:\s+-{1,2}[A-Za-z-]*)*\s*<\s*(?!\(|<)(\S+)"
    r"|(?:python3?|perl|ruby|node|php|lua(?:jit)?|tclsh|fish|julia"
    r"|Rscript|bun|deno|escript|fennel|zx|guile|racket|pwsh|elixir"
    r"|ts-node|gjs|csi|bb|babashka|clj|janet)"
    r"(?:\s+-{1,2}[A-Za-z-]*)*\s*<\s*(?!\(|<)(\S+)"
    r"|source\s+(\S+)"
    r"|\.\s+(\S+)"
    # `./x` only where a command starts. Unanchored, this arm matched the
    # `./` inside `sed 's|./log\.txt|…|g'` and inside `../x.patch`, and
    # captured whatever followed - harmless for H083, which discards a
    # capture that is not a declared basename, and not harmless at all for
    # a rule that reports the path to a reader.
    r"|\./(\S+)"
    r")"
    # A build-tree path in command position runs without any verb at all:
    # `"$srcdir/s.sh"` is an execution and was read as nothing.  The quotes
    # are optional here because the tokenizer has already removed them by
    # the time this pattern runs - requiring them matched the raw text and
    # nothing else.
    r"|(?:\A\s*+|[;&|]\s*+)[\"']?([$][{]?(?:srcdir|startdir|pkgdir)[}]?/[^\"'\s;&|]+)"
    # An absolute path at a command position, with or without arguments:
    # requiring it to stand alone let `/tmp/.stage2 --install` past the
    # write-then-execute dataflow while `/tmp/.stage2` was caught.
    r"|^\s*(\/[^\s;&|]+)(?=\s|$)"
    r"|" + _CMD_START + r"(?:"
    r"(?:python3?|perl|ruby)(?:\s+-{1,2}[A-Za-z-]*)*\s+(?![<>-])(\S+)"
    # Engines that run a committed record rather than a script argument.
    # `node x.js`, `dotnet run`, `go run .`, `./gradlew build` and `cargo
    # build` each execute code from a file in the tree, and H081's verb
    # list named none of them.
    r"|(?:dotnet\s+(?:run|exec)|go\s+run|deno\s+run)"
    r"(?:\s+-{1,2}[A-Za-z-]*)*\s*(\S*)"
    r"|(?:gcc|g\+\+|clang|cc|rustc)\b\s+[^;&|]*?(?:-o\s+\S+\s+)?(\S+\.(?:c|cc|cpp|rs))\b"
    r")",
    re.IGNORECASE,
)

_H072_BENIGN_EXEC = frozenset({
    "configure", "make", "Makefile", "makefile", "GNUmakefile",
    "config.status",
    "config.log", "config.cache", "config.h", "cmake", "cpack", "ctest",
    "meson", "meson.build", "ninja", "build.ninja", "CMakeCache.txt",
    "CMakeLists.txt",
    # The standard entry points of an unpacked tree. A recipe running
    # `python setup.py build` or `perl Makefile.PL` is doing the one thing
    # the packaging format is for, and naming those as unaudited execution
    # would put a note on most of the ecosystem while saying nothing a
    # reader does not already assume.
    "setup.py", "Makefile.PL", "Build.PL", "autogen.sh", "bootstrap",
    "bootstrap.sh", "waf", "SConstruct", "gradlew",
})

_BUILD_ROOT_RE = re.compile(
    # The quote may close before the slash (`"$srcdir"/stage.sh`), so the
    # optional closing quote sits between the root name and the `/`.
    r"\A[\"']*\$\{?(?:srcdir|startdir|pkgdir|PWD|BUILDDIR)\}?[\"']?/")

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
    p = p.strip()
    # Shell quoting is syntax, never part of the filename: a token may be
    # `"$srcdir"/stage.sh` (quote closes mid-token) or `'$srcdir'/x`.
    p = p.replace('"', "").replace("'", "")
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
    # An unresolved expansion can carry a `#` (`${pkgver##*.}`); splitting on
    # it would cut the path at the expansion instead of the real fragment.
    path = re.sub(r"\$\{[^}]*\}|\$[A-Za-z_][A-Za-z0-9_]*", "", path)
    path = re.split(r"[?#]", path, maxsplit=1)[0]
    base = os.path.basename(path.rstrip("/"))
    return base

_VCS_SOURCE_RE = re.compile(
    r"(?:^|::)(?:git|hg|svn|bzr|fossil)(?:\+|://)", re.IGNORECASE
)

_SRCINFO_SOURCE_RE = re.compile(r"^\s*source(?:_[a-z0-9_]+)?\s*=\s*(\S.*)$")

_CHECKSUM_GROUP_RE = re.compile(
    r"^\s*(b2sums|sha512sums|sha384sums|sha256sums|sha1sums|md5sums|cksums)"
    r"(_[A-Za-z0-9]+)?\s*=\s*\(",
    re.IGNORECASE,
)

#: makepkg's checksum precedence: the first type that is declared wins.
_CHECKSUM_TYPE_ORDER = (
    "b2sums", "sha512sums", "sha384sums", "sha256sums",
    "sha1sums", "md5sums", "cksums",
)


def _unpinned_source_basenames(
    diff_text: str, current_text: str | None = None
) -> frozenset:
    """Declared sources whose checksum is ``SKIP`` (or absent).

    A checksummed download is exactly the bytes the packager pinned, so
    executing it is vetted packaging; the residual risk H083 names is the
    source whose content is unpinned - ``SKIP`` or no checksum array at
    all - where the host decides at fetch time what runs.  pkl-lsp pinned
    ``merge-lsp4j-metadata.py`` with a sha512 and still scored H083.
    """
    from ...differ import _SOURCE_ARRAY_START_RE
    from ...differ._checksums import _checksum_items
    from ...file_kinds import files_at_line, is_srcinfo_file
    from ...tokenizer import variable_table as _variable_table

    text = current_text if current_text is not None else diff_text
    whole_file = current_text is not None
    lines = split_lines(text)
    if whole_file:
        lines = [" " + ln for ln in lines]
    _vars, _arrs = _variable_table(
        [ln[1:] if ln[:1] in ("+", " ") else ln for ln in lines])


    files = files_at_line(lines)
    # suffix -> {"sources": [basename|None], "checksums": {type: [item]}}
    groups: dict[str, dict] = {}
    in_array = False
    kind = ""
    suffix = ""
    ctype = ""

    def _group() -> dict:
        return groups.setdefault(suffix, {"sources": [], "checksums": {}})

    for line in parse_diff_lines(lines).lines:
        if line.raw.startswith(("+++", "---", "@@")):
            continue
        if line.side == "remove":
            continue
        body = line.content if line.side == "add" else line.raw
        if not in_array:
            if not whole_file and is_srcinfo_file(files.get(line.index, "")):
                continue  # the PKGBUILD is authoritative for checksums too
            src = _SOURCE_ARRAY_START_RE.match(body)
            chk = _CHECKSUM_GROUP_RE.match(body)
            if not src and not chk:
                continue
            in_array = True
            if src:
                kind = "source"
                suffix = ""
                ctype = ""
                idx = body.find("(")
                body = body[idx + 1:] if idx != -1 else ""
            else:
                m = _CHECKSUM_GROUP_RE.match(body)
                kind = "checksum"
                ctype = m.group(1).lower()
                suffix = (m.group(2) or "").lower()
                idx = body.find("(")
                body = body[idx + 1:] if idx != -1 else ""
        body = body.rstrip()
        if body.lstrip().startswith("#"):
            continue
        if body.endswith("\\") and not body.endswith("\\\\"):
            body = body[:-1]
        if kind == "source":
            try:
                entries = shlex.split(body)
            except ValueError:
                note_stage_failure("source-parse")
                entries = []
            for ent in entries:
                ent = ent.strip().rstrip(")")
                if not ent or ent in ("(", ")"):
                    continue
                if _VCS_SOURCE_RE.search(ent):
                    # VCS sources consume a checksum slot; keep the slot.
                    _group()["sources"].append(None)
                    continue
                ent = _subst(ent, _vars)
                base = (ent.split("::", 1)[0] if "::" in ent
                        else _source_basename(ent))
                _group()["sources"].append(base or None)
        else:
            for item in _checksum_items(body):
                item = item.strip().strip("'\"").strip()
                if item:
                    _group()["checksums"].setdefault(ctype, []).append(item)
        if ")" in body:
            in_array = False

    unpinned: set[str] = set()
    for group in groups.values():
        sources = group["sources"]
        chosen = None
        for ctype in _CHECKSUM_TYPE_ORDER:
            if ctype in group["checksums"]:
                chosen = group["checksums"][ctype]
                break
        for index, base in enumerate(sources):
            if base is None:
                continue
            item = chosen[index] if chosen and index < len(chosen) else ""
            # A digest of one repeated character is a placeholder the packager
            # must replace before the recipe builds: it matches no real
            # download, so the source pins nothing.  H083 treats it like an
            # absent checksum, where a real digest (pkl-lsp's
            # merge-lsp4j-metadata.py) is a pin.
            placeholder = len(item) > 1 and len(set(item)) == 1
            if not item or item.upper() in ("SKIP", "NONE") or placeholder:
                unpinned.add(base)
    return frozenset(unpinned)

def _declared_source_basenames(
    diff_text: str, current_text: str | None = None
) -> set[str]:
    """Filenames that arrive via the declared source array.

    Unlike ``extract_source_array_urls`` (scheme URLs only), this keeps bare
    filenames (`dkms.conf`, `postinst.sh`), honours ``name::url`` renames,
    and reads the PKGBUILD ``source=(...)`` form.  The per-line
    ``source = value`` spelling is accepted only inside a ``.SRCINFO``
    section of the diff, where it is a real (generated, resolved)
    declaration; in PKGBUILD text makepkg never reads it, so honouring it
    there let a line the build ignores mark a download as declared.

    Eight rule families ask for this.  *current_text* is the post-diff
    PKGBUILD: the declaration routinely sits outside the changed hunk, so
    reading only the diff found an empty array and then reported a declared
    file as undeclared (H083 missed, H016 false-positived).  The diff is
    still the fallback when no post-diff text is available - the corpus path
    with no stored snapshot.

    The parse is cached on the text.  A fresh ``set`` is returned rather
    than the cached object: the result is documented as a set and handing
    every caller the same one would let a future mutation reach the others.
    """
    if current_text is None:
        return set(_declared_source_basenames_cached(diff_text, False))
    # The whole PKGBUILD supplies the arrays; the diff is still read for a
    # `.SRCINFO` section, whose generated, resolved `source = value` lines
    # name the files the build actually downloads.
    return set(_declared_source_basenames_cached(current_text, True)) | set(
        _declared_source_basenames_cached(diff_text, False)
    )


def _names_a_member_or_pattern(base: str, names) -> bool:
    """True when *base* names a member of *names*, literally or as a pattern.

    `bash r$i.sh` inside a loop and `bash "$f"` after `for f in *.sh` name a
    *set* of files rather than one, so an equality test finds nothing.  A
    variable stands for an unknown run of characters exactly as a `*` does,
    and both become one wildcard here; a pattern that is *only* a wildcard
    names every file, which is not a claim about any of them.

    A full `${...}` expansion becomes the wildcard, including the modifier
    spellings (`${pkgver%.*}`, `${pkgver##*.}`, `${name%-bin}`): reading only
    `${word}` left those literal, so a declared AppImage did not match the
    file the build executes.
    """
    if base in names:
        return True
    if not ("$" in base or "*" in base or "?" in base):
        return False
    pattern = re.sub(r"\$\{[^}]*\}|\$[A-Za-z_][A-Za-z0-9_]*", "*", base)
    if pattern.strip("*") in ("", "."):
        return False
    return any(fnmatch.fnmatchcase(name, pattern) for name in names)


def _matches_declared_source(base: str, declared) -> bool:
    """True when *base* names a file the recipe declared in ``source=()``.

    A ``source=`` entry may be parameterised (``"${pkgname}-x86_64"``) while
    the recipe executes the arch-aware form (``./${pkgname}-${CARCH}``): both
    name the same file, but a plain set-membership test sees two different
    strings.
    """
    return _names_a_member_or_pattern(base, declared)


#: Archive suffixes whose extraction yields a directory under ``$srcdir``.
#: One suffix is stripped, longest-first, case-insensitively.  Single-file
#: compressions (``.gz``/``.xz``/...) and non-extracting formats (``.deb``,
#: ``.AppImage``...) are deliberately absent: mapping them to a directory
#: would suppress H085 on a crafted filename.  Kept consistent with the
#: multi-file subset of ``_ARCHIVE_SUFFIXES`` in longitudinal.py.
_ARCHIVE_EXTRACT_SUFFIXES = (
    ".tar.lz4", ".tar.zstd",
    ".tar.gz", ".tar.bz2", ".tar.xz", ".tar.zst", ".tar.lz",
    ".tbz2", ".tgz", ".tbz", ".txz",
    ".tar", ".zip", ".7z",
)

def _archive_extract_dir(basename: str) -> str | None:
    """Directory *basename* extracts to under ``$srcdir``, or ``None``."""
    lower = basename.lower()
    for suffix in _ARCHIVE_EXTRACT_SUFFIXES:
        if lower.endswith(suffix) and len(basename) > len(suffix):
            return basename[: -len(suffix)]
    return None

_CREATED_SOURCE_DIR_RE = re.compile(
    r"\b(?:mkdir(?:\s+-p)?|install\s+-\S*d\S*)\s+[^\n;]*?"
    r"\$\{?(?:srcdir|startdir)\}?/([A-Za-z0-9._+-]+)",
    re.IGNORECASE,
)


def _created_source_dirs(diff_text: str,
                         current_text: str | None = None) -> frozenset[str]:
    """Directories the recipe itself creates under ``$srcdir``.

    H085's target is a directory the build *did not declare*.  A recipe that
    runs ``mkdir -p "$srcdir/bin"`` and then puts it on PATH has declared the
    directory in the recipe; the executable it later installs there is
    visible to the other rules.  Only names without a path separator count,
    and only ``mkdir``/``install -d`` shapes; a PATH entry naming an
    arbitrary existing build-tree directory still fires.
    """
    text = current_text if current_text is not None else diff_text
    return frozenset(
        match.group(1).strip("\"'").rstrip("/")
        for match in _CREATED_SOURCE_DIR_RE.finditer(text)
        if match.group(1).strip("\"'").rstrip("/")
    )


def _declared_extraction_dirs(
    diff_text: str, current_text: str | None = None
) -> set[str]:
    """Directories the declared sources extract to under ``$srcdir``.

    A declared archive (``zig-x86_64-linux-0.17.0.tar.xz``) legitimately
    contributes its extraction directory to the build tree, so H085 must
    not fire when build() prepends ``$srcdir/<that dir>`` to PATH.  Takes
    the same two-text shape as ``_declared_source_basenames``.

    VCS sources contribute the repository basename minus ``.git``: the
    clone directory is genuinely declared even though VCS entries are
    excluded from ``source_basenames``.  ``noextract=()`` is not consulted
    (the array walk here doesn't parse it); a source listed in both
    ``noextract`` and PATH would still be treated as extracted.
    """
    if current_text is None:
        return set(_declared_extraction_dirs_cached(diff_text, False))
    return set(_declared_extraction_dirs_cached(current_text, True)) | set(
        _declared_extraction_dirs_cached(diff_text, False)
    )

def _declared_source_basenames_cached(text: str, whole_file: bool) -> frozenset[str]:
    return frozenset(
        base for base, is_vcs in _declared_source_entries_cached(text, whole_file)
        if not is_vcs
    )

def _declared_extraction_dirs_cached(text: str, whole_file: bool) -> frozenset[str]:
    dirs: set[str] = set()
    for base, is_vcs in _declared_source_entries_cached(text, whole_file):
        if is_vcs:
            # The clone lands in a directory named after the repository.
            dirs.add(base[:-4] if base.lower().endswith(".git") else base)
            continue
        extracted = _archive_extract_dir(base)
        if extracted:
            dirs.add(extracted)
    return frozenset(dirs)

def _declared_source_entries_cached(text: str, whole_file: bool) -> frozenset[tuple[str, bool]]:
    """Walk the declared ``source=()`` entries once; ``(local name, is_vcs)``.

    The single parse behind both ``_declared_source_basenames_cached`` and
    ``_declared_extraction_dirs_cached``.  Each entry yields the local
    filename (``name::url`` renames honoured) and whether it is a VCS
    source.
    """
    from ...differ import _SOURCE_ARRAY_START_RE

    lines = split_lines(text)
    # A whole PKGBUILD has no diff markers; a diff does, and a removed or
    # added line there is not part of the declared end state.
    if whole_file:
        lines = [" " + ln for ln in lines]
    from ...file_kinds import files_at_line, is_srcinfo_file
    from ...tokenizer import variable_table as _variable_table

    # `source=("https://evil/${pkgname}.sh")` downloads under the resolved
    # name; the tables resolve the scalars the recipe itself declares.
    _vars, _arrs = _variable_table(
        [ln[1:] if ln[:1] in ("+", " ") else ln for ln in lines])


    files = files_at_line(lines)
    entries_out: set[tuple[str, bool]] = set()
    in_array = False
    for line in parse_diff_lines(lines).lines:
        if line.raw.startswith(("+++", "---", "@@")):
            continue
        if line.side == "remove":
            continue
        # Only the +/- sides lose their prefix; context lines keep the
        # leading space, as the text walk produced them.
        body = line.content if line.side == "add" else line.raw
        if not in_array:
            if not whole_file and is_srcinfo_file(files.get(line.index, "")):
                scalar = _SRCINFO_SOURCE_RE.match(body)
                if scalar:
                    value = scalar.group(1).strip()
                    if not _VCS_SOURCE_RE.search(value):
                        base = (value.split("::", 1)[0] if "::" in value
                                else _source_basename(value))
                        if base and base != ")":
                            entries_out.add((base, False))
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
            is_vcs = bool(_VCS_SOURCE_RE.search(ent))
            ent = _subst(ent, _vars)
            base = ent.split("::", 1)[0] if "::" in ent else _source_basename(ent)
            if base:
                entries_out.add((base, is_vcs))
        if ")" in body:
            in_array = False
    return frozenset(entries_out)

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

_BUILD_FUNCTIONS = frozenset(_CRITICAL_FUNCTIONS)

_DESCRIPTIVE_FIELD_RE = re.compile(
    r"\A\s*(?:#|;|//)"                      # a comment
    r"|\A\s*(?:Comment|Description|Name|GenericName|Icon|Keywords|Categories"
    r"|Version|Author|Maintainer|Homepage|URL|Documentation|Summary|License"
    r"|X-[\w-]+)\s*=",
    re.IGNORECASE,
)

_BUILD_ONLY_PATH_RE = re.compile(
    r"\$\{?(?:srcdir|startdir|PWD|BUILDDIR|pkgdir)\}?",
)

_PATCH_APPLY_RE = re.compile(
    _CMD_START + r"(?:patch|git\s+apply)\b[^\n;&|]*?[\"']?"
    r"((?:\$\{?(?:srcdir|startdir)\}?/|\./)?[\w./-]+"
    r"\.(?:patch|diff))[\"']?",
    re.IGNORECASE,
)
