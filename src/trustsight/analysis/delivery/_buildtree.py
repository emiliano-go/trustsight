"""Extracted from delivery.py: _buildtree."""

import fnmatch
import os
import re
import shlex
from ...config import (
    EXEC_WRAPPER as _EXEC_WRAPPER,
    NETWORK_CLIENT as _NETWORK_CLIENT,
    SCRIPT_EXECUTOR as _SCRIPT_EXECUTOR,
    _SUBCOMMAND_OPTS as _SUBCOMMAND_OPTS,
)
from ...coverage import note_stage_failure
from ...deps import _strip_comment
from ...findings import stamp
from ...rules import (
    MAX_RULE_LINE_BYTES,
    ScopeResolver,
)
from ...tokenizer import resolve_added_lines
from ..build import (
    _REMOTE_PROC_SUBST_OUT_RE,
    _REMOTE_PROC_SUBST_RE,
    _recipe_lines,
)
from ._common import _BUILD_FUNCTIONS, _ELF_MAGIC, _EXECUTION_RE, _H072_BENIGN_EXEC, _IMPLICIT_BUILD_INPUTS, _SCOPE_FUNCTIONS, _collect_writes, _declared_source_basenames, _find_line, _heredoc_body_indices, _norm_path, _source_basename

__all__ = ['_ARRAY_BINDING_RE', '_COMMITTED_CARRIER_RE', '_COMMITTED_PAYLOAD_RE', '_EXECSTART_RE', '_INSTALL_CMD_RE', '_LOOP_BINDING_RE', '_PATH_ASSIGN_RE', '_PATH_BUILD_DIR_RE', '_POSITIONAL_NAMES', '_SET_POSITIONAL_RE', '_STARTDIR_PATH_RE', '_TEST_DIR_RE', '_TEST_NAME_RE', '_committed_execution_findings', '_implicit_build_input', '_installed_executables', '_is_test_fixture', '_loop_bindings', '_matches_committed', 'scan_tree_manifest']

_EXECSTART_RE = re.compile(r"^ExecStart\s*=\s*(.+)$", re.IGNORECASE | re.MULTILINE)

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
        # A line the rules engine clamps cannot be read by the pairing
        # passes either; the run already declares `line_truncated`.
        if len(line) > MAX_RULE_LINE_BYTES:
            continue
        body = _strip_comment(line[1:])
        if not _INSTALL_CMD_RE.search(body):
            continue
        # Mode: explicit 7xx or no -m flag (install defaults to 755).
        # `install -m 0755` and `install -m0755` spell the same mode as
        # `-m755`; the leading zero is a width convention, not a different
        # permission bit, so it is stripped before the 7 test.
        mode_match = re.search(r"\s-[a-zA-Z]*[mM]\s*(\d+)", body)
        if mode_match and not mode_match.group(1).lstrip("0").startswith("7"):
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

_PATH_ASSIGN_RE = re.compile(r"(?<!:)\bPATH\s*=\s*([^;\n]+)", re.IGNORECASE)

_PATH_BUILD_DIR_RE = re.compile(
    r"\$\{?(?:srcdir|pkgdir|startdir|BUILDDIR)\}?/([^:\s]+)",
    re.IGNORECASE,
)

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

_LOOP_BINDING_RE = re.compile(
    r"\bfor\s+(?P<var>\w+)\s+in\s+(?P<words>[^;\n]*?)(?:;|\s+do\b)",
    re.IGNORECASE,
)

_SET_POSITIONAL_RE = re.compile(
    # `\A\s*`, not `\A`: a recipe line is indented, and anchoring at the
    # very first character meant the binding was only ever found on a line
    # that began in column one.
    r"(?:\A\s*|[;&|]\s*)set\s+--\s+(?P<words>[^;\n]+)"
)

_ARRAY_BINDING_RE = re.compile(
    r"\b(?:mapfile|readarray)\b(?:\s+-\S+)*\s+(?P<mvar>\w+)"
    r"[^;\n]*?<\s*(?:<\s*\()?(?P<mwords>[^;\n)]*)"
    r"|(?:\A\s*|[;&|]\s*)(?P<avar>\w+)=\((?P<awords>[^)\n]*)\)"
)

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
    declared (H081).

    H069/H072 own files the recipe itself writes; H066 owns committed ELF
    binaries.  Between them sat the cleartext helper script: committed to
    the AUR repository, never named in ``source=()`` (so makepkg never
    copies it into ``$srcdir`` and its bytes never reach the differ), and
    executed through ``$startdir`` or a ``../`` climb.  Two signals, either
    sufficient:

    - the executed path references ``${startdir}``/``$startdir`` or walks
      ``../`` (available even when the repository tree was not analyzed);
    - the executed basename is present in the tree manifest (only when a
      manifest was supplied; without one the rule never guesses).

    Declared ``source=()`` basenames, files the recipe wrote earlier in the
    same function, and the configure/make artifact names H072 already
    exempts stay silent.  The manifest signal requires a relative path: an
    absolute ``/usr/share/...`` target cannot be a repository file, however
    its basename collides.
    """
    lines = resolve_added_lines(diff_text)
    scopes = ScopeResolver(lines, _recipe_lines(current_text))
    source_basenames = _declared_source_basenames(diff_text, current_text)
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
        # A line the rules engine clamps cannot be read by the pairing
        # passes either; the run already declares `line_truncated`.
        if len(line) > MAX_RULE_LINE_BYTES:
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
            add("H081", "Committed File Executed Without Declaration", "HIGH",
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
            if base in _H072_BENIGN_EXEC and not committed_and_undeclared:
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
            add("H081", "Committed File Executed Without Declaration", "HIGH", "execution",
                f"{fn}() executes repo-committed file not declared in source=(): {base}",
                line=_find_line(diff_text, raw.strip().strip('"\'')[:60] or base),
                position=fn, path=path)
            return

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

_COMMITTED_PAYLOAD_RE = re.compile(
    r"(?:" + _NETWORK_CLIENT + r")[^\n]{0,400}?\|\s*"
    r"(?:" + _EXEC_WRAPPER + r")?(?:/(?:usr/)?bin/)?(?:" + _SCRIPT_EXECUTOR + r")\b"
    r"|(?:" + _SCRIPT_EXECUTOR + r")\s+-c\s+[\"']?\$\([^\n]{0,200}?"
    r"(?:" + _NETWORK_CLIENT + r")"
    # The same indirect shapes H075 owns diff-scope, for the campaign that
    # put them in a committed scriptlet instead: `bash <(curl -L URL)` has
    # no pipe, so the arms above read it as nothing.  Both patterns are
    # group-free, so appending them does not move any capture numbering.
    r"|" + _REMOTE_PROC_SUBST_RE.pattern
    + "|" + _REMOTE_PROC_SUBST_OUT_RE.pattern,
    re.IGNORECASE,
)

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

def scan_tree_manifest(files, source_urls, package_name: str = "") -> list[dict]:
    """H066, H090 and C032 findings for a repository file manifest.

    *files* is ``[(path, head_bytes)]`` from a git tree or a snapshot
    tarball.  A committed ELF file that is not a declared ``source=``
    filename and not a test fixture fires H066; a committed unit, rule,
    hook or patch whose content fetches and runs code fires H090; a
    committed install scriptlet that executes commands outside every hook
    function fires C032.
    """
    source_basenames = {_source_basename(u) for u in source_urls if _source_basename(u)}
    from ..edges import edge_committed_payload, edge_scriptlet_top_level_execution
    from ..persistence_engine import emit_committed_build_path

    findings: list[dict] = []
    for name, head in files:
        if _is_test_fixture(name, os.path.basename(name.rstrip("/"))):
            continue
        payload = (edge_committed_payload(name, head)
                   or edge_scriptlet_top_level_execution(name, head)
                   or emit_committed_build_path(name, head))
        if payload is not None:
            # Every carrier, not just the first.  The early `break` let a
            # HIGH on an earlier file hide a CRITICAL on a later one - a
            # `.desktop` naming `$srcdir` stopped the scan before the
            # `.service` that pipes a download into a shell was ever read.
            findings.append(payload)
    for name, head in files:
        if not head.startswith(_ELF_MAGIC):
            continue
        base = os.path.basename(name.rstrip("/"))
        if base in source_basenames:
            continue
        if _is_test_fixture(name, base):
            continue
        findings.append(stamp({
            "rule_id": "H066", "name": "Embedded Binary In Tree",
            "severity": "HIGH", "category": "obfuscation",
            "match": f"ELF file committed to the repository: {name}",
            "file": name,
            "params": {"path": name},
        }))
        break
    return findings
