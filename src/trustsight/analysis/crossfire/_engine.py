"""Extracted from crossfire.py: _engine."""

from __future__ import annotations
import re
from ...buckets import url_host_is_non_routable, url_line_is_inert
from ...coverage import note_stage_failure
from ...deps import _strip_comment
from ...file_kinds import files_at_line, is_shell_file
from ...tokenizer import join_line_continuations, split_lines
from ...rules import _PRINTER_LINE_RE, _blank_quoted, clamp_text
from ._common import _DECEPTIVE_SPACE_RE, _FENCE_RE, _command_words, _continuation_lines, _dependency_array_lines, _executes, _home_alias_hit, _loop_variable_names, _path_lookup_names, _pipeline_sink, _resolved_records, log
from ._x01_x08 import (X001_RE, X002_SHAPES, X003_SHAPES, X004_SHAPES, X006_SHAPES,
                       X034_ARCHIVE_RE, X034_EXECUTOR_RE)
from ._x09_x16 import X009_RE, X010_RE, X011_RE, X011_STANDDOWN_RE, X012_RE, X013_RE, X013_STANDDOWN_RE, X014_RE, X014_STANDDOWN_RE, X015_RE, X018_RE, X019_RE, _DISTRO_INSTALL_RE, _X009_CLIENT_RE, _X016_CONSUMER_RE, _X016_FETCH_RE, _X016_KNOWN_EXECUTOR_RE, _consumer_after_override, _consumer_at, _x013_is_trusted_registry
from ._x17_x25 import X017_RE, X021_RE, X024_RE, _BUILD_MANIFEST_RE, _CONTENT_WRITE_VERB_RE, _HEREDOC_OPEN_RE, _MANIFEST_COMMAND_RE, _X017_FIND_RE, _X021_RUN_POSITIONAL_RE, _X021_SET_GLOB_RE, _X022_CONFIG_FLAG_RE, _X022_PAYLOAD_RE, _X022_WRITE_RE, _multiline_function_shadow_lines, _normalise_dest, _redirect_target, _x017_find_runs_a_script, _x024_is_benign_build_path, _x024_is_passthrough, _x024_is_test_pythonpath, _x024_is_trusted_path_append, _x024_is_benign_path_suffix

__all__ = ['crossfire_techniques']

#: A grep invocation (optionally after leading assignments).  A pattern
#: passed to grep is data being searched for, not an assignment the shell
#: will execute.
_GREP_CMD_RE = re.compile(
    r"(?:^|[;&|]\s*)\s*(?:[\w./-]+=\S+\s+)*grep\b")

def crossfire_techniques(diff_text: str, current_text: str | None = None) -> dict[str, list[tuple[int, str, str]]]:
    """``{rule_id: [(line, shape, quoted), ...]}`` for every technique found.

    Returned as data rather than findings so X007 can count techniques
    without re-deriving them, and so a caller can ask "what evasion is in
    this diff" without going through the scorer.
    """
    clamped = clamp_text(diff_text) or ""
    raw_lines = split_lines(clamped)
    lines = join_line_continuations(raw_lines)
    from ...rules import _classify_enclosing_function
    from ...tokenizer import resolve_added_lines, variable_table

    enclosing = _classify_enclosing_function(lines)
    files = files_at_line(lines)
    # Names the tokenizer reduced to a literal value. A command word that
    # resolves is not an evasion; one that does not is the whole point.
    readable = [
        ln[1:] for ln in lines
        if (ln.startswith("+") or ln.startswith(" ")) and not ln.startswith("+++")
    ]
    try:
        var_table, array_table = variable_table(readable)
        # A variable defined outside every hunk (an unchanged `local
        # _pip="$srcdir/venv/bin/pip"` a later hunk's command uses) is
        # invisible to the diff-only table, so the command name reads as
        # non-literal and X002 fires CRITICAL on an ordinary recipe.  Seed
        # the whole recipe's assignments underneath the diff's: a name the
        # diff carries still wins, since that side is the one under review.
        if current_text:
            whole_vars, whole_arrays = variable_table(split_lines(current_text))
            for name, value in whole_vars.items():
                var_table.setdefault(name, value)
            for name, values in whole_arrays.items():
                array_table.setdefault(name, values)
        # An array whose elements are statically known is as readable as a
        # scalar: `A=(curl)` then `${A[0]}` resolves to `curl`, so X002
        # stands down for the static subscript and the payload rules own
        # the resolved pipeline.  A dynamic subscript (`${A[$i]}`) is not
        # exempted by the word check below, so it still fires.
        loop_vars = _loop_variable_names(readable)
        resolvable = (
            frozenset(var_table)
            | frozenset(array_table)
            | loop_vars
            | _path_lookup_names(readable)
        )
        # The scalar *values*, so a spliced name (`${_arch}-cmake`) whose
        # expansions are all known can be collapsed to a literal.  A loop
        # variable has no single value; it iterates a list, so any literal
        # stands in and the *name* splice (`${_arch}-cmake`) collapses to a
        # literal command-name shape.  The loop list's own contents are the
        # payload rules' business, not this one's.
        scalar_values = dict(var_table)
        for name in loop_vars:
            scalar_values.setdefault(name, "x")
    except Exception:
        # Without the table every command word reads as unresolvable, which
        # is X002's whole trigger condition inverted: the family goes quiet
        # exactly when the recipe is hardest to parse.
        log.debug("variable table resolution failed", exc_info=True)
        note_stage_failure("variable-resolution")
        resolvable = frozenset(_path_lookup_names(readable))
        scalar_values = {}

    # The resolved counterpart of every line, index-aligned by the
    # tokenizer's own contract ("order and count are preserved").  The
    # pipeline rules below ask whether the pipeline is a fetch; the text
    # the shell runs is the resolved one, so a fetch that resolution made
    # literal belongs to R001/R002/X009 and not to the evasion family.
    # X002 does not use this: a word is exempted only when the tokenizer
    # can read it statically (a known scalar or a static array subscript),
    # because partial-quote and ANSI-C spellings resolve through literal
    # reconstruction and must still be claimed as techniques.
    try:
        resolved_lines = resolve_added_lines(clamped)
    except Exception:
        log.debug("line resolution failed", exc_info=True)
        note_stage_failure("variable-resolution")
        resolved_lines = list(lines)
    carried = _continuation_lines(raw_lines, len(lines))
    #: X011 stands down inside a dependency array: the words there are a
    #: description, not a command the build runs.
    dependency_data = _dependency_array_lines(lines)
    #: X015 stands down inside a heredoc that only prints.  A `cat
    #: <<'MESSAGE'` body listing `systemctl --user enable --now x` is an
    #: instruction to the user, not work scheduled at build time.  Deferred
    #: because `delivery` imports this module's neighbours.
    from ..delivery import _printed_heredoc_body_indices
    printed_heredoc = _printed_heredoc_body_indices(lines)
    #: X015 also stands down in a hook the recipe does not wire up: work
    #: scheduled inside a `.install` file that `install=` never names never
    #: runs (notebook; C024 already names that nit).  Certainty needs the
    #: declared file, from the complete recipe when the caller has it.
    from ..edges import _dead_hook_files, _declared_install_basename
    dead_hooks = _dead_hook_files(files, _declared_install_basename(diff_text, current_text))
    found: dict[str, list[tuple[int, str, str]]] = {}
    #: X012 is the one rule here that spans two lines: an override is inert
    #: until a build step reads it.
    toolchain: list[tuple[int, str, str]] = []

    def record(rule_id, line_no, shape, quoted):
        found.setdefault(rule_id, []).append((line_no, shape, quoted[:120]))

    # X020 pairs a manifest *target* with the commands written into it, so
    # the heredoc region has to be tracked the way `_packaged_content_findings`
    # tracks it: the redirect names the file and the body carries the steps.
    manifest_delims: list[str] = []
    manifest_open = False
    positional_glob = False
    written_configs: dict[str, tuple[int, str]] = {}

    for index, line in enumerate(lines):
        if not line.startswith("+") or line.startswith("+++"):
            continue
        raw = line[1:]
        if _FENCE_RE.match(raw):
            continue

        stripped = raw.strip()
        if manifest_delims and stripped == manifest_delims[-1]:
            manifest_delims.pop()
            manifest_open = False
        elif manifest_delims:
            if manifest_open and _MANIFEST_COMMAND_RE.search(raw):
                record("X020", index + 1,
                       "recipe writes the build steps the engine runs",
                       raw.strip())
                manifest_open = False
        else:
            opener = _HEREDOC_OPEN_RE.search(raw)
            if opener and opener.group(2):
                manifest_delims.append(opener.group(2))
                manifest_open = bool(_BUILD_MANIFEST_RE.search(
                    raw[:opener.start()]))
            elif (">" in raw
                    and _BUILD_MANIFEST_RE.search(raw[raw.rfind(">"):])
                    # Authoring, not transforming. `sed -e ... Makefile >
                    # dest` rewrites steps that came from upstream - which
                    # is how a DKMS package substitutes a kernel version,
                    # and was this rule's only benign fire. `printf` and
                    # `echo` write steps the recipe chose.
                    and _CONTENT_WRITE_VERB_RE.search(raw[:raw.rfind(">")])
                    and _MANIFEST_COMMAND_RE.search(raw[:raw.rfind(">")])):
                record("X020", index + 1,
                       "recipe writes the build steps the engine runs",
                       raw.strip())
        body = _strip_comment(raw)
        if not body.strip():
            continue
        # A printed heredoc body is output text, not executed shell.  The
        # advisory `cat <<'MSG'` in engined's hook lists `$EDITOR …` and
        # `systemctl --user …`; the command rules below would read those as
        # the recipe's own commands.  X020 (manifest), tracked above, is the
        # one rule that must still see the body.
        if index in printed_heredoc:
            continue
        # The same line after variable/array/alias resolution.  Falls back
        # to the raw body when the resolved list is out of step, which
        # fires toward looking rather than going quiet.
        resolved_line = resolved_lines[index] if index < len(resolved_lines) else ""
        resolved_body = (
            _strip_comment(resolved_line[1:])
            if resolved_line.startswith("+")
            else body
        )
        line_no = index + 1
        # Which file the line is in decides whether it is shell; the
        # function it sits in no longer decides anything, because
        # *top-level* code runs when makepkg sources the recipe - before
        # any build step, and before any rule that reads a function body.
        # A diff with no `+++` header (a fragment handed straight to
        # `scan_diff`) keeps the old function gate rather than losing
        # detection: unknown fails toward looking.
        path = files.get(index)
        if path is None:
            executing = _executes(enclosing.get(index))
        else:
            executing = is_shell_file(path)

        # X006 is checked on every line, not only a `source=` one: the two
        # shapes it carries - a URL shortener and a raw-IP host - are never
        # legitimate anywhere in a recipe, and a fetch inside `build()` is
        # the same fact as one in the source array. This was written as an
        # if/else whose branches were identical, so the source-field test
        # decided nothing; it is stated once instead.
        #
        # A raw-IP host that is loopback or private is the one exception: it
        # distributes nothing, so a `http://127.0.0.1:…` printed as local
        # documentation is not a "source pointing somewhere unexpected".  A
        # public raw IP stays HIGH.  A line that only *prints* a URL (an
        # `echo` in `.install`, or a heredoc body) names no source either.
        if not url_line_is_inert(body) and index not in printed_heredoc:
            for shape, pattern in X006_SHAPES:
                match = pattern.search(body)
                if match is None:
                    continue
                if shape == "raw-ip-source" and url_host_is_non_routable(match.group(0)):
                    continue
                record("X006", line_no, shape, body.strip())

        if not executing:
            continue

        if X001_RE.search(body):
            record("X001", line_no, "decode-to-shell", body.strip())

        # X002 is the one position-sensitive rule here, so it is the one
        # that must stand down on a line whose command position lives
        # further up. The rest match on content and are unaffected.
        #
        # The stand-down is in `_command_words`: a known scalar or a static
        # array subscript resolves to a literal (`A=(curl)` then `${A[0]}`
        # is `curl`), so R001 owns the pipeline and X002 claiming it too
        # would score one command twice.  A dynamic `${A[$i]}` or a nameref
        # does not resolve and is still yielded.
        if index not in carried:
            for word in _command_words(body, resolvable, scalar_values):
                for shape, pattern in X002_SHAPES:
                    if pattern.match(word):
                        record("X002", line_no, shape, body.strip())
                        break

        for shape, pattern in X003_SHAPES:
            if pattern.search(body):
                record("X003", line_no, shape, body.strip())

        for shape, pattern in X004_SHAPES:
            if pattern.search(body):
                record("X004", line_no, shape, body.strip())

        alias = _home_alias_hit(body)
        if alias:
            record("X005", line_no, alias, body.strip())

        space = _DECEPTIVE_SPACE_RE.search(body)
        if space:
            record("X008", line_no, f"U+{ord(space.group()):04X}", body.strip())

        # X022 - a config written here, handed to a tool below.
        target = _redirect_target(body) if _X022_WRITE_RE.search(body) else None
        if target:
            cut, dest = target
            if _X022_PAYLOAD_RE.search(body[:cut]):
                written_configs[_normalise_dest(dest)] = (line_no, body.strip())
        elif written_configs:
            plain = _normalise_dest(body)
            for path, (origin, quoted) in list(written_configs.items()):
                parent = path.rsplit("/", 1)[0] if "/" in path else ""
                names_file = len(path) > 2 and path in plain
                names_dir = (len(parent) > 2 and parent in plain
                             and _X022_CONFIG_FLAG_RE.search(body))
                if names_file or names_dir:
                    record("X022", origin,
                           "a generated config is handed to the tool that "
                           "reads it", quoted)
                    written_configs.clear()
                    break

        # The pipeline rules read the resolved text: what the shell pipes is
        # the expansion, not the spelling.  A resolved `curl ... | bash` is
        # R001's, and a resolved `aria2c ... | bash` is X009's; X023 is for
        # the pipeline that is *still* not a fetch after resolution (a
        # command substitution or nameref the tokenizer refuses to fold).
        sink = _pipeline_sink(resolved_body)
        head = resolved_body.split("|", 1)[0]

        # X009 wanted the shell immediately after the pipe, so one filter
        # in between hid the whole chain: `dig +short txt e | head -c 2000
        # | bash` scored nothing. R001 and R002 read past intervening
        # stages for `curl` and `wget`, and the uncatalogued half did not -
        # the same asymmetry, in the rule written to cover the remainder.
        #
        # The sink is the one `_pipeline_sink` already computes for X016,
        # so both arms now ask about the *end* of the pipeline rather than
        # about the character after the first bar.
        if X009_RE.search(resolved_body) or (
                sink and _X009_CLIENT_RE.search(head)
                and _X016_KNOWN_EXECUTOR_RE.match(sink)):
            record("X009", line_no, "uncatalogued fetch to a shell", body.strip())

        if (sink
                and _X016_FETCH_RE.search(head)
                and not _X016_CONSUMER_RE.match(sink)
                and not _X016_KNOWN_EXECUTOR_RE.match(sink)):
            record("X016", line_no, f"fetch piped into {sink}", body.strip())

        # X023 - the pipeline ends in a shell and does not start with a
        # fetch. `pass otp e | bash`, `gpg-connect-agent … | bash`,
        # `cat /sys/kernel/tracing/trace | bash`, `perf script -i … | bash`:
        # the bytes are produced locally, so no fetch rule has anything to
        # say, and what runs is whatever that command printed.
        #
        # A fetch head is left to R001/R002 and X009, which say the more
        # specific thing. Everything else is claimed here, because no
        # package in the 3,739-diff benign corpus pipes anything at all
        # into a shell.
        if (sink
                and _X016_KNOWN_EXECUTOR_RE.match(sink)
                and not _X016_FETCH_RE.search(head)
                and not _X009_CLIENT_RE.search(head)):
            record("X023", line_no, "command output executed as a script",
                   body.strip())

        # X034 - an archival service laundered into an executor. The archived
        # path carries a second absolute URL, so a trusted archive host fronts
        # a fresh origin. Gated on an executor on the same line, so a
        # legitimate `source=()` fetch of a vanished upstream through
        # web.archive.org stays quiet, and stood down when a plain curl/wget
        # fetch-to-shell rule (R001/R002) already owns the line.
        if (index not in printed_heredoc
                and X034_ARCHIVE_RE.search(body)
                and X034_EXECUTOR_RE.search(body)
                and not (sink and _X016_FETCH_RE.search(head)
                         and _X016_KNOWN_EXECUTOR_RE.match(sink))):
            record("X034", line_no,
                   "fetch laundered through an archival service", body.strip())

        if _X021_SET_GLOB_RE.search(body):
            positional_glob = True
        elif positional_glob and _X021_RUN_POSITIONAL_RE.search(body):
            record("X021", line_no,
                   "a glob was pushed into the positional parameters and run",
                   body.strip())
            positional_glob = False

        if X021_RE.search(body):
            record("X021", line_no, "the file the executor runs is not a literal",
                   body.strip())

        find_exec = _X017_FIND_RE.search(body)
        if find_exec is not None:
            if _x017_find_runs_a_script(body, find_exec, lines, index):
                record("X017", line_no, "a tool is given a command to run",
                       body.strip())
        elif X017_RE.search(body):
            record("X017", line_no, "a tool is given a command to run",
                   body.strip())

        if X018_RE.search(body):
            record("X018", line_no,
                   "an interpreter one-liner assembles the name it calls",
                   body.strip())

        if X019_RE.search(body):
            record("X019", line_no, "host material sent or packaged",
                   body.strip())

        if X010_RE.search(body):
            record("X010", line_no, "interpreter reaches the network", body.strip())

        if (index not in printed_heredoc
                and files.get(index) not in dead_hooks
                and X015_RE.search(body)):
            record("X015", line_no, "work scheduled to run after the build",
                   body.strip())

        x014_body = _blank_quoted(body) if _GREP_CMD_RE.search(body) else body
        env_code = X014_RE.search(x014_body)
        if env_code and not X014_STANDDOWN_RE.search(x014_body):
            record("X014", line_no,
                   f"{env_code.group('var')} names code the shell will run",
                   body.strip())

        x013 = X013_RE.search(body)
        if (x013 and not X013_STANDDOWN_RE.search(body)
                and not _x013_is_trusted_registry(body, x013)):
            record("X013", line_no, "fetch redirected or trust replaced",
                   body.strip())

        # A printer's quoted text is data, not shell: an install notice that
        # says `export PATH="$(aqua root-dir)/bin:$PATH"` does not assign
        # PATH.  `_blank_quoted` keeps `$(...)` in double quotes, because
        # that substitution really runs.
        x024_body = _blank_quoted(body) if _PRINTER_LINE_RE.match(body) else body
        indirect = X024_RE.search(x024_body)
        if (indirect is not None
                and not _x024_is_passthrough(x024_body, indirect)
                and not _x024_is_benign_build_path(x024_body, indirect)
                and not _x024_is_benign_path_suffix(x024_body, indirect)
                and not _x024_is_test_pythonpath(
                    x024_body, indirect, enclosing.get(index))
                and not _x024_is_trusted_path_append(
                    x024_body, indirect, lines, index)):
            record("X024", line_no,
                   "sensitive variable assigned an indirect value",
                   body.strip())

        # The stand-down is about *language* package managers, where a
        # local path means "install what this recipe just built".  For the
        # distribution's own tools it means the opposite: `pacman -U
        # ./evil.pkg.tar.zst` installs a local package as root, scriptlets
        # and all, and the leading `./` is not a mitigation.
        distro = _DISTRO_INSTALL_RE.search(body)
        local_target = _x011_local_target(body)
        # In an install scriptlet the manager installs the distribution's
        # own signed packages at install time (tape16-bin: `pacman -S
        # xorg-xwayland` in post_install) - not fetched code running at
        # build time, which is what this technique claims.
        in_hook = bool(path) and path.endswith(".install")
        if (index not in dependency_data
                and not in_hook
                and X011_RE.search(body)
                and (distro or not (X011_STANDDOWN_RE.search(body) or local_target))):
            record("X011", line_no, "package manager runs fetched code",
                   body.strip())

        override = X012_RE.search(body)
        if override and not toolchain and (
            _consumer_after_override(body, override)
            or _consumer_at(lines, index + 1)
        ):
            # The override only matters because something later uses it.
            # The consumer is looked for from here rather than waited for,
            # because it need not be an added line: an override placed
            # above an *unchanged* `make` is the shape where the attacker
            # supplies one line and the existing recipe supplies the rest.
            toolchain.append((line_no, override.group("var"), body.strip()))
            record("X012", line_no,
                   f"{override.group('var')} points into the source tree",
                   body.strip())

    # X025: multi-line function shadow.  H097 catches `msg() {` on one
    # line; this catches the continuation variant where the brace is on
    # the next line.  Must run on raw lines before joining continuations.
    for shadow_line in _multiline_function_shadow_lines(raw_lines):
        record("X025", shadow_line,
               "function shadow defined across multiple lines",
               raw_lines[shadow_line - 1].strip())

    return _resolved_records(found)


def _x011_local_target(body: str) -> bool:
    """True when the install target is a local path, not a registry name.

    `npm install ./pkg` installs what the recipe just built; the same `./`
    before the manager (`./tools/node/bin/npm install evil`) is the
    executable path and the fetch is still a registry fetch.
    """
    words = [word.strip("\"'") for word in body.split()]
    for index, word in enumerate(words):
        if word.lower() in {
            "install", "i", "add", "ci", "sync", "fetch", "get",
            "require", "update", "build",
        }:
            return any(
                later == "." or later.startswith("./")
                for later in words[index + 1:]
            )
    return False
