"""Extracted from security_gates.py: _core."""

import ast
import contextlib
import io
import json
import re
from pathlib import Path

__all__ = ['Gate', 'HOSTILE', 'H_SERIES_REDUCTION_TARGET', 'ROOT', 'SRC', '_ANALYSIS_FETCH_ALLOWED', '_ARTIFACT_MODULES', '_ARTIFACT_READ_EXEMPT', '_ATX_PUNCT_RE', '_BOUNDED_IO_MODULE', '_PATH_READ_MODULES', '_BOUND_CONSTANTS', '_DYNAMIC_SQL_NODES', '_ENDPOINT_HOST', '_FORBIDDEN_CALLS', '_GIT_ALLOWED_IMPORTS', '_INLINE_CODE_RE', '_MD_LINK_RE', '_MIRROR_HOSTS', '_MIRROR_MODULES', '_NETWORK_CALLS', '_NETWORK_MODULES', '_PERMISSION_PHRASES', '_PERMISSION_REGEXES', '_RELEASE_HOSTS', '_RELEASE_MODULES', '_SHARED_ANALYSIS', '_URL_LITERAL_RE', '_anchor', '_call_name', '_demo_fact', '_enclosing_functions', '_h_series_live_ceiling', '_hostile_fact', '_hostile_result', '_parity_fact', '_python_files', '_rel', '_render_forget_list', '_render_inspect_text', '_render_list_rows', '_seed_ioc_baseline']

ROOT = Path(__file__).resolve().parent.parent.parent

SRC = ROOT / "src" / "trustsight"

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
    return path.relative_to(ROOT).as_posix()

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

_NETWORK_MODULES = {
    "discovery.py",
    "fetcher.py",
    "full_aur/fetch.py",
    "full_aur/metadata.py",
    "notify.py",
    "release.py",
    # The isolated git worker clones the AUR repository (A16), but only
    # through its own loopback bridge and the parent CONNECT proxy pinned to
    # aur.archlinux.org:443.
    "sandbox/git_worker.py",
    "sandbox/_linux_sandbox.py",
    "sandbox/_aur_proxy.py",
}

_NETWORK_CALLS = ("urlopen", "urlretrieve", "clone_repository", "create_connection")

_URL_LITERAL_RE = re.compile(r"https?://([A-Za-z0-9.-]+\.[A-Za-z]{2,})")

_ENDPOINT_HOST = "aur.archlinux.org"

#: The read-only GitHub AUR mirror the corpus fetcher falls back to when the
#: AUR's cgit snapshot endpoint is rate-limiting.  A declared, literal host,
#: reachable only from the fetch modules - never from analysis.
_MIRROR_HOSTS = frozenset({"codeload.github.com"})

_MIRROR_MODULES = {"full_aur/fetch.py"}

_RELEASE_HOSTS = frozenset({"github.com", "api.github.com"})

_RELEASE_MODULES = {"release.py"}

_BOUNDED_IO_MODULE = "bounded_io.py"

#: Modules whose local reads must go through ``bounded_io``.  ``doc_cache``
#: reads a JSON file derived from attacker text, so ``read_text``/``read_bytes``
#: here would bypass the cap the same way a bare ``read()`` does.
_PATH_READ_MODULES = {"doc_cache.py"}

_ARTIFACT_MODULES = (
    "db/_seed.py",
    "ioc_baseline.py",
    "seed_build.py",
    "full_aur/export.py",
)

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

_DYNAMIC_SQL_NODES = (ast.JoinedStr, ast.BinOp)

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
        "contacts": {
            "available": True, "note": "",
            "records": [{"kind": "host", "value": HOSTILE, "basis": "ledger"}],
        },
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

def _seed_ioc_baseline(source: str = "test-feed", expires_at: str = ""):
    """Import a tiny IOC baseline into the current db; return its entries."""
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

_ANALYSIS_FETCH_ALLOWED = {
    "clone_or_fetch",
    "get_head_commit",
    "get_maintainer_from_commit",
    "get_pkgbuild_at_commit",
    # Same shape as get_pkgbuild_at_commit: a tree read keyed by commit id,
    # for the H092 metadata/recipe comparison on the review path.
    "get_srcinfo_at_commit",
    "get_pkgver_from_head",
    # Local only, despite living in discovery.py next to the RPC: compares
    # two version strings via pacman's vercmp or pyalpm and opens no socket.
    "_vercmp",
}

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
    # Punctuation removal can leave runs of spaces (and a heading may already
    # contain hyphens); the renderer collapses both into one separator.
    slug = _ATX_PUNCT_RE.sub("", text.lower())
    return re.sub(r"[\s-]+", "-", slug).strip("-")

_PERMISSION_PHRASES = (
    "no issues", "looks fine", "looks good", "nothing to review",
    "no need to review", "safe to install", "safe to update", "safe to build",
    "you may proceed", "good to go", "all clear", "verified safe",
    "no action needed", "no concerns", "appears safe", "is safe",
)

_PERMISSION_REGEXES = (
    r"\bpackage is clean\b", r"\bverdict:?\s*clean\b", r"\bno risk\b",
    r"\bnothing (?:to worry|suspicious found)\b",
)

_BOUND_CONSTANTS = {
    "rules/_common.py": ["MAX_RULE_LINE_BYTES", "MAX_SCANNED_LINES"],
    "recipedoc.py": ["MAX_ALIGNMENT_CELLS"],
    "full_aur/properties.py": ["MAX_PROPERTY_ITEMS",
                               "MAX_PROPERTY_TRANSITIONS_PER_KEY"],
    "doc_cache.py": ["MAX_DOC_CACHE_BYTES"],
    "expansion.py": ["_MAX_EXPANSION_PASSES", "_MAX_VALUE_LEN",
                     "_MAX_LINE_LEN", "_MAX_TABLE_BYTES", "_MAX_TEXT_LEN",
                     "_MAX_GLOB_PATTERN_LEN", "_MAX_GLOB_STEPS"],
    "_tokenizer_engine/_common.py": ["_MAX_ARRAY_ENTRIES"],
    "sandbox/protocol.py": ["MAX_FRAME_BYTES", "MAX_RESPONSE_BYTES"],
    "sandbox/expand_worker.py": ["_WORKER_MEMORY_BYTES", "_WORKER_CPU_SECONDS",
                                 "_WORKER_NOFILE"],
    "sandbox/client.py": ["REQUEST_TIMEOUT_SECONDS", "MAX_REQUESTS_PER_WORKER",
                          "WORKER_POOL_SIZE"],
    "db/_connection.py": ["MAX_SEED_BYTES", "MAX_SEED_MEMBER_BYTES"],
    "differ/_bounds.py": ["MAX_GENERATED_DIFF_BYTES", "MAX_DIFF_PATCHES",
                  "MAX_DIFF_SUMMARY_FILES", "MAX_PATCH_BYTES", "MAX_PATCH_SOURCE_BYTES",
                  "MAX_PKG_BUILD_BYTES", "MAX_COMPANION_TREE_ENTRIES",
                  "MAX_COMPANION_NAME_BYTES", "MAX_COMPANION_BYTES",
                  "MAX_COMPANION_FILES", "MAX_DIFF_PATH_BYTES",
                  "MAX_HISTORY_COMMITS"],
    "full_aur/fetch.py": ["MAX_RESPONSE_BYTES", "MAX_TAR_MEMBERS",
                          "MAX_TAR_MEMBER_BYTES", "_HTTP_TIMEOUT"],
    "analysis/manifests/_common.py": ["MAX_UPSTREAM_MANIFEST_BYTES",
                                      "MAX_UPSTREAM_MANIFEST_FILES",
                                      "MAX_UPSTREAM_DEP_PAIRS",
                                      "MAX_UPSTREAM_DEP_NAME_BYTES",
                                      "MAX_UPSTREAM_DEP_HOST_BYTES"],
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
    "sandbox/git_bounds.py": [
        "GIT_WORKER_MEMORY_BYTES", "GIT_WORKER_CPU_SECONDS",
        "GIT_WORKER_RETIRE_CPU_SECONDS", "GIT_WORKER_FSIZE_BYTES",
        "GIT_WORKER_NOFILE", "GIT_WORKER_WRITE_BYTES",
        "GIT_WORKER_MAX_FILES", "GIT_WORKER_MONITOR_SECONDS",
        "GIT_WORKER_HOME_BYTES", "GIT_WORKER_HOME_FILES",
        "GIT_WORKER_ROOT_BYTES", "GIT_WORKER_ROOT_FILES",
        "GIT_PACK_MAX_OBJECTS",
        "GIT_PROXY_HEADER_BYTES", "GIT_PROXY_REQUEST_BODY_BYTES",
        "GIT_PROXY_TOTAL_REQUEST_BYTES", "GIT_PROXY_RESPONSE_BYTES",
        "GIT_PROXY_MAX_REQUESTS", "GIT_PROXY_DEADLINE_SECONDS",
        "GIT_PROXY_HEADER_SECONDS", "GIT_PROXY_BODY_SECONDS",
        "GIT_PROXY_ADVERT_BYTES", "GIT_PROXY_MAX_REFS",
        "GIT_PROXY_MAX_WANTS", "GIT_PROXY_RESPONSE_HEADER_BYTES",
        "GIT_TRANSFER_DEADLINE_SECONDS", "GIT_FETCH_TIMEOUT_SECONDS",
        "GIT_OP_TIMEOUT_SECONDS", "MAX_TRANSFER_BYTES",
        "MAX_TOTAL_TRANSFER_BYTES", "GIT_DIFF_MAX_CONTEXT_LINES",
        "GIT_TREE_MAX_ENTRIES", "GIT_COMMIT_META_MAX_OIDS",
        "GIT_FILE_AT_MAX_BYTES",
    ],
}

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
        suppressed_rules=[{"rule_id": "R099", "severity": "LOW",
                           "indicator_corroborated": True}],
        overrides_expired=["H029"],
        acknowledged_urls=[{
            "url": "https://example.org/known.tar.gz",
            "reason": "reviewed 2026-10-01",
        }],
    )

_SHARED_ANALYSIS = {
    "analyze_outdated_batch", "discover_packages",     # review
    "analyze_package",                                 # inspect
    "analyze_package_text",                            # text / corpus
    "evaluate_fact", "evaluate_review_row", "report_body",
}

_GIT_ALLOWED_IMPORTS = frozenset({
    "sandbox/git_project.py",
    "sandbox/git_worker.py",
})

def _h_series_live_ceiling() -> int:
    from trustsight.rule_id_history import ANCHOR_RULE_IDS, FROZEN_H_IDS

    return len(FROZEN_H_IDS) - len(ANCHOR_RULE_IDS)

H_SERIES_REDUCTION_TARGET = (55, 65)
