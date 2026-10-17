"""The persistence engine: write-target + location-class predicates as data.

 consolidates the "write to a sensitive location, with a
declaration check" rules onto one path-classification table.  This module owns
the :data:`PERSISTENCE_INSTANCES` table and the predicates; the shared
:class:`~trustsight.analysis.edges.GraphContext` supplies the resolved lines,
scope resolver and heredoc bodies, so no rule rebuilds them.

Rule ids, severities and finding text are unchanged.  H004/H017/H023 (the
command/declaration arm, not path classification) and the delivery-side
carrier rules H084/H085/H089/H093/H095 stay on their own surfaces.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Callable

from ..deps import _strip_comment
from ..diffdoc import parse_diff_lines
from ..findings import stamp
from ..rules import MAX_RULE_LINE_BYTES
from ..tokenizer import split_lines
from .build import (
    _HOOK_ADMIN_RE,
    _HOOK_EXEC_RE,
    _INSTALL_HOOKS,
    _added_line_number,
    _network_fetch_url,
    _sudo_escalates,
)
from .delivery import (
    _BOOT_ARTIFACT_RE,
    _BUILD_FUNCTIONS,
    _BUILD_ONLY_PATH_RE,
    _COMMITTED_CARRIER_RE,
    _CONTENT_WRITE_RE,
    _DESCRIPTIVE_FIELD_RE,
    _EXECSTART_RE,
    _HEREDOC_OPEN_RE,
    _PATH_ASSIGN_RE,
    _PATH_BUILD_DIR_RE,
    _PKGDIR_TARGET_RE,
    _SCOPE_FUNCTIONS,
    _collect_executions,
    _find_line,
    _installed_executables,
    _norm_path,
)
from .edges import GraphContext
from .persistence import (
    _BUILD_TIME_FUNCTIONS,
    _DEVICE_TARGET_RE,
    _ES_RE,
    _HOME_PREFIX_RE,
    _INSTALL_SCRIPTLETS,
    _INLINE_OPEN_WRITE_RE,
    _INPLACE_EDIT_RE,
    _MKTEMP_RE,
    _PACMAN_HOOK_RE,
    _PLAIN_ABS_PATH_RE,
    _RC_BASENAME_RE,
    _RUNTIME_WRITABLE_RE,
    _WW_CD_RE,
    _WW_DIR_RE,
    _is_staged,
    _raw_targets,
    collapse_path_slashes,
)


@dataclass(frozen=True)
class PersistenceInstance:
    """One persistence rule's predicate row."""

    rule_id: str
    name: str
    location_class: str
    declaration_check: bool
    severity: str
    doc: str
    fixtures: tuple[str, ...]
    emitter: Callable[[GraphContext, Callable], None]


def emit_systemd_unit(ctx: GraphContext, add: Callable) -> None:
    """H039: a systemd unit whose ExecStart points at a runtime-writable path.

    Scans unit *content* (the ExecStart line itself, which can live in a
    heredoc body), so no scope/heredoc filter applies.
    """
    for i, line in enumerate(ctx.lines):
        if not line.startswith("+"):
            continue
        m = _ES_RE.match(line[1:])
        if not m:
            continue
        target = m.group(1).strip("\"'")
        if _RUNTIME_WRITABLE_RE.search(target):
            add("H039", "Systemd ExecStart From Runtime-Writable Path", "HIGH",
                "persistence",
                f"systemd unit ExecStart points at runtime-writable path: {target}",
                line=i + 1, exec_target=target)
            return


def emit_pacman_hook(ctx: GraphContext, add: Callable) -> None:
    """H062: a pacman hook installed into the libalpm hook directory."""
    for i, line in enumerate(ctx.lines):
        if not line.startswith("+") or not ctx.scopes.within(i, _SCOPE_FUNCTIONS):
            continue
        if i in ctx.heredoc_body:
            continue
        for t in _raw_targets(_strip_comment(line[1:])):
            if _PACMAN_HOOK_RE.search(_norm_path(t)):
                add("H062", "Pacman Hook Installed", "MEDIUM", "persistence",
                    f"{ctx.scopes.label(i, _SCOPE_FUNCTIONS)}() installs a pacman hook: {t}",
                    line=i + 1, position=ctx.scopes.within(i, _SCOPE_FUNCTIONS), path=t)
                return


def emit_home_rc(ctx: GraphContext, add: Callable) -> None:
    """H032: a write into a user's home or shell rc file."""
    for i, line in enumerate(ctx.lines):
        if not line.startswith("+") or not ctx.scopes.within(i, _SCOPE_FUNCTIONS):
            continue
        if i in ctx.heredoc_body:
            continue
        for t in _raw_targets(_strip_comment(line[1:])):
            t_clean = t.strip().strip("\"'")
            if _is_staged(t_clean):
                continue
            base = os.path.basename(t_clean)
            if _HOME_PREFIX_RE.search(t_clean) or _RC_BASENAME_RE.match(base):
                in_scriptlet = ctx.scopes.direct(i) in _INSTALL_SCRIPTLETS
                severity = "CRITICAL" if in_scriptlet else "HIGH"
                add("H032", "Write To User Home Or RC", severity, "persistence",
                    f"{ctx.scopes.label(i, _SCOPE_FUNCTIONS)}() writes into the user's home/rc: {t}",
                    line=i + 1, position=ctx.scopes.within(i, _SCOPE_FUNCTIONS), path=t)
                return


def emit_worldwritable(ctx: GraphContext, add: Callable) -> None:
    """H038: work staged in a world-writable directory."""
    for i, line in enumerate(ctx.lines):
        if not line.startswith("+") or not ctx.scopes.within(i, _SCOPE_FUNCTIONS):
            continue
        if i in ctx.heredoc_body:
            continue
        body = _strip_comment(line[1:])
        if _MKTEMP_RE.search(body):
            continue
        for t in _raw_targets(body):
            if _WW_DIR_RE.search(collapse_path_slashes(t.strip().strip("\"'"))):
                add("H038", "World-Writable Staging", "HIGH", "persistence",
                    f"{ctx.scopes.label(i, _SCOPE_FUNCTIONS)}() stages work in a world-writable path: {t}",
                    line=i + 1, position=ctx.scopes.within(i, _SCOPE_FUNCTIONS), path=t)
                return
        for t in _collect_executions(body):
            if _WW_DIR_RE.search(collapse_path_slashes(t)):
                add("H038", "World-Writable Staging", "HIGH", "persistence",
                    f"{ctx.scopes.label(i, _SCOPE_FUNCTIONS)}() executes from a world-writable path: {t}",
                    line=i + 1, position=ctx.scopes.within(i, _SCOPE_FUNCTIONS), path=t)
                return
        if _WW_CD_RE.search(collapse_path_slashes(body)):
            add("H038", "World-Writable Staging", "HIGH", "persistence",
                f"{ctx.scopes.label(i, _SCOPE_FUNCTIONS)}() works from a world-writable directory: {body.strip()[:80]}",
                line=i + 1, position=ctx.scopes.within(i, _SCOPE_FUNCTIONS), body=body.strip()[:80])
            return


def emit_outside_staging(ctx: GraphContext, add: Callable) -> None:
    """H076: a build-time function writes outside the staging root."""
    for i, line in enumerate(ctx.lines):
        if not line.startswith("+"):
            continue
        fn = ctx.scopes.within(i, _BUILD_TIME_FUNCTIONS)
        if fn is None:
            if ctx.scopes.direct(i) is not None:
                continue
            fn = "top level"
        if i in ctx.heredoc_body:
            continue
        body = _strip_comment(line[1:])
        for target in _raw_targets(body):
            path = target.strip().strip("\"'")
            if _is_staged(path) or _DEVICE_TARGET_RE.match(path):
                continue
            if not _PLAIN_ABS_PATH_RE.match(path):
                continue
            add("H076", "Build Writes Outside Staging Root", "HIGH",
                "persistence",
                f"{fn}() writes to {path}, outside $pkgdir/$srcdir",
                line=i + 1, position=fn, path=path)
            return
        # The shell target scan cannot see a write spelled inside an
        # interpreter: `perl -pi ... /etc/x` and `open("/etc/x", "a")`.
        for match in _INPLACE_EDIT_RE.finditer(body):
            path = match.group(1).strip("\"'")
            if _is_staged(path) or not _PLAIN_ABS_PATH_RE.match(path):
                continue
            add("H076", "Build Writes Outside Staging Root", "HIGH",
                "persistence",
                f"{fn}() edits {path} in place, outside $pkgdir/$srcdir",
                line=i + 1, position=fn, path=path)
            return
        for match in _INLINE_OPEN_WRITE_RE.finditer(body):
            path = match.group(1).strip("\"'")
            if _is_staged(path) or not _PLAIN_ABS_PATH_RE.match(path):
                continue
            add("H076", "Build Writes Outside Staging Root", "HIGH",
                "persistence",
                f"{fn}() writes to {path}, outside $pkgdir/$srcdir",
                line=i + 1, position=fn, path=path)
            return


def emit_sudo(ctx: GraphContext, add: Callable) -> None:
    """H004: a build/install function escalates privilege."""
    context = ctx.line_context
    printed_heredoc = ctx.printed_heredoc
    for i, line in enumerate(ctx.lines):
        if not line.startswith("+") or not ctx.scopes.within(i, _SCOPE_FUNCTIONS):
            continue
        # A message prints, it does not run: an install hook that *tells* the
        # user to run `echo uinput | sudo tee ...` was read as the escalation
        # itself (keymux), a CRITICAL on informational text.  Same carve-out
        # H017 and R052 already make.
        if context.get(i) == "message" or i in printed_heredoc:
            continue
        body = _strip_comment(line[1:])
        if _sudo_escalates(body):
            add("H004", "Privilege Escalation", "CRITICAL", "privilege",
                f"{ctx.scopes.label(i, _SCOPE_FUNCTIONS)}() escalates privilege: "
                f"{body.strip()[:80]}",
                line=_added_line_number(ctx.diff_text, body.strip()[:30]),
                position=ctx.scopes.direct(i), body=body.strip()[:80])
            return


def emit_install_hook(ctx: GraphContext, add: Callable) -> None:
    """H017: an install hook fetches or executes."""
    context = ctx.line_context
    printed_heredoc = ctx.printed_heredoc
    for i, line in enumerate(ctx.lines):
        if not line.startswith("+") or not ctx.scopes.within(i, _INSTALL_HOOKS):
            continue
        if context.get(i) == "message" or i in printed_heredoc:
            continue
        body = _strip_comment(line)
        label = ctx.scopes.label(i, _INSTALL_HOOKS)
        if _network_fetch_url(body) or _HOOK_EXEC_RE.search(body):
            # Fetch or dynamic execution: the high arm the rule names.
            add("H017", "Install Hook Fetches Or Executes", "HIGH", "installer",
                f"{label}() runs as root and contains: {body.strip()[:80]}",
                position=ctx.scopes.direct(i), body=body.strip()[:80])
            break
        if _HOOK_ADMIN_RE.search(body):
            # Privileged setup (service enable, account change, sudoers, setuid
            # bit): reported, but MEDIUM - it is the ordinary shape of a
            # legitimate hook, not fetch-or-execute.
            add("H017", "Install Hook Fetches Or Executes", "MEDIUM", "installer",
                f"{label}() runs as root and performs privileged setup: "
                f"{body.strip()[:80]}",
                position=ctx.scopes.direct(i), body=body.strip()[:80])
            break


def emit_service_binary(ctx: GraphContext, add: Callable) -> None:
    """H084: a systemd service ExecStart targets an undeclared binary."""
    source_basenames = ctx.source_basenames
    manifest_basenames = (
        None if ctx.tree_manifest is None
        else {os.path.basename(name.rstrip("/")) for name, _ in ctx.tree_manifest}
    )
    installed = _installed_executables(ctx.diff_text, ctx.current_text)
    if not installed:
        return

    service_texts: list[str] = []
    if ctx.tree_manifest is not None:
        for name, data in ctx.tree_manifest:
            if name.endswith(".service"):
                service_texts.append(data.decode("utf-8", errors="replace"))
    current_service = False
    body_lines: list[str] = []
    for line in parse_diff_lines(split_lines(ctx.diff_text)).lines:
        raw = line.raw
        if raw.startswith("+++ "):
            if current_service and body_lines:
                service_texts.append("\n".join(body_lines))
            current_service = raw[4:].strip().endswith(".service")
            body_lines = []
        elif current_service and line.side == "add" and not raw.startswith("+++"):
            body_lines.append(line.content)
    if current_service and body_lines:
        service_texts.append("\n".join(body_lines))

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
        add("H084", "Service ExecStart Targets Undeclared Binary", "HIGH", "persistence",
            f"systemd service runs {dst}, installed from undeclared {src_base}",
            line=_find_line(ctx.diff_text, dst.split("/")[-1]),
            exec_target=dst, source_file=src_base)
        return


def emit_path_injection(ctx: GraphContext, add: Callable) -> None:
    """H085: PATH is extended with an undeclared build-tree directory."""
    source_basenames = ctx.source_basenames
    manifest_basenames = (
        None if ctx.tree_manifest is None
        else {os.path.basename(name.rstrip("/")) for name, _ in ctx.tree_manifest}
    )
    for i, line in enumerate(ctx.lines):
        fn = ctx.scopes.within(i, _BUILD_FUNCTIONS)
        if not line.startswith("+") or fn is None:
            continue
        if i in ctx.heredoc_body:
            continue
        if len(line) > MAX_RULE_LINE_BYTES:
            continue
        body = _strip_comment(line[1:])
        for m in _PATH_ASSIGN_RE.finditer(body):
            rhs = m.group(1)
            for dirm in _PATH_BUILD_DIR_RE.finditer(rhs):
                subdir = dirm.group(1).strip('"\'').rstrip("/")
                if not subdir or "/" in subdir:
                    continue
                if subdir in source_basenames:
                    continue
                if manifest_basenames is not None and subdir in manifest_basenames:
                    continue
                add("H085", "PATH Injection With Undeclared Directory", "HIGH", "build",
                    f"{fn}() adds undeclared $srcdir/{subdir} to PATH",
                    line=_find_line(ctx.diff_text, f"PATH={rhs.strip()[:40]}"),
                    position=fn, directory=subdir)
                return


def _report_packaged_path(add: Callable, diff_text: str,
                          body: str, target: str) -> None:
    named = _BUILD_ONLY_PATH_RE.search(body)
    add("H089", "Packaged File Names A Build-Only Path", "HIGH", "persistence",
        f"a file staged into the package names {named.group(0)}, "
        "a directory that exists only while the package is built",
        line=_find_line(diff_text, body.strip()),
        path=named.group(0),
        body=body.strip()[:120])


def emit_packaged_content(ctx: GraphContext, add: Callable) -> None:
    """H089: content written into ``$pkgdir`` naming a build-only path."""
    open_target = ""
    delims: list[str] = []
    for i, line in enumerate(ctx.lines):
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
                _report_packaged_path(add, ctx.diff_text, raw, open_target)
                return
            continue
        if ctx.scopes.within(i, _SCOPE_FUNCTIONS) is None:
            continue
        body = _strip_comment(raw)
        opener = _HEREDOC_OPEN_RE.search(body)
        if opener and opener.group(2):
            delims.append(opener.group(2))
            open_target = body if _PKGDIR_TARGET_RE.search(body) else ""
            continue
        cut = body.rfind(">")
        if cut < 0:
            continue
        content, target = body[:cut], body[cut:]
        if not _PKGDIR_TARGET_RE.search(target):
            continue
        if not _CONTENT_WRITE_RE.search(content):
            continue
        if _BUILD_ONLY_PATH_RE.search(content):
            _report_packaged_path(add, ctx.diff_text, body, target)
            return


def emit_boot_artifact(ctx: GraphContext, add: Callable) -> None:
    """H095: boot or image material built from the source tree."""
    for i, line in enumerate(ctx.lines):
        fn = ctx.scopes.within(i, _SCOPE_FUNCTIONS)
        if not line.startswith("+") or fn is None or i in ctx.heredoc_body:
            continue
        body = _strip_comment(line[1:])
        m = _BOOT_ARTIFACT_RE.search(body)
        if not m:
            continue
        named = _BUILD_ONLY_PATH_RE.search(m.group(1))
        if named is None:
            continue
        add("H095", "Boot Or Image Artifact Built From The Source Tree",
            "HIGH", "persistence",
            f"{fn}() builds boot or image material naming {named.group(0)}, "
            "so content from the build tree runs before userspace",
            line=_find_line(ctx.diff_text, body.strip()[:50]),
            position=fn, body=body.strip()[:120])
        return


def emit_boot_mutation(ctx: GraphContext, add: Callable) -> None:
    """C031: a build-time function runs a boot or system-image tool.

    H095 covers the same tools when they name a path from the source tree.
    A tool run against the live host (`mkinitcpio -P`, `grub-install
    /dev/sda`, `update-initramfs -u`) names no build path and so walked past
    it, yet a recipe that builds a package must never rewrite the builder's
    boot configuration.  The install hooks are where these legitimately run,
    so only the build-time functions are in scope; `post_upgrade() {
    mkinitcpio -P; }` stays silent.
    """
    for i, line in enumerate(ctx.lines):
        if not line.startswith("+") or i in ctx.heredoc_body:
            continue
        fn = ctx.scopes.within(i, _BUILD_TIME_FUNCTIONS)
        if fn is None:
            continue
        body = _strip_comment(line[1:])
        m = _BOOT_ARTIFACT_RE.search(body)
        if not m:
            continue
        add("C031", "Boot Or System Image Tool Run During Build", "HIGH",
            "persistence",
            f"{fn}() runs {m.group(0).strip()[:40]}, rewriting the build "
            "host's boot or image configuration",
            line=i + 1, position=fn, body=body.strip()[:120])
        return


def emit_committed_build_path(name: str, head: bytes) -> dict | None:
    """H093: a committed companion runs a build-only path (manifest scope)."""
    if not _COMMITTED_CARRIER_RE.search(name.rstrip("/")):
        return None
    try:
        text = head.decode("utf-8", errors="replace")
    except Exception:
        return None
    if name.lower().endswith((".patch", ".diff")):
        text = "\n".join(
            ln.content for ln in parse_diff_lines(split_lines(text)).lines
            if ln.side == "add" and not ln.raw.startswith("+++")
        )
    for line in split_lines(text):
        named = _BUILD_ONLY_PATH_RE.search(line)
        if named is None:
            continue
        if _DESCRIPTIVE_FIELD_RE.search(line):
            continue
        return stamp({
            "rule_id": "H093",
            "name": "Committed Config Points At A Build-Only Path",
            "severity": "HIGH", "category": "persistence",
            "match": f"{name} runs {named.group(0)}, a directory that exists "
                     "only while the package is built",
            "file": name,
            "params": {"path": name, "named": named.group(0),
                       "body": line.strip()[:120]},
        })
    return None


#: Dispatch order mirrors the historical emission order so finding order is
#: preserved.  H042 (hidden drop) is intentionally absent here - it is the
#: quietest rule and is registered in the edge engine.
PERSISTENCE_INSTANCES: tuple[PersistenceInstance, ...] = (
    PersistenceInstance("H039", "Systemd ExecStart From Runtime-Writable Path",
                        "runtime_writable", False, "HIGH",
                        "docs/reference/rules/install-and-persist.md",
                        ("tests/test_persistence_rules.py",), emit_systemd_unit),
    PersistenceInstance("H062", "Pacman Hook Installed", "pacman_hook", False,
                        "MEDIUM", "docs/reference/rules/install-and-persist.md",
                        ("tests/test_persistence_rules.py",), emit_pacman_hook),
    PersistenceInstance("H032", "Write To User Home Or RC", "home_rc", False,
                        "HIGH/CRITICAL", "docs/reference/rules/install-and-persist.md",
                        ("tests/test_persistence_rules.py",), emit_home_rc),
    PersistenceInstance("H038", "World-Writable Staging", "world_writable",
                        False, "HIGH",
                        "docs/reference/rules/staging-and-recon.md",
                        ("tests/test_persistence_rules.py",), emit_worldwritable),
    PersistenceInstance("H076", "Build Writes Outside Staging Root",
                        "absolute_outside", False, "HIGH",
                        "docs/reference/rules/staging-and-recon.md",
                        ("tests/test_persistence_rules.py",), emit_outside_staging),
    PersistenceInstance("H004", "Privilege Escalation", "privilege", False,
                        "CRITICAL", "docs/reference/rules/fetch-and-execution.md",
                        ("tests/test_rules.py",), emit_sudo),
    PersistenceInstance("H017", "Install Hook Fetches Or Executes",
                        "install_hook", False, "HIGH",
                        "docs/reference/rules/install-and-persist.md",
                        ("tests/test_deps_rules.py",), emit_install_hook),
    PersistenceInstance("H084", "Service ExecStart Targets Undeclared Binary",
                        "execstart_declaration", True, "HIGH",
                        "docs/reference/rules/install-and-persist.md",
                        ("tests/regressions/test_followup_fixes.py",),
                        emit_service_binary),
    PersistenceInstance("H085", "PATH Injection With Undeclared Directory",
                        "path_injection", True, "HIGH",
                        "docs/reference/rules/staging-and-recon.md",
                        ("tests/regressions/test_scope_closure.py",),
                        emit_path_injection),
    PersistenceInstance("H089", "Packaged File Names A Build-Only Path",
                        "build_only_content", False, "HIGH",
                        "docs/reference/rules/install-and-persist.md",
                        ("tests/regressions/test_execution_surfaces.py",),
                        emit_packaged_content),
    PersistenceInstance("H095", "Boot Or Image Artifact Built From The Source Tree",
                        "build_only_content", False, "HIGH",
                        "docs/reference/rules/install-and-persist.md",
                        ("tests/regressions/test_w_series.py",),
                        emit_boot_artifact),
    PersistenceInstance("C031", "Boot Or System Image Tool Run During Build",
                        "boot_mutation", False, "HIGH",
                        "docs/reference/rules/install-and-persist.md",
                        ("tests/test_persistence_rules.py",),
                        emit_boot_mutation),
    # H093 is manifest-scope: its emitter is `emit_committed_build_path`,
    # called by `scan_tree_manifest`, so the table row has no graph emitter.
    PersistenceInstance("H093", "Committed Config Points At A Build-Only Path",
                        "build_only_content", True, "HIGH",
                        "docs/reference/rules/install-and-persist.md",
                        ("tests/regressions/test_w_series.py",), None),
)


def run_persistence_instances(
    ctx: GraphContext, add: Callable, *, only: frozenset[str] | None = None
) -> None:
    """Dispatch the persistence predicates over *ctx*.

    A row with no graph emitter (the manifest-scope H093) is skipped, so a
    dispatch without *only* is safe rather than a ``TypeError``.
    """
    for instance in PERSISTENCE_INSTANCES:
        if instance.emitter is None:
            continue
        if only is not None and instance.rule_id not in only:
            continue
        instance.emitter(ctx, add)
