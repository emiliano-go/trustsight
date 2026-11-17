"""A-series: artifact inspection.

Mechanically distinct from every text-analysis series: an A rule inspects
the built package manifest, not the diff.  It is the optional L9 layer -
off by default, execution only inside the project's rootless, networkless
container, and never blended into the static score.

This module is the *inspection* half, and it is pure: it reads a manifest
(file list, modes, types) and the recipe's declared surface.  The build
lane that produces the manifest runs elsewhere; when it is not
enabled or the read-role sandbox is unavailable, the caller reports
``l9_unavailable`` - a weight-0 boundary, never a negative verdict.

The production L9 path parses and inspects the manifest inside the
read-role sandbox; this module supplies the bounded, side-effect-free
inspector that worker calls.

The static core never executes package code.  Nothing here runs anything.
"""

from __future__ import annotations

import posixpath
import re

from ..tokenizer import split_lines

__all__ = ["inspect_manifest", "inspect_manifest_bounded", "unsafe_runpath"]

#: Paths whose executable bit is ordinary; an executable outside them is A005.
_USUAL_EXEC_PREFIXES = ("/usr/bin/", "/usr/sbin/", "/usr/lib/", "/bin/", "/sbin/")
#: systemd unit/timer/tmpfiles locations.
_UNIT_SUFFIXES = (".service", ".timer", ".socket", ".mount", ".target", ".tmpfiles")
#: Files the recipe may justify a setuid bit for via a documented mode intent.
_SETUID_JUSTIFICATIONS = ("setuid", "setgid", "A_SETUID_OK")


#: Bounded content inspection for a shipped hook/udev rule/install script.
MAX_CONTENT_BYTES = 64 * 1024
MAX_CONTENT_TOTAL = 256 * 1024
MAX_CONTENT_LINE_BYTES = 8 * 1024

#: Bounded L9 manifest inspection.  The manifest is attacker-controlled
#: evidence, so every count, length and result list has a fixed ceiling.
MAX_MANIFEST_BYTES = 8 * 1024 * 1024
MAX_MANIFEST_ENTRIES = 10_000
MAX_LINKS_PER_ENTRY = 4_096
MAX_LINKS_TOTAL = 65_536
MAX_RUNPATHS_PER_ENTRY = 256
MAX_RUNPATH_TOTAL = 4_096
MAX_PATH_BYTES = 4_096
MAX_PATH_TOTAL = 2 * 1024 * 1024
MAX_FINDINGS = 4_096
MAX_FINDING_BYTES = 8 * 1024
MAX_LIMIT_REASONS = 16
MAX_LIMIT_REASON_BYTES = 128
MAX_CAPS_DISPLAY = 256
MAX_DECLARED_DEPENDS = 10_000
MAX_DECLARED_UNITS = 10_000
MAX_DECLARED_TEXT_BYTES = 256 * 1024
MAX_DECLARED_MODE_BYTES = 1_024

#: Paths that extend privilege or persistence beyond the package's files.
_PRIVILEGED_PREFIXES = (
    "/etc/polkit-1/", "/etc/sudoers.d/", "/etc/pam.d/", "/etc/modprobe.d/",
    "/etc/modules-load.d/", "/usr/lib/modules/", "/lib/modules/",
)


def _is_privileged_surface(path: str) -> bool:
    lower = path.lower()
    return (
        lower.startswith(_PRIVILEGED_PREFIXES)
        or lower.endswith(".ko")
        or "/kernel/" in lower
    )


def _is_unit(path: str) -> bool:
    lower = path.lower()
    if lower.endswith(_UNIT_SUFFIXES):
        return True
    return "/tmpfiles.d/" in lower or lower.endswith(".tmpfiles")


def _unusual_exec(path: str) -> bool:
    return not path.startswith(_USUAL_EXEC_PREFIXES)


def unsafe_runpath(value) -> bool:
    """True for a DT_RPATH/DT_RUNPATH that searches an unsafe location.

    ``$ORIGIN`` is relative to the binary's own (package-owned) directory, so
    it is not automatically unsafe; an empty, relative or system-temp path is.
    """
    path = str(value or "").strip()
    if not path:
        return True
    if "$ORIGIN" in path or "${ORIGIN}" in path:
        # Resolve the expansion against a sentinel package directory, then
        # normalise the lexical path.  A token such as ``$ORIGIN/../../tmp``
        # must not inherit blanket trust merely because it mentions ORIGIN.
        resolved = path.replace("${ORIGIN}", "$ORIGIN").replace(
            "$ORIGIN", "/__trustsight_origin__")
        if not resolved.startswith("/"):
            return True
        resolved = posixpath.normpath(resolved)
        if (resolved == "/__trustsight_origin__"
                or resolved.startswith("/__trustsight_origin__/")):
            return False
        if resolved == "/":
            return True
        path = resolved
    if path in (".", "..") or not path.startswith("/"):
        return True
    if path.startswith("/"):
        path = "/" + path.lstrip("/")
        path = posixpath.normpath(path)
    if path == "/":
        return True
    for prefix in ("/tmp", "/var/tmp", "/dev/shm", "/home", "/root"):
        if path == prefix or path.startswith(prefix + "/"):
            return True
    return False


def _hook_is_broad(content: str) -> bool:
    """A libalpm hook whose trigger fires on every transaction and runs a command."""
    broad = has_exec = False
    for raw in split_lines(content):
        line = raw.strip()[:MAX_CONTENT_LINE_BYTES]
        if not line or line.startswith(("#", ";")):
            continue
        key, sep, value = line.partition("=")
        if not sep:
            continue
        key = key.strip().lower()
        value = value.strip().strip("\"'")
        if key == "operation" and value.lower() in ("*", "any", "all"):
            broad = True
        elif key == "exec" and value:
            has_exec = True
    return broad and has_exec


def _strip_comments(content: str) -> str:
    return "\n".join(
        line for line in split_lines(content)
        if not line.strip().startswith(("#", ";")))


def _runs_fetch_or_user_path(content: str) -> bool:
    """A hook/udev/install body that fetches, or runs from a user/temp path."""
    for raw in split_lines(content):
        line = raw.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.lower().startswith("exec"):
            _, _, command = line.partition("=")
            line = command.strip()
        # A printer that only mentions a client or a path is output, not a
        # command.  Command substitution and a pipe still execute and remain
        # in scope.
        if (re.match(r"^(?:\S*/)?(?:echo|printf)\b", line, re.IGNORECASE)
                and not re.search(
                    r"\$\(|`|\|\s*(?:\S*/)?(?:ba|z|da|k)?sh\b", line)):
            continue
        lowered = line.lower()
        for token in ("curl", "wget", "aria2c"):
            if token in lowered:
                return True
        for token in ("/tmp/", "/dev/shm", "/var/tmp/", "$home", "${home}",
                      "~/", "/home/", "/root/"):
            if token in lowered:
                return True
    return False


def _udev_runs_program(content: str) -> bool:
    lowered = _strip_comments(content).lower()
    return any(token in lowered for token in (
        "run+=", "run{", "program==", "import{program}"))


def _cap_utf8(value: str, limit: int) -> tuple[str, bool]:
    encoded = value.encode("utf-8", "replace")
    if len(encoded) <= limit:
        return value, False
    return encoded[:limit].decode("utf-8", "ignore"), True


def inspect_manifest_bounded(manifest, declared=None) -> dict:
    """A001-A015 over an attacker-controlled manifest, with visible bounds.

    The returned ``limits`` dictionary records every ceiling reached.  A
    bounded inspection is never silently complete: a caller that sees
    ``truncated`` must report partial coverage.
    """
    reasons: list[str] = []
    truncated = False

    def note(reason: str) -> None:
        if len(reasons) >= MAX_LIMIT_REASONS:
            return
        reason, _cut = _cap_utf8(reason, MAX_LIMIT_REASON_BYTES)
        if reason not in reasons:
            reasons.append(reason)

    if not isinstance(declared, dict):
        declared = {}
        truncated = True
        note("invalid declared")

    depends: set[str] = set()
    raw_depends = declared.get("depends") or ()
    if isinstance(raw_depends, str):
        raw_depends = (raw_depends,)
    if isinstance(raw_depends, (list, tuple)):
        for index, dep in enumerate(raw_depends):
            if index >= MAX_DECLARED_DEPENDS:
                truncated = True
                note("declared depends")
                break
            if not isinstance(dep, str):
                continue
            dep, cut = _cap_utf8(dep, MAX_PATH_BYTES)
            if cut:
                truncated = True
                note("declared depends")
            depends.add(dep.split(">", 1)[0].split("=", 1)[0].strip())
    elif raw_depends:
        truncated = True
        note("invalid declared")

    declared_units: set[str] = set()
    raw_units = declared.get("units") or ()
    if isinstance(raw_units, str):
        raw_units = (raw_units,)
    if isinstance(raw_units, (list, tuple)):
        for index, unit in enumerate(raw_units):
            if index >= MAX_DECLARED_UNITS:
                truncated = True
                note("declared units")
                break
            if not isinstance(unit, str):
                continue
            unit, cut = _cap_utf8(unit, MAX_PATH_BYTES)
            if cut:
                truncated = True
                note("declared units")
            declared_units.add(unit)
    elif raw_units:
        truncated = True
        note("invalid declared")

    raw_mode = declared.get("mode_intent")
    mode_intent = ""
    if isinstance(raw_mode, str):
        mode_intent, cut = _cap_utf8(raw_mode.lower(), MAX_DECLARED_MODE_BYTES)
        if cut:
            truncated = True
            note("declared mode")
    elif raw_mode:
        truncated = True
        note("invalid declared")
    justified_setuid = any(j.lower() in mode_intent for j in _SETUID_JUSTIFICATIONS)

    out: list[dict] = []
    content_total = 0
    path_total = 0
    links_seen = 0
    runpaths_seen = 0
    entries_seen = 0
    invalid_entries = 0

    for index, entry in enumerate(manifest or ()):
        if index >= MAX_MANIFEST_ENTRIES:
            truncated = True
            note("manifest entries")
            break
        entries_seen += 1
        if not isinstance(entry, dict):
            invalid_entries += 1
            truncated = True
            note("invalid entries")
            continue
        if len(out) >= MAX_FINDINGS:
            truncated = True
            note("findings")
            break

        raw_path = entry.get("path")
        if raw_path is None or raw_path == "":
            continue
        if not isinstance(raw_path, str):
            invalid_entries += 1
            truncated = True
            note("invalid entries")
            continue
        path, cut = _cap_utf8(raw_path, MAX_PATH_BYTES)
        if cut:
            truncated = True
            note("paths")
        path_bytes = len(path.encode("utf-8", "replace"))
        if path_total + path_bytes > MAX_PATH_TOTAL:
            remaining = max(0, MAX_PATH_TOTAL - path_total)
            path, cut = _cap_utf8(path, remaining)
            path_bytes = len(path.encode("utf-8", "replace"))
            truncated = True
            note("path bytes")
            if not path:
                continue
        path_total += path_bytes

        mode = entry.get("mode")
        setuid = bool(entry.get("setuid")) or bool(entry.get("setgid"))
        if setuid and not justified_setuid:
            out.append({
                "rule_id": "A001", "name": "Setuid File In Artifact",
                "severity": "HIGH", "category": "artifact",
                "match": f"{path} carries the setuid/setgid bit",
                "file": path,
            })
        if _is_unit(path) and path not in declared_units:
            out.append({
                "rule_id": "A002", "name": "Undeclared Unit In Artifact",
                "severity": "MEDIUM", "category": "artifact",
                "match": f"{path} is a unit/timer/tmpfiles the recipe does not declare",
                "file": path,
            })

        raw_elf = entry.get("elf")
        elf = raw_elf if isinstance(raw_elf, dict) else {}
        if raw_elf and not isinstance(raw_elf, dict):
            invalid_entries += 1
            truncated = True
            note("invalid entries")

        raw_links = entry.get("links")
        if not raw_links:
            raw_links = elf.get("needed") or ()
        if isinstance(raw_links, str):
            raw_links = (raw_links,)
        elif not isinstance(raw_links, (list, tuple)):
            if raw_links:
                invalid_entries += 1
                truncated = True
                note("invalid entries")
            raw_links = ()
        entry_links = 0
        for lib in raw_links:
            if (entry_links >= MAX_LINKS_PER_ENTRY
                    or links_seen >= MAX_LINKS_TOTAL):
                truncated = True
                note("links")
                break
            entry_links += 1
            links_seen += 1
            if not isinstance(lib, str):
                invalid_entries += 1
                truncated = True
                note("invalid entries")
                continue
            lib, cut = _cap_utf8(lib, MAX_PATH_BYTES)
            if cut:
                truncated = True
                note("library names")
            base = lib.rsplit("/", 1)[-1]
            if not base or base.split(".so", 1)[0] in depends:
                continue
            if ".so" in base and base not in depends:
                out.append({
                    "rule_id": "A003", "name": "Library Outside Depends",
                    "severity": "MEDIUM", "category": "artifact",
                    "match": f"{path} links {base}, outside the declared depends closure",
                    "file": path,
                })
                break

        raw_caps = entry.get("caps")
        if raw_caps:
            caps_text, cut = _cap_utf8(
                raw_caps if isinstance(raw_caps, str) else str(raw_caps),
                MAX_CAPS_DISPLAY,
            )
            if cut:
                truncated = True
                note("caps display")
            out.append({
                "rule_id": "A006", "name": "File Capabilities In Artifact",
                "severity": "HIGH", "category": "artifact",
                "match": f"{path} carries Linux file capabilities: {caps_text}",
                "file": path,
            })
        if _is_privileged_surface(path):
            out.append({
                "rule_id": "A007", "name": "Privileged Surface In Artifact",
                "severity": "MEDIUM", "category": "artifact",
                "match": (f"{path} is a polkit/sudoers/PAM/kernel-module surface "
                          "the declared recipe does not explain"),
                "file": path,
            })
        if elf:
            runpaths: list[str] = []
            entry_runpaths = 0
            for key in ("rpath", "runpath"):
                values = elf.get(key) or ()
                if isinstance(values, str):
                    values = (values,)
                elif not isinstance(values, (list, tuple)):
                    if values:
                        invalid_entries += 1
                        truncated = True
                        note("invalid entries")
                    values = ()
                for runpath in values:
                    if (entry_runpaths >= MAX_RUNPATHS_PER_ENTRY
                            or runpaths_seen >= MAX_RUNPATH_TOTAL):
                        truncated = True
                        note("runpaths")
                        break
                    entry_runpaths += 1
                    runpaths_seen += 1
                    if not isinstance(runpath, str):
                        invalid_entries += 1
                        truncated = True
                        note("invalid entries")
                        continue
                    runpath, cut = _cap_utf8(runpath, MAX_PATH_BYTES)
                    if cut:
                        truncated = True
                        note("runpaths")
                    runpaths.append(runpath)
            unsafe = [rp for rp in runpaths if unsafe_runpath(rp)]
            if unsafe:
                out.append({
                    "rule_id": "A014",
                    "name": "Unsafe ELF Runpath",
                    "severity": "HIGH", "category": "artifact",
                    "match": (f"{path} searches for libraries in "
                              + ", ".join(unsafe[:3])),
                    "file": path,
                })
            if elf.get("packed"):
                out.append({
                    "rule_id": "A015",
                    "name": "Packed Or Encrypted ELF Section",
                    "severity": "MEDIUM", "category": "artifact",
                    "match": f"{path} is a packed or encrypted ELF binary",
                    "file": path,
                })
        if entry.get("bpf") or path.lower().endswith((".bpf.o", ".bpf.c")):
            out.append({
                "rule_id": "A008", "name": "eBPF Artifact In Package",
                "severity": "HIGH", "category": "artifact",
                "match": f"{path} is an eBPF object/loader (rootkit-capable)",
                "file": path,
            })

        content = entry.get("content")
        if isinstance(content, str) and content:
            encoded = content.encode("utf-8", "replace")
            if len(encoded) > MAX_CONTENT_BYTES:
                encoded = encoded[:MAX_CONTENT_BYTES]
                truncated = True
                note("content bytes")
            if content_total + len(encoded) > MAX_CONTENT_TOTAL:
                truncated = True
                note("content bytes")
            else:
                content_total += len(encoded)
                content = encoded.decode("utf-8", "ignore")
                lower_path = path.lower()
                if lower_path.endswith(".hook") and _hook_is_broad(content):
                    out.append({
                        "rule_id": "A011",
                        "name": "Hook Runs On Every Transaction",
                        "severity": "MEDIUM", "category": "artifact",
                        "match": (f"{path} is a hook with a broad trigger and "
                                  "an Exec command"),
                        "file": path,
                    })
                if (lower_path.endswith((".hook", ".rules", ".install"))
                        and _runs_fetch_or_user_path(content)):
                    out.append({
                        "rule_id": "A012",
                        "name": "Shipped Hook Or Udev Fetches Or Runs A User Path",
                        "severity": "HIGH", "category": "artifact",
                        "match": (f"{path} fetches or runs a program from a "
                                  "user/temp path"),
                        "file": path,
                    })
                if lower_path.endswith(".rules") and _udev_runs_program(content):
                    out.append({
                        "rule_id": "A013",
                        "name": "Udev Rule Runs A Program",
                        "severity": "MEDIUM", "category": "artifact",
                        "match": f"{path} runs a program from a udev rule",
                        "file": path,
                    })
        if entry.get("world_writable"):
            out.append({
                "rule_id": "A005", "name": "Unusual Artifact Mode",
                "severity": "INFO", "category": "artifact",
                "match": f"{path} is world-writable",
                "file": path,
            })
        elif (isinstance(mode, int) and not isinstance(mode, bool)
                and mode & 0o111 and not path.startswith("/usr/bin/")
                and _unusual_exec(path)):
            out.append({
                "rule_id": "A005", "name": "Unusual Artifact Mode",
                "severity": "INFO", "category": "artifact",
                "match": f"{path} is executable in an unusual path",
                "file": path,
            })

    built_install = declared.get("built_install_text")
    declared_install = declared.get("install_text")
    if isinstance(built_install, str) and isinstance(declared_install, str):
        built_text, built_cut = _cap_utf8(built_install, MAX_DECLARED_TEXT_BYTES)
        declared_text, declared_cut = _cap_utf8(
            declared_install, MAX_DECLARED_TEXT_BYTES)
        if built_cut or declared_cut:
            truncated = True
            note("declared text")
        elif built_text and declared_text and built_text != declared_text:
            out.append({
                "rule_id": "A004",
                "name": "Install Hook Diverges From Declaration",
                "severity": "HIGH", "category": "artifact",
                "match": "the built .INSTALL differs from the recipe's install= file",
                "file": ".INSTALL",
            })

    if len(out) > MAX_FINDINGS:
        del out[MAX_FINDINGS:]
        truncated = True
        note("findings")

    return {
        "findings": out,
        "limits": {
            "entries_seen": entries_seen,
            "entries_limit": MAX_MANIFEST_ENTRIES,
            "links_seen": links_seen,
            "links_limit": MAX_LINKS_TOTAL,
            "findings_returned": len(out),
            "findings_limit": MAX_FINDINGS,
            "content_bytes": content_total,
            "content_limit": MAX_CONTENT_TOTAL,
            "invalid_entries": invalid_entries,
            "truncated": truncated,
            "reasons": reasons,
        },
    }


def inspect_manifest(manifest, declared=None) -> list[dict]:
    """A001-A015 over a built-package manifest.

    This compatibility wrapper returns only findings.  Production callers use
    :func:`inspect_manifest_bounded`; it exposes the truncation state a clean
    verdict must not lose.
    """
    return inspect_manifest_bounded(manifest, declared)["findings"]
