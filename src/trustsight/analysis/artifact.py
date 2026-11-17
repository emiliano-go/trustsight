"""A-series: artifact inspection.

Mechanically distinct from every text-analysis series: an A rule inspects
the built package manifest, not the diff.  It is the optional L9 layer -
off by default, execution only inside the project's rootless, networkless
container, and never blended into the static score.

This module is the *inspection* half, and it is pure: it reads a manifest
(file list, modes, types) and the recipe's declared surface.  The build
lane that produces the manifest runs elsewhere; when it is not
enabled or the container is unavailable, the caller reports
``l9_unavailable`` - a weight-0 boundary, never a negative verdict.

The static core never executes package code.  Nothing here runs anything.
"""

from __future__ import annotations

__all__ = ["inspect_manifest", "unsafe_runpath"]

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
        return False
    if path in (".", "..") or not path.startswith("/"):
        return True
    for prefix in ("/tmp", "/var/tmp", "/dev/shm", "/home", "/root"):
        if path == prefix or path.startswith(prefix + "/"):
            return True
    return False


def _hook_is_broad(content: str) -> bool:
    """A libalpm hook whose trigger fires on every transaction and runs a command."""
    broad = has_exec = False
    for raw in content.splitlines():
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


def _runs_fetch_or_user_path(content: str) -> bool:
    """A hook/udev/install body that fetches, or runs from a user/temp path."""
    lowered = content.lower()
    for token in ("curl", "wget", "aria2c"):
        if token in lowered:
            return True
    for token in ("/tmp/", "/dev/shm", "/var/tmp/", "$home", "${home}",
                  "~/", "/home/", "/root/"):
        if token in lowered:
            return True
    for token in ("sh -c", "bash -c", "dash -c", "zsh -c", "ksh -c"):
        if token in lowered:
            return True
    return False


def _udev_runs_program(content: str) -> bool:
    lowered = content.lower()
    return any(token in lowered for token in (
        "run+=", "run{", "program==", "import{program}"))


def inspect_manifest(manifest, declared=None) -> list[dict]:
    """A001-A005 over a built-package manifest.

    *manifest* is an iterable of file records: ``{"path", "mode",
    "setuid", "setgid", "unit", "links", "world_writable"}``.  *declared* is
    the recipe's declared surface: ``{"depends", "units", "install_text",
    "mode_intent"}``.  Returns findings; each has a ``severity`` and never
    changes the static score.
    """
    declared = declared or {}
    depends = {str(d).split(">", 1)[0].split("=", 1)[0].strip()
               for d in (declared.get("depends") or ())}
    declared_units = {str(u) for u in (declared.get("units") or ())}
    mode_intent = str(declared.get("mode_intent") or "").lower()
    justified_setuid = any(j.lower() in mode_intent for j in _SETUID_JUSTIFICATIONS)

    out: list[dict] = []
    content_total = 0
    for entry in manifest or ():
        path = str(entry.get("path", ""))
        if not path:
            continue
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
        elf = entry.get("elf") or {}
        links = entry.get("links") or elf.get("needed") or ()
        for lib in links:
            base = str(lib).rsplit("/", 1)[-1]
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
        if entry.get("caps"):
            out.append({
                "rule_id": "A006", "name": "File Capabilities In Artifact",
                "severity": "HIGH", "category": "artifact",
                "match": f"{path} carries Linux file capabilities: {entry['caps']}",
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
            runpaths = list(elf.get("rpath") or ()) + list(
                elf.get("runpath") or ())
            unsafe = [rp for rp in runpaths if unsafe_runpath(rp)]
            if unsafe:
                out.append({
                    "rule_id": "A014",
                    "name": "Unsafe ELF Runpath",
                    "severity": "HIGH", "category": "artifact",
                    "match": (f"{path} searches for libraries in "
                              + ", ".join(str(rp) for rp in unsafe[:3])),
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
                content = encoded[:MAX_CONTENT_BYTES].decode(
                    "utf-8", "ignore")
            if content_total + len(content) <= MAX_CONTENT_TOTAL:
                content_total += len(content)
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
        elif (isinstance(mode, int) and mode & 0o111
                and not path.startswith("/usr/bin/")
                and _unusual_exec(path)):
            out.append({
                "rule_id": "A005", "name": "Unusual Artifact Mode",
                "severity": "INFO", "category": "artifact",
                "match": f"{path} is executable in an unusual path",
                "file": path,
            })

    # A004: the built .INSTALL differs from the declared install= file.
    built_install = declared.get("built_install_text")
    declared_install = declared.get("install_text")
    if built_install and declared_install and built_install != declared_install:
        out.append({
            "rule_id": "A004", "name": "Install Hook Diverges From Declaration",
            "severity": "HIGH", "category": "artifact",
            "match": "the built .INSTALL differs from the recipe's install= file",
            "file": ".INSTALL",
        })
    return out
