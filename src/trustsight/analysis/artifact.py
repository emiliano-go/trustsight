"""A-series: artifact inspection (Addendum 5 §12).

Mechanically distinct from every text-analysis series: an A rule inspects
the built package manifest, not the diff.  It is the optional L9 layer -
off by default, execution only inside the project's rootless, networkless
container, and never blended into the static score.

This module is the *inspection* half, and it is pure: it reads a manifest
(file list, modes, types) and the recipe's declared surface.  The build
lane that produces the manifest runs elsewhere (§12.4); when it is not
enabled or the container is unavailable, the caller reports
``l9_unavailable`` - a weight-0 boundary, never a negative verdict.

The static core never executes package code.  Nothing here runs anything.
"""

from __future__ import annotations

__all__ = ["inspect_manifest"]

#: Paths whose executable bit is ordinary; an executable outside them is A005.
_USUAL_EXEC_PREFIXES = ("/usr/bin/", "/usr/sbin/", "/usr/lib/", "/bin/", "/sbin/")
#: systemd unit/timer/tmpfiles locations.
_UNIT_SUFFIXES = (".service", ".timer", ".socket", ".mount", ".target", ".tmpfiles")
#: Files the recipe may justify a setuid bit for via a documented mode intent.
_SETUID_JUSTIFICATIONS = ("setuid", "setgid", "A_SETUID_OK")


def _is_unit(path: str) -> bool:
    lower = path.lower()
    if lower.endswith(_UNIT_SUFFIXES):
        return True
    return "/tmpfiles.d/" in lower or lower.endswith(".tmpfiles")


def _unusual_exec(path: str) -> bool:
    return not path.startswith(_USUAL_EXEC_PREFIXES)


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
        for lib in entry.get("links", ()) or ():
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
