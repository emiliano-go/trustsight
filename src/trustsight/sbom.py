"""CycloneDX 1.5 SBOM export.

The document describes what the recipe declares and what the analysis saw:
the package itself, its declared sources, and its dependency components.
It is a projection, not a second analysis.  Findings come from the same
evaluated report every other surface renders, and nothing here fetches,
executes or extracts a package.

The export is deterministic (no timestamp or random serial), bounded, and
attributes each finding to the component its evidence names.  A component
that cannot be resolved is marked opaque rather than omitted or guessed.
"""

from __future__ import annotations

import json
import re
from typing import Any, Iterable

from .deps import normalize_dependency
from .safe_text import clean

__all__ = [
    "MAX_RECIPE_BYTES",
    "MAX_SBOM_BYTES",
    "MAX_SBOM_COMPONENTS",
    "MAX_SBOM_FINDINGS",
    "build_sbom",
    "render_sbom",
    "sbom_for_package",
]

#: Bounds on what a hostile recipe can make this export retain.  A real
#: PKGBUILD is far below every one of them; the ceilings are here because
#: the counts and names are attacker-chosen.
MAX_SBOM_COMPONENTS = 192
MAX_SBOM_FINDINGS = 1024
MAX_RECIPE_BYTES = 512 * 1024
MAX_PROPERTY_BYTES = 192
MAX_SBOM_BYTES = 2 * 1024 * 1024
MAX_NAME_BYTES = 128

_DEP_FIELDS = ("depends", "makedepends", "checkdepends", "optdepends")
_CHECKSUM_ALGS = (
    ("sha512sums", "SHA-512"),
    ("sha384sums", "SHA-384"),
    ("sha256sums", "SHA-256"),
    ("sha224sums", "SHA-224"),
    ("sha1sums", "SHA-1"),
    ("md5sums", "MD5"),
    ("b2sums", "BLAKE2b-512"),
)
_VCS_PREFIXES = ("git+", "svn+", "hg+", "bzr+")
_PIN_MARKERS = (
    ("#commit=", "commit"),
    ("#tag=", "tag"),
    ("#rev=", "rev"),
    ("?rev=", "rev"),
    ("?tag=", "tag"),
    ("#branch=", "branch"),
)
_CONSTRAINT_RE = re.compile(r"([<>=]+)\s*([^\s:]+)")
_REF_RE = re.compile(r"[^A-Za-z0-9._~:@/+-]+")


def _text(value: Any, limit: int = MAX_PROPERTY_BYTES) -> str:
    text = clean("" if value is None else str(value))
    return text[:limit] if len(text) > limit else text


def _ref(value: Any) -> str:
    token = _REF_RE.sub("-", _text(value, 160)).strip("-")
    return token or "unknown"


def _prop(name: str, value: Any) -> dict:
    return {"name": _text(name, MAX_NAME_BYTES), "value": _text(value)}


def _props(items: Iterable[dict]) -> list[dict]:
    return sorted(items, key=lambda item: (item["name"], item["value"]))


def _version() -> str:
    try:
        from . import __version__
    except Exception:  # pragma: no cover - an installed package always has it
        return ""
    return _text(__version__, 64)


def _recipe_arrays(text: str) -> tuple[dict[str, tuple[str, ...]], str]:
    """Read the declared arrays, naming why the projection is incomplete."""
    if not text:
        return {}, "recipe_unavailable"
    clipped = text[:MAX_RECIPE_BYTES]
    try:
        from .recipedoc import parse_recipe

        doc = parse_recipe(clipped)
    except Exception:
        return {}, "recipe_unavailable"
    status = "recipe_truncated" if len(text) > MAX_RECIPE_BYTES else ""
    return dict(doc.arrays), status


def _suffixes(arrays: dict[str, tuple[str, ...]], family: str) -> list[str]:
    found = {""} if family in arrays else set()
    prefix = family + "_"
    found.update(key[len(family):] for key in arrays if key.startswith(prefix))
    return sorted(found)


def _checksum_for(
    arrays: dict[str, tuple[str, ...]], suffix: str
) -> tuple[tuple[str, ...], str]:
    for name, algorithm in _CHECKSUM_ALGS:
        key = name + suffix
        if key in arrays:
            return arrays[key], algorithm
    return (), ""


def _basename(url: str) -> str:
    name = url.rsplit("/", 1)[-1]
    return name.split("?", 1)[0].split("#", 1)[0] or url


def _split_source(entry: str) -> tuple[str, str]:
    if "::" in entry:
        name, url = entry.split("::", 1)
        return name.strip() or _basename(url), url.strip()
    return _basename(entry), entry


def _pin(url: str) -> tuple[str, str]:
    for marker, kind in _PIN_MARKERS:
        if marker in url:
            value = url.split(marker, 1)[1].split("&", 1)[0].split("#", 1)[0]
            return kind, value
    return "", ""


def _source_rows(arrays: dict[str, tuple[str, ...]]) -> list[dict]:
    rows: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for suffix in _suffixes(arrays, "source"):
        entries = arrays.get("source" + suffix) or ()
        sums, algorithm = _checksum_for(arrays, suffix)
        for index, raw in enumerate(entries):
            entry = _text(raw, 1024)
            if not entry:
                continue
            name, url = _split_source(entry)
            checksum = _text(sums[index], 256) if index < len(sums) else ""
            key = (url, checksum)
            if key in seen:
                continue
            seen.add(key)
            lowered = url.lower()
            is_vcs = lowered.startswith(_VCS_PREFIXES)
            skip = checksum.upper() == "SKIP"
            reasons = []
            if is_vcs:
                reasons.append("vcs_source")
            if skip:
                reasons.append("skip_checksum")
            elif not checksum:
                reasons.append("unpinned")
            pin_kind, pin_value = _pin(url)
            rows.append({
                "name": name,
                "url": url,
                "checksum": checksum,
                "algorithm": algorithm,
                "pin_kind": pin_kind,
                "pin_value": pin_value,
                "opaque": reasons,
            })
    return sorted(rows, key=lambda row: (row["url"], row["name"], row["checksum"]))


def _constraint(raw: str) -> str:
    match = _CONSTRAINT_RE.search(str(raw))
    if match is None:
        return ""
    operator = match.group(1)
    if operator == "==":
        operator = "="
    return f"{operator}{match.group(2).strip()}"


def _dependency_rows(fact, arrays: dict[str, tuple[str, ...]]) -> dict[str, dict]:
    rows: dict[str, dict] = {}

    def row(name: str) -> dict:
        return rows.setdefault(
            name, {"name": name, "fields": set(), "constraints": set()})

    for field in _DEP_FIELDS:
        for suffix in _suffixes(arrays, field):
            for raw in arrays.get(field + suffix) or ():
                name = normalize_dependency(str(raw))
                if not name:
                    continue
                item = row(name)
                item["fields"].add(field)
                constraint = _constraint(str(raw))
                if constraint:
                    item["constraints"].add(constraint)

    for dependency in getattr(fact, "dependencies", None) or ():
        name = normalize_dependency(getattr(dependency, "name", ""))
        if name:
            row(name)["analyzed"] = dependency
    return rows


def _strings(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield str(key)
            yield from _strings(item)
    elif isinstance(value, (list, tuple, set)):
        for item in value:
            yield from _strings(item)


def _finding_key(finding: dict) -> tuple[str, str]:
    return (
        _text(finding.get("rule_id"), MAX_NAME_BYTES),
        _text(finding.get("severity"), 32) or "UNKNOWN",
    )


def _attach_findings(
    findings: list[dict], sources: list[dict], dependencies: dict[str, dict]
) -> list[tuple[str, str]]:
    root: list[tuple[str, str]] = []
    remaining = MAX_SBOM_FINDINGS
    source_tokens = []
    for source in sources:
        tokens = {
            token for token in (
                source["url"], source["name"], _basename(source["url"]))
            if len(token) >= 4
        }
        source_tokens.append(tokens)

    for finding in findings:
        if remaining <= 0:
            break
        key = _finding_key(finding)
        evidence = finding.get("evidence") or {}
        haystack = [
            _text(value, 1024)
            for value in _strings(evidence)
        ]
        haystack.append(_text(finding.get("file"), 512))
        assigned = False
        for source, tokens in zip(sources, source_tokens):
            if any(token in value for token in tokens for value in haystack):
                source.setdefault("findings", []).append(key)
                assigned = True
                break
        if assigned:
            remaining -= 1
            continue
        evidence_map = evidence if isinstance(evidence, dict) else {}
        dependency_name = _text(
            evidence_map.get("dep_name"), MAX_NAME_BYTES).lower()
        if dependency_name in dependencies:
            dependencies[dependency_name].setdefault("findings", []).append(key)
            remaining -= 1
            continue
        root.append(key)
        remaining -= 1
    return root


def _component(
    kind: str,
    name: str,
    version: str,
    ref: str,
    properties: list[dict],
    *,
    scope: str = "",
    hashes: Iterable[dict] = (),
    references: Iterable[dict] = (),
) -> dict:
    component = {
        "type": kind,
        "name": _text(name, MAX_NAME_BYTES) or "unknown",
        "bom-ref": ref,
    }
    if version:
        component["version"] = _text(version, MAX_NAME_BYTES)
    if scope:
        component["scope"] = scope
    if hashes:
        component["hashes"] = sorted(
            hashes, key=lambda item: (item.get("alg", ""), item.get("content", "")))
    if references:
        component["externalReferences"] = sorted(
            references, key=lambda item: (item.get("type", ""), item.get("url", "")))
    if properties:
        component["properties"] = _props(properties)
    return component


def _finding_props(rows: Iterable[tuple[str, str]]) -> list[dict]:
    return [
        _prop("trustsight:finding", f"{rule_id}:{severity}")
        for rule_id, severity in sorted(set(rows))
    ]


def _opaque_props(reasons: Iterable[str]) -> list[dict]:
    items = sorted({reason for reason in reasons if reason})
    properties = [_prop("trustsight:opaque-reason", reason) for reason in items]
    if items:
        properties.append(_prop("trustsight:opaque", "true"))
    return properties


def build_sbom(fact, *, recipe_text: str = "") -> dict:
    """Project one analysis fact into a deterministic CycloneDX 1.5 document.

    The package is the metadata component.  Declared sources become ``file``
    components with their hash and external reference; declared and analysed
    dependencies become ``library`` components.  A finding is attached to the
    source or dependency its evidence names, and every other finding stays on
    the root component.  A source is opaque when it is a VCS entry, carries
    ``SKIP``, or has no checksum; the root is opaque when any coverage gap
    leaves the graph incomplete.

    :param fact: the :class:`~trustsight.schema.PackageFact` to project.
    :param recipe_text: the current PKGBUILD, or "" when it could not be read.
    :returns: the CycloneDX document as a plain dict.
    """
    findings = [
        {
            "rule_id": getattr(entry, "rule_id", ""),
            "severity": getattr(entry, "severity", ""),
            "file": getattr(entry, "file", ""),
            "evidence": getattr(entry, "evidence", None) or {},
            "description": (getattr(entry, "reason", "")
                            or getattr(entry, "template", "")),
        }
        for entry in (getattr(fact, "score_breakdown", None) or ())
        if getattr(entry, "rule_id", "")
    ]
    package = _text(
        getattr(fact, "package_name", ""), MAX_NAME_BYTES) or "unknown"
    version = _text(
        getattr(fact, "new_version", "") or getattr(fact, "pkgver_new", ""),
        MAX_NAME_BYTES)
    arrays, recipe_status = _recipe_arrays(recipe_text)

    sources = _source_rows(arrays)
    omitted_sources = max(0, len(sources) - MAX_SBOM_COMPONENTS)
    sources = sources[:MAX_SBOM_COMPONENTS]
    dependency_map = _dependency_rows(fact, arrays)
    dependency_names = sorted(dependency_map)
    omitted_dependencies = max(
        0, len(dependency_names) - MAX_SBOM_COMPONENTS)
    dependencies = {
        name: dependency_map[name]
        for name in dependency_names[:MAX_SBOM_COMPONENTS]
    }
    root_findings = _attach_findings(findings, sources, dependencies)

    covered = sum(
        len(source.get("findings") or ()) for source in sources
    ) + sum(len(row.get("findings") or ()) for row in dependencies.values())
    omitted_findings = max(0, len(findings) - covered - len(root_findings))

    root_reasons: list[str] = []
    if recipe_status:
        root_reasons.append(recipe_status)
    if getattr(fact, "coverage_gaps", None):
        root_reasons.append("coverage_gap")
    if getattr(fact, "depth_truncated", False):
        root_reasons.append("dependency_graph_incomplete")
    if getattr(fact, "diff_truncated", False):
        root_reasons.append("diff_truncated")
    if getattr(fact, "scan_truncated", False):
        root_reasons.append("scan_truncated")
    if omitted_findings:
        root_reasons.append("findings_truncated")

    components: list[tuple[str, dict]] = []
    for index, source in enumerate(sources):
        ref = f"urn:trustsight:source:{index}:{_ref(source['name'])}"
        properties: list[dict] = [
            _prop("trustsight:source-index", str(index)),
        ]
        if source["pin_kind"]:
            properties.append(
                _prop("trustsight:pin", f"{source['pin_kind']}={source['pin_value']}"))
        properties.extend(_finding_props(source.get("findings") or ()))
        properties.extend(_opaque_props(source["opaque"]))
        hashes = []
        if source["algorithm"] and source["checksum"] and source["checksum"] != "SKIP":
            hashes.append({
                "alg": source["algorithm"],
                "content": _text(source["checksum"], 256),
            })
        references = []
        url = source["url"]
        for prefix in _VCS_PREFIXES:
            if url.startswith(prefix):
                url = url[len(prefix):]
                break
        if "://" in url:
            references.append({"type": "distribution", "url": _text(url, 1024)})
        components.append((
            "file",
            _component(
                "file", source["name"],
                source["pin_value"] if source["pin_kind"] in (
                    "commit", "tag", "rev") else "",
                ref, properties, hashes=hashes, references=references),
        ))

    dependency_refs: list[str] = []
    for name in sorted(dependencies):
        row = dependencies[name]
        analyzed = row.get("analyzed")
        constraints = sorted(row["constraints"])
        exact = sorted({
            constraint[1:] for constraint in constraints
            if constraint.startswith("=") and len(constraint) > 1
        })
        dependency_version = exact[0] if len(exact) == 1 else ""
        reasons = []
        if analyzed is not None:
            if getattr(analyzed, "failed", False):
                reasons.append("analysis_failed")
            if getattr(analyzed, "coverage_gaps", None):
                reasons.append("coverage_gap")
        else:
            if (getattr(fact, "depth_truncated", False)
                    or "deps_not_scanned" in (getattr(fact, "coverage_gaps", None) or ())):
                reasons.append("dependency_graph_incomplete")
        scope = ("optional" if row["fields"] == {"optdepends"}
                 else "required")
        properties = [
            _prop("trustsight:dependency-field", field)
            for field in sorted(row["fields"])
        ]
        properties.extend(
            _prop("trustsight:constraint", constraint)
            for constraint in constraints)
        properties.append(_prop(
            "trustsight:analyzed",
            "true" if analyzed is not None else "false"))
        if analyzed is not None:
            properties.extend([
                _prop("trustsight:depth", getattr(analyzed, "depth", "")),
                _prop("trustsight:score", getattr(analyzed, "score", "")),
                _prop("trustsight:risk", getattr(analyzed, "risk", "")),
                _prop(
                    "trustsight:finding-count",
                    getattr(analyzed, "finding_count", "")),
            ])
            via = _text(getattr(analyzed, "via", ""), MAX_NAME_BYTES)
            parent = _text(getattr(analyzed, "parent", ""), MAX_NAME_BYTES)
            if via:
                properties.append(_prop("trustsight:via", via))
            if parent:
                properties.append(_prop("trustsight:parent", parent))
        properties.extend(_finding_props(row.get("findings") or ()))
        properties.extend(_opaque_props(reasons))
        ref = f"urn:trustsight:dependency:{_ref(name)}"
        dependency_refs.append(ref)
        components.append((
            "library",
            _component(
                "library", name, dependency_version, ref, properties,
                scope=scope),
        ))

    keep = MAX_SBOM_COMPONENTS
    kept = components[:keep]
    omitted_components = (
        omitted_sources + omitted_dependencies
        + max(0, len(components) - len(kept))
    )
    if omitted_components:
        root_reasons.append("components_truncated")
        for _kind, component in components[keep:]:
            root_findings.extend(
                (prop["value"].split(":", 1)[0], prop["value"].split(":", 1)[1])
                for prop in component.get("properties", ())
                if prop["name"] == "trustsight:finding" and ":" in prop["value"]
            )
    root_reasons = sorted(set(root_reasons))

    root_properties: list[dict] = [
        _prop("trustsight:coverage-gap", gap)
        for gap in sorted(set(getattr(fact, "coverage_gaps", None) or ()))
    ]
    root_properties.extend(_finding_props(root_findings))
    root_properties.extend(_opaque_props(root_reasons))
    if omitted_components:
        root_properties.append(
            _prop("trustsight:omitted-components", str(omitted_components)))
    if omitted_findings:
        root_properties.append(
            _prop("trustsight:omitted-findings", str(omitted_findings)))
    if omitted_components or omitted_findings:
        root_properties.append(_prop("trustsight:truncated", "true"))

    root_ref = f"urn:trustsight:package:{_ref(package)}"
    if version:
        root_ref += f"@{_ref(version)}"
    root = _component(
        "application", package, version, root_ref, root_properties)

    kept_refs = {component["bom-ref"] for _kind, component in kept}
    dependencies_payload = [{
        "ref": root_ref,
        "dependsOn": sorted(
            ref for ref in dependency_refs if ref in kept_refs),
    }]

    tool_version = _version()
    tools = {
        "components": [{
            "type": "application",
            "name": "trustsight",
            **({"version": tool_version} if tool_version else {}),
        }],
    }
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {"component": root, "tools": tools},
        "components": sorted(
            (component for _kind, component in kept),
            key=lambda component: (
                component["type"], component["name"].casefold(),
                component.get("version", ""), component["bom-ref"])),
        "dependencies": dependencies_payload,
    }


def render_sbom(bom: dict) -> str:
    """Serialize a document deterministically, one trailing newline."""
    return json.dumps(
        bom, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def _current_recipe(fact) -> str:
    """Read the package's current PKGBUILD, or "" when the read fails."""
    try:
        from .fetcher import (
            clone_or_fetch,
            get_head_commit,
            get_pkgbuild_at_commit,
        )

        project = clone_or_fetch(getattr(fact, "package_name", ""))
        try:
            commit = getattr(fact, "new_commit", "") or get_head_commit(project)
            return get_pkgbuild_at_commit(project, commit) if commit else ""
        finally:
            project.close()
    except Exception:
        return ""


def sbom_for_package(package: str, *, depth: int | None = None) -> dict:
    """Analyse *package* and return its CycloneDX document."""
    from .analysis import analyze_package

    fact = analyze_package(package, depth=depth)
    return build_sbom(fact, recipe_text=_current_recipe(fact))
