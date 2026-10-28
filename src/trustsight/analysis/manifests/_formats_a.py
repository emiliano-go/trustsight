"""Extracted from manifests.py: _formats_a."""

from __future__ import annotations
import re
from ...tokenizer import split_lines
from ..manifest_syntax import (
    load_json,
    load_toml,
)
from ._common import Dep, ManifestDoc, _host, _is_default_registry, _origin, _pep508, _registry_host, _url_source
from ._formats_b import _add_pixi, _as_list, _source_dep

__all__ = ['_GEMLOCK_SPEC_RE', '_GEM_LINE_RE', '_GEM_SOURCE_RE', '_GO_BLOCK_RE', '_GO_REPLACE_RE', '_GO_REQUIRE_RE', '_NODE_MODULES_RE', '_NPMRC_HOST_RE', '_NPMRC_RE', '_PIP_OPTION_RE', '_PLATFORM_PREFIXES', '_PNPM_NAME_RE', '_PNPM_URL_RE', '_YARNRC_RE', '_YARN_URL_RE', '_cargo_config', '_cargo_lock', '_cargo_toml', '_composer_json', '_composer_lock', '_gemfile', '_gemfile_lock', '_go_mod', '_go_sum', '_is_go_path', '_json_deps', '_json_object', '_npm_lock', '_npm_package_json', '_npmrc', '_pipfile', '_pnpm_lock', '_poetry_dep_tables', '_poetry_lock', '_pyproject', '_requirements', '_toml_lock', '_yarn_lock', '_yarnrc']

def _cargo_toml(text: str) -> ManifestDoc | None:
    data = load_toml(text)
    deps: list[Dep] = []
    redirects: list[tuple[str, str]] = []
    tables = []
    for key in ("dependencies", "dev-dependencies", "build-dependencies"):
        if isinstance(data.get(key), dict):
            tables.append(data[key])
    ws = data.get("workspace")
    if isinstance(ws, dict) and isinstance(ws.get("dependencies"), dict):
        tables.append(ws["dependencies"])
    # [patch.crates-io] / [replace] can point a registry dep at a git source.
    for key in ("patch", "replace"):
        section = data.get(key)
        if isinstance(section, dict):
            for sub in section.values():
                if isinstance(sub, dict):
                    tables.append(sub)
    for target in (data.get("target") or {}).values():
        if not isinstance(target, dict):
            continue
        for key in ("dependencies", "dev-dependencies", "build-dependencies"):
            if isinstance(target.get(key), dict):
                tables.append(target[key])
    for table in tables:
        for name, value in table.items():
            if isinstance(value, str):
                deps.append(Dep(name, value or None, "registry", None))
            elif isinstance(value, dict):
                if value.get("git"):
                    constraint = (value.get("tag") or value.get("branch")
                                  or value.get("rev") or value.get("version"))
                    deps.append(Dep(name, constraint, "git", _host(value["git"]),
                                    origin=_origin(value["git"])))
                elif value.get("path"):
                    deps.append(Dep(name, value.get("version"), "path", None))
                elif value.get("registry"):
                    # A per-dep custom registry (e.g. sparse+https://host/...)
                    remote = _registry_host(value["registry"])
                    deps.append(Dep(name, value.get("version"), "registry", remote,
                                    origin=_origin(value["registry"])))
                    if remote:
                        redirects.append(("cargo-dependency-registry", remote))
                else:
                    deps.append(Dep(name, value.get("version"), "registry", None))
    return ManifestDoc("", "cargo", tuple(deps), redirects=tuple(redirects))

def _cargo_lock(text: str) -> ManifestDoc | None:
    data = load_toml(text)
    deps = []
    for pkg in data.get("package", ()) or ():
        if not isinstance(pkg, dict):
            continue
        name = pkg.get("name", "")
        version = pkg.get("version")
        source = pkg.get("source", "") or ""
        integrity = pkg.get("checksum")
        if source.startswith("git+"):
            deps.append(Dep(name, version, "git", _host(source),
                            origin=_origin(source), integrity=integrity))
        elif source.startswith(("registry+", "sparse+")):
            prefix = "registry+" if source.startswith("registry+") else "sparse+"
            deps.append(Dep(name, version, "registry",
                            _registry_host(source[len(prefix):]),
                            origin=_origin(source), integrity=integrity))
        elif source:
            deps.append(Dep(name, version, "unknown", _registry_host(source),
                            origin=_origin(source), integrity=integrity))
        else:
            deps.append(Dep(name, version, "path", None, integrity=integrity))
    return ManifestDoc("", "cargo", tuple(deps))

def _cargo_config(text: str) -> ManifestDoc | None:
    data = load_toml(text)
    redirects: list[tuple[str, str]] = []
    sources = data.get("source") or {}
    if isinstance(sources, dict):
        for name, table in sources.items():
            if not isinstance(table, dict):
                continue
            if table.get("replace-with"):
                redirects.append(("cargo-replace-with", f"{name} -> {table['replace-with']}"))
            if table.get("registry"):
                redirects.append(("cargo-registry", _host(table["registry"]) or table["registry"]))
    # [registries.<name>] index = "sparse+https://host/..." - a named registry
    # a dep can then select by name, and [registry] default = "<name>".
    registries = data.get("registries") or {}
    if isinstance(registries, dict):
        for table in registries.values():
            if isinstance(table, dict) and table.get("index"):
                redirects.append(("cargo-registries",
                                  _host(table["index"]) or table["index"]))
    registry = data.get("registry")
    if isinstance(registry, dict) and registry.get("default"):
        redirects.append(("cargo-default-registry", str(registry["default"])))
    return ManifestDoc("", "cargo", (), redirects=tuple(redirects))

def _json_object(text: str) -> dict:
    """Parse JSON that must be an object; a top-level array is not a manifest."""
    data = load_json(text)
    if not isinstance(data, dict):
        raise TypeError("manifest is not a JSON object")
    return data

def _json_deps(section) -> list[Dep]:
    deps = []
    if not isinstance(section, dict):
        return deps
    for name, value in section.items():
        if not isinstance(value, str):
            continue
        v = value.strip()
        low = v.lower()
        if low.startswith(("github:", "gitlab:", "bitbucket:")):
            forge = low.split(":", 1)[0]
            host = {"github": "github.com", "gitlab": "gitlab.com",
                    "bitbucket": "bitbucket.org"}[forge]
            deps.append(Dep(name, None, "git", host, origin=_origin(v)))
        elif (re.fullmatch(r"[\w.-]+/[\w.-]+(?:#.*)?", v)
                and "://" not in v and not v.startswith((".", "/"))):
            # npm's `user/repo` GitHub shorthand (not a relative path).
            deps.append(Dep(name, None, "git", "github.com",
                            origin=f"github.com/{v.split('#', 1)[0]}"))
        elif low.startswith(("git+", "git://", "git:")) or v.startswith("git@"):
            deps.append(Dep(name, None, "git", _host(v), origin=_origin(v)))
        elif low.startswith(("file:", "link:")):
            deps.append(Dep(name, None, "path", None))
        elif low.startswith("npm:"):
            target = v[4:]
            # Keep the alias target, not its version, so npm:foo -> npm:evil
            # is visible while an ordinary version update stays quiet.
            target_name = target.rsplit("@", 1)[0] if "@" in target else target
            deps.append(Dep(name, None, "registry", None,
                            origin=f"npm:{target_name}"))
        elif "://" in v:
            deps.append(Dep(name, None, "git", _host(v), origin=_origin(v)))
        else:
            deps.append(Dep(name, v, "registry", None))
    return deps

def _npm_package_json(text: str) -> ManifestDoc | None:
    data = _json_object(text)
    deps = []
    for key in ("dependencies", "devDependencies", "peerDependencies",
                "optionalDependencies", "overrides", "resolutions"):
        deps.extend(_json_deps(data.get(key)))
    return ManifestDoc("", "npm", tuple(deps))

_NODE_MODULES_RE = re.compile(r"(?:^|node_modules/)(@?[^/]+)(?:/|$)")

def _npm_lock(text: str) -> ManifestDoc | None:
    data = _json_object(text)
    deps = []
    packages = data.get("packages")
    if isinstance(packages, dict):  # lockfile v2/v3
        for key, entry in packages.items():
            if not key or not isinstance(entry, dict):
                continue
            # Nested lock paths end at the package itself; splitting at the
            # last node_modules preserves both scoped and unscoped identities.
            name = key.rsplit("node_modules/", 1)[-1]
            resolved = entry.get("resolved", "") or entry.get("from", "")
            kind, host = _url_source(resolved)
            deps.append(Dep(name, entry.get("version"), kind, host,
                            origin=_origin(resolved), integrity=entry.get("integrity")))
    deps_section = data.get("dependencies")
    if isinstance(deps_section, dict):  # lockfile v1
        for name, entry in deps_section.items():
            if not isinstance(entry, dict):
                continue
            resolved = entry.get("resolved", "") or entry.get("from", "")
            kind, host = _url_source(resolved)
            deps.append(Dep(name, entry.get("version"), kind, host,
                            origin=_origin(resolved), integrity=entry.get("integrity")))
    return ManifestDoc("", "npm", tuple(deps))

_NPMRC_RE = re.compile(r"^\s*(?P<scope>@[\w.-]+:)?registry\s*=\s*(?P<url>\S+)\s*$",
                       re.MULTILINE | re.IGNORECASE)

_NPMRC_HOST_RE = re.compile(r"^\s*//(?P<host>[^/\s:]+)(?:[/:].*)?$",
                            re.MULTILINE | re.IGNORECASE)

def _npmrc(text: str) -> ManifestDoc | None:
    redirects = []
    for m in _NPMRC_RE.finditer(text):
        url = m.group("url")
        if _is_default_registry(url):
            continue
        redirects.append(("npm-registry", _host(url) or url))
    # `//host/:_authToken=...` names a registry the resolver talks to.
    for m in _NPMRC_HOST_RE.finditer(text):
        host = m.group("host").lower()
        if _is_default_registry(host):
            continue
        redirects.append(("npm-registry-auth", host))
    return ManifestDoc("", "npm", (), redirects=tuple(redirects))

_YARN_URL_RE = re.compile(r"(?:git\+https|git\+ssh|git\+|https?)://[^\s'\"]+")

def _yarn_lock(text: str) -> ManifestDoc | None:
    deps = []
    name = None
    for line in split_lines(text):
        if not line.strip():
            continue
        if not line[0].isspace():
            # `name@range, name@range2:` (v1) or `"name@npm:1":` (berry)
            spec = line.split(",", 1)[0].rsplit(":", 1)[0].strip().strip('"')
            name = spec.rsplit("@", 1)[0] if "@" in spec else spec
        else:
            if not name:
                continue
            for url in _YARN_URL_RE.findall(line):
                if _is_default_registry(url):
                    continue
                deps.append(Dep(name, None, "git", _host(url), origin=_origin(url)))
    return ManifestDoc("", "npm", tuple(deps))

_PNPM_URL_RE = re.compile(r"(?:git\+https|git\+ssh|git\+|https?)://[^\s'\"#]+")

_PNPM_NAME_RE = re.compile(r"/(@?[\w.-]+(?:/[\w.-]+)?)@")

def _pnpm_lock(text: str) -> ManifestDoc | None:
    """pnpm-lock.yaml is YAML; read it line-class (no YAML dependency)."""
    deps = []
    for line in split_lines(text):
        m = _PNPM_NAME_RE.search(line)
        name = m.group(1) if m else ""
        for url in _PNPM_URL_RE.findall(line):
            if _is_default_registry(url):
                continue
            deps.append(Dep(name, None, "git", _host(url)))
    return ManifestDoc("", "npm", tuple(deps))

def _pyproject_uv(uv: dict, deps: list[Dep]) -> list[tuple[str, str]]:
    """uv indexes, sources, and dependency overrides."""
    redirects: list[tuple[str, str]] = []
    for index in uv.get("index", ()) or ():
        if isinstance(index, dict) and index.get("url"):
            if not _is_default_registry(index["url"]):
                redirects.append(("uv-index", _host(index["url"]) or index["url"]))
    for name, src in (uv.get("sources") or {}).items():
        deps.extend(_source_dep(name, src))
    for key in ("dev-dependencies", "constraint-dependencies",
                "override-dependencies", "build-constraint-dependencies"):
        for raw in _as_list(uv.get(key)):
            dep = _pep508(str(raw))
            if dep and dep.name:
                deps.append(dep)
    return redirects


def _pyproject_extra_tools(tool: dict, deps: list[Dep]) -> list[tuple[str, str]]:
    """pdm, hatch, flit and pixi dependency tables."""
    redirects: list[tuple[str, str]] = []
    pdm = tool.get("pdm") or {}
    dev = pdm.get("dev-dependencies")
    for values in dev.values() if isinstance(dev, dict) else ():
        for raw in _as_list(values):
            dep = _pep508(str(raw))
            if dep and dep.name:
                deps.append(dep)
    hatch = tool.get("hatch") or {}
    envs = hatch.get("envs") if isinstance(hatch, dict) else None
    if isinstance(envs, dict):
        for entry in envs.values():
            if isinstance(entry, dict):
                for raw in _as_list(entry.get("dependencies")):
                    dep = _pep508(str(raw))
                    if dep and dep.name:
                        deps.append(dep)
    flit = tool.get("flit") or {}
    flit_meta = flit.get("metadata") if isinstance(flit, dict) else None
    if isinstance(flit_meta, dict):
        for raw in _as_list(flit_meta.get("requires")):
            dep = _pep508(str(raw))
            if dep and dep.name:
                deps.append(dep)
        extra = flit_meta.get("requires-extra")
        for values in extra.values() if isinstance(extra, dict) else ():
            for raw in _as_list(values):
                dep = _pep508(str(raw))
                if dep and dep.name:
                    deps.append(dep)
    pixi = tool.get("pixi")
    if isinstance(pixi, dict):
        _add_pixi(pixi, deps, redirects)
    return redirects


def _pyproject_poetry_extras(poetry: dict, deps: list[Dep]) -> list[tuple[str, str]]:
    """Poetry plugins, build constraints, and named sources."""
    redirects: list[tuple[str, str]] = []
    for table in (poetry.get("requires-plugins"), poetry.get("build-constraints")):
        if isinstance(table, dict):
            for name, value in table.items():
                deps.append(Dep(name, value if isinstance(value, str) else None,
                                "registry", None))
    source = poetry.get("source")
    for _name, table in (source.items() if isinstance(source, dict) else ()):
        if isinstance(table, dict) and table.get("url"):
            if not _is_default_registry(table["url"]):
                redirects.append(("poetry-source",
                                  _host(table["url"]) or table["url"]))
    return redirects


def _pyproject(text: str) -> ManifestDoc | None:
    data = load_toml(text)
    deps: list[Dep] = []
    redirects: list[tuple[str, str]] = []
    project = data.get("project") or {}
    for raw in project.get("dependencies", ()) or ():
        dep = _pep508(str(raw))
        if dep:
            deps.append(dep)
    optional = project.get("optional-dependencies") or {}
    for values in optional.values():
        for raw in values or ():
            dep = _pep508(str(raw))
            if dep:
                deps.append(dep)
    # PEP 735 dependency groups (a top-level table, not under [project]).
    groups = data.get("dependency-groups") or {}
    if isinstance(groups, dict):
        for values in groups.values():
            for raw in values or ():
                if isinstance(raw, str):
                    dep = _pep508(raw)
                    if dep:
                        deps.append(dep)
    build = data.get("build-system") or {}
    for raw in build.get("requires", ()) or ():
        dep = _pep508(str(raw))
        if dep:
            deps.append(dep)
    poetry = (data.get("tool") or {}).get("poetry") or {}
    for table in _poetry_dep_tables(poetry):
        for name, value in table.items():
            if name.lower() == "python":
                continue
            if isinstance(value, str):
                deps.append(Dep(name, value, "registry", None))
            elif isinstance(value, dict):
                if value.get("git"):
                    deps.append(Dep(name, value.get("version"), "git", _host(value["git"])))
                elif value.get("path"):
                    deps.append(Dep(name, value.get("version"), "path", None))
                else:
                    deps.append(Dep(name, value.get("version"), "registry", None))
    uv = (data.get("tool") or {}).get("uv") or {}
    redirects.extend(_pyproject_uv(uv, deps))
    tool = data.get("tool")
    if isinstance(tool, dict):
        redirects.extend(_pyproject_extra_tools(tool, deps))
    redirects.extend(_pyproject_poetry_extras(poetry, deps))
    return ManifestDoc("", "pip", tuple(deps), redirects=tuple(redirects))

def _poetry_dep_tables(poetry: dict):
    if isinstance(poetry.get("dependencies"), dict):
        yield poetry["dependencies"]
    group = poetry.get("group")
    if isinstance(group, dict):
        for entry in group.values():
            if isinstance(entry, dict) and isinstance(entry.get("dependencies"), dict):
                yield entry["dependencies"]
    dev = poetry.get("dev-dependencies")
    if isinstance(dev, dict):
        yield dev

_PIP_OPTION_RE = re.compile(
    r"^\s*(?:(?:--(?:extra-)?index-url|-i)\s*=?\s*(?P<index>\S+)"
    r"|--trusted-host\s+(?P<trusted>\S+)"
    r"|(?:-f|--find-links)\s*=?\s*(?P<find>\S+)"
    r"|(?:-r|--requirement|-c|--constraint)\s*=?\s*(?P<include>\S+))",
    re.MULTILINE | re.IGNORECASE,
)

def _requirements(text: str) -> ManifestDoc | None:
    deps = []
    redirects = []
    text = re.sub(r"\\\r?\n", " ", text)  # join line continuations
    for m in _PIP_OPTION_RE.finditer(text):
        if m.group("trusted"):
            redirects.append(("pip-trusted-host", _host(m.group("trusted")) or m.group("trusted")))
            continue
        index = m.group("index")
        if index and not _is_default_registry(index):
            redirects.append(("pip-index-url", _host(index) or index))
            continue
        find = m.group("find")
        if find and not _is_default_registry(find):
            redirects.append(("pip-find-links", _host(find) or find))
            continue
        include = m.group("include")
        if include and "://" in include and not _is_default_registry(include):
            redirects.append(("pip-requirements-url", _host(include) or include))
    for raw in split_lines(text):
        line = raw.split(" #", 1)[0].strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith(("-e", "--editable")):
            parts = line.split(None, 1)
            rest = (parts[1] if len(parts) > 1 else "").split(" #", 1)[0].strip()
            dep = _pep508(rest)
            if dep and (dep.name or dep.source_kind == "git"):
                deps.append(dep)
            continue
        if line.startswith("-"):
            continue  # -r/-c includes and other options
        dep = _pep508(line)
        if dep and dep.name:
            deps.append(dep)
        elif dep and dep.source_kind == "git":
            deps.append(dep)
    return ManifestDoc("", "pip", tuple(deps), redirects=tuple(redirects))

def _pipfile(text: str) -> ManifestDoc | None:
    # Pipfile is TOML; Pipfile.lock is JSON.
    stripped = text.lstrip()
    if stripped.startswith("{"):
        data = _json_object(text)
        deps = []
        for section in ("default", "develop"):
            for name, entry in (data.get(section) or {}).items():
                if isinstance(entry, dict):
                    if entry.get("git"):
                        deps.append(Dep(name, entry.get("version"), "git", _host(entry["git"])))
                    elif entry.get("path"):
                        deps.append(Dep(name, entry.get("version"), "path", None))
                    else:
                        deps.append(Dep(name, entry.get("version"), "registry", None))
        redirects = []
        meta = data.get("_meta") or {}
        for src in (meta.get("sources", ()) if isinstance(meta, dict) else ()) or ():
            if isinstance(src, dict) and src.get("url"):
                if not _is_default_registry(src["url"]):
                    redirects.append(("pipfile-source", _host(src["url"]) or src["url"]))
        return ManifestDoc("", "pip", tuple(deps), redirects=tuple(redirects))
    data = load_toml(text)
    deps = []
    for section in ("packages", "dev-packages"):
        for name, value in (data.get(section) or {}).items():
            if isinstance(value, str):
                deps.append(Dep(name, value if value != "*" else None, "registry", None))
            elif isinstance(value, dict):
                if value.get("git"):
                    deps.append(Dep(name, value.get("version"), "git", _host(value["git"])))
                elif value.get("path"):
                    deps.append(Dep(name, value.get("version"), "path", None))
                else:
                    deps.append(Dep(name, value.get("version"), "registry", None))
    return ManifestDoc("", "pip", tuple(deps))

def _poetry_lock(text: str) -> ManifestDoc | None:
    data = load_toml(text)
    deps = []
    for pkg in data.get("package", ()) or ():
        if not isinstance(pkg, dict):
            continue
        source = pkg.get("source") or {}
        url = source.get("url", "") if isinstance(source, dict) else ""
        stype = source.get("type", "") if isinstance(source, dict) else ""
        if url and "git" in stype:
            deps.append(Dep(pkg.get("name", ""), pkg.get("version"), "git", _host(url)))
        elif url:
            kind, host = _url_source(url)
            deps.append(Dep(pkg.get("name", ""), pkg.get("version"), kind, host))
        else:
            deps.append(Dep(pkg.get("name", ""), pkg.get("version"), "registry", None))
    return ManifestDoc("", "pip", tuple(deps))

def _toml_lock(text: str) -> ManifestDoc | None:
    """uv.lock / pdm.lock: ``[[package]]`` with a source dict or git/path key."""
    data = load_toml(text)
    deps = []
    for pkg in data.get("package", ()) or ():
        if not isinstance(pkg, dict):
            continue
        name, version = pkg.get("name", ""), pkg.get("version")
        source = pkg.get("source")
        if isinstance(source, dict):
            if source.get("git"):
                deps.append(Dep(name, version, "git", _host(source["git"])))
            elif source.get("registry"):
                kind, host = _url_source(source["registry"])
                deps.append(Dep(name, version, kind, host))
            elif source.get("url"):
                kind, host = _url_source(source["url"])
                deps.append(Dep(name, version, kind, host))
            elif any(source.get(k) for k in ("path", "editable", "virtual",
                                             "directory")):
                deps.append(Dep(name, version, "path", None))
            else:
                deps.append(Dep(name, version, "registry", None))
        elif pkg.get("git"):
            deps.append(Dep(name, version, "git", _host(pkg["git"])))
        elif pkg.get("path"):
            deps.append(Dep(name, version, "path", None))
        else:
            deps.append(Dep(name, version, "registry", None))
    return ManifestDoc("", "pip", tuple(deps))

_YARNRC_RE = re.compile(
    r"npmRegistryServer\s*:\s*\"?(?P<url>[^\s\"']+)\"?",
    re.IGNORECASE,
)

def _yarnrc(text: str) -> ManifestDoc | None:
    redirects = []
    for m in _YARNRC_RE.finditer(text):
        url = m.group("url")
        if _is_default_registry(url):
            continue
        redirects.append(("yarn-registry", _host(url) or url))
    return ManifestDoc("", "npm", (), redirects=tuple(redirects))

_GO_REQUIRE_RE = re.compile(r"^\s*require\s+(?!\()(\S+)\s+(\S+)", re.MULTILINE)

_GO_BLOCK_RE = re.compile(r"require\s*\((.*?)\)", re.DOTALL)

_GO_REPLACE_RE = re.compile(r"^\s*replace\s+(\S+)(?:\s+\S+)?\s*=>\s*(\S+)", re.MULTILINE)

def _go_mod(text: str) -> ManifestDoc | None:
    deps = []
    for name, version in _GO_REQUIRE_RE.findall(text):
        deps.append(Dep(name, version, "registry", None))
    for block in _GO_BLOCK_RE.findall(text):
        for raw in split_lines(block):
            parts = raw.split()
            if len(parts) >= 2:
                deps.append(Dep(parts[0], parts[1], "registry", None))
    replaced = {m.group(1): m.group(2) for m in _GO_REPLACE_RE.finditer(text)}
    out = []
    for dep in deps:
        target = replaced.get(dep.name)
        if target and _is_go_path(target):
            out.append(Dep(dep.name, dep.constraint, "path", None))
        else:
            out.append(dep)
    return ManifestDoc("", "go", tuple(out))

def _is_go_path(target: str) -> bool:
    """A go ``replace`` target is a filesystem path, not another module."""
    if target.startswith(("./", "../", "/", ".")):
        return True
    if "://" in target:
        return True
    return "/" not in target

def _go_sum(text: str) -> ManifestDoc | None:
    deps = []
    seen = set()
    for raw in split_lines(text):
        parts = raw.split()
        if len(parts) >= 2:
            key = (parts[0], parts[1])
            if key in seen:
                continue
            seen.add(key)
            deps.append(Dep(parts[0], parts[1], "registry", None,
                            integrity=parts[2] if len(parts) > 2 else None))
    return ManifestDoc("", "go", tuple(deps))

_GEM_LINE_RE = re.compile(r"^\s*gem\s+['\"]([\w.-]+)['\"](.*)$", re.MULTILINE)

_GEM_SOURCE_RE = re.compile(r"^\s*source\s+['\"]([^'\"]+)['\"]", re.MULTILINE)

def _gemfile(text: str) -> ManifestDoc | None:
    deps = []
    for m in _GEM_LINE_RE.finditer(text):
        name, rest = m.group(1), m.group(2)
        constraint = None
        cm = re.search(r"['\"]([~><=][^'\"]*)['\"]", rest)
        if cm:
            constraint = cm.group(1)
        git = re.search(r"git:\s*['\"]([^'\"]+)", rest)
        shorthand = re.search(r"(github|gitlab|bitbucket):\s*['\"]([^'\"]+)", rest)
        if git:
            deps.append(Dep(name, constraint, "git", _host(git.group(1))))
        elif shorthand:
            host = {"github": "github.com", "gitlab": "gitlab.com",
                    "bitbucket": "bitbucket.org"}[shorthand.group(1)]
            deps.append(Dep(name, constraint, "git", host))
        elif re.search(r"path:\s*['\"]", rest):
            deps.append(Dep(name, constraint, "path", None))
        else:
            deps.append(Dep(name, constraint, "registry", None))
    redirects = []
    for m in _GEM_SOURCE_RE.finditer(text):
        url = m.group(1)
        if "rubygems.org" not in url:
            redirects.append(("gem-source", _host(url) or url))
    return ManifestDoc("", "gem", tuple(deps), redirects=tuple(redirects))

_GEMLOCK_SPEC_RE = re.compile(r"^\s{4}([\w.-]+)\s+\(")

def _gemfile_lock(text: str) -> ManifestDoc | None:
    deps = []
    mode = ""
    remote = None
    for line in split_lines(text):
        if line and not line[0].isspace():
            mode = line.strip()
            remote = None
        elif mode in ("GIT", "PATH") and line.strip().startswith("remote:"):
            remote = line.split(":", 1)[1].strip()
        else:
            m = _GEMLOCK_SPEC_RE.match(line)
            if m:
                kind = "git" if mode == "GIT" and remote else (
                    "path" if mode == "PATH" else "registry")
                deps.append(Dep(m.group(1), None, kind,
                                _host(remote) if remote and kind == "git" else None))
    return ManifestDoc("", "gem", tuple(deps))

_PLATFORM_PREFIXES = ("php", "hhvm", "ext-", "lib-", "composer-",
                      "composer-plugin-api", "composer-runtime-api")

def _composer_json(text: str) -> ManifestDoc | None:
    data = _json_object(text)
    deps = []
    for key in ("require", "require-dev"):
        for name, value in (data.get(key) or {}).items():
            if name.startswith(_PLATFORM_PREFIXES):
                continue
            if isinstance(value, str) and ("://" in value or value.startswith(("dev-",))):
                if "://" in value:
                    deps.append(Dep(name, None, "git", _host(value)))
                else:
                    deps.append(Dep(name, value, "registry", None))
            else:
                deps.append(Dep(name, value if isinstance(value, str) else None,
                                "registry", None))
    redirects = []
    for repo in data.get("repositories", ()) or ():
        if isinstance(repo, dict) and repo.get("url"):
            redirects.append(("composer-repository", _host(repo["url"]) or repo["url"]))
    return ManifestDoc("", "composer", tuple(deps), redirects=tuple(redirects))

def _composer_lock(text: str) -> ManifestDoc | None:
    data = _json_object(text)
    deps = []
    for section in ("packages", "packages-dev"):
        for pkg in data.get(section, ()) or ():
            if not isinstance(pkg, dict):
                continue
            source = pkg.get("source") or {}
            url = source.get("url", "") if isinstance(source, dict) else ""
            name = pkg.get("name", "")
            if url and ("://" in url):
                deps.append(Dep(name, pkg.get("version"), "git", _host(url)))
            else:
                deps.append(Dep(name, pkg.get("version"), "registry", None))
    return ManifestDoc("", "composer", tuple(deps))
