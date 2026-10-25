"""Extracted from manifests.py: _common."""

from __future__ import annotations
import fnmatch
import re
from dataclasses import dataclass
from urllib.parse import urlsplit
from ...buckets import canonical_host
from ...tokenizer import split_lines

__all__ = ['Dep', 'MAX_MANIFEST_BYTES', 'MAX_UPSTREAM_DEP_HOST_BYTES', 'MAX_UPSTREAM_DEP_NAME_BYTES', 'MAX_UPSTREAM_DEP_PAIRS', 'MAX_UPSTREAM_MANIFEST_BYTES', 'MAX_UPSTREAM_MANIFEST_FILES', 'ManifestDoc', '_CARGO_REPLACE_RE', '_DEFAULT_REGISTRY_FRAGMENTS', '_FALLBACK_FILENAMES', '_FORGE_HOSTS', '_GIT_FIELD_RE', '_GIT_URL_RE', '_LEADING_KEY_RE', '_PEP508_URL_RE', '_REGISTRY_FIELD_RE', '_REGISTRY_KEY_RE', '_glob_rank', '_host', '_is_default_registry', '_live_text', '_matches', '_pep508', '_pep508_name', '_registry_host', '_table', '_url_source', 'manifest_filenames', 'manifest_format', 'upstream_redirect_signals', 'upstream_source_deps', 'upstream_source_hosts']

MAX_MANIFEST_BYTES = 512 * 1024

# The corpus path reads manifest text from the snapshot tarball to answer
# G004.  These bounds are per package and constants: together they cap the
# bytes held in the fetch prefetch window and the dependency pairs a
# hostile manifest can turn into database rows.  A package past a bound is
# refused and reported as a coverage gap, never truncated and parsed.
MAX_UPSTREAM_MANIFEST_BYTES = 256 * 1024
MAX_UPSTREAM_MANIFEST_FILES = 64
MAX_UPSTREAM_DEP_PAIRS = 4096
MAX_UPSTREAM_DEP_NAME_BYTES = 256
MAX_UPSTREAM_DEP_HOST_BYTES = 253

_FALLBACK_FILENAMES: tuple[str, ...] = (
    "cargo::Cargo.toml",
    "cargo::Cargo.lock",
    "cargo::cargo/config.toml",
    "cargo::.cargo/config.toml",
    "cargo::cargo/config",
    "cargo::.cargo/config",
    "npm::package.json",
    "npm::package-lock.json",
    "npm::npm-shrinkwrap.json",
    "npm::yarn.lock",
    "npm::pnpm-lock.yaml",
    "npm::.npmrc",
    "npm::.yarnrc.yml",
    "pip::pyproject.toml",
    "pip::requirements.txt",
    "pip::requirements*.txt",
    "pip::requirements/*.txt",
    "pip::*-requirements.txt",
    "pip::requirements*.in",
    "pip::constraints.txt",
    "pip::constraints*.txt",
    "pip::Pipfile",
    "pip::Pipfile.lock",
    "pip::poetry.lock",
    "pip::uv.lock",
    "pip::uv.toml",
    "pip::pdm.lock",
    "pip::pylock.toml",
    "pip::pylock.*.toml",
    "pip::setup.py",
    "pip::setup.cfg",
    "pip::tox.ini",
    "pip::noxfile.py",
    "pip::pip.conf",
    "pip::pip.ini",
    "pip::.pip/pip.conf",
    "pip::.config/pip/pip.conf",
    "pip::.pypirc",
    "conda::environment.yml",
    "conda::environment.yaml",
    "conda::meta.yaml",
    "conda::pixi.toml",
    "conda::pixi.lock",
    "conda::conda-lock.yml",
    "conda::*.conda-lock.yml",
    "go::go.mod",
    "go::go.sum",
    "go::go.work",
    "go::go.work.sum",
    "gem::Gemfile",
    "gem::Gemfile.lock",
    "gem::*.gemspec",
    "composer::composer.json",
    "composer::composer.lock",
    "npm::deno.json",
    "npm::deno.jsonc",
    "npm::bun.lock",
    "jvm::pom.xml",
    "jvm::build.gradle",
    "jvm::build.gradle.kts",
    "jvm::settings.gradle",
    "jvm::settings.gradle.kts",
    "jvm::gradle/libs.versions.toml",
    "dotnet::*.csproj",
    "dotnet::*.fsproj",
    "dotnet::*.vbproj",
    "dotnet::packages.config",
    "dotnet::NuGet.config",
    "dotnet::Directory.Packages.props",
    "dart::pubspec.yaml",
    "dart::pubspec.lock",
    "crystal::shard.yml",
    "crystal::shard.lock",
    "julia::Project.toml",
    "julia::Manifest.toml",
    "cpp::vcpkg.json",
    "cpp::conanfile.txt",
    "haskell::*.cabal",
    "ocaml::*.opam",
    "elixir::mix.exs",
    "elixir::mix.lock",
    "r::DESCRIPTION",
    "r::renv.lock",
    "perl::cpanfile",
    "fortran::fpm.toml",
    "gleam::gleam.toml",
    "swift::Package.resolved",
    "swift::Package.swift",
    "swift::Podfile",
    "swift::Cartfile",
    "swift::Cartfile.resolved",
    "zig::build.zig.zon",
    "d::dub.json",
    "nim::*.nimble",
    "lua::*.rockspec",
    "clojure::deps.edn",
    "clojure::project.clj",
    "ocaml::dune-project",
    "elixir::rebar.config",
    "elixir::rebar.lock",
    "haskell::cabal.project",
    "haskell::cabal.project.freeze",
    "haskell::stack.yaml",
    "haskell::stack.yaml.lock",
    "haskell::package.yaml",
    "cpp::CMakeLists.txt",
    "cpp::meson.build",
    "bazel::MODULE.bazel",
    "perl::META.json",
    "perl::META.yml",
)

@dataclass(frozen=True)
class Dep:
    """One dependency line, normalized across formats."""

    name: str
    constraint: str | None
    source_kind: str  # "registry" | "git" | "path" | "unknown"
    remote: str | None  # canonical host of a git or non-default-registry source
    #: Canonical host+path, without credentials, query or fragment. This
    #: distinguishes two repositories on one host without leaking secrets.
    origin: str | None = None
    #: Declared lock integrity (algorithm+hash), when the format carries it.
    integrity: str | None = None

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "constraint": self.constraint,
            "source_kind": self.source_kind,
            "remote": self.remote,
            "origin": self.origin,
            "integrity": self.integrity,
        }

@dataclass
class ManifestDoc:
    """A parsed manifest: its dependencies, refusals, and redirect signals."""

    path: str
    format: str
    dependencies: tuple[Dep, ...] = ()
    #: Named refusals ("malformed json", "over the byte cap", ...).  A refused
    #: manifest is a boundary the report names, never a silent skip (B2).
    unresolved: tuple[str, ...] = ()
    #: U004 redirect signals: (kind, value) for a resolver being pointed
    #: somewhere other than the default registry.
    redirects: tuple[tuple[str, str], ...] = ()

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "format": self.format,
            "dependencies": [d.to_dict() for d in self.dependencies],
            "unresolved": list(self.unresolved),
            "redirects": [list(r) for r in self.redirects],
        }

def manifest_filenames() -> tuple[str, ...]:
    """The configured ``format::name`` table, from patterns.toml."""
    try:
        from ...config import DEFAULT_MANIFEST_FILENAMES, load_patterns

        patterns = load_patterns().get("patterns", {})
        table = patterns.get("manifest_filenames")
        if table:
            return tuple(str(x) for x in table)
        return tuple(DEFAULT_MANIFEST_FILENAMES)
    except Exception:  # noqa: BLE001 - config is an optimization here
        return _FALLBACK_FILENAMES

def _table() -> list[tuple[str, str]]:
    """``(name-glob, format)`` in table order, normalized (lowercased)."""
    out: list[tuple[str, str]] = []
    for entry in manifest_filenames():
        fmt, _, name = str(entry).partition("::")
        if name:
            out.append((name.lower(), fmt))
    return out

def _glob_rank(name: str) -> tuple[int, int]:
    """Sort key: exact before glob, then longer (more specific) first."""
    return (name.count("*") + name.count("?"), -len(name))

def _matches(lowered: str, base: str, name: str) -> bool:
    """Does the manifest name-glob *name* own path *lowered*?"""
    if "/" in name:
        if lowered == name or lowered.endswith("/" + name):
            return True
        return (fnmatch.fnmatchcase(lowered, name)
                or fnmatch.fnmatchcase(lowered, "*/" + name))
    return base == name or fnmatch.fnmatchcase(base, name)

def manifest_format(path: str) -> str | None:
    """The format family owning *path*, or None when it is not a manifest.

    Names are globs (``requirements*.txt``, ``*.csproj``).  The most
    specific match wins - an exact ``requirements.txt`` over
    ``requirements*.txt`` - so a glob added for one tool cannot silently
    capture another tool's exact file.
    """
    lowered = path.lower()
    base = lowered.rsplit("/", 1)[-1]
    best_fmt: str | None = None
    best_key: tuple[int, int] | None = None
    for name, fmt in _table():
        if not _matches(lowered, base, name):
            continue
        key = _glob_rank(name)
        if best_key is None or key < best_key:
            best_key, best_fmt = key, fmt
    return best_fmt

def _host(url: str) -> str | None:
    """Canonical host of a dependency address, git or plain URL.

    Handles a scheme, `git+`/scp forms, a protocol-relative `//host/...`,
    and a bare dotted `host.tld/path` - the spellings an attacker uses to
    hide the host from a scheme-only reader.
    """
    if not url:
        return None
    value = url.strip().strip("\"'")
    for prefix in ("git+", "hg+", "svn+", "bzr+"):
        if value.startswith(prefix):
            value = value[len(prefix):]
            break
    if value.startswith("git@"):
        host = value[len("git@"):].split(":", 1)[0].split("/", 1)[0]
        return canonical_host(host) or None
    if value.startswith("//"):
        value = "https:" + value
    if "://" in value:
        return canonical_host(urlsplit(value).netloc) or None
    # A bare `host.tld/path` (no scheme).  A bare `user/repo` shorthand has
    # no dot in its first segment and is not a host.
    first = value.split("/", 1)[0]
    if "." in first and " " not in first and "@" not in first:
        return canonical_host(first) or None
    return None

_DEFAULT_REGISTRY_FRAGMENTS = (
    "crates.io", "registry.npmjs.org", "registry.yarnpkg.com",
    "pypi.org", "files.pythonhosted.org", "pythonhosted.org",
    "rubygems.org", "packagist.org",
    "repo.maven.apache.org", "repo1.maven.org", "maven.org",
    "nuget.org", "jsr.io", "deno.land", "pub.dev", "hex.pm",
    "hackage.haskell.org", "opam.ocaml.org", "crates.io",
    "proxy.golang.org", "conda.anaconda.org", "anaconda.org",
)

def _is_default_registry(url: str) -> bool:
    """Whether *url* names an official registry, never an official-looking one.

    Compare the canonical host, not the whole URL: an attacker can put an
    official name in a hostname suffix, path, or query.  The crates index is
    the one path-identified exception because it is hosted on github.com.
    """
    value = (url or "").strip()
    for prefix in ("registry+", "sparse+"):
        if value.startswith(prefix):
            value = value[len(prefix):]
            break
    host = _host(value)
    if not host:
        return False
    if host == "github.com":
        path = urlsplit(value).path.rstrip("/")
        if path == "/rust-lang/crates.io-index":
            return True
    return any(
        host == domain or host.endswith("." + domain)
        for domain in _DEFAULT_REGISTRY_FRAGMENTS
    )

def _registry_host(url: str) -> str | None:
    """The host of a registry address, or None when it is a default registry."""
    if not url:
        return None
    value = url
    for prefix in ("registry+", "sparse+"):
        if value.startswith(prefix):
            value = value[len(prefix):]
            break
    if _is_default_registry(value):
        return None
    return _host(value)

def _url_source(url: str) -> tuple[str, str | None]:
    """``(source_kind, host)`` for a lockfile resolved/from URL.

    A tarball or registry URL on the default host is not a remote: naming it
    one would flag every lockfile's first commit.  A git URL, or any URL on a
    host the ecosystem does not default to, is.
    """
    if not url:
        return "registry", None
    low = url.lower()
    if low.startswith(("git+", "git://", "git@")) or "git+" in low:
        return "git", _host(url)
    host = _host(url)
    if host and not _is_default_registry(url):
        return "registry", host
    return "registry", None


def _origin(url: str) -> str | None:
    """A bounded, credential-free repository identity for *url*.

    Host alone cannot distinguish two upstreams on one forge. Keep the path,
    drop userinfo, query and fragment, and normalize trailing separators.
    Overlong identities are refused rather than truncated into a collision.
    """
    value = str(url or "").strip().strip("\"'")
    if not value or len(value.encode("utf-8", "replace")) > 2048:
        return None
    lowered = value.lower()
    for forge, host in _FORGE_HOSTS.items():
        if lowered.startswith(forge + ":"):
            return f"{host}/{value.split(':', 1)[1].strip('/')}"
    for prefix in ("registry+", "sparse+", "git+", "hg+", "svn+", "bzr+"):
        if value.startswith(prefix):
            value = value[len(prefix):]
            break
    if value.startswith("git@"):
        host, _, path = value[4:].partition(":")
        return f"{host}/{path.strip('/')}" if host and path else None
    if value.startswith("//"):
        value = "https:" + value
    parsed = urlsplit(value)
    host = _host(value)
    if not host:
        return None
    path = parsed.path.strip("/")
    return f"{host}/{path}" if path else host

_FORGE_HOSTS = {
    "github": "github.com", "gitlab": "gitlab.com", "bitbucket": "bitbucket.org",
}

_GIT_URL_RE = re.compile(
    r"\bgit\+[A-Za-z0-9]+://[^\s\"'<>()]+"
    r"|\bgit://[^\s\"'<>()]+"
    r"|\bgit@[A-Za-z0-9._-]+"
    r"|\b(?:github|gitlab|bitbucket):[^\s\"'<>()]+",
    re.IGNORECASE,
)

_GIT_FIELD_RE = re.compile(
    r"\bgit\s*[:=]\s*(?:\"(?P<dq>[^\"]*)\"|'(?P<sq>[^']*)'|(?P<raw>[^\s,}\]]+))"
)

_REGISTRY_FIELD_RE = re.compile(
    r"\b(?:source|registry)\s*[:=]\s*\"?"
    r"(?P<val>(?:(?:registry|sparse|git)\+)?(?:https?|ssh|git)://[^\s\"',}\]]+)"
)

_LEADING_KEY_RE = re.compile(r"^\s*[\"']?(?P<name>[A-Za-z0-9_.@+/-]+)[\"']?\s*[:=]")

_PEP508_URL_RE = re.compile(r"@\s*(?:git\+|git://|https?://|github:|gitlab:|bitbucket:)")

def _pep508_name(line: str) -> str:
    """The requirement name to the left of a PEP 508 ``@ url``, if any."""
    at = _PEP508_URL_RE.search(line)
    if not at:
        return ""
    head = line[:at.start()].strip().strip("\"'").rstrip("@").strip()
    if not head:
        return ""
    token = head.split(",")[0].strip().split("[", 1)[0].strip()
    return token if re.fullmatch(r"[A-Za-z0-9_.-]+", token) else ""

def _live_text(text: str) -> str:
    """*text* without its comment lines: a commented source fetches nothing."""
    return "\n".join(
        line for line in split_lines(text)
        if not line.lstrip().startswith(("#", "//"))
    )

def upstream_source_hosts(text: str) -> set[str]:
    """Hosts named by a git or non-default-registry spelling anywhere in *text*."""
    hosts: set[str] = set()
    text = _live_text(text)
    for m in _GIT_URL_RE.finditer(text):
        token = m.group(0)
        low = token.lower()
        for forge, host in _FORGE_HOSTS.items():
            if low.startswith(forge + ":"):
                hosts.add(host)
                break
        else:
            found = _host(token)
            if found:
                hosts.add(found)
    for m in _GIT_FIELD_RE.finditer(text):
        found = _host(m.group("dq") or m.group("sq") or m.group("raw") or "")
        if found:
            hosts.add(found)
    for m in _REGISTRY_FIELD_RE.finditer(text):
        found = _registry_host(m.group("val"))
        if found:
            hosts.add(found)
    return hosts

def upstream_source_deps(text: str) -> list[Dep]:
    """Best-effort dep names for the source spellings *text* carries."""
    deps: list[Dep] = []
    for line in split_lines(text):
        stripped = line.lstrip()
        if stripped.startswith(("#", "//")):
            continue
        hosts = upstream_source_hosts(line)
        if not hosts:
            continue
        m = _LEADING_KEY_RE.match(line)
        name = m.group("name") if m else _pep508_name(line)
        for host in sorted(hosts):
            deps.append(Dep(name, None, "git", host))
    return deps

_CARGO_REPLACE_RE = re.compile(r"\breplace-with\s*[:=]\s*\"(?P<name>[^\"]+)\"")

_REGISTRY_KEY_RE = re.compile(
    r"\bregistry\s*[:=]\s*\"?"
    r"(?P<url>(?:(?:registry|sparse|git)\+)?[^\s\"',}\]]+)"
)

def upstream_redirect_signals(text: str) -> set[tuple[str, str]]:
    """Resolver redirects readable without their enclosing section."""
    out: set[tuple[str, str]] = set()
    text = _live_text(text)
    for m in _CARGO_REPLACE_RE.finditer(text):
        out.add(("cargo-replace-with", m.group("name")))
    for m in _REGISTRY_KEY_RE.finditer(text):
        url = m.group("url")
        host = _host(url)
        # A dependency literally named `registry = "1.0"` is not a redirect.
        # Require an actual registry locator in the section-agnostic fallback;
        # a bare host is accepted only with a path, not a version-shaped token.
        locator = "://" in url or url.startswith(("git@", "//")) or "/" in url
        if not host or not locator or _is_default_registry(url):
            continue
        out.add(("registry-override", host))
    return out

def _pep508(raw: str) -> Dep | None:
    """Parse one PEP 508 requirement string into a dep (best effort)."""
    text = raw.strip().strip("\"'")
    if not text or text.startswith("-") or text.startswith("#"):
        return None
    # `name @ url` (PEP 508 allows whitespace around `@` to be omitted).
    m = re.match(r"^(?P<name>[A-Za-z0-9_.-]+)\s*(?:\[[^\]]*\])?\s*@\s*(?P<url>\S+)", text)
    if m:
        name, url = m.group("name"), m.group("url")
        if url.lower().startswith("file:"):
            return Dep(name, None, "path", None)
        kind, remote = ("git", _host(url)) if "://" in url else ("unknown", None)
        return Dep(name, None, kind, remote, origin=_origin(url))
    # `git+url#egg=name`
    if text.startswith(("git+", "hg+", "svn+", "bzr+")):
        remote = _host(text)
        name = ""
        m = re.search(r"[#&]egg=([A-Za-z0-9_.-]+)", text)
        if m:
            name = m.group(1)
        return Dep(name, None, "git", remote)
    if "://" in text:  # direct URL without a name
        return Dep("", None, "git", _host(text))
    m = re.match(r"^([A-Za-z0-9_.-]+)\s*(?:\[[^\]]*\])?\s*(.*)$", text)
    if not m:
        return None
    name, rest = m.group(1), m.group(2).strip()
    return Dep(name, rest or None, "registry", None)
