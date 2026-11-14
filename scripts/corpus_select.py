"""Shape-based corpus selection.

Strata are packaging shapes, never rule targets.  A predicate answers one
question about a package's metadata or repository tree; the corpus builder
feeds candidates through the metadata stage first, then fetches the branch and
runs the tree stage only when the shape needs file content.

Keeping the predicates here (rather than in `build_corpus.py`) lets the
selector be tested with synthetic metadata and trees, and lets the shape-drift
job re-run the exact same predicates against current AUR metadata.
"""

from __future__ import annotations

import re

EXISTING = (
    "bin_repack", "vcs_git", "source_patched", "dkms_kernel",
    "lang_ecosystem", "autotools", "data_fonts", "large_electron",
)

NEW = (
    "persist_surface", "signed_sources", "multi_client_fetch",
    "maintainer_churn", "dependency_heavy", "vcs_other",
    "appimage_repack", "lang_deep", "runtime_carriers",
)

#: Strata whose predicate needs the repository tree or PKGBUILD text.
TREE_STRATA = frozenset({
    "persist_surface", "signed_sources", "multi_client_fetch",
    "maintainer_churn", "vcs_other", "appimage_repack", "lang_deep",
    "runtime_carriers",
})

_LANG_PREFIXES = ("python-", "ruby-", "perl-", "rust-", "go-")
_FONT_PREFIXES = ("ttf-", "otf-", "fonts-")
_DEP_FIELDS = (
    "Depends", "MakeDepends", "CheckDepends", "OptDepends",
    "Provides", "Replaces", "Conflicts",
)

_PERSIST_HINTS = re.compile(
    r"systemd|service|daemon|timer|tmpfiles|udev|dbus|polkit|autostart|"
    r"desktop|session|system|server|agent|kernel|module", re.I)
_SIGNED_HINTS = re.compile(
    r"gpg|pgp|signature|signed|verify|validpgp|checksum|sha[0-9]*sums|source", re.I)
_FETCH_HINTS = re.compile(
    r"aria2|axel|lftp|wget2|fetch|download|git|curl|http|client|"
    r"download manager|mirror|network|api|repository", re.I)
_VCS_HINTS = re.compile(r"\bhg\b|mercurial|subversion|\bsvn\b|bzr|bazaar|fossil", re.I)
_APPIMAGE_HINTS = re.compile(r"appimage|app run|portable", re.I)
_RUNTIME_HINTS = re.compile(
    r"systemd|service|daemon|timer|socket|tmpfiles|udev|dbus|polkit|"
    r"autostart|tracerpid|ptrace|strace", re.I)
_SCRIPT_SUFFIXES = (".sh", ".bash", ".py", ".pl", ".rb", ".install")
_LANG_DEEP_HINTS = re.compile(
    r"vendor|cargo|go module|golang|npm|node|julia|\br\b|haskell|cabal|dotnet|"
    r"\.net|nuget|composer|maven|gradle|python|ruby|rust|electron", re.I)

_UNIT_SUFFIXES = (".service", ".timer", ".socket", ".mount", ".target", ".tmpfiles")
_UNIT_MARKERS = (
    "/tmpfiles.d/", "/udev/rules.d/", "/dbus-1/system.d/", "/autostart/",
    "/profile.d/", "/pam.d/", "/sudoers.d/", "/polkit-1/",
)


def _meta_text(pkg: dict) -> str:
    keywords = " ".join(str(k) for k in (pkg.get("Keywords") or []))
    return " ".join(str(pkg.get(k) or "") for k in
                    ("Name", "Description", "URL")) + " " + keywords


def dependency_count(pkg: dict) -> int:
    total = 0
    for field in _DEP_FIELDS:
        total += len(pkg.get(field) or pkg.get(field.lower()) or ())
    return total


def metadata_match(pkg: dict, stratum: str) -> bool:
    """Stage 1: decide whether a package is worth a branch fetch."""
    name = str(pkg.get("Name") or "")
    text = _meta_text(pkg)
    lower = text.lower()

    if stratum == "bin_repack":
        return name.endswith("-bin") and not name.endswith("-git")
    if stratum == "vcs_git":
        return name.endswith("-git")
    if stratum == "lang_ecosystem":
        return name.startswith(_LANG_PREFIXES)
    if stratum == "data_fonts":
        return name.startswith(_FONT_PREFIXES) or "font" in lower
    if stratum == "dkms_kernel":
        return "dkms" in lower
    if stratum == "source_patched":
        return "patch" in lower or name.endswith("-patched")
    if stratum == "autotools":
        return any(h in lower for h in ("autotools", "autoconf", "automake", "configure"))
    if stratum == "large_electron":
        return "electron" in lower or "asar" in lower
    if stratum == "persist_surface":
        return bool(_PERSIST_HINTS.search(text))
    if stratum == "signed_sources":
        return bool(_SIGNED_HINTS.search(text))
    if stratum == "multi_client_fetch":
        return bool(_FETCH_HINTS.search(text))
    if stratum == "maintainer_churn":
        # No metadata signal exists: the candidate pool is capped by the
        # builder and the tree stage counts authors.
        return True
    if stratum == "dependency_heavy":
        return dependency_count(pkg) >= 15
    if stratum == "vcs_other":
        return bool(_VCS_HINTS.search(text))
    if stratum == "appimage_repack":
        return bool(_APPIMAGE_HINTS.search(text)) or "appimage" in lower
    if stratum == "runtime_carriers":
        return bool(_RUNTIME_HINTS.search(text))
    if stratum == "lang_deep":
        return bool(_LANG_DEEP_HINTS.search(text))
    return False


def source_lines(pkgbuild: str) -> list[str]:
    """The PKGBUILD lines that declare or fetch sources."""
    return [line for line in pkgbuild.splitlines()
            if re.search(r"\b(source|_url|url|sha[0-9]*sums)\b", line, re.I)]


def _has_unit(paths: list[str]) -> bool:
    for path in paths:
        lower = path.lower()
        if lower.endswith(_UNIT_SUFFIXES) or any(m in lower for m in _UNIT_MARKERS):
            return True
    return False


def tree_match(
    pkg: dict,
    stratum: str,
    *,
    paths: list[str] | None = None,
    pkgbuild: str = "",
    authors: int | None = None,
) -> bool:
    """Stage 2: the shape check that needs file content or git history."""
    paths = paths or []
    lower = pkgbuild.lower()
    joined_paths = "\n".join(paths).lower()

    if stratum == "persist_surface":
        return (_has_unit(paths) or "install=" in lower
                or "systemctl" in lower or "tmpfiles" in lower
                or bool(_PERSIST_HINTS.search(pkgbuild)))
    if stratum == "signed_sources":
        return ("validpgpkeys" in lower
                or bool(re.search(r"\.(asc|sig)\b", lower))
                or bool(re.search(r"\.(asc|sig)\b", joined_paths))
                or "gpg --verify" in lower or "gpgv " in lower
                or "minisign" in lower)
    if stratum == "multi_client_fetch":
        return bool(re.search(
            r"\b(aria2c|axel|lftp|wget2|wget|curl|git\s+clone|"
            r"python[0-9.]*\s+-c|requests\.get|urllib|http\.client|"
            r"fetch|download)\b", lower))
    if stratum == "maintainer_churn":
        return bool(authors is not None and authors >= 3)
    if stratum == "dependency_heavy":
        return dependency_count(pkg) >= 15
    if stratum == "vcs_other":
        sources = "\n".join(source_lines(pkgbuild)).lower()
        return any(tok in sources for tok in
                   ("hg+", "hg://", "svn+", "svn://", "bzr+", "bzr://",
                    "fossil", "mercurial", "hg clone", "svn checkout"))
    if stratum == "appimage_repack":
        return "appimage" in lower or ".appimage" in joined_paths
    if stratum == "lang_deep":
        return (
            ("vendor/" in joined_paths and ".cargo/config.toml" in joined_paths)
            or "go.mod" in joined_paths
            or "package-lock.json" in joined_paths
            or "npm-shrinkwrap.json" in joined_paths
            or "stack.yaml" in joined_paths
            or any(p.endswith((".cabal", ".csproj", ".fsproj")) for p in paths)
            or "description" in joined_paths
            or "project.toml" in joined_paths
            or "composer.lock" in joined_paths
            or any(token in lower for token in (
                "cargo vendor", "cargo build", "go mod", "go build",
                "npm install", "npm ci", "yarn install", "pnpm install",
                "julia ", "cabal ", "dotnet ", "composer ", "mvn ",
                "gradle ", "nuget ", "stack build", "cargo fetch",
            ))
        )
    if stratum == "runtime_carriers":
        return (_has_unit(paths)
                or any(p.lower().endswith(_SCRIPT_SUFFIXES) for p in paths))
    # The eight existing strata were already verified by their metadata
    # predicate; their tree stage adds no further constraint.
    return True


def requires_tree(stratum: str) -> bool:
    return stratum in TREE_STRATA
