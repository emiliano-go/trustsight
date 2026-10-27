"""The June 2026 campaign's shape, on the single-package path.

The corpus rules already describe mass adoption (H045, H074) and orphan
reachability (H046, H057, H060), but every one of them needs a ``full-aur``
cycle. Somebody running ``trustsight review`` over their installed packages
sees none of them, and those are the people the campaign actually hit.

Three rules here, and the third is the one that matters:

* **H086** - the AUR reported this package orphaned, and now reports a
  maintainer. That is the campaign's entry point: adoption is how the
  attacker got commit rights to something the reviewer already trusted.
* **H087** - the recipe changed but upstream did not: same ``source=``
  URLs, same checksums, same ``pkgver``, yet dependencies *and* a build
  function both moved.
  This is what made the attack invisible to a reviewer scanning source
  lines, and it is the signature that separates it from an ordinary update,
  which almost always moves ``pkgver`` and the checksums together.
* **H088** - the composition. H086 and H087 are individually survivable:
  packages do get adopted honestly, and recipes do get fixed without an
  upstream release. What is not ordinary is *adopted, then the recipe
  rewritten, and the build now pulling unpinned code from a registry* - the
  three together, in one change. Scoring the composition rather than
  inflating any single rule is how this clears the flag threshold without
  spending benign fire rate, the same reasoning H036 and H065 use.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

from ..diffdoc import parse_diff_lines
from ..findings import stamp
from ..tokenizer import join_line_continuations, split_lines
from ..rules import clamp_text
from .buildfetch import BUILD_FUNCTIONS, registry_resolutions

#: Findings that already prove the diff executes code fetched from a source.
_SOURCE_EXECUTION_RULES = frozenset({
    "H082", "H083", "H072", "H081", "H075", "H090",
})

_URL_ASSIGN_RE = re.compile(
    r"^\s*url\s*=\s*['\"]?([^'\"\s]+)", re.IGNORECASE | re.MULTILINE)


def _source_identity(url: str) -> tuple[str, ...]:
    """A coarse origin identity: host plus the first two path components.

    The host alone is not enough: a campaign can keep github.com and change
    the owner/repository (the CHAOS-RAT shape).  The first two path
    components distinguish ``upstream/project`` from ``attacker/project``
    without guessing at forge-specific APIs.
    """
    try:
        parsed = urlparse(url)
    except ValueError:
        return ()
    host = (parsed.hostname or "").lower()
    parts = [part for part in parsed.path.split("/") if part]
    if len(parts) >= 2:
        repository = re.sub(
            r"\.(?:tar\.(?:gz|xz|bz2|zst)|tgz|zip|git)$", "", parts[1],
            flags=re.IGNORECASE)
        return (host, parts[0], repository)
    return (host, *parts[:2])


def source_takeover_finding(
    *,
    package_name: str,
    findings: list[dict],
    adopted: bool,
    maintainer_changed: bool,
    added_urls: tuple[str, ...],
    removed_urls: tuple[str, ...],
    current_text: str | None,
) -> dict | None:
    """H105: a takeover adds a source and executes code from it.

    Adoption alone is ordinary; a new upstream source is ordinary; executing
    a declared source file can be ordinary too.  The conjunction is the
    CHAOS-RAT / 2018 acroread shape: a package changes hands or is newly
    controlled, points at a source identity the package did not use before,
    and the build runs code from that source.  H088 owns the registry variant;
    this is the declared-source variant.

    The caller supplies *adopted* (H086/orphan state) or
    *maintainer_changed* (H044/H026-style transition).  The source identity
    is compared with the recipe's ``url=`` and the sources removed by this
    diff, so an honest adopter moving upstream still has a path to quiet.
    """
    if not (adopted or maintainer_changed) or not added_urls:
        return None
    executed = any(
        str(finding.get("rule_id")) in _SOURCE_EXECUTION_RULES
        for finding in findings if isinstance(finding, dict)
    )
    if not executed:
        return None

    previous = set()
    for url in removed_urls:
        previous.add(_source_identity(url))
    if current_text:
        match = _URL_ASSIGN_RE.search(current_text)
        if match:
            previous.add(_source_identity(match.group(1)))
    new = [(url, _source_identity(url)) for url in added_urls]
    new = [(url, identity) for url, identity in new
           if identity and identity not in previous]
    if not new:
        return None

    url, _identity = new[0]
    return stamp({
        "rule_id": "H105",
        "name": "Adopted Source Executed",
        "severity": "HIGH",
        "category": "takeover",
        "match": (f"{package_name} adds source {url[:100]} and executes "
                  "code from it after an ownership change"),
        "params": {"source": url[:200]},
    })


_DEP_FIELDS = ("depends", "makedepends", "checkdepends", "optdepends")

_DEP_ASSIGN_RE = re.compile(
    r"^\s*(?:" + "|".join(_DEP_FIELDS) + r")(?:_[A-Za-z0-9_]+)?\s*(?:\+)?=",
    re.IGNORECASE,
)

_SOURCE_ASSIGN_RE = re.compile(r"^\s*source(?:_[A-Za-z0-9_]+)?\s*(?:\+)?=", re.IGNORECASE)

_CHECKSUM_ASSIGN_RE = re.compile(
    r"^\s*(?:(?:md5|sha1|sha224|sha256|sha384|sha512|b2)sums)"
    r"(?:_[A-Za-z0-9_]+)?\s*(?:\+)?=",
    re.IGNORECASE,
)

_PKGVER_RE = re.compile(r"^\s*pkgver\s*=", re.IGNORECASE)

_FUNCTION_OPEN_RE = re.compile(r"^\s*(\w+)\s*\(\s*\)\s*\{")


def _changed_kinds(
    diff_text: str, pkgver_moved: bool = False
) -> dict[str, bool]:
    """Which parts of the recipe this diff touches.

    Read off added *and* removed lines: a checksum that was edited shows as
    one of each, and "the checksums did not move" has to mean neither side
    touched them.

    *pkgver_moved* is the canonical ``pkgver_move_in_diff`` result.  A
    variable-driven bump (``_gtkver=1.2.3`` -> ``1.2.4`` with
    ``pkgver=${_gtkver}`` context) edits no ``pkgver=`` line, so the lexical
    scan below missed it and H087 claimed "pkgver did not [move]" about a
    version that did.
    """
    lines = parse_diff_lines(
        join_line_continuations(split_lines(clamp_text(diff_text)))).lines
    kinds = {
        "deps": False,
        "source": False,
        "checksums": False,
        "pkgver": pkgver_moved,
        "build_function": False,
    }
    depth = 0
    for line in lines:
        if line.raw.startswith(("+++", "---", "@@")):
            continue
        if line.is_content:
            marker = {"add": "+", "remove": "-", "context": " "}[line.side]
            body = line.content
        else:
            marker, body = "", line.raw
        stripped = body.lstrip()

        opened = _FUNCTION_OPEN_RE.match(stripped)
        inside_build = depth > 0
        if opened:
            depth += 1
            if opened.group(1) in BUILD_FUNCTIONS and marker in ("+", "-"):
                kinds["build_function"] = True
            if stripped.rstrip().endswith("}"):
                depth -= 1
            continue
        if stripped.startswith("}") and depth > 0:
            depth -= 1
            continue

        if marker not in ("+", "-"):
            continue
        if inside_build:
            kinds["build_function"] = True
            continue
        if _DEP_ASSIGN_RE.match(body):
            kinds["deps"] = True
        elif _SOURCE_ASSIGN_RE.match(body):
            kinds["source"] = True
        elif _CHECKSUM_ASSIGN_RE.match(body):
            kinds["checksums"] = True
        elif _PKGVER_RE.match(body):
            kinds["pkgver"] = True
    return kinds


def is_recipe_only_change(diff_text: str, pkgver_moved: bool = False) -> bool:
    """True when the recipe gained build inputs *and* build steps, upstream unmoved.

    Two conjunctions, both measured rather than guessed.

    "Upstream did not move" means no ``source=`` edit, no checksum edit and
    no ``pkgver`` edit. Any one of those means the package points at
    different upstream bytes, which is an ordinary update whatever else
    changed with it.

    "The recipe gained capability" means a dependency array changed **and** a
    build function changed. Requiring both is what makes this specific, and
    the numbers are the reason: against the 3,739-diff locked benign corpus,
    ``deps or build`` fires on 11.53%, ``deps only`` on 4.36%, ``build only``
    on 5.75%, and ``deps and build`` on **1.42%**. The disjunction is under
    the 30% ceiling but it is eight times the noise for no extra detection -
    the June 2026 campaign changed both, because new build dependencies are
    useless without a build step that invokes them.

    It also keeps H087 out of two neighbours' territory. A dependency added
    with no build change is a packaging fix. A build function edited with no
    dependency change is H015, which is INFO precisely because it fires on
    21.4% of benign diffs; a MEDIUM twin of it would be the same mistake with
    a different id.
    """
    kinds = _changed_kinds(diff_text, pkgver_moved=pkgver_moved)
    upstream_moved = kinds["source"] or kinds["checksums"] or kinds["pkgver"]
    gained_capability = kinds["deps"] and kinds["build_function"]
    return gained_capability and not upstream_moved


def adoption_findings(
    diff_text: str,
    *,
    package_name: str,
    was_orphaned: int,
    currently_maintained: bool,
    add,
    pkgver_moved: bool = False,
    current_text: str | None = None,
) -> None:
    """Emit H086, H087 and the H088 composition.

    *was_orphaned* is the tri-state from :func:`db.get_aur_orphan_state`:
    1 orphaned, 0 maintained, -1 never recorded. H086 requires 1, so a
    database with no prior observation says nothing rather than guessing.

    *pkgver_moved* is the canonical version move, so "upstream did not
    move" is judged by the same answer the rest of the engine uses.

    *current_text* is the post-diff PKGBUILD: the registry-resolution
    scope has to follow the call graph, and the call graph is only complete
    when the whole file is visible.
    """
    adopted = was_orphaned == 1 and currently_maintained
    recipe_only = is_recipe_only_change(diff_text, pkgver_moved=pkgver_moved)
    resolutions = registry_resolutions(diff_text, current_text)

    if adopted:
        add("H086", "Adopted From Orphan", "MEDIUM", "maintainer",
            f"{package_name} was orphaned in the AUR and now has a maintainer",
            package=package_name)

    if recipe_only:
        add("H087", "Recipe Changed Without Upstream", "MEDIUM", "integrity",
            "build recipe changed while source URLs, checksums and pkgver did not",
            package=package_name)

    # The composition. Each part is ordinary alone; together they are the
    # June 2026 chain in one diff, and the whole point of scoring it here is
    # that no single member has to carry a weight its benign fire rate
    # cannot support.
    if adopted and recipe_only and resolutions:
        function, command = resolutions[0]
        add("H088", "Adopted, Recipe Rewritten, Unpinned Fetch", "HIGH", "takeover",
            f"{package_name} was adopted from orphan, its recipe changed with no "
            f"upstream move, and {function}() now resolves dependencies from a "
            f"registry: {command[:80]}",
            package=package_name, position=function, body=command[:80])


#: Findings that already prove network egress or an upload in this change.
_EGRESS_RULES = frozenset({"H016", "H017", "H041", "H071", "H075", "H082", "H090"})

_CREDENTIAL_PATH_RE = re.compile(
    r"(?:~|\$HOME|\$\{HOME\})/\.(?:ssh|aws|gnupg|docker|netrc|npmrc|config/gh)\b"
    r"|\b(?:id_rsa|id_ed25519|known_hosts|\.npmrc|\.netrc|\.docker/config\.json|"
    r"Cookies|Login Data|Local Storage|/etc/shadow|/proc/[^\s]+/environ)\b",
    re.IGNORECASE,
)
_CREDENTIAL_READ_RE = re.compile(
    r"\b(?:cat|cp|tar|base64|grep|sed|awk|find|curl|wget|scp|rsync|"
    r"python3?|openssl|gpg|strings|printenv|env)\b",
    re.IGNORECASE,
)


def credential_egress_finding(
    *, package_name: str, findings: list[dict], diff_text: str
) -> dict | None:
    """H107: a build/install step reads a credential store and sends data out.

    Reading a config file is ordinary; sending data is ordinary in isolation.
    The conjunction is a credential-stealer step written directly in the
    recipe rather than hidden in an external binary.  No egress finding, no
    H107: the rule must not accuse a package merely for reading its own
    configuration.
    """
    if not any(str(f.get("rule_id")) in _EGRESS_RULES
               for f in findings if isinstance(f, dict)):
        return None
    for line in parse_diff_lines(join_line_continuations(split_lines(clamp_text(diff_text)))).lines:
        if line.side != "add" or line.raw.startswith("+++"):
            continue
        body = line.content
        if _CREDENTIAL_PATH_RE.search(body) and _CREDENTIAL_READ_RE.search(body):
            return stamp({
                "rule_id": "H107",
                "name": "Credential Store Access With Egress",
                "severity": "HIGH",
                "category": "exfil",
                "match": (f"{package_name} reads a credential path while the "
                          "same change has network egress or an upload"),
                "params": {"path": body.strip()[:120]},
            })
    return None
