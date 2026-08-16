"""Phase 7 - Class E indicator matching (plan §9).

R106 is the only rule in TrustSight that recognises a *specific* artefact.
Every other rule describes a shape - what the code structurally does - which
is what keeps them alive when an attacker changes mechanism.  R106 is the
opposite trade: it names the artefact, so it is exact, unarguable, and
expires the moment the attacker moves.

That is why it never generalises.  The match is dict equality against the
shipped list (:mod:`trustsight.iocs`) on four declared surfaces:

- the package's own name;
- names added to ``depends``/``makedepends``/``optdepends``/``checkdepends``
  and ``provides``/``replaces``;
- the host of any URL on an added line;
- any hex digest on an added line.

A near miss is a miss: ``evil.example`` does not match ``notevil.example``
or ``cdn.evil.example``, and a truncated digest matches nothing.  The
severity comes from the entry's confidence tier, so an unsourced indicator
can never carry a confirmed one's weight, and a *miss says nothing at all* -
the list records what has already been reported, never what is safe.
"""

import re

from ..deps import extract_dependency_changes
from ..iocs import load_indicators
from ..tokenizer import resolve_added_lines
from .base import iter_scheme_urls
from ..tokenizer import split_lines

# A URL's authority, and separately a bare host token (``curl evil.example``
# carries no scheme).  Both are only ever used to produce a candidate for an
# equality test, so being generous here costs nothing: a token that is not
# on the list is not a finding.
# URL authorities come from base.iter_scheme_urls: the regex form rescanned
# from every position on a line with no "://" and went quadratic.
# Host labels may be non-ASCII: an internationalised host is normalized to
# its punycode form before comparison, so it must be captured first.
_BARE_HOST_RE = re.compile(r"(?<![\w.-])((?:[^\W_](?:[\w\-]*[^\W_])?\.)+[^\W\d_]{2,})(?![\w-])")
_HEX_RE = re.compile(r"(?<![0-9a-fA-F])([0-9a-fA-F]{32,128})(?![0-9a-fA-F])")

_DEP_FIELDS = ("depends", "makedepends", "optdepends", "checkdepends",
               "provides", "replaces")


def _added_bodies(diff_text: str) -> list[str]:
    """Added lines with the ``+`` marker stripped, variables resolved."""
    bodies = []
    for line in resolve_added_lines(diff_text):
        if not line.startswith("+") or line.startswith("+++"):
            continue
        bodies.append(line[1:])
    return bodies


def as_added(text: str) -> str:
    """Present whole-file text as an all-added diff.

    R106 is a statement about the package's *current* state, not about what
    one revision changed: a dependency on a package later published as
    malware does not stop being one because today's diff left it alone.
    Marking every line as added lets the same extractors - and the same
    variable resolution - read the file, without a second code path that
    could disagree with the diff one.
    """
    return "\n".join("+" + line for line in split_lines(text))


def _hosts_in(body: str):
    """Yield ``(host, origin)`` candidates: URL authorities and bare hosts.

    The origin is kept because they are not the same claim.  A host in a
    URL's authority is where the package points; a bare token is a mention,
    which is why ``https://indicator.example@real.example/x`` reports the
    real authority and the mention separately rather than pretending the
    userinfo half was the destination.
    """
    for _scheme, url in iter_scheme_urls(body):
        authority = url.split("://", 1)[1].split("/", 1)[0]
        yield authority.split("@")[-1].split(":", 1)[0], "url"
    for match in _BARE_HOST_RE.finditer(body):
        yield match.group(1), "bare"


def _digests_in(body: str):
    for match in _HEX_RE.finditer(body):
        yield match.group(1)


def _line_of(diff_text: str, needle: str) -> int | None:
    """1-based diff line carrying *needle* on an added line."""
    lowered = needle.lower()
    for i, line in enumerate(split_lines(diff_text)):
        if line.startswith("+") and not line.startswith("+++"):
            if lowered in line.lower():
                return i + 1
    return None


def _ioc_findings(diff_text, package_name, config, add, indicators=None,
                  current_text=None) -> None:
    """R106 - a declared fact matches a shipped indicator exactly.

    When *current_text* is given (the PKGBUILD as it now stands) the whole
    file is read instead of only the diff's added lines, because an
    indicator already present before this revision is still present now.
    Line numbers still come from the diff, so a standing reference reports
    ``line: null`` rather than a line that does not exist in the hunk.

    ``indicators`` is injectable so the corpus-side pivot and the tests can
    match against a set that is not the user's installed list.
    """
    indicators = load_indicators() if indicators is None else indicators
    if not indicators:
        return

    scan_text = as_added(current_text) if current_text else diff_text
    seen: set[tuple[str, str]] = set()

    def report(ind, surface: str, detail: str, line: int | None, **extra) -> None:
        key = (ind.type, ind.value)
        if key in seen:
            return
        seen.add(key)
        add("R106", "Known Indicator of Compromise", ind.severity, "ioc",
            detail, line=line,
            ioc_type=ind.type, ioc_value=ind.value, surface=surface,
            confidence=ind.confidence or "unspecified",
            provenance=ind.provenance, campaign=ind.campaign,
            list_version=indicators.version, **extra)

    if package_name:
        hit = indicators.match_package(package_name)
        if hit:
            report(hit, "package_name",
                   f"package name '{package_name}' is a known indicator", None)

    if indicators.values("package"):
        declared = extract_dependency_changes(scan_text, package_name)
        for field in _DEP_FIELDS:
            for name in sorted(declared.get(field, ())):
                hit = indicators.match_package(name)
                if hit:
                    report(hit, field,
                           f"{field} '{name}' is a known indicator",
                           _line_of(diff_text, name), field=field)

    want_hosts = bool(indicators.values("domain"))
    want_hashes = bool(indicators.values("hash"))
    if not (want_hosts or want_hashes):
        return

    for body in _added_bodies(scan_text):
        if want_hosts:
            for host, origin in _hosts_in(body):
                hit = indicators.match_domain(host)
                if hit:
                    surface = "source_host" if origin == "url" else "referenced_host"
                    where = "points at" if origin == "url" else "mentions"
                    report(hit, surface,
                           f"PKGBUILD {where} known-malicious host {hit.value}",
                           _line_of(diff_text, hit.value))
        if want_hashes:
            for digest in _digests_in(body):
                hit = indicators.match_hash(digest)
                if hit:
                    report(hit, "artifact_hash",
                           f"PKGBUILD carries known-malicious digest {hit.value}",
                           _line_of(diff_text, hit.value))
