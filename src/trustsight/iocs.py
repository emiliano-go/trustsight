"""Class E - the indicator list behind H056 (plan §9).

An indicator is a *confirmed* artefact of a real incident: a package name
that was published as malware, a domain a payload was fetched from, the hash
of a dropped binary.  H056 does exactly one thing with it - exact equality.
Nothing here infers, resembles, or scores: a hit means "this is the known
artefact", and anything short of equality is not a hit at all.

Two properties follow from that and are enforced here rather than at the
call sites:

- **A miss is uninformative.**  The list is a record of what has already
  been reported; it says nothing about a package it does not name.  No
  caller may read an empty result as evidence of cleanliness.
- **Every entry carries provenance and a confidence tier.**  The tier picks
  the severity (``confirmed`` -> CRITICAL), so an unsourced entry cannot
  quietly acquire the weight of a confirmed one.

The file is versioned (``[meta] version``) so a corpus artifact can state
which indicator set it was analysed against.
"""

import functools
import logging
import re

from .config import load_iocs

log = logging.getLogger(__name__)

# The entry types H056 and the federation baseline know how to match.  A new
# type needs a matcher in analysis/ioc.py and analysis/ioc_match.py, so an
# unknown one is dropped rather than ignored.  This is the single source of
# truth: `ioc_baseline` imports it too, so the two layers cannot drift.
IOC_TYPES = frozenset({"package", "domain", "hash", "file_path", "pkgbuild_pattern"})

#: Types the corpus pivot understands.  `file_path` and `pkgbuild_pattern`
#: describe a file or a line shape, not an artefact a stored corpus row
#: references, so the inverse lookup has nothing to search.
PIVOT_IOC_TYPES = frozenset({"package", "domain", "hash"})

#: A `pkgbuild_pattern` is matched as a regex, so it is a weaker claim than
#: the exact equality the other types make.  It can never reach FATAL: a
#: confirmed tier is capped at CRITICAL so a regex can never short-circuit
#: the score to 100 on its own.
PATTERN_SEVERITY = {
    "confirmed": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
}

#: Bounds on curator-supplied patterns.  A pattern is compiled once per
#: process and searched per added line, so an unbounded set is a denial of
#: service a signed baseline could carry.
PATTERN_MAX_LENGTH = 2000
MAX_PATTERN_ENTRIES = 500

#: An alternation inside a quantified group — `(a|aa)+` — is the second
#: classic catastrophic shape.  `regex_safety.has_nested_quantifier` misses
#: it on purpose (a prefix alternation is linear under some engine shapes),
#: but it is exponential here, so it is refused statically.  This is a
#: conservative over-approximation: a pattern that merely *contains* such a
#: group is refused, which no IOC pattern needs to do.
_QUANTIFIED_ALTERNATION_RE = re.compile(r"\([^()]*\|[^()]*\)\s*(?:[+*]|\{\d)")

# Confidence tier -> finding severity.  A tier is a claim about the evidence
# behind the entry, never about how bad the package is.
#
# ``confirmed`` is FATAL for the same reason R012/R013 are: referencing an
# artefact published as malware has no legitimate packaging explanation, so
# there is nothing for the score to weigh.  That is also why the entry
# demands provenance - the tier is what makes the FATAL defensible, and an
# entry that cannot cite a report does not belong at this tier.
CONFIDENCE_SEVERITY = {
    "confirmed": "FATAL",
    "high": "CRITICAL",
    "medium": "HIGH",
}
# An entry whose tier is missing or unrecognised still matches, but at the
# lowest severity: the indicator may be real, its evidence is undeclared.
DEFAULT_SEVERITY = "MEDIUM"

# Digest lengths accepted for a hash entry (md5, sha1, sha224, sha256,
# sha384, sha512/b2).  A value outside this set is a typo, not a digest.
_HASH_LENGTHS = frozenset({32, 40, 56, 64, 96, 128})
_HEX_RE = re.compile(r"^[0-9a-f]+$")

_HOST_RE = re.compile(r"^[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)+$")


@functools.lru_cache(maxsize=1024)
def compile_ioc_pattern(pattern: str) -> re.Pattern | None:
    """Compile a curator-supplied pattern, or None if unusable or unsafe.

    A signed baseline is third-party text, so the check must itself be safe:
    it is entirely static.  The measured superlinear check the rule linter
    uses *runs* the pattern on adversarial input, which hangs on exactly the
    catastrophic patterns it is meant to reject, so it is not used here.  A
    nested quantifier, or an alternation inside a quantified group, is
    refused; both are the classic shape and neither is anything a curator
    needs.  Cached because the static checks are not free and the same
    pattern is compiled on every analysis.
    """
    if not pattern or len(pattern) > PATTERN_MAX_LENGTH:
        return None
    try:
        compiled = re.compile(pattern)
    except re.error:
        return None
    from .regex_safety import has_nested_quantifier

    if has_nested_quantifier(pattern):
        return None
    if _QUANTIFIED_ALTERNATION_RE.search(pattern):
        return None
    return compiled


class Indicator:
    """One entry of the shipped list."""

    __slots__ = ("type", "value", "confidence", "provenance", "campaign", "added")

    def __init__(self, type: str, value: str, confidence: str,
                 provenance: str = "", campaign: str = "", added: str = ""):
        self.type = type
        self.value = value
        self.confidence = confidence
        self.provenance = provenance
        self.campaign = campaign
        self.added = added

    @property
    def severity(self) -> str:
        if self.type == "pkgbuild_pattern":
            return PATTERN_SEVERITY.get(self.confidence, DEFAULT_SEVERITY)
        return CONFIDENCE_SEVERITY.get(self.confidence, DEFAULT_SEVERITY)

    def evidence(self) -> dict:
        """The declared facts behind the entry, for the finding."""
        return {
            "ioc_type": self.type,
            "ioc_value": self.value,
            "confidence": self.confidence,
            "provenance": self.provenance,
            "campaign": self.campaign,
        }

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"Indicator({self.type}={self.value!r}, {self.confidence})"


class IndicatorSet:
    """Indicators grouped by type, keyed by their normalized value.

    Lookup is a dict hit on the normalized value - never a prefix, suffix,
    subdomain or substring test.  ``version`` is the list version the
    indicators came from, so a report can name what it was matched against.
    """

    def __init__(self, version: int = 0, indicators: list[Indicator] | None = None):
        self.version = version
        self._by_type: dict[str, dict[str, Indicator]] = {t: {} for t in IOC_TYPES}
        self._patterns: list[tuple[Indicator, re.Pattern]] = []
        for ind in indicators or []:
            self._by_type[ind.type][ind.value] = ind
            if ind.type == "pkgbuild_pattern":
                compiled = compile_ioc_pattern(ind.value)
                if compiled is not None and len(self._patterns) < MAX_PATTERN_ENTRIES:
                    self._patterns.append((ind, compiled))

    def __bool__(self) -> bool:
        return any(self._by_type[t] for t in IOC_TYPES)

    def __len__(self) -> int:
        return sum(len(self._by_type[t]) for t in IOC_TYPES)

    def all(self) -> list[Indicator]:
        return [ind for t in sorted(IOC_TYPES) for ind in self._by_type[t].values()]

    def values(self, type: str) -> frozenset[str]:
        return frozenset(self._by_type.get(type, {}))

    def match(self, type: str, value: str) -> Indicator | None:
        """Return the indicator *value* equals exactly, or None."""
        normalized = normalize(type, value)
        if normalized is None:
            return None
        return self._by_type.get(type, {}).get(normalized)

    def match_package(self, name: str) -> Indicator | None:
        return self.match("package", name)

    def match_domain(self, host: str) -> Indicator | None:
        return self.match("domain", host)

    def match_hash(self, digest: str) -> Indicator | None:
        return self.match("hash", digest)

    def match_file_path(self, path: str) -> Indicator | None:
        return self.match("file_path", path)

    def patterns(self) -> tuple[tuple[Indicator, re.Pattern], ...]:
        """The compiled `pkgbuild_pattern` entries, already safety-checked."""
        return tuple(self._patterns)


def normalize(type: str, value: str) -> str | None:
    """Normalize *value* for exact comparison, or None if it is not one.

    Normalization is limited to differences that are not part of the
    identity: case for hosts and hex digests, a trailing root dot, a
    surrounding quote.  A host is never stripped of a subdomain and a name
    is never stemmed - that would turn equality into resemblance.
    """
    if not isinstance(value, str):
        return None
    value = value.strip().strip("'\"")
    if not value:
        return None
    if type == "hash":
        value = value.lower()
        if len(value) not in _HASH_LENGTHS or not _HEX_RE.match(value):
            return None
        return value
    if type == "domain":
        value = value.lower().rstrip(".")
        if "://" in value:
            value = value.split("://", 1)[1]
        value = value.split("/", 1)[0].split("@")[-1].split(":", 1)[0]
        ascii_host = _to_ascii_host(value)
        if ascii_host is None or not _HOST_RE.match(ascii_host):
            return None
        return ascii_host
    if type == "package":
        # Folded, as pacman names are written and as
        # deps.normalize_dependency already folds them.  Comparing the entry
        # raw would answer differently depending on which surface the name
        # arrived from - a dependency (folded) or the package's own name
        # (not) - and a silent miss on a confirmed indicator is the worst
        # failure this rule has.
        return value.lower()
    if type == "file_path":
        # A committed file the recipe names, or a path a diff touches.
        # Separators are folded and a leading `./` and trailing `/` dropped;
        # the path stays case-sensitive, because Linux paths are.
        path = value.replace("\\", "/")
        while "//" in path:
            path = path.replace("//", "/")
        if path.startswith("./"):
            path = path[2:]
        path = path.rstrip("/")
        if not path or path == ".":
            return None
        return path
    if type == "pkgbuild_pattern":
        # The canonical form is the pattern text itself; whether it is a
        # usable, safe pattern is decided by `compile_ioc_pattern`.
        return value
    return None


def _to_ascii_host(host: str) -> str | None:
    """Return *host* in its IDNA/punycode form, or None if it will not encode.

    An indicator may be written in the script its registration used while
    the PKGBUILD carries the ``xn--`` encoding of the same name, or the
    reverse.  They are one host, so both sides are compared in the single
    ASCII form rather than one of them silently failing to match.
    """
    if host.isascii():
        return host
    try:
        return host.encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        return None


def _entry_rows(data: dict) -> list[dict]:
    """Accept both the top-level and the ``[iocs]``-nested entry forms."""
    rows = data.get("entries")
    if rows is None:
        rows = (data.get("iocs") or {}).get("entries")
    if isinstance(rows, dict):  # a single [entries] table, not an array
        rows = [rows]
    return [r for r in (rows or []) if isinstance(r, dict)]


def _version(data: dict) -> int:
    meta = data.get("meta") or data.get("iocs") or {}
    try:
        return int(meta.get("version", 0))
    except (TypeError, ValueError):
        return 0


def load_indicators(data: dict | None = None, on_skip=None) -> IndicatorSet:
    """Load and validate iocs.toml into an :class:`IndicatorSet`.

    A malformed entry is dropped with a warning, never coerced: an entry
    whose type is unknown has no matcher, and an entry whose value does not
    normalize (a truncated digest, a URL where a host belongs) cannot be
    compared for equality.  A missing or unknown confidence tier is kept at
    the lowest severity rather than dropped - the indicator is still real,
    only its evidence is undeclared.

    *on_skip* is called with a short label for each dropped entry, so an
    analysis can mark itself degraded rather than matching a smaller list
    than the operator believes is loaded.
    """
    if data is None:
        data = load_iocs()
    indicators: list[Indicator] = []

    def skipped(label: str) -> None:
        if on_skip is not None:
            on_skip(label)

    for row in _entry_rows(data):
        type_ = str(row.get("type", "")).strip().lower()
        if type_ not in IOC_TYPES:
            log.warning("iocs.toml: dropping entry with unknown type %r", row.get("type"))
            skipped(type_ or "unknown-type")
            continue
        value = normalize(type_, row.get("value", ""))
        if value is None:
            log.warning(
                "iocs.toml: dropping %s entry with unusable value %r",
                type_, row.get("value"),
            )
            skipped(type_)
            continue
        if type_ == "pkgbuild_pattern" and compile_ioc_pattern(value) is None:
            log.warning(
                "iocs.toml: dropping pattern entry that is invalid or risks "
                "catastrophic backtracking: %r", value,
            )
            skipped(type_)
            continue
        confidence = str(row.get("confidence", "")).strip().lower()
        if confidence not in CONFIDENCE_SEVERITY:
            log.warning(
                "iocs.toml: %s entry %r has no known confidence tier; "
                "matching it at %s", type_, value, DEFAULT_SEVERITY,
            )
        indicators.append(
            Indicator(
                type=type_,
                value=value,
                confidence=confidence,
                provenance=str(row.get("provenance", "")),
                campaign=str(row.get("campaign", "")),
                added=str(row.get("added", "")),
            )
        )
    return IndicatorSet(version=_version(data), indicators=indicators)
