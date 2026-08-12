"""The rule taxonomy: what kind of claim a rule makes.

Every rule already carries a ``category`` field, but that field answers a
different question.  ``category`` names the *capability* a single match
touched (``network``, ``obfuscation``, ``persistence``), which is what R072
counts when it looks for capability density.  It is deliberately
fine-grained, it is set per-rule in ``rules.toml`` by whoever wrote the
rule, and several values exist that only one rule uses.

:class:`RuleCategory` answers "what sort of thing does this rule detect?"
There is exactly one per rule, the set is closed, and it is the axis the
reference documentation is organised along: each member owns one page under
``docs/reference/rules/``.  The two are not interchangeable - R072 is
``category = "meta"`` and :data:`RuleCategory.COMPOSITION`, because the
capability it reports is "none of them" while the claim it makes is "several
stages co-occurred".

Nothing here changes what a finding contains.  Adding the taxonomy to the
report payload would rewrite every baseline for a field no scoring path
reads, so this module is a lookup: docs are generated and checked against
it, and callers that want to group findings by claim can ask for it.
"""

from __future__ import annotations

from enum import StrEnum

__all__ = [
    "RuleCategory",
    "RULE_CATEGORIES",
    "category_of",
    "rules_in",
]


class RuleCategory(StrEnum):
    """The kind of claim a rule makes.

    The value is the slug, which is also the basename of the reference page
    that documents every rule in the category.
    """

    FETCH_AND_EXECUTION = "fetch-and-execution"
    OBFUSCATION = "obfuscation"
    DECEPTION = "deception"
    INSTALL_AND_PERSIST = "install-and-persist"
    STAGING_AND_RECON = "staging-and-recon"
    INTEGRITY = "integrity"
    NAMING_AND_DEPENDENCY = "naming-and-dependency"
    MAINTAINER_AND_METADATA = "maintainer-and-metadata"
    TEMPORAL = "temporal"
    COMPOSITION = "composition"
    COUNT_BASED = "count-based"
    CORPUS_BEHAVIORAL = "corpus-behavioral"
    CROSSFIRE = "crossfire"

    @property
    def doc_page(self) -> str:
        """Path of the reference page, relative to ``docs/reference/rules/``."""
        return f"{self.value}.md"

    @property
    def title(self) -> str:
        """Human-readable heading for the category's page."""
        return _TITLES[self]

    @property
    def summary(self) -> str:
        """One sentence stating what a rule in this category claims."""
        return _SUMMARIES[self]

    @property
    def implemented(self) -> bool:
        """False for a category that is specified but ships no rules yet."""
        return self is not RuleCategory.CROSSFIRE


_TITLES: dict[RuleCategory, str] = {
    RuleCategory.FETCH_AND_EXECUTION: "Fetch and Execution",
    RuleCategory.OBFUSCATION: "Obfuscation",
    RuleCategory.DECEPTION: "Deception and Anti-Analysis",
    RuleCategory.INSTALL_AND_PERSIST: "Install and Persistence",
    RuleCategory.STAGING_AND_RECON: "Staging and Reconnaissance",
    RuleCategory.INTEGRITY: "Integrity and Verification",
    RuleCategory.NAMING_AND_DEPENDENCY: "Naming and Dependencies",
    RuleCategory.MAINTAINER_AND_METADATA: "Maintainer and Metadata",
    RuleCategory.TEMPORAL: "Temporal Context",
    RuleCategory.COMPOSITION: "Composition",
    RuleCategory.COUNT_BASED: "Count-Based",
    RuleCategory.CORPUS_BEHAVIORAL: "Corpus Behavioral",
    RuleCategory.CROSSFIRE: "Crossfire",
}

_SUMMARIES: dict[RuleCategory, str] = {
    RuleCategory.FETCH_AND_EXECUTION: (
        "Code reaches the machine and runs: a fetch, an execution, or the "
        "path between the two."
    ),
    RuleCategory.OBFUSCATION: (
        "The recipe hides what it does from a reader by encoding, "
        "indirection, or runtime assembly."
    ),
    RuleCategory.DECEPTION: (
        "The recipe targets whoever reviews it rather than the shell that "
        "runs it, or checks whether it is being watched."
    ),
    RuleCategory.INSTALL_AND_PERSIST: (
        "Something survives the build: a root-time hook, a unit, a "
        "privileged bit, a file in the user's profile."
    ),
    RuleCategory.STAGING_AND_RECON: (
        "The build steps outside its staging roots, hides a drop, or "
        "profiles the host it is running on."
    ),
    RuleCategory.INTEGRITY: (
        "A verification the recipe used to carry is weakened, removed, or "
        "cannot cover what it claims to."
    ),
    RuleCategory.NAMING_AND_DEPENDENCY: (
        "A name is claimed or a dependency set changes in a way that "
        "redirects what gets installed."
    ),
    RuleCategory.MAINTAINER_AND_METADATA: (
        "Who owns the package, or a long-stable declared property, changed."
    ),
    RuleCategory.TEMPORAL: (
        "How recently the package or this revision appeared, independent of "
        "any diff content."
    ),
    RuleCategory.COMPOSITION: (
        "Distinct kinds of finding co-occurred; the combination is the "
        "signal, and the points are already scored elsewhere."
    ),
    RuleCategory.COUNT_BASED: (
        "A count of indicators crossed a fixed threshold within one artifact "
        "or one cluster."
    ),
    RuleCategory.CORPUS_BEHAVIORAL: (
        "The package's position in, or deviation from, the corpus baseline - "
        "silent without prior observations."
    ),
    RuleCategory.CROSSFIRE: (
        "Proposed: signals that only exist when two packages are compared "
        "against each other rather than against the corpus."
    ),
}


# Every documented rule id, mapped to the one category that owns it.
#
# `R071` is documented twice, once for the per-package path and once for the
# corpus path; both sections live on the maintainer page, so the id appears
# once here.  Ids listed in the reference as reserved (`R015`, `R026`-`R038`,
# `R078`, `R091`, `R099`, `R103`-`R104`, `R109`, `R113`) are absent by
# design: an unassigned id has no claim to categorise.  The `P` series is
# absent too - a declared practice is not a detection.
_C = RuleCategory

RULE_CATEGORIES: dict[str, RuleCategory] = {
    # -- fetch and execution -------------------------------------------
    "R001": _C.FETCH_AND_EXECUTION,
    "R002": _C.FETCH_AND_EXECUTION,
    "R006": _C.FETCH_AND_EXECUTION,
    "R008": _C.FETCH_AND_EXECUTION,
    "R009": _C.FETCH_AND_EXECUTION,
    "R010": _C.FETCH_AND_EXECUTION,
    "R011": _C.FETCH_AND_EXECUTION,
    "R020": _C.FETCH_AND_EXECUTION,
    "R022": _C.FETCH_AND_EXECUTION,
    "R041": _C.FETCH_AND_EXECUTION,
    "R042": _C.FETCH_AND_EXECUTION,
    "R044": _C.FETCH_AND_EXECUTION,
    "R046": _C.FETCH_AND_EXECUTION,
    "R047": _C.FETCH_AND_EXECUTION,
    "R048": _C.FETCH_AND_EXECUTION,
    "R051": _C.FETCH_AND_EXECUTION,
    "R055": _C.FETCH_AND_EXECUTION,
    "R056": _C.FETCH_AND_EXECUTION,
    "R057": _C.FETCH_AND_EXECUTION,
    "R060": _C.FETCH_AND_EXECUTION,
    "R061": _C.FETCH_AND_EXECUTION,
    "R076": _C.FETCH_AND_EXECUTION,
    "R080": _C.FETCH_AND_EXECUTION,
    "R087": _C.FETCH_AND_EXECUTION,
    "R120": _C.FETCH_AND_EXECUTION,
    "R121": _C.FETCH_AND_EXECUTION,
    "R123": _C.FETCH_AND_EXECUTION,
    "R124": _C.FETCH_AND_EXECUTION,
    "R127": _C.FETCH_AND_EXECUTION,
    "R129": _C.FETCH_AND_EXECUTION,
    "R136": _C.FETCH_AND_EXECUTION,
    "R137": _C.FETCH_AND_EXECUTION,
    "R138": _C.FETCH_AND_EXECUTION,
    "C007": _C.FETCH_AND_EXECUTION,
    # -- obfuscation ---------------------------------------------------
    "R003": _C.OBFUSCATION,
    "R025": _C.OBFUSCATION,
    "R039": _C.OBFUSCATION,
    "R040": _C.OBFUSCATION,
    "R043": _C.OBFUSCATION,
    "R045": _C.OBFUSCATION,
    "R117": _C.OBFUSCATION,
    "R132": _C.OBFUSCATION,
    # -- deception and anti-analysis -----------------------------------
    "R012": _C.DECEPTION,
    "R013": _C.DECEPTION,
    "R023": _C.DECEPTION,
    "R024": _C.DECEPTION,
    "R119": _C.DECEPTION,
    # -- install and persistence ---------------------------------------
    "R007": _C.INSTALL_AND_PERSIST,
    "R017": _C.INSTALL_AND_PERSIST,
    "R052": _C.INSTALL_AND_PERSIST,
    "R053": _C.INSTALL_AND_PERSIST,
    "R054": _C.INSTALL_AND_PERSIST,
    "R059": _C.INSTALL_AND_PERSIST,
    "R062": _C.INSTALL_AND_PERSIST,
    "R068": _C.INSTALL_AND_PERSIST,
    "R077": _C.INSTALL_AND_PERSIST,
    "R081": _C.INSTALL_AND_PERSIST,
    "R085": _C.INSTALL_AND_PERSIST,
    "R114": _C.INSTALL_AND_PERSIST,
    "R139": _C.INSTALL_AND_PERSIST,
    # -- staging and reconnaissance ------------------------------------
    "R018": _C.STAGING_AND_RECON,
    "R021": _C.STAGING_AND_RECON,
    "R058": _C.STAGING_AND_RECON,
    "R084": _C.STAGING_AND_RECON,
    "R086": _C.STAGING_AND_RECON,
    "R088": _C.STAGING_AND_RECON,
    "R128": _C.STAGING_AND_RECON,
    "R140": _C.STAGING_AND_RECON,
    # -- integrity and verification ------------------------------------
    "R004": _C.INTEGRITY,
    "R005": _C.INTEGRITY,
    "R014": _C.INTEGRITY,
    "R019": _C.INTEGRITY,
    "R049": _C.INTEGRITY,
    "R050": _C.INTEGRITY,
    "R063": _C.INTEGRITY,
    "R064": _C.INTEGRITY,
    "R069": _C.INTEGRITY,
    "R070": _C.INTEGRITY,
    "R079": _C.INTEGRITY,
    "R094": _C.INTEGRITY,
    "R118": _C.INTEGRITY,
    "R122": _C.INTEGRITY,
    "R130": _C.INTEGRITY,
    "R131": _C.INTEGRITY,
    "C001": _C.INTEGRITY,
    "C002": _C.INTEGRITY,
    "C003": _C.INTEGRITY,
    "C004": _C.INTEGRITY,
    "C005": _C.INTEGRITY,
    # -- naming and dependencies ---------------------------------------
    "R016": _C.NAMING_AND_DEPENDENCY,
    "R074": _C.NAMING_AND_DEPENDENCY,
    "R095": _C.NAMING_AND_DEPENDENCY,
    "R101": _C.NAMING_AND_DEPENDENCY,
    "R110": _C.NAMING_AND_DEPENDENCY,
    "R116": _C.NAMING_AND_DEPENDENCY,
    "D001": _C.NAMING_AND_DEPENDENCY,
    "D002": _C.NAMING_AND_DEPENDENCY,
    "D003": _C.NAMING_AND_DEPENDENCY,
    "D004": _C.NAMING_AND_DEPENDENCY,
    # -- maintainer and metadata ---------------------------------------
    "R071": _C.MAINTAINER_AND_METADATA,
    "R083": _C.MAINTAINER_AND_METADATA,
    "R090": _C.MAINTAINER_AND_METADATA,
    "R096": _C.MAINTAINER_AND_METADATA,
    "R097": _C.MAINTAINER_AND_METADATA,
    "R098": _C.MAINTAINER_AND_METADATA,
    "R102": _C.MAINTAINER_AND_METADATA,
    "R108": _C.MAINTAINER_AND_METADATA,
    "R115": _C.MAINTAINER_AND_METADATA,
    "R126": _C.MAINTAINER_AND_METADATA,
    "C006": _C.MAINTAINER_AND_METADATA,
    # -- temporal context ----------------------------------------------
    "R065": _C.TEMPORAL,
    "R066": _C.TEMPORAL,
    "R067": _C.TEMPORAL,
    # -- composition ---------------------------------------------------
    "R072": _C.COMPOSITION,
    "R089": _C.COMPOSITION,
    # -- count-based ---------------------------------------------------
    "R075": _C.COUNT_BASED,
    "R082": _C.COUNT_BASED,
    "R092": _C.COUNT_BASED,
    "R100": _C.COUNT_BASED,
    "R105": _C.COUNT_BASED,
    # -- corpus behavioral ---------------------------------------------
    "R073": _C.CORPUS_BEHAVIORAL,
    "R093": _C.CORPUS_BEHAVIORAL,
    "R106": _C.CORPUS_BEHAVIORAL,
    "R107": _C.CORPUS_BEHAVIORAL,
    "R111": _C.CORPUS_BEHAVIORAL,
    "R112": _C.CORPUS_BEHAVIORAL,
    "R125": _C.CORPUS_BEHAVIORAL,
}

del _C


def category_of(rule_id: str) -> RuleCategory | None:
    """Return the category owning *rule_id*, or None if it is not a rule.

    Reserved and unassigned ids return None rather than raising: callers
    read ids out of stored findings and old baselines, and an id that no
    longer exists is a fact about the data, not a programming error.
    """
    return RULE_CATEGORIES.get(rule_id.upper())


def rules_in(category: RuleCategory) -> list[str]:
    """Return the sorted rule ids belonging to *category*."""
    return sorted(rid for rid, cat in RULE_CATEGORIES.items() if cat is category)
