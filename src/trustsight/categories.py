"""The rule taxonomy: what kind of claim a rule makes.

Every rule already carries a ``category`` field, but that field answers a
different question.  ``category`` names the *capability* a single match
touched (``network``, ``obfuscation``, ``persistence``), which is what H027
counts when it looks for capability density.  It is deliberately
fine-grained, it is set per-rule in ``rules.toml`` by whoever wrote the
rule, and several values exist that only one rule uses.

:class:`RuleCategory` answers "what sort of thing does this rule detect?"
There is exactly one per rule, the set is closed, and it is the axis the
reference documentation is organised along: each member owns one page under
``docs/reference/rules/``.  The two are not interchangeable - H027 is
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
    SABOTAGE = "sabotage"
    #: The W series. Not a risk claim: a statement about what the analysis
    #: could not verify, on a surface too common to price. See
    #: `unverifiable.md` for why these carry no weight.
    UNVERIFIABLE = "unverifiable"

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
        return True


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
    RuleCategory.SABOTAGE: "Sabotage",
    RuleCategory.UNVERIFIABLE: "Unverifiable",
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
        "The evasion technique itself, not the payload it hides: a rule here "
        "fires on how a thing was written rather than on what it does."
    ),
    RuleCategory.SABOTAGE: (
        "A payload aimed at the operator's machine rather than at getting "
        "something out of it: resource exhaustion, deletion, permission "
        "sabotage, service disruption, resource theft."
    ),
    RuleCategory.UNVERIFIABLE: (
        "Not a claim about the recipe but about the analysis: something the "
        "package will run that this run could not read. Weight 0 always, "
        "and always shown."
    ),
}


# Every documented rule id, mapped to the one category that owns it.
#
# `H026` is documented twice, once for the per-package path and once for the
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
    "H003": _C.FETCH_AND_EXECUTION,
    "R008": _C.FETCH_AND_EXECUTION,
    "H004": _C.FETCH_AND_EXECUTION,
    "R010": _C.FETCH_AND_EXECUTION,
    "R011": _C.FETCH_AND_EXECUTION,
    "H009": _C.FETCH_AND_EXECUTION,
    "H011": _C.FETCH_AND_EXECUTION,
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
    "H015": _C.FETCH_AND_EXECUTION,
    "H016": _C.FETCH_AND_EXECUTION,
    "H031": _C.FETCH_AND_EXECUTION,
    "H034": _C.FETCH_AND_EXECUTION,
    "H041": _C.FETCH_AND_EXECUTION,
    "H068": _C.FETCH_AND_EXECUTION,
    "H069": _C.FETCH_AND_EXECUTION,
    "H071": _C.FETCH_AND_EXECUTION,
    "H072": _C.FETCH_AND_EXECUTION,
    "H075": _C.FETCH_AND_EXECUTION,
    "H077": _C.FETCH_AND_EXECUTION,
    "H081": _C.FETCH_AND_EXECUTION,
    "H082": _C.FETCH_AND_EXECUTION,
    "H083": _C.FETCH_AND_EXECUTION,
    "C007": _C.FETCH_AND_EXECUTION,
    # -- obfuscation ---------------------------------------------------
    "R003": _C.OBFUSCATION,
    "H014": _C.OBFUSCATION,
    "R039": _C.OBFUSCATION,
    "R040": _C.OBFUSCATION,
    "R043": _C.OBFUSCATION,
    "R045": _C.OBFUSCATION,
    "H065": _C.OBFUSCATION,
    "H080": _C.OBFUSCATION,
    # -- deception and anti-analysis -----------------------------------
    "R012": _C.DECEPTION,
    "R013": _C.DECEPTION,
    "H012": _C.DECEPTION,
    "H013": _C.DECEPTION,
    "H067": _C.DECEPTION,
    # -- install and persistence ---------------------------------------
    "R007": _C.INSTALL_AND_PERSIST,
    "R017": _C.INSTALL_AND_PERSIST,
    "R052": _C.INSTALL_AND_PERSIST,
    "R053": _C.INSTALL_AND_PERSIST,
    "R054": _C.INSTALL_AND_PERSIST,
    "R059": _C.INSTALL_AND_PERSIST,
    "H017": _C.INSTALL_AND_PERSIST,
    "H023": _C.INSTALL_AND_PERSIST,
    "H032": _C.INSTALL_AND_PERSIST,
    "H035": _C.INSTALL_AND_PERSIST,
    "H039": _C.INSTALL_AND_PERSIST,
    "H062": _C.INSTALL_AND_PERSIST,
    "H084": _C.INSTALL_AND_PERSIST,
    # -- staging and reconnaissance ------------------------------------
    "H007": _C.STAGING_AND_RECON,
    "H010": _C.STAGING_AND_RECON,
    "R058": _C.STAGING_AND_RECON,
    "H038": _C.STAGING_AND_RECON,
    "H040": _C.STAGING_AND_RECON,
    "H042": _C.STAGING_AND_RECON,
    "H076": _C.STAGING_AND_RECON,
    "H085": _C.STAGING_AND_RECON,
    "H086": _C.MAINTAINER_AND_METADATA,
    "H087": _C.INTEGRITY,
    "H088": _C.MAINTAINER_AND_METADATA,
    "R144": _C.INSTALL_AND_PERSIST,
    "H089": _C.INSTALL_AND_PERSIST,
    "H090": _C.FETCH_AND_EXECUTION,
    "H091": _C.INTEGRITY,
    "H092": _C.INTEGRITY,
    "H093": _C.INSTALL_AND_PERSIST,
    "H094": _C.FETCH_AND_EXECUTION,
    "H095": _C.INSTALL_AND_PERSIST,
    "W001": _C.UNVERIFIABLE,
    "W002": _C.UNVERIFIABLE,
    "W003": _C.UNVERIFIABLE,
    "W004": _C.UNVERIFIABLE,
    "W005": _C.UNVERIFIABLE,
    "W006": _C.UNVERIFIABLE,
    "X001": _C.CROSSFIRE,
    "X002": _C.CROSSFIRE,
    "X003": _C.CROSSFIRE,
    "X004": _C.CROSSFIRE,
    "X005": _C.CROSSFIRE,
    "X006": _C.CROSSFIRE,
    "X007": _C.CROSSFIRE,
    "X008": _C.CROSSFIRE,
    "X009": _C.CROSSFIRE,
    "X010": _C.CROSSFIRE,
    "X011": _C.CROSSFIRE,
    "X012": _C.CROSSFIRE,
    "X013": _C.CROSSFIRE,
    "X014": _C.CROSSFIRE,
    "X015": _C.CROSSFIRE,
    "X016": _C.CROSSFIRE,
    "X017": _C.CROSSFIRE,
    "X018": _C.CROSSFIRE,
    "X019": _C.CROSSFIRE,
    "X020": _C.CROSSFIRE,
    "X021": _C.CROSSFIRE,
    "X022": _C.CROSSFIRE,
    "X023": _C.CROSSFIRE,
    "S001": _C.SABOTAGE,
    "S002": _C.SABOTAGE,
    "S003": _C.SABOTAGE,
    "S004": _C.SABOTAGE,
    "S005": _C.SABOTAGE,
    "S006": _C.SABOTAGE,
    "S007": _C.SABOTAGE,
    "S008": _C.SABOTAGE,
    # -- integrity and verification ------------------------------------
    "H001": _C.INTEGRITY,
    "H002": _C.INTEGRITY,
    "H005": _C.INTEGRITY,
    "H008": _C.INTEGRITY,
    "R049": _C.INTEGRITY,
    "R050": _C.INTEGRITY,
    "H018": _C.INTEGRITY,
    "H019": _C.INTEGRITY,
    "H024": _C.INTEGRITY,
    "H025": _C.INTEGRITY,
    "H033": _C.INTEGRITY,
    "H047": _C.INTEGRITY,
    "H066": _C.INTEGRITY,
    "H070": _C.INTEGRITY,
    "H078": _C.INTEGRITY,
    "H079": _C.INTEGRITY,
    "C001": _C.INTEGRITY,
    "C002": _C.INTEGRITY,
    "C003": _C.INTEGRITY,
    "C004": _C.INTEGRITY,
    "C005": _C.INTEGRITY,
    "C008": _C.INTEGRITY,
    "C009": _C.INTEGRITY,
    # -- naming and dependencies ---------------------------------------
    "H006": _C.NAMING_AND_DEPENDENCY,
    "H029": _C.NAMING_AND_DEPENDENCY,
    "H048": _C.NAMING_AND_DEPENDENCY,
    "H053": _C.NAMING_AND_DEPENDENCY,
    "H059": _C.NAMING_AND_DEPENDENCY,
    "H064": _C.NAMING_AND_DEPENDENCY,
    "D001": _C.NAMING_AND_DEPENDENCY,
    "D002": _C.NAMING_AND_DEPENDENCY,
    "D003": _C.NAMING_AND_DEPENDENCY,
    "D004": _C.NAMING_AND_DEPENDENCY,
    # -- maintainer and metadata ---------------------------------------
    "H026": _C.MAINTAINER_AND_METADATA,
    "H037": _C.MAINTAINER_AND_METADATA,
    "H044": _C.MAINTAINER_AND_METADATA,
    "H049": _C.MAINTAINER_AND_METADATA,
    "H050": _C.MAINTAINER_AND_METADATA,
    "H051": _C.MAINTAINER_AND_METADATA,
    "H054": _C.MAINTAINER_AND_METADATA,
    "H058": _C.MAINTAINER_AND_METADATA,
    "H063": _C.MAINTAINER_AND_METADATA,
    "H074": _C.MAINTAINER_AND_METADATA,
    "C006": _C.MAINTAINER_AND_METADATA,
    # -- temporal context ----------------------------------------------
    "H020": _C.TEMPORAL,
    "H021": _C.TEMPORAL,
    "H022": _C.TEMPORAL,
    # -- composition ---------------------------------------------------
    "H027": _C.COMPOSITION,
    "H043": _C.COMPOSITION,
    # -- count-based ---------------------------------------------------
    "H030": _C.COUNT_BASED,
    "H036": _C.COUNT_BASED,
    "H045": _C.COUNT_BASED,
    "H052": _C.COUNT_BASED,
    "H055": _C.COUNT_BASED,
    # -- corpus behavioral ---------------------------------------------
    "H028": _C.CORPUS_BEHAVIORAL,
    "H046": _C.CORPUS_BEHAVIORAL,
    "H056": _C.CORPUS_BEHAVIORAL,
    "H057": _C.CORPUS_BEHAVIORAL,
    "H060": _C.CORPUS_BEHAVIORAL,
    "H061": _C.CORPUS_BEHAVIORAL,
    "H073": _C.CORPUS_BEHAVIORAL,
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
