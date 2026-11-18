"""Descriptive metadata for findings: CWE and remediation.

These are labels, never signal.  A CWE identifier and a one-line remediation
help a reader act on a finding; neither is scored, and neither can lower a
finding (B1/B10).  The values resolve in three steps: a per-rule override, a
per-category default, then an empty value for a pseudo rule that no reference
page owns (``COVERAGE``, ``NOVELTY``, ``SOURCE_BUCKET``).
"""

from __future__ import annotations

from .categories import RuleCategory, category_of

__all__ = [
    "CATEGORY_CWE",
    "CATEGORY_REMEDIATION",
    "RULE_CWE",
    "RULE_REMEDIATION",
    "cwe_of",
    "remediation_of",
]

#: A representative CWE per claim category.  A rule may name a more precise
#: one in ``RULE_CWE``.
CATEGORY_CWE: dict[str, str] = {
    RuleCategory.FETCH_AND_EXECUTION.value: "CWE-94",
    RuleCategory.OBFUSCATION.value: "CWE-506",
    RuleCategory.DECEPTION.value: "CWE-506",
    RuleCategory.INSTALL_AND_PERSIST.value: "CWE-506",
    RuleCategory.STAGING_AND_RECON.value: "CWE-506",
    RuleCategory.INTEGRITY.value: "CWE-354",
    RuleCategory.NAMING_AND_DEPENDENCY.value: "CWE-427",
    RuleCategory.MAINTAINER_AND_METADATA.value: "CWE-290",
    RuleCategory.TEMPORAL.value: "CWE-506",
    RuleCategory.COMPOSITION.value: "CWE-506",
    RuleCategory.COUNT_BASED.value: "CWE-506",
    RuleCategory.CORPUS_BEHAVIORAL.value: "CWE-506",
    RuleCategory.CROSSFIRE.value: "CWE-506",
    RuleCategory.SABOTAGE.value: "CWE-506",
    RuleCategory.UNVERIFIABLE.value: "CWE-693",
    RuleCategory.META.value: "CWE-693",
    RuleCategory.ENTROPY.value: "CWE-506",
    RuleCategory.CORRELATION.value: "CWE-506",
    RuleCategory.ARTIFACT.value: "CWE-506",
    RuleCategory.INDICATOR.value: "CWE-506",
    RuleCategory.UPSTREAM_MANIFESTS.value: "CWE-494",
    RuleCategory.UPSTREAM_RELEASE.value: "CWE-494",
}

#: A short, category-level action.  Per-rule text overrides it where the
#: correct action is narrower.
CATEGORY_REMEDIATION: dict[str, str] = {
    RuleCategory.FETCH_AND_EXECUTION.value:
        "Do not pipe or execute fetched content in the build; vendor it or "
        "pin and verify a checked source.",
    RuleCategory.OBFUSCATION.value:
        "Remove encoded or dynamically constructed commands so the build is "
        "readable and reviewable.",
    RuleCategory.DECEPTION.value:
        "Remove reviewer-directed or misleading text; the recipe should "
        "describe only real build steps.",
    RuleCategory.INSTALL_AND_PERSIST.value:
        "Keep install hooks to declared files; do not create services, "
        "timers or autostart entries at install time.",
    RuleCategory.STAGING_AND_RECON.value:
        "Remove host probing and staging from the build; it is not needed to "
        "produce the package.",
    RuleCategory.INTEGRITY.value:
        "Restore the strongest available checksum and confirm the source "
        "change was intentional.",
    RuleCategory.NAMING_AND_DEPENDENCY.value:
        "Use the declared upstream name and dependency; explain any fork or "
        "rename.",
    RuleCategory.MAINTAINER_AND_METADATA.value:
        "Confirm the maintainer or metadata change with the project and keep "
        "the recipe consistent with it.",
    RuleCategory.TEMPORAL.value:
        "Confirm the unusual timing with the maintainer and the upstream "
        "release.",
    RuleCategory.COMPOSITION.value:
        "Split the change so each step can be reviewed, or explain why the "
        "signals co-occur.",
    RuleCategory.COUNT_BASED.value:
        "Reduce the mixed capability set or justify why the build needs it.",
    RuleCategory.CORPUS_BEHAVIORAL.value:
        "Explain the deviation from the package's established behaviour.",
    RuleCategory.CROSSFIRE.value:
        "Remove the environment or refusal manipulation; the build must not "
        "attack its own tooling.",
    RuleCategory.SABOTAGE.value:
        "Remove the destructive or resource-abusing command; it is not part "
        "of a build.",
    RuleCategory.UNVERIFIABLE.value:
        "Provide a readable, checksum-pinned form the analysis can inspect; "
        "treat the unread surface as unverified.",
    RuleCategory.META.value:
        "Resolve the underlying findings; the meta entry summarises them, it "
        "is not a separate defect.",
    RuleCategory.ENTROPY.value:
        "Replace the high-entropy added content with readable source.",
    RuleCategory.CORRELATION.value:
        "Review the related packages named by the correlation as a campaign "
        "signal.",
    RuleCategory.ARTIFACT.value:
        "Remove the artifact feature the recipe does not justify, or declare "
        "and document it.",
    RuleCategory.INDICATOR.value:
        "Treat the named artifact as known-bad; do not build or install it.",
    RuleCategory.UPSTREAM_MANIFESTS.value:
        "Confirm the upstream dependency change and pin it before building.",
    RuleCategory.UPSTREAM_RELEASE.value:
        "Confirm the upstream repository or CI change with the publisher "
        "before building.",
}

#: Per-rule precision where the category default is too broad.
RULE_CWE: dict[str, str] = {
    "C001": "CWE-354",
    "C022": "CWE-328",
    "H001": "CWE-354",
    "H002": "CWE-354",
    "H024": "CWE-347",
    "T001": "CWE-494",
    "T003": "CWE-494",
    "T004": "CWE-347",
    "U007": "CWE-200",
    "U008": "CWE-522",
    "A001": "CWE-250",
    "A006": "CWE-250",
    "A008": "CWE-506",
    "A009": "CWE-506",
    "A010": "CWE-250",
}

#: Per-rule action where the category default would misdirect the reader.
RULE_REMEDIATION: dict[str, str] = {
    "C001": "Restore the previous checksum or bump the version with an "
            "explained source change.",
    "C022": "Keep the strongest checksum the recipe had; a weaker hash is not "
            "a substitute for the removed one.",
    "H024": "Restore the declared signing key or document the intentional "
            "removal.",
    "T001": "Verify the new signing key belongs to the upstream publisher "
            "before trusting it.",
    "A009": "Remove the compiled binary from the source archive; build it "
            "from source.",
    "A010": "Remove the setuid/setgid bit; a source archive should not ship "
            "one.",
}


def _category_value(rule_id: str) -> str:
    category = category_of(rule_id)
    return str(category.value) if category is not None else ""


def cwe_of(rule_id: str) -> str:
    """The CWE identifier for *rule_id*, or "" for a pseudo rule."""
    if rule_id in RULE_CWE:
        return RULE_CWE[rule_id]
    return CATEGORY_CWE.get(_category_value(rule_id), "")


def remediation_of(rule_id: str) -> str:
    """The one-line remediation for *rule_id*, or "" for a pseudo rule."""
    if rule_id in RULE_REMEDIATION:
        return RULE_REMEDIATION[rule_id]
    return CATEGORY_REMEDIATION.get(_category_value(rule_id), "")
