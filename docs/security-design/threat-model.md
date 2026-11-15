<!-- description: TrustSight's threat model and limitations: the adversary it assumes, the trust boundary it enforces, what a result claims, and the limits that are inherent rather than unfixed. -->

# Threat Model and Limitations

TrustSight reads hostile input. The threat model starts from that fact: the
recipe, the diff, the committed files and the declared metadata are all
attacker-controlled until proven otherwise, and the tool must stay safe while
reading them.

## The adversary

The model assumes an attacker who can:

- change a `PKGBUILD` and any file committed beside it;
- declare any URL, checksum, key, maintainer identity or upstream story;
- write text designed to make a reviewer or a parser misread the recipe; and
- wait, re-adopt an orphaned package, or coordinate several packages.

The model does **not** assume the attacker can change TrustSight's own code,
the signed baselines, or the machine it runs on. The
[Security Model](security-model.md) states the invariants that keep that
boundary, and [Security Boundaries](security-boundaries.md) enumerates the
`A1`-`A15` invariants that keep the reading machine safe.

## The trust boundary

The analysis process treats every parsed byte as untrusted:

- the `PKGBUILD` is never executed;
- a declared URL is never fetched during analysis;
- committed manifests are parsed in a sandbox rather than the analysis
  process;
- writes stay inside the data directories; and
- a bound that drops input records a coverage gap, so an incomplete analysis
  cannot present an unflagged verdict.

## What a result claims

A result is an assertion about **evidence found in the analysed material**,
not a statement that a package is safe. The clauses are stated in full in
[What a Result Claims](what-a-result-claims.md): the score is a sum of matched
evidence, an unflagged verdict is never issued for an incomplete analysis,
FATAL cannot be switched off, suppression is visible, and the prose reports
what changed rather than only what fired.

## Limitations

Some limits are inherent to auditing a recipe without building it:

- **What the build will actually fetch** can be computed at build time; the
  static text may not contain the URL.
- **What a binary does** cannot be learned from its name or its declared
  intent. The optional artifact lane inspects a built manifest, outside the
  static score.
- **What an upstream will serve tomorrow** is not visible in today's diff.
- **What a reviewer will notice** is not modeled. TrustSight reduces the
  surface a person must read; it does not replace the person.

The reasoned ceiling, including which limits are inherent and which are
merely unfixed, is in
[Limitations and Uncertainty](../explanation/limitations-and-uncertainty.md).
Coverage gaps and their effect on the verdict are in the
[Security Model](security-model.md).

## Related documentation

- [Security Model](security-model.md): guarantees and their enforcement.
- [Security Boundaries](security-boundaries.md): the `A1`-`A15` invariants.
- [Assurance Layers](assurance-layers.md): how evidence is grouped and what a
  layer label does not mean.
- [What a Result Claims](what-a-result-claims.md): the `B1`-`B11` clauses.
- [Rule Interpretation](../rules/interpretation.md): how to read a finding
  without over-reading it.
