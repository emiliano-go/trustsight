# What TrustSight Cannot See

This page describes the reasoned ceiling of the tool. These are not bugs; they are inherent limits of auditing *PKGBUILD metadata* rather than *build artifacts*. Understanding these limits is part of using the tool responsibly.

## The upstream-payload gap

A PKGBUILD is a recipe, not a meal. A signed, version-bumped PKGBUILD with a checksum that matches a backdoored tarball is invisible to this tool. The audit checks the recipe, not the cooked meal.

This is the fundamental limit. TrustSight can tell you that the recipe looks normal. It cannot tell you that the tarball at the other end of that checksum is safe.

## The parser boundary

PKGBUILDs are shell scripts with structure. Not all structure is resolvable without execution. When the parser encounters:

- Unresolvable variable references in source URLs
- Conditional expressions that determine command execution
- Dynamically-constructed command strings

...the result is `INCONCLUSIVE`, not score 0. Reporting "couldn't verify" is more honest than guessing. The parser refuses to resolve what it cannot determine statically.

## Build-dependency blind spot

Dependency changes (`depends`, `makedepends`, `optdepends`) are filtered out of the analysis. This avoids false positives from routine dependency updates, but it also means a compromised build dependency is not detected as a signal. A PKGBUILD that adds a compromised build tool as a dependency will not be flagged for that change.

## Deliberately-unremarkable PKGBUILDs

A malicious PKGBUILD that contains no detectable patterns : no `curl`, no `base64`, no checksum changes, no new URLs, no untrusted source buckets; will score 0. The tool detects *patterns associated with compromise*, not compromise itself. An attacker who knows the rule set can craft a PKGBUILD that evades all signals.

## Sandbox-aware malware

When the sandbox module is available (see [Sandbox Security Model](sandbox-security-model.md)), it provides behavioral signals. But sandbox-aware malware (code that detects it is running in a container or namespace and alters its behaviour) is unwinnable. "Observed clean" does not mean safe.

## What INCONCLUSIVE means

`INCONCLUSIVE` exists precisely because of these limits. It means: *"the tool saw enough uncertainty to refuse scoring."* It is not a pass or a fail; it is a signal that the tool's analysis could not complete. Users should treat `INCONCLUSIVE` as requiring manual review.
