# What TrustSight Cannot See

This page describes the reasoned ceiling of the tool. These are not bugs; they are inherent limits of auditing *PKGBUILD metadata* rather than *build artifacts*. Understanding these limits is part of using the tool responsibly.

## The upstream-payload gap

A PKGBUILD is a recipe, not a meal. A signed, version-bumped PKGBUILD with a checksum that matches a backdoored tarball is invisible to this tool. The audit checks the recipe, not the cooked meal.

This is the fundamental limit. TrustSight can tell you that the recipe looks normal. It cannot tell you that the tarball at the other end of that checksum is safe. The checksum verification step in pacman will catch a tampered tarball *after* download, but that verification is downstream of the audit; TrustSight cannot pre-verify a tarball it never downloads.

### What this means in practice

A sophisticated attack against an established package would:

1. Compromise the upstream maintainer's signing key or CI pipeline.
2. Push a legitimate-looking PKGBUILD update with a version bump, a checksum matching the backdoored tarball, and no additional commands.
3. The backdoor is in the tarball, not the PKGBUILD.

TrustSight would score this package 0 (CLEAN) because nothing in the PKGBUILD changed except the version and checksum. The attack is invisible to PKGBUILD-level auditing. The defense against this class of attack is upstream signing and reproducible builds, not diff analysis.

## The parser boundary

PKGBUILDs are shell scripts with structure. Not all structure is resolvable without execution. When the parser encounters:

- Unresolvable variable references in source URLs: `source=("https://example.com/$pkgver.tar.gz")` where `$pkgver` is set by a function call the parser cannot evaluate.
- Conditional expressions that determine command execution: `if [[ "$CARCH" = "x86_64" ]]; then source+=("https://example.com/specific-binary"); fi`.
- Dynamically constructed command strings: `local cmd="curl $url | $shell"; eval "$cmd"`.
- Loop-generated sources: `for pkg in "${pkgs[@]}"; do source+=("https://example.com/$pkg.tar.gz"); done`.

In all these cases, the parser marks the relevant fields as unresolvable and the pipeline produces `INCONCLUSIVE`, not score 0. Reporting "could not verify" is more honest than guessing.

### Why not execute the PKGBUILD

Running the PKGBUILD to resolve variables would produce accurate resolution but at the cost of executing untrusted code. A malicious PKGBUILD could detect execution and behave differently, or it could perform harmful actions during the attempted resolution. TrustSight is a static analysis tool by design; it does not execute PKGBUILDs, sandboxed or otherwise, because execution introduces both a security boundary problem and a behavioral ambiguity problem (the PKGBUILD might detect the sandbox and hide its true behavior).

## Build-dependency blind spot

Dependency changes (`depends`, `makedepends`, `optdepends`) are filtered out of *pattern* matching: `rules.py` strips those lines before any rule runs. Dependencies change frequently and legitimately, so matching patterns inside them produces a false-positive rate too high to be useful.

The trade-off used to be that a dependency-based attack was entirely invisible. The [D-series rules](../reference/rules.md#d-series) narrow that gap by asking a different question. Rather than pattern-matching the text, they compare the dependency arrays before and after the diff and check each newly added name against every dependency name ever observed in the AUR. A name nobody has ever depended on is rare and worth attention, where "this line mentions a package" is not.

This narrows the gap; it does not close it:

- A backdoor introduced into an *established* dependency is still invisible. D001 asks whether the **name** is novel, not whether the package behind it is trustworthy. Depending on a popular library that was itself compromised upstream produces no signal at all, and that is the same upstream-payload gap described above.
- Removing a dependency is not scored. Dropping a hardening library is a real weakening, but it is indistinguishable from ordinary cleanup.
- The rules are only as good as the seeded corpus. Against an unseeded database, D001 stays silent by design rather than flagging every dependency it sees.

The D-series is enabled by default since v0.7.0; see [`[experimental_rules]`](../reference/configuration.md#experimental_rules).

## Deliberately-unremarkable PKGBUILDs

A malicious PKGBUILD that contains no detectable patterns (no `curl`, no `base64`, no checksum changes, no new URLs, no untrusted source buckets) will score 0. The tool detects *patterns associated with compromise*, not compromise itself. An attacker who knows the rule set can craft a PKGBUILD that evades all signals.

### The adversarial context

This is not a theoretical risk. TrustSight's rules are public (defined in `rules.toml` and documented in the reference section). An attacker can test their PKGBUILD against the tool and adjust until it scores 0. This is a fundamental property of any signature-based detection system: the defender publishes rules, the attacker optimizes against them.

TrustSight mitigates this in three ways:

1. **Novelty signals (tier C) catch patterns the rules do not anticipate.** An attacker who carefully avoids every known pattern but adds a URL from an unknown domain is caught by the source bucket classifier. An attacker who reuses a known domain but changes the path may be caught by URL novelty tracking.
2. **The scoring model is additive, not a pass/fail gate.** A score of 5 or 10 is not a clean bill of health; it means no structural patterns were detected, not that the package is safe. The score is a continuous measure, and low scores still warrant review if the reviewer is concerned.
3. **Deterministic verdicts ensure full disclosure.** Rule-based templates describe every triggered signal; a compromised package that triggers no rules but has a novel URL on an unknown domain will still score above 0 and the verdict will still flag the unknown domain.

None of these mitigations eliminate the problem. A PKGBUILD that reuses well-known domains, has stable checksums, and contains no detectable command patterns will score 0 regardless of the tarball content at the other end of the checksum.

## The novelty ceiling (R103/R109)

The ruleset detects *known patterns and reuse*: commands, hosts, checksums, maintainers, and dependency names that match a documented signature or have been observed before. It does not detect novelty in general. An attacker with fresh infrastructure and no known pattern is not caught by most rules; that ceiling is what the R103/R109 tier codifies. R126 (adopt-then-immediately-modify) is the exception: it fires on the *first* package of a campaign timeline, from the maintainer field and commit times, before any novel payload shape appears.

The composition rules that narrow this ceiling are grounded in real events. R089 (attack-chain composition) exists because both the 2018 acroread supply-chain attack and the 2026 Atomic Arch campaign progressed through multiple distinct kill-chain stages, and requiring several stages to co-occur is how the rule separates a genuine chain from single-stage noise.

## The limits of corpus-based detection

The corpus prior is only as good as the corpus. Three failure modes exist:

1. **A new legitimate domain that appears in exactly one package is classified as `unknown` and penalized.** This is a false positive. It resolves as the corpus accumulates observations of the domain, but on first encounter it is indistinguishable from a malicious single-use domain.

2. **A compromised domain that is already well-established in the corpus is classified as `trusted_forge` or `official` and not penalized.** If an attacker compromises a popular GitHub repository and pushes a malicious PKGBUILD from that repository, the source bucket classifier sees `github.com` (trusted) and does not add a penalty. The structural rules would need to catch the malicious commands directly.

3. **Corpus regeneration lag.** Between weekly regenerations, new legitimate domains might be penalized as `unknown`. This resolves automatically at the next regeneration but can produce false positives for up to a week.

## What INCONCLUSIVE means

`INCONCLUSIVE` exists precisely because of these limits. It means: *"the tool saw enough uncertainty to refuse scoring."* It is not a pass or a fail; it is a signal that the tool's analysis could not complete. Users should treat `INCONCLUSIVE` as requiring manual review.

The INCONCLUSIVE state can be triggered by:

- Unresolvable source URL (parser could not determine what the source is).
- Score in Medium range driven entirely by novelty signals in a cold database.
- A combination of factors that prevent a confident CLEAN or FLAGGED classification.

When INCONCLUSIVE is triggered, the output still shows the partial evidence breakdown, so the reviewer can see what signals were or were not detected. The verdict is "inconclusive", not "clean", because the tool cannot assess confidence.
