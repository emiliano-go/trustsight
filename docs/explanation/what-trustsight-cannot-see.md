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

TrustSight would score this package 0 (UNFLAGGED) because nothing in the PKGBUILD changed except the version and checksum. The attack is invisible to PKGBUILD-level auditing. The defense against this class of attack is upstream signing and reproducible builds, not diff analysis.

### What can be tracked instead

The payload is out of reach, but the *carrier* has an identity, and that
identity is in the diff even when its bytes are not. A checksum, a commit, a
submodule gitlink, a Git-LFS object id and a committed binary's blob id all
name content this analysis never reads - and a change to one of them, with no
corresponding version change, is the observable form of "the code was
replaced".

That reading is what [R079](../reference/rules/integrity.md#r079) already
applies to a git ref and [C001](../reference/rules/integrity.md#c001) to a
checksum, and [C008](../reference/rules/integrity.md#c008) now applies it to
the rest. The binary case needed no new reading at all: a git blob id *is* a
content hash, so comparing two trees answers "did this file change" exactly,
without opening either version. That matters because git emits no diff body
for a binary, so before this the analysis reported the same thing whether a
committed ELF had been replaced or left untouched.

This does not close the gap - it changes what the gap costs. An attacker who
swaps upstream content must now do it either under a new version, where the
change is expected and the reader is looking, or under a stable one, where it
is claimed. What remains genuinely invisible is a *first* analysis, which has
no previous identity to compare against, and a legitimate upstream release
that happens to contain a payload: no amount of tracking distinguishes that
from an ordinary update.

### The build driver is part of the tarball

The same limit has a shape that looks less like "upstream was compromised" and more like an ordinary recipe. A tarball carries its own build files, and a PKGBUILD that runs `make` executes them:

```bash
source=("https://upstream.example/p-1.0.tar.gz")
sha256sums=('...')
build() {
  cd "$srcdir/p-1.0"
  make
}
```

Every verb here is the most ordinary thing a PKGBUILD does. The code that runs is in the `Makefile` inside the tarball, which this analysis never downloads and never reads.

It is not about `make` specifically. Every driver has this property - `cmake --build`, `ninja -C`, `autoreconf && ./configure`, `python setup.py build`, and equally `sh p-1.0/bootstrap.sh` or `perl p-1.0/Makefile.PL`. An execution is paired with a file this analysis can read only when that file is *individually declared* in `source=()` (R138) or *committed to the AUR repository* (R136). A script inside a declared tarball is neither: the tarball is declared as one entry, its contents are never read, and no rule knows the script exists.

Nor is the answer to add the verbs. Measured against the 3,246-diff locked benign corpus, executing a path that is neither declared nor committed is what **half** of all packages do - `python setup.py build`, `bash ./autogen.sh`, `./configure` are the ordinary shape of building software. A rule over that would fire on the corpus more often than not, and a coverage gap over it would put most packages into Inconclusive permanently. Either would replace a precise instrument with a warning nobody can act on.

There is a third option, and it is the one taken: **say it without pricing it.** `W001` reports that a build function runs a script whose content this analysis never read, and contributes nothing to the score, the risk band or the flagged decision. It is not a risk claim - it is a statement about what could not be checked, attached to the line it applies to, which is the same act as a coverage gap moved from the run to the line. See [Unverifiable](../reference/rules/unverifiable.md).

That leaves the *documented* boundary narrower than it was. The excluded majority above - the standard entry points of an unpacked tree, `configure`, `setup.py`, `Makefile.PL`, `autogen.sh` - stays excluded, because naming them would put a note on most of the ecosystem while telling a reader nothing they do not already assume. What `W001` names is the remainder: an interpreter invoked on a specific file from the tree, or a `./` invocation, where nothing else in the ruleset could speak. That is 0.09% of the benign corpus. The tarball's *contents* remain unread - `W001` says that a script inside it ran, never what the script does.

Two adjacent cases *are* covered, and the boundary between them is worth being precise about:

- A `Makefile` **committed to the AUR repository** and not declared in `source=()` is code the maintainer added, not code that arrived with the tarball. `R136` fires on it (see [Fetch and Execution](../reference/rules/fetch-and-execution.md#r136)).
- A source that is **not pinned** - `git+https://…#branch=main`, or a bare `git+` URL - means the content is chosen by upstream at build time rather than fixed by this recipe. That is reported as `P008`, a weight-0 declared fact.

What is left is the checksum-pinned tarball. There the content *is* fixed by the recipe: changing it requires changing the checksum, and that change is in the diff. So the recipe-level analysis has real, if indirect, coverage - it can tell you the meal came from the same sealed tin, not what is in the tin.

## The parser boundary

PKGBUILDs are shell scripts with structure. Not all structure is resolvable without execution. When the parser encounters:

- Unresolvable variable references in source URLs: `source=("https://example.com/$pkgver.tar.gz")` where `$pkgver` is set by a function call the parser cannot evaluate.
- Conditional expressions that determine command execution: `if [[ "$CARCH" = "x86_64" ]]; then source+=("https://example.com/specific-binary"); fi`.
- Dynamically constructed command strings: `local cmd="curl $url | $shell"; eval "$cmd"`.
- Loop-generated sources: `for pkg in "${pkgs[@]}"; do source+=("https://example.com/$pkg.tar.gz"); done`.

Where this affects a `source=` entry, the pipeline records the `unresolved_source` coverage gap, and the run is reported as `Inconclusive` rather than UNFLAGGED. Reporting "could not verify" is more honest than guessing. The other constructions above are seen as text and matched as text: a conditional branch is not taken, but the command inside it is still read.

### Why not execute the PKGBUILD

Running the PKGBUILD to resolve variables would produce accurate resolution but at the cost of executing untrusted code. A malicious PKGBUILD could detect execution and behave differently, or it could perform harmful actions during the attempted resolution. TrustSight is a static analysis tool by design; it does not execute PKGBUILDs, sandboxed or otherwise, because execution introduces both a security boundary problem and a behavioral ambiguity problem (the PKGBUILD might detect the sandbox and hide its true behavior).

## Build-dependency blind spot

Dependency changes (`depends`, `makedepends`, `optdepends`) are filtered out of *pattern* matching: `rules.py` strips those lines before any rule runs. Dependencies change frequently and legitimately, so matching patterns inside them produces a false-positive rate too high to be useful.

The trade-off used to be that a dependency-based attack was entirely invisible. The [D-series rules](../reference/rules/system.md#d-series) narrow that gap by asking a different question. Rather than pattern-matching the text, they compare the dependency arrays before and after the diff and check each newly added name against every dependency name ever observed in the AUR. A name nobody has ever depended on is rare and worth attention, where "this line mentions a package" is not.

This narrows the gap; it does not close it:

- A backdoor introduced into an *established* dependency is still invisible. D001 asks whether the **name** is novel, not whether the package behind it is trustworthy. Depending on a popular library that was itself compromised upstream produces no signal at all, and that is the same upstream-payload gap described above.
- Removing a dependency is not scored. Dropping a hardening library is a real weakening, but it is indistinguishable from ordinary cleanup.
- The rules are only as good as the seeded corpus. Against an unseeded database, D001 stays silent by design rather than flagging every dependency it sees.

The D-series is enabled by default since v0.7.0; see [`[experimental_rules]`](../reference/configuration.md#experimental_rules).

## Registry-payload gap

Campaign and corpus rules can identify a **shape**: coordinated package
adoptions, synchronized metadata changes, or several packages converging on a
shared source reference. That context can make a reviewer look harder, but it
does not make registry content visible. TrustSight never downloads or executes
the bytes that npm, PyPI, Cargo, or another registry returns to an unpinned
build-time dependency. It therefore cannot determine whether that payload is
malicious, whether a registry served different bytes to different users, or
whether a lockfile accurately represents what was installed. `unpinned_build_deps`
is reported as a coverage gap for this reason.

## Deliberately-unremarkable PKGBUILDs

A malicious PKGBUILD that contains no detectable patterns (no `curl`, no `base64`, no checksum changes, no new URLs, no untrusted source buckets) will score 0. The tool detects *patterns associated with compromise*, not compromise itself. An attacker who knows the rule set can craft a PKGBUILD that evades all signals.

### The adversarial context

This is not a theoretical risk. TrustSight's rules are public (defined in `rules.toml` and documented in the reference section). An attacker can test their PKGBUILD against the tool and adjust until it scores 0. This is a fundamental property of any signature-based detection system: the defender publishes rules, the attacker optimizes against them.

TrustSight mitigates this in three ways:

1. **Novelty signals (tier C) catch patterns the rules do not anticipate.** An attacker who carefully avoids every known pattern but adds a URL from an unknown domain is caught by the source bucket classifier. An attacker who reuses a known domain but changes the path may be caught by URL novelty tracking.
2. **The scoring model is additive, not a pass/fail gate.** An UNFLAGGED verdict means no structural patterns were detected and no gaps were recorded; it does not mean the package is safe. The score is a continuous measure, and low scores still warrant review if the reviewer is concerned.
3. **Deterministic verdicts ensure full disclosure.** Rule-based templates describe every triggered signal; a compromised package that triggers no rules but has a novel URL on an unknown domain will still score above 0 and the verdict will still flag the unknown domain.

None of these mitigations eliminate the problem. A PKGBUILD that reuses well-known domains, has stable checksums, and contains no detectable command patterns will score 0 regardless of the tarball content at the other end of the checksum.

## The novelty ceiling (R103/R109)

The ruleset detects *known patterns and reuse*: commands, hosts, checksums, maintainers, and dependency names that match a documented signature or have been observed before. It does not detect novelty in general. An attacker with fresh infrastructure and no known pattern is not caught by most rules; that ceiling is what the R103/R109 tier codifies. R126 (adopt-then-immediately-modify) is the exception: it fires on the *first* package of a campaign timeline, from the maintainer field and commit times, before any novel payload shape appears.

The composition rules that narrow this ceiling are grounded in real events. R089 (attack-chain composition) exists because both the 2018 acroread supply-chain attack and the 2026 Atomic Arch campaign progressed through multiple distinct kill-chain stages, and requiring several stages to co-occur is how the rule separates a genuine chain from single-stage noise.

## The limits of corpus-based detection

The corpus prior is optional and only as good as the corpus. Structural rules
continue to run without it; novelty, dependency-history, and longitudinal
signals are deliberately silent or reduced rather than treating an empty state
as evidence. When an operator uses it, three failure modes exist:

1. **A new legitimate domain that appears in exactly one package is classified as `unknown` and penalized.** This is a false positive. Source buckets are static configuration, so corpus observations do not change it; an operator must deliberately classify the domain if that is appropriate.

2. **A compromised domain that is already well-established in the corpus is classified as `trusted_forge` or `official` and not penalized.** If an attacker compromises a popular GitHub repository and pushes a malicious PKGBUILD from that repository, the source bucket classifier sees `github.com` (trusted) and does not add a penalty. The structural rules would need to catch the malicious commands directly.

3. **Configuration lag.** A legitimate domain remains `unknown` until the configured source-bucket lists are updated. Corpus regeneration cannot promote it, by design.

## What INCONCLUSIVE means

`INCONCLUSIVE` exists precisely because of these limits. It means the tool could not form a picture, not that the picture is good. Treat it as requiring manual review.

It is triggered by exactly two things:

- **A coverage gap**: the diff was truncated, a line was longer than the matching limit, the repository tree was unavailable, or a `source=` entry is computed at build time. Any of these forbids an UNFLAGGED verdict.
- **A cold database**: a Medium-band score held up entirely by novelty, with fewer than 25 recorded analyses behind it, the point where maturity crosses 0.5.

A HIGH, CRITICAL or FATAL finding is never downgraded this way; it keeps its band, because hiding a confirmed finding behind "inconclusive" would lose the thing that matters most.

When INCONCLUSIVE is reported, the output still shows the evidence breakdown and names the gap, so the reviewer can see both what fired and what was never examined. The exact rule, and the gate that enforces it, are in [the security model](../security.md#b2-an-unflagged-verdict-is-never-issued-for-an-analysis-that-was-incomplete).
