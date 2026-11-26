<!-- description: U-series rules read the dependency manifests committed beside a recipe - across every language, from Cargo.toml/package.json/requirements.txt/pyproject.toml to go.mod, Gemfile, pom.xml, *.csproj, pubspec.yaml, mix.exs and peers - which the tree walk and the diff already see, without a fetch or an extraction. -->

# Upstream Manifests

## Overview


TrustSight never fetches what a package declares (A2) and never extracts an
upstream archive (A8): the cargo stays sealed. But the dependency manifests
that ship *beside* a recipe are committed to the repository, so the existing
tree walk and diff already read them. A manifest whose contents changed
between sailings is evidence without a single seal being broken, and the
manifest is exactly the document a reviewer is entitled to read.

This layer sits between the declared `source=()` surface and the
`unpinned_build_deps` boundary: the committed manifests are the one window
the build-time registry blind spot has, and these rules are the sensor in
that window.

Most AUR packages commit only the PKGBUILD, so the manifests that matter live
inside the declared source archive. The optional `[upstream_scan]` lane (off by
default, server-side) closes that gap: for an allowlisted forge source with a
strong checksum it fetches the archive through `upstream_fetch.py`, verifies
the checksum, extracts the manifests in the sandboxed read-role worker, and
feeds them into this same state/delta path as `upstream/<path>`. The archive's
versioned root directory is dropped from that path: it carries the upstream
commit, and keeping it made every manifest read as removed and re-added
whenever the package moved to a new commit. The first observation is a
baseline, not an "added" delta. With the lane disabled - the default - these
rules see only what the AUR repository commits, and
[W011](unverifiable.md#w011) names that limit.

One rule lists at most 25 findings for a single package; a tree with more
manifests reports the remainder as one counted finding, so a large source
archive cannot turn one update into hundreds of rows.

Adding a dependency is ordinary packaging, so most of the series is a
weight-0 ledger. Only **fetch-surface extension** (a new remote source),
**an origin move**, and **a redirected resolver** score. On the full-AUR
watcher, complete normalized manifest and workflow state is compared between
cycles; an incomplete read preserves the prior state instead of inventing a
delta.

This is a reference page. For how weight and scope work, see
[Rule Mechanics](mechanics.md).

## Reading a U finding

- U003, U004 and U011 are **MEDIUM floors, not ceilings**: corpus measurement
  decides the published rate, as with the X-series. A git dependency is
  normal in Rust `-git` packaging; a redirected resolver or origin is not.
- U001, U002, U006 and U012 are **weight 0** reader-facing ledgers and never
  move a number. U005 is also weight 0, but is feed-only: its primary consumer
  is the correlation feed rather than the default findings list.
- A manifest that cannot be parsed is named by
  [W009](unverifiable.md#w009), never skipped.

---

## Threat context

This is the discipline of **checking a citation against the original text**. A
paper can quote a source flawlessly and still be wrong, because the page it
cites was never printed. Upstream projects increasingly publish metadata about
themselves (release manifests, SBOMs, signature files, `.SRCINFO`-like
declarations), and the upstream-manifest rules compare what a recipe claims
about its source against what the upstream actually published: a version that
does not exist, a hash that does not match the manifest, a source name
upstream never released.

The point is to catch the recipe that is internally consistent but
*externally* wrong: checksums that verify against the wrong artifact, or a
`source` array naming a file no upstream release contains. This is the
supply-chain-integrity check turned outward - not "does this recipe agree with
itself?" but "does it agree with the world?".

## Detection mechanisms

The rules that make up this category are listed below, each with the series that implements it and the severity it carries. Scoring, matching and identifier allocation are shared across every category: see [Rule Mechanics](mechanics.md).

## Individual rules

<!-- generated: page-index -->
| Rule | Name | Severity |
|---|---|---|
| [U001](#u001) | Manifest Added Or Removed | INFO |
| [U002](#u002) | Upstream Dependency Delta | INFO |
| [U003](#u003) | New Remote Source In Manifest | MEDIUM |
| [U004](#u004) | Registry Redirect | MEDIUM |
| [U005](#u005) | Dependency Surface Jump | INFO |
| [U006](#u006) | Manifest Changed Without Its Lockfile | INFO |
| [U011](#u011) | Upstream Origin Changed | MEDIUM |
| [U012](#u012) | Lockfile Integrity Weakened | INFO |
| [U015](#u015) | Federated Upstream Manifest Delta | INFO |
<!-- /generated: page-index -->

### U001: Manifest Added Or Removed {#u001}

- **Target:** committed manifest files
- **Severity:** INFO (weight 0)
- **Category:** `dependency-manifest`

- **Condition:** A known manifest (from `[patterns] manifest_filenames`) is
  added to or removed from the repository in the diff.

Ledger only. A new or removed manifest changes what the committed dependency
surface is, but its mere presence is not a claim about intent.

### U002: Upstream Dependency Delta {#u002}

- **Target:** committed manifest files
- **Severity:** INFO (weight 0)
- **Category:** `dependency-manifest`

- **Condition:** A manifest's parsed dependency set gains or loses a name.

A declared-surface ledger entry, presented with its own group and the
"TrustSight does not verify these" line: it reports the names the committed
manifest added or removed, never scores them (B10). Lockfile churn is
reported as counts and named top-level dependencies, not a full delta.

### U003: New Remote Source In Manifest {#u003}

- **Target:** committed manifest files
- **Severity:** MEDIUM (weight 15)
- **Category:** `dependency-manifest`

- **Condition:** A manifest gains a `source_kind=git` dependency, or a
  non-default-registry dependency, whose canonical host was not present in
  the old manifest.

The scored core. The gained hosts are run through the same host
canonicalization as a `source=()` URL and join the run's `hosts_gained`
view, so host-novelty tiers, source buckets and the G-series treat a
manifest-introduced host exactly like a declared one. The claim is precise:
"the build will now fetch from a host the recipe did not declare."

The claim is per host, not per file: a monorepo can declare the same new
host in a dozen manifests, and that is one fact about the build. Manifests
under an example, integration, test, CI or documentation tree describe
someone else's project rather than the surface this package installs, so
they do not contribute.

### U004: Registry Redirect {#u004}

- **Target:** committed manifest files
- **Severity:** MEDIUM (weight 15)
- **Category:** `dependency-manifest`

- **Condition:** A committed file redirects the resolver away from its
  default: a pip `--index-url`/`--extra-index-url`, `pip.conf`/`pip.ini` or
  `.pypirc`; an npm `registry` override or `.yarnrc.yml`; a cargo `[source]`
  replacement or `[registries]`; a uv/poetry/pdm index; a composer
  `repositories` entry; a Maven `<repository>`; a NuGet package source; a
  conda/pixi channel; a Podfile `source` - added by this change.

A redirected resolver sends every dependency the build installs somewhere
other than the default registry, which is the destination a reviewer has no
other way to see.

### U005: Dependency Surface Jump {#u005}

- **Target:** committed manifest files
- **Severity:** INFO (weight 0)
- **Category:** `dependency-manifest`

- **Condition:** A manifest's dependency count multiplies past
  `[thresholds] u005.jump_factor` (default 3x) in one update.

Ledger only, and its primary consumer is the correlation feed: a dependency
surface that multiplies in one update is a campaign shape the G-series joins
across packages, not a per-package verdict.

### U006: Manifest Changed Without Its Lockfile {#u006}

- **Target:** committed manifest files
- **Severity:** INFO (weight 0)
- **Category:** `dependency-manifest`

- **Condition:** A declaration manifest (`go.mod`, `Cargo.toml`,
  `package.json`, `pyproject.toml`/`requirements*.txt`, `pubspec.yaml`,
  `mix.exs`, `stack.yaml`, `shard.yml`, `Package.swift`, `*.cabal`) changed in
  the diff but no lockfile that pins it did.

A real integrity signal (spec section 7.2): the resolved dependency set is not
committed alongside the declaration, so what the build will actually fetch is
unstated. It stays **weight 0** because VCS and library packaging legitimately
omit lockfiles - the corpus must adjudicate a scored rate before it can be
promoted.

### U011: Upstream Origin Changed {#u011}

- **Target:** committed manifest files
- **Severity:** MEDIUM (weight 15)
- **Category:** `dependency-manifest`

- **Condition:** A dependency present in both the old and new manifest changes origin (source kind or registry/host) while at least one side names one.

The declared origin moved under a dependency that already existed: a
registry entry became a git/VCS entry, or a lockfile entry started resolving
from a different registry or host. The build now fetches the same name from a
different place, which is the manifest-level counterpart of a source host
move. A dependency that merely appears or disappears is owned by U001/U002.

### U012: Lockfile Integrity Weakened {#u012}

- **Target:** committed manifest files
- **Severity:** INFO (weight 0)
- **Category:** `dependency-manifest`

- **Condition:** A dependency in a committed lockfile loses its integrity value, or its integrity algorithm is downgraded (e.g. `sha512` to `sha256`), or the lockfile itself is removed.

Verification of the dependency's bytes was weakened. INFO and weight 0: a
lockfile can legitimately drop integrity for a path or workspace entry, and
the finding is a review prompt rather than a scored change. The lockfile's
removal is reported here because the file that pinned every dependency is
gone.

### U015: Federated Upstream Manifest Delta {#u015}

- **Target:** declared upstream repository and version (federation-fed)
- **Severity:** INFO (weight 0)
- **Category:** `dependency-manifest`

- **Condition:** A signed `upstream_manifest` federation entry names the
  `host/owner/repo` and `pkgver` this recipe declares, carrying the bounded
  projection a server-side scan observed (new remote hosts, dependency
  changes, resolver redirects).

The local analysis does not fetch: this is the signed result of the
server-side `[upstream_scan]` lane, reported at weight 0 (anergic) as an
indicator. A miss is uninformative.

## Interpretation

- The finding names the mismatch between the recipe and the upstream
  declaration, with both values.
- A manifest mismatch is often decisive: it means the thing being verified is
  not the thing the upstream intended, regardless of the recipe's own
  consistency.
- These rules need network access to the upstream manifest, so on an offline
  run they report reduced coverage rather than passing silently.

## Related documentation

- [Integrity and Verification](integrity.md)
