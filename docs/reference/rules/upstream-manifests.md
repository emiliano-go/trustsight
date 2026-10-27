<!-- description: U-series rules read the dependency manifests committed beside a recipe - across every language, from Cargo.toml/package.json/requirements.txt/pyproject.toml to go.mod, Gemfile, pom.xml, *.csproj, pubspec.yaml, mix.exs and peers - which the tree walk and the diff already see, without a fetch or an extraction. -->

# Upstream Manifests

Where these rules come from and what a finding means: [Rule Nature](../nature/upstream-manifests.md).

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

Adding a dependency is ordinary packaging, so most of the series is a
weight-0 ledger. Only **fetch-surface extension** (a new remote source),
**an origin move**, and **a redirected resolver** score. On the full-AUR
watcher, complete normalized manifest and workflow state is compared between
cycles; an incomplete read preserves the prior state instead of inventing a
delta.

This is a reference page. For how weight and scope work, see
[Rule System](system.md).

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

<!-- generated: page-index -->
## Rules on this page

| Rule | Name | Severity |
|---|---|---|
| [U001](#u001) | Manifest Added Or Removed | INFO |
| [U002](#u002) | Upstream Dependency Delta | INFO |
| [U003](#u003) | New Remote Source In Manifest | MEDIUM |
| [U004](#u004) | Registry Redirect | MEDIUM |
| [U005](#u005) | Dependency Surface Jump | INFO |
| [U006](#u006) | Manifest Changed Without Its Lockfile | INFO |
| [U011](#u011) | Upstream Origin Changed | - |
| [U012](#u012) | Lockfile Integrity Weakened | - |
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

- **Condition:** A dependency present in both the old and new manifest changes origin (source kind or registry/host) while at least one side names one.

The declared origin moved under a dependency that already existed: a
registry entry became a git/VCS entry, or a lockfile entry started resolving
from a different registry or host. The build now fetches the same name from a
different place, which is the manifest-level counterpart of a source host
move. A dependency that merely appears or disappears is owned by U001/U002.

### U012: Lockfile Integrity Weakened {#u012}

- **Condition:** A dependency in a committed lockfile loses its integrity value, or its integrity algorithm is downgraded (e.g. `sha512` to `sha256`), or the lockfile itself is removed.

Verification of the dependency's bytes was weakened. INFO and weight 0: a
lockfile can legitimately drop integrity for a path or workspace entry, and
the finding is a review prompt rather than a scored change. The lockfile's
removal is reported here because the file that pinned every dependency is
gone.
