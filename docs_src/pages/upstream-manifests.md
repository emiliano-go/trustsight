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
