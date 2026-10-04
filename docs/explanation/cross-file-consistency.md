<!-- description: How TrustSight compares a recipe against the other files that describe or ship with it, which cross-file checks exist today, and the residuals a future rule would close. -->

# Cross-File Consistency

A package is more than a `PKGBUILD`. The same facts are stated again in
`.SRCINFO`, committed files are named by the recipe, and an `install=`
declaration points at a scriptlet that ships beside it. An analysis that
reads one document can be misled by another that says something different:
the recipe fetches one host while the metadata names another, a build
executes a committed file the recipe never mentions, or a declared hook is
not in the tree at all. These are cross-file questions, and no single-line
regex can ask them.

## What is checked today

| Check | Rule or gap | Compares |
|-------|-------------|----------|
| Metadata names a source the recipe does not | H092 | `.SRCINFO` hosts against PKGBUILD hosts |
| Metadata and recipe disagree on a security-relevant field | H103 | `install=`, checksum arrays and `depends` between the two documents |
| A named hook is not in the committed tree | `tree_not_analyzed` | `install=` against the snapshot manifest |
| A committed file is executed without being declared | H081 | build commands against committed file names |
| A downloaded source file is executed | H083 | `source=()` entries against execution sites |
| A committed payload is inspected | H066-tree | the snapshot manifest against the rule's own reading |
| The hook script ships with the declaration | H100 | `install=` against the diff's file list |

The most important property is the one all of these share: the analysis
prefers the document it trusts least. The PKGBUILD is what `makepkg`
runs, `.SRCINFO` is a generated convenience that makepkg does not read,
and a committed file is only as good as the recipe that names it. When
they disagree, the disagreement itself is the signal.

## How H103 compares

H103 is the value-level comparison this page used to record as open. It
compares `install=`, the checksum arrays and `depends`, and only when both
documents carry the field and neither side has an unresolved variable:
anything else reads as "not seen", never as a divergence. A stale `pkgver`
alone is silent because it changes nothing the build does, and reordering
is silent because the comparison is a set. That conservatism is what keeps
a stale `.SRCINFO` - the ordinary shape of an AUR package whose maintainer
forgot `makepkg --printsrcinfo` - from firing.

## Residual gaps

- **H092 is one-directional and host-only.** It reports a host `.SRCINFO`
  names and the recipe does not. H103 compares its fields symmetrically,
  but a host only the recipe names is not reported by H092, and a URL path
  or checksum *value* difference is invisible to it.
- **H103 compares a short field list.** `install=`, the checksum arrays and
  `depends`; `license`, `provides`, `conflicts` and the rest stay
  uncompared, and a field carrying an unresolved variable is skipped.
- **Richer-side reads are still uncompared outside H103.** Property
  extraction and the review path prefer `.SRCINFO` for `depends` and
  `license`; H103 compares `depends`, but `license` is read from one side
  only.
- **A caller-supplied `.SRCINFO` need not match the PKGBUILD.** The API's
  text path takes both as arguments, so the pair may describe different
  revisions; the review and corpus paths read both from the same commit.

The per-line `source = value` spelling is no longer accepted inside
PKGBUILD text: it is honoured only in a `.SRCINFO` section, where it is a
real generated declaration, so a line makepkg never reads can no longer
mark a download as declared.

## See also

- [What TrustSight Cannot See](what-trustsight-cannot-see.md): the general limit this page narrows.
- [Evidence Tiers](../reference/evidence-tiers.md): how declared facts are reported.
- [Rules Reference](../reference/rules/index.md): H081, H083, H092, H103 and the rest.
