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

## Residual gaps

- **H092 is one-directional.** It reports a host `.SRCINFO` names and the
  recipe does not. A host the recipe names and the metadata omits is not
  reported, and the comparison is host-only: a different URL path, checksum
  or dependency list is invisible to it.
- **Richer-side reads are uncompared.** Property extraction and the review
  path prefer `.SRCINFO` for `depends` and `license`; nothing compares
  those values against the PKGBUILD's, and a stale `.SRCINFO` is the
  ordinary shape of an AUR package whose maintainer forgot
  `makepkg --printsrcinfo`.
- **A `.SRCINFO` spelling is accepted inside PKGBUILD text.** The declared
  source reader honours the per-line `source = value` form used in
  `.SRCINFO` when it appears in a PKGBUILD, where no shell ever treats it
  as a declaration. Removing that acceptance is a rule change with its own
  fixtures and fire-rate gate, so it is recorded here rather than folded
  into a parser migration.
- **A caller-supplied `.SRCINFO` need not match the PKGBUILD.** The API's
  text path takes both as arguments, so the pair may describe different
  revisions; the review and corpus paths read both from the same commit.

## Where a value-level rule would go

A rule that compares the security-relevant keys (`pkgver`, `install=`,
checksum arrays, `depends`) between the two documents would extend H092
rather than replace it: the host check keeps its calibration history, and
the value comparison needs its own fire-rate measurement on the locked
corpus before it ships. The readers already exist (`srcinfo.parse_srcinfo`
and the typed recipe), so the work is a rule, a fixture pair, and a
measurement, not a new parser.

## See also

- [What TrustSight Cannot See](what-trustsight-cannot-see.md): the general limit this page narrows.
- [Evidence Tiers](../reference/evidence-tiers.md): how declared facts are reported.
- [Rules Reference](../reference/rules/index.md): H081, H083, H092 and the rest.
