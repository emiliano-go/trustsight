<!-- description: Where the upstream-release rules come from (a declared upstream's build automation and the source transports a local read cannot reach) and what a finding means. -->

# Upstream Release Integrity

Mechanics live on the [Upstream Release Integrity system page](../rules/upstream-release.md).

<!-- generated: nature-rules -->
**Rules in this nature:** [U007](../rules/upstream-release.md#u007), [U008](../rules/upstream-release.md#u008), [U009](../rules/upstream-release.md#u009), [U010](../rules/upstream-release.md#u010) (4 rules).
<!-- /generated: nature-rules -->

## Where it comes from

A recipe names the upstream it trusts: a `url=`, a set of `source=()`
entries, sometimes a `validpgpkeys=`. That declaration is a promise about
code the reviewer usually cannot see. The upstream-release family is the
reading of that promise at the border.

Two of its rules look at build automation. The workflow lives in the
upstream repository, and A2 forbids a local analyser from fetching it, so a
scanner with legitimate access publishes a signed `upstream_repo` shape over
the federation channel. U007 and U008 consume that shape; they never read
the workflow themselves. When the channel is cold, a miss is reported as a
boundary rather than as absence of malice.

The other two read only the recipe the diff already carries. U009 notes a
workflow committed beside the package, and U010 reads the access mode of a
source the diff gained: SSH, `file://`, a private-network literal, or an
embedded credential.

The same signed channel carries `upstream_hash`: an exact
`url|version|checksum` triple a scanner observed at the vendor. C001 reads
it to corroborate a checksum change the local source cannot explain: a
match reports the change at weight 0, a miss leaves the HIGH weight alone.

The spec's flagship, a release re-tagged under an unchanged URL and
version, is already [C001 Checksum Changed Without Source
Change](../rules/integrity.md). This family does not file it twice. On the
8,393-diff benign corpus C001 fires on 5 (0.13%), the false-positive floor the
re-tag reading carries against ordinary package churn.

## What a finding means

- A U007/U008 finding attributes an upstream repository to a published,
  signed shape. It is evidence from the federation channel, not a local
  fetch, and it never lowers a score.
- U009 is a weight-0 ledger entry: a new automation surface in the package
  repository is worth noting, not scoring. It corroborates U007/U008 or an
  IOC hit when they co-occur.
- U010 says the public cannot inspect a declared source. Without
  `validpgpkeys` the finding is amplified: nobody can see the source and no
  signature vouches for it. Corporate intranet packages legitimately look
  like this, which is why it is a review-queue signal and not a verdict.
- None of these rules reads upstream content. A finding is about a
  declaration or a signed observation, never about the cargo inside the
  box.

## See also

- [Upstream Manifests](upstream-manifests.md); the declared repository tree
- [Indicators](indicator.md); the signed-data mechanism the federation rules use
- [Integrity and Verification](integrity.md); the checksum promise C001 reads
